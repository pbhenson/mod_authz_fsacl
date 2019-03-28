/*
 * Filesystem ACL authorization module for Apache
 *
 * Paul B. Henson <henson@acm.org>
 *
 * Copyright (c) 2008-2019 Paul B. Henson -- see COPYRIGHT file for details
 *
 */

#include <grp.h>
#include <pwd.h>
#include <sys/acl.h>
#include "apr_errno.h"
#include "apr_file_info.h"
#include "apr_strings.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "mod_auth.h"

module AP_MODULE_DECLARE_DATA authz_fsacl_module;

/* Copied from mod_dir.c, must be updated if source changes. */
typedef struct dir_config_struct {
	apr_array_header_t *index_names;
} dir_config_rec;

static authz_status fsacl_check_authz(request_rec *r, const char *require_args,
				      const void *parsed_require_args) {
	char *index_file = NULL;
	struct group *gr;
	struct passwd *pw;
	acl_t *aclp;
	void *ace_list;
	int acl_index;
	int result = 0;

	if (r->finfo.filetype == APR_NOFILE) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
			"authz_fsacl: no file found for request (uri=%s)", r->uri);
		return AUTHZ_DENIED;
	}

	if (r->path_info && *r->path_info) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"authz_fsacl: found unexpected path_info (uri=%s)", r->uri);
		return AUTHZ_DENIED;
	}

	/* If it's a directory, look for index files */
	if (r->finfo.filetype == APR_DIR) {
		module *mod_dir_module = ap_find_linked_module("mod_dir.c");

		if (mod_dir_module) {
			dir_config_rec *dir_config = (dir_config_rec *)ap_get_module_config(r->per_dir_config,
											    mod_dir_module);
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl: looking for index files");
			char **names_ptr;
			int num_names;
			char *default_index[1];

			if (dir_config->index_names) {
				names_ptr = (char **)dir_config->index_names->elts;
				num_names = dir_config->index_names->nelts;
			}
			else {
				default_index[0] = AP_DEFAULT_INDEX;
				names_ptr = default_index;
				num_names = 1;
			}

			for (; num_names; ++names_ptr, --num_names) {
				apr_finfo_t finfo;
				apr_status_t result;

				char *index_path = apr_pstrcat(r->pool, r->filename, "/", *names_ptr, NULL);
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl: looking for index %s", index_path);
				if ((result = apr_stat(&finfo, index_path, APR_FINFO_PROT, r->pool)) != APR_SUCCESS) {
					if (APR_STATUS_IS_EACCES(result)) {
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
							"authz_fsacl: stat %s failed with EACCES", index_path);
						return AUTHZ_DENIED;
					}
					else if (!APR_STATUS_IS_ENOENT(result)) {
						ap_log_rerror(APLOG_MARK, APLOG_ERR, apr_get_os_error(), r,
							"authz_fsacl: unexpected stat failure on %s", index_path);
						return AUTHZ_GENERAL_ERROR;
					}
				}
				else if (finfo.protection & APR_FPROT_WREAD) {
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
						"authz_fsacl: index %s is world readable", index_path);
					return AUTHZ_GRANTED;
				}
				else {
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
						"authz_fsacl: index %s is not world readable", index_path);

					if (!r->user) {
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
							"authz_fsacl: returning AUTHZ_DENIED_NO_USER");
					        return AUTHZ_DENIED_NO_USER;
					}
					else {
						index_file = index_path;
						break;
					}
				}
			}
			if (!index_file) {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl: no index file found");
			}
		}
		else {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl: mod_dir not loaded");
		}
	}

	if (!index_file) {
		if (r->finfo.protection & APR_FPROT_WREAD) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl: %s is world readable", r->filename);
			return AUTHZ_GRANTED;
		}
		else {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl: %s is not world readable", r->filename);
			if (!r->user) {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
					"authz_fsacl: returning AUTHZ_DENIED_NO_USER");
			        return AUTHZ_DENIED_NO_USER;
			}
		}
	}

	if ((pw = getpwnam(r->user)) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "authz_fsacl: getpwnam failed for user %s (uri=%s)", r->user, r->uri);
		return AUTHZ_GENERAL_ERROR;
	}

	if (acl_get(index_file ? index_file : r->filename, 0, &aclp) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, apr_get_os_error(), r,
				"authz_fsacl: acl_get failed for file %s (uri=%s)", 
				index_file ? index_file : r->filename, r->uri);
		return AUTHZ_GENERAL_ERROR;
	}

	if (aclp->acl_type != ACE_T) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"authz_fsacl: invalid acl type for file %s (uri=%s)",
				index_file ? index_file : r->filename, r->uri);
		result = -1;
		goto acl_loop_end;
	}

	ace_list = aclp->acl_aclp;

	for (acl_index = 0; acl_index < aclp->acl_cnt; acl_index++) {

		ace_t *ace = (ace_t *)(ace_list+acl_index*sizeof(ace_t));

		if (ace->a_flags & ACE_INHERIT_ONLY_ACE)
			continue;

		/* XXX - deny entries are not currently handled properly */
		if (ace->a_access_mask & ACE_READ_DATA && ace->a_type == ACE_ACCESS_ALLOWED_ACE_TYPE) {

			if (ace->a_flags & ACE_EVERYONE) {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl: ace %d everyone", acl_index);
				result = 1;
				goto acl_loop_end;
			}
			else if (ace->a_flags & (ACE_GROUP|ACE_IDENTIFIER_GROUP)) {
				gid_t gid = (ace->a_flags & ACE_GROUP) ? r->finfo.group : ace->a_who;
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl: ace %d group %d", acl_index, gid);

				char **member;

				if (pw->pw_gid == gid) {
					result = 1;
					goto acl_loop_end;
				}

				if ((gr = getgrgid(gid)) == NULL) {
					ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
							"authz_fsacl: getgrgid failed for group %d (uri=%s)", gid, r->uri);
					result = -1;
					goto acl_loop_end;
				}

				for (member = gr->gr_mem ; *member != NULL; member++) {
					if (strcmp(pw->pw_name, *member) == 0) {
						result = 1;
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl: ace %d group matched", acl_index);
						goto acl_loop_end;
					}
				}
			}
			else {
				uid_t uid = (ace->a_flags & ACE_OWNER) ? r->finfo.user : ace->a_who;
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl: ace %d user %d", acl_index, uid);

				if (pw->pw_uid == uid) {
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl: ace %d user matched", acl_index);
					result = 1;
					goto acl_loop_end;
				}
			}
		}
		else {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl: ace %d not read/allow", acl_index);
		}
	} acl_loop_end:

	acl_free(aclp);

	if (result == 1) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl: returning AUTHZ_GRANTED", acl_index);
		return AUTHZ_GRANTED;
	}
	else if (result == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "authz_fsacl: permission denied user=%s uri=%s", r->user, r->uri);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl: returning AUTHZ_DENIED", acl_index);
		return AUTHZ_DENIED;
	}
	else {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl: returning AUTHZ_GENERAL_ERROR", acl_index);
		return AUTHZ_GENERAL_ERROR;
	}
}

static const authz_provider authz_fsacl_provider =
{
	&fsacl_check_authz,
	NULL,
};

static void register_hooks(apr_pool_t *p) {
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "fs-acl",
				  AUTHZ_PROVIDER_VERSION, &authz_fsacl_provider,
				  AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(authz_fsacl) =
{
	STANDARD20_MODULE_STUFF,
	NULL,				/* dir config creater */
	NULL,				/* dir merger --- default is to override */
	NULL,				/* server config */
	NULL,				/* merge server config */
	NULL,				/* command apr_table_t */
	register_hooks			/* register hooks */
};
