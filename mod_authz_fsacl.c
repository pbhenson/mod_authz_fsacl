/*
 * Filesystem ACL authorization module for Apache
 *
 * Paul B. Henson <henson@acm.org>
 *
 * Copyright (c) 2008,2009 Paul B. Henson -- see COPYRIGHT file for details
 *
 */

#include <grp.h>
#include <pwd.h>
#include <sys/acl.h>

/* Not defined in public acl header file */
typedef enum acl_type {
	ACLENT_T = 0,
	ACE_T = 1
} acl_type_t;

void *acl_data(acl_t *aclp);

#include "apr_errno.h"
#include "apr_file_info.h"
#include "apr_strings.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"

module AP_MODULE_DECLARE_DATA authz_fsacl_module;

/* Copied from mod_dir.c, must be updated if source changes. */
typedef struct dir_config_struct {
	apr_array_header_t *index_names;
} dir_config_rec;

static int authz_fsacl_check_user_id(request_rec *r) {

	const apr_array_header_t *reqs_arr = ap_requires(r);

	if (!reqs_arr) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			"authz_fsacl_check_user_id: no requires found (uri=%s)", r->uri);
		return DECLINED;
	}

	if (strcmp(((require_line *)reqs_arr->elts)[0].requirement, "fs-acl") != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			"authz_fsacl_check_user_id: require != fs-acl (uri=%s)", r->uri);
		return DECLINED;
	}
	
	if (r->finfo.filetype == APR_NOFILE) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			"authz_fsacl_check_user_id: no file found for request (uri=%s)", r->uri);
		return HTTP_NOT_FOUND;
	}

	if (*(r->path_info) != NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"authz_fsacl_check_user_id: found unexpected path_info (uri=%s)", r->uri);
		return HTTP_NOT_FOUND;
	}

	/* If it's a directory, look for index files */
	if (r->finfo.filetype == APR_DIR) {
		module *mod_dir_module = ap_find_linked_module("mod_dir.c");
		dir_config_rec *dir_config;

		if (mod_dir_module) {
			dir_config = (dir_config_rec *)ap_get_module_config(r->per_dir_config, mod_dir_module);
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

				if ((result = apr_stat(&finfo, index_path, APR_FINFO_PROT, r->pool)) != APR_SUCCESS) {
					if (APR_STATUS_IS_EACCES(result)) {
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
							"authz_fsacl_check_user_id: stat %s failed with EACCES", index_path);
						return HTTP_FORBIDDEN;
					}
					else if (!APR_STATUS_IS_ENOENT(result)) {
						ap_log_rerror(APLOG_MARK, APLOG_ERR, apr_get_os_error(), r,
							"authz_fsacl_check_user_id: unexpected stat failure on %s", index_path);
						return HTTP_INTERNAL_SERVER_ERROR;
					}
				}
				else {
					/* Save index path for next stage */
					ap_set_module_config(r->request_config, &authz_fsacl_module, index_path);

					if (finfo.protection & APR_FPROT_WREAD) {
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
							"authz_fsacl_check_user_id: index %s is world readable", index_path);
						return OK;
					}
					else {
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
							"authz_fsacl_check_user_id: index %s is not world readable", index_path);

						/* Let authentication modules do their thing */
						return DECLINED;
					}
				}
			}
		}
		else {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl_check_user_id: mod_dir not loaded");
		}
	}

	if (r->finfo.protection & APR_FPROT_WREAD) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl_check_user_id: %s is world readable", r->filename);
		return OK;
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl_check_user_id: %s is not world readable", r->filename);

	/* Let authentication modules do their thing */
	return DECLINED;
}

static int authz_fsacl_check_auth(request_rec *r) {

	const apr_array_header_t *reqs_arr = ap_requires(r);

	/* If we previously noted a directory index check it instead of the containing directory */
	char *index_path = (char *)ap_get_module_config(r->request_config, &authz_fsacl_module);
	char *path = index_path ? index_path : r->filename;

	struct group *gr;
	struct passwd *pw;
	acl_t *aclp;
	void *ace_list;
	int acl_index;
	int result = 0;

	if (!reqs_arr) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl_check_auth: no requires found (uri=%s)", r->uri);
		return DECLINED;
	}

	if (strcmp(((require_line *)reqs_arr->elts)[0].requirement, "fs-acl") != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl_check_auth: require != fs-acl (uri=%s)", r->uri);
		return DECLINED;
	}

	/* If there's no user for the request, the resource is world readable */
	if (!r->user) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl_check_auth: no user, auth skipped (uri=%s)", r->uri);
		return OK;
	}

	if ((pw = getpwnam(r->user)) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "authz_fsacl_check_auth: getpwnam failed for user %s (uri=%s)", r->user, r->uri);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (acl_get(path, 0, &aclp) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, apr_get_os_error(), r,
				"authz_fsacl_check_auth: acl_get failed for file %s (uri=%s)", path, r->uri);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (acl_type(aclp) != ACE_T) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"authz_fsacl_check_auth: invalid acl type for file %s (uri=%s)", path, r->uri);
		result = -1;
		goto acl_loop_end;
	}

	ace_list = acl_data(aclp);

	for (acl_index = 0; acl_index < acl_cnt(aclp); acl_index++) {

		ace_t *ace = (ace_t *)(ace_list+acl_index*sizeof(ace_t));

		if (ace->a_flags & (ACE_FILE_INHERIT_ACE|ACE_DIRECTORY_INHERIT_ACE))
			continue;

		if (ace->a_access_mask & ACE_READ_DATA) {

			if (ace->a_flags & ACE_EVERYONE) {
				if (ace->a_type == ACE_ACCESS_ALLOWED_ACE_TYPE) result = 1;
				goto acl_loop_end;
			}
			else if (ace->a_flags & (ACE_GROUP|ACE_IDENTIFIER_GROUP)) {
				gid_t gid = (ace->a_flags & ACE_GROUP) ? r->finfo.group : ace->a_who;

				char **member;

				if (pw->pw_gid == gid) {
					if (ace->a_type == ACE_ACCESS_ALLOWED_ACE_TYPE) result = 1;
					goto acl_loop_end;
				}

				if ((gr = getgrgid(gid)) == NULL) {
					ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
							"authz_fsacl_check_auth: getgrgid failed for group %d (uri=%s)", gid, r->uri);
					result = -1;
					goto acl_loop_end;
				}

				for (member = gr->gr_mem ; *member != NULL; member++) {
					if (strcmp(pw->pw_name, *member) == 0) {
						if (ace->a_type == ACE_ACCESS_ALLOWED_ACE_TYPE) result = 1;
						goto acl_loop_end;
					}
				}
			}
			else {
				uid_t uid = (ace->a_flags & ACE_OWNER) ? r->finfo.user : ace->a_who;

				if (pw->pw_uid == uid) {
					if (ace->a_type == ACE_ACCESS_ALLOWED_ACE_TYPE) result = 1;
					goto acl_loop_end;
				}
			}
		}
	} acl_loop_end:

	acl_free(aclp);

	if (result == 1) {
		return OK;
	}
	else if (result == 0) {
		return HTTP_FORBIDDEN;
	}
	else {
		return HTTP_INTERNAL_SERVER_ERROR;
	}
}

static void register_hooks(apr_pool_t *p) {

	ap_hook_check_user_id(authz_fsacl_check_user_id, NULL, NULL, APR_HOOK_FIRST);
	ap_hook_auth_checker(authz_fsacl_check_auth, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA authz_fsacl_module = {
	STANDARD20_MODULE_STUFF,
	NULL,				/* dir config creater */
	NULL,				/* dir merger --- default is to override */
	NULL,				/* server config */
	NULL,				/* merge server config */
	NULL,				/* command apr_table_t */
	register_hooks			/* register hooks */
};
