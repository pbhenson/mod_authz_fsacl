/*
 * Filesystem ACL authorization module for Apache
 *
 * Paul B. Henson <henson@acm.org>
 *
 * Copyright (c) 2008 Paul B. Henson -- see COPYRIGHT file for details
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

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"

static int authz_fsacl_check_user_id(request_rec *r) {

	const apr_array_header_t *reqs_arr = ap_requires(r);

	if (!reqs_arr) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl_check_user_id: no requires found");
		return DECLINED;
	}

	if (strcmp(((require_line *)reqs_arr->elts)[0].requirement, "fs-acl") != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl_check_user_id: require != fs-acl");
		return DECLINED;
	}
	
	if (r->finfo.filetype == APR_NOFILE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "authz_fsacl_check_user_id: no file found for request");
		return HTTP_NOT_FOUND;
	}

	if (*(r->path_info) != NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "authz_fsacl_check_user_id: found unexpected path_info");
		return HTTP_NOT_FOUND;
	}

	if (r->finfo.protection & APR_FPROT_WREAD) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl_check_user_id: requested file is world readable");
		return OK;
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl_check_user_id: requested file not world readable");

	/* Let authentication modules do their thing */
	return DECLINED;
}

static int authz_fsacl_check_auth(request_rec *r) {

	const apr_array_header_t *reqs_arr = ap_requires(r);
	struct group *gr;
	struct passwd *pw;
	acl_t *aclp;
	void *ace_list;
	int acl_index;
	int result = 0;

	if (!reqs_arr) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl_check_auth: no requires found");
		return DECLINED;
	}

	if (strcmp(((require_line *)reqs_arr->elts)[0].requirement, "fs-acl") != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl_check_auth: require != fs-acl");
		return DECLINED;
	}

	/* If there's no user for the request, the resource is world readable */
	if (!r->user) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authz_fsacl_check_auth: no user");
		return OK;
	}

	if ((pw = getpwnam(r->user)) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "authz_fsacl_check_auth: getpwnam failed for user %s", r->user);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (acl_get(r->filename, 0, &aclp) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, apr_get_os_error(), r,
				"authz_fsacl_check_auth: acl_get failed for file %s", r->filename);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (acl_type(aclp) != ACE_T) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"authz_fsacl_check_auth: invalid acl type for file %s", r->filename);
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
							"authz_fsacl_check_auth: getgrgid failed for group %d", gid);
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

