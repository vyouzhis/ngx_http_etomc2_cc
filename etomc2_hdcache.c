/*
 * =====================================================================================
 *
 *       Filename:  etomc2_hdcache.c
 *
 *    Description: hd cache  M_RED  M_GREEN  LOOP URI
 *
 *        Version:  1.0
 *        Created:  2020年04月18日 22时10分55秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  etomc2@etomc2.com (), etomc2@etomc2.com
 *   Organization:  etomc2.com
 *
 * =====================================================================================
 */
#include "etomc2.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <libgen.h>
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  hdcache_create_dir
 *  Description:
 * =====================================================================================
 */
int hdcache_create_dir(const char *path, const mode_t mode) {
    if (strcmp(path, "/") == 0)  // No need of checking if we are at root.
        return 0;

    struct stat st;
    char *pathnew = NULL;
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        // Check and create parent dir tree first.
        pathnew = strdup(path);
        if (pathnew == NULL) return -2;
        char *parent_dir_path = dirname(pathnew);
        if (hdcache_create_dir(parent_dir_path, mode) == -1) {
            free(pathnew);

            return -1;
        }
        // Create this dir.
        if (mkdir(path, mode) == -1) {
            free(pathnew);

            return -1;
        }

        free(pathnew);
    }

    return 0;

} /* -----  end of function hdcache_create_dir  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  hdcache_create_file
 *  Description:
 * =====================================================================================
 */
void hdcache_create_file(const char *path, int inten, int timestamp) {
    FILE *fp;
    fp = fopen(path, "w+");
    if (fp == NULL) return;
    fprintf(fp, "%d-%d", inten, timestamp);
    fclose(fp);
} /* -----  end of function hdcache_create_file  ----- */
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  hdcache_unlink_file
 *  Description:  
 * =====================================================================================
 */
int  hdcache_unlink_file ( const char *path ){
   int i = unlink(path);
    return i;
}		/* -----  end of function hdcache_unlink_file  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  hdcache_file_exist
 *  Description:
 * =====================================================================================
 */
int hdcache_file_exist(const char *file) {
    struct stat st = {0};
    return stat(file, &st);
} /* -----  end of function hdcache_file_exist  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  hdcache_file_content
 *  Description:
 * =====================================================================================
 */
int hdcache_file_content(const char *file, int *timestamp) {
    FILE *fp;
    fp = fopen(file, "r");
    if (fp == NULL) return -1;
    int m = -1;

    fscanf(fp, "%d-%d", &m, timestamp);
    fclose(fp);
    return m;
} /* -----  end of function hdcache_file_content  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  hdcache_file_build
 *  Description:
 * =====================================================================================
 */
ngx_str_t hdcache_file_build(ngx_http_request_t *r, ngx_str_t path,
        ngx_str_t file_name) {
    const char *fmt = "%.*s/%.*s";
    ngx_str_t file_path;
    file_path.len = snprintf(NULL, 0, fmt, path.len, path.data, file_name.len,
            file_name.data);
    file_path.len += 1;
    file_path.data = ngx_pcalloc(r->pool, file_path.len);
    if (!file_path.data) {
        file_path.len = 0;
        return file_path;
    }
    snprintf((char *)file_path.data, file_path.len, fmt, path.len, path.data,
            file_name.len, file_name.data);

    return file_path;
} /* -----  end of function hdcache_file_build  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  hdcache_hash_to_dir_def
 *  Description:
 * =====================================================================================
 */
ngx_str_t hdcache_hash_to_dir_def(ngx_http_request_t *r, const char *path,
        uint32_t num, CC_THIN_COOKIE_MARK mark) {

    ngx_str_t dir;
    /** const char *path = "/var/cache/nginx/hdcache"; */

    const char *path_fmt = "%s/%d/%d/%d/%d/%d/%d";
    dir.len = 0;
    /** uint32_t pnum = num; */
    int pname[5];
    int m = 0;
    while (num > 0)  // do till num greater than  0
    {
        uint32_t mod = num % 100;  // split last digit from number
        pname[m] = mod;
        m++;

        num = num / 100;  // divide num by 10. num /= 10 also a valid one
    }

    dir.len = snprintf(NULL, 0, path_fmt, path, mark, pname[0], pname[1],
            pname[2], pname[3], pname[4]);

    dir.len += 1;
    dir.data = ngx_pcalloc(r->pool, dir.len);
    if (!dir.data) return dir;
    snprintf((char *)dir.data, dir.len, path_fmt, path, mark, pname[0],
            pname[1], pname[2], pname[3], pname[4]);

    return dir;
} /* -----  end of function hdcache_hash_to_dir_def  ----- */
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  hdcache_hash_to_dir
 *  Description:  
 * =====================================================================================
 */
ngx_str_t hdcache_hash_to_dir(ngx_http_request_t *r,
        uint32_t num, CC_THIN_COOKIE_MARK mark) {
    ngx_http_etomc2_loc_conf_t *lccf;
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!lccf) {
       ngx_str_t n;
      n.len = 0; 
        return n;
    }

    return hdcache_hash_to_dir_def(r,(char*)lccf->hdcache_path.data,num,mark);
}		/* -----  end of function hdcache_hash_to_dir  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  hdcache_behavior
 *  Description:
 * =====================================================================================
 */
int hdcache_behavior(ngx_http_request_t *r,
        ngx_str_t *key, CC_THIN_COOKIE_MARK mark, int *timestamp) {

    uint32_t hash = to_hash((char *)key->data, key->len);
    ngx_str_t path =
        hdcache_hash_to_dir(r, hash, mark);

    ngx_str_t file_path = hdcache_file_build(r, path, *key);

    int i = hdcache_file_content((char *)file_path.data, timestamp);

    return i;

} /* -----  end of function hdcache_behavior  ----- */
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  hdcache_behavior_exist
 *  Description:  
 * =====================================================================================
 */
int  hdcache_behavior_exist ( ngx_http_request_t *r,ngx_str_t*key, CC_THIN_COOKIE_MARK mark){
    uint32_t hash;
    ngx_str_t path;
    ngx_str_t file_path;

    hash = to_hash((char *)key->data, key->len);
    path = hdcache_hash_to_dir(r, hash, mark);
    file_path = hdcache_file_build(r, path, *key);
    int isexit = hdcache_file_exist((char *)file_path.data);

    return isexit;
}		/* -----  end of function hdcache_behavior_exist  ----- */
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  custom_black_ip_attack
 *  Description:  
 * =====================================================================================
 */
int  custom_ip_attack_exist ( ngx_http_request_t *r,CC_THIN_COOKIE_MARK mark ){
    ngx_str_t ip = client_forward_ip(r);

    uint32_t hash = to_hash((char *)ip.data, ip.len);
    /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"[ip:%s]len:%d  black hash:%z",ip.data,ip.len,hash); */

    ngx_str_t path =
        hdcache_hash_to_dir(r, hash, mark);

    ngx_str_t file_path = hdcache_file_build(r, path, ip);
/**     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, */
                      /** "custom_ip_path file_path:%s", file_path.data); */
    return hdcache_file_exist((char*)file_path.data);

}		/* -----  end of function custom_black_ip_attack  ----- */


