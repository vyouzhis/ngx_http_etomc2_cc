/*
 * =====================================================================================
 *
 *       Filename:  etomc2_web_api.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2020年10月23日 11时29分51秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  etomc2@etomc2.com (), etomc2@etomc2.com
 *   Organization:  etomc2.com
 *
 * =====================================================================================
 */
#include "etomc2.h"

/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * web_route_main_conf Description:
 * =====================================================================================
 */
ngx_str_t *web_route_main_conf(ngx_http_request_t *r,
        ngx_http_etomc2_loc_conf_t *lccf) {
    ngx_uint_t i, m;
    volatile ngx_list_part_t *part;
    ngx_shm_zone_t *shm_zone;
    ngx_slab_pool_t *shpool;
    size_t size;
    ngx_str_t *tmp, *res;

    const char *fmt_1 =
        "{\"shm_name\":\"%.*s\",\"total\":%d,\"free\":%d,\"size\":%d}";
    const char *fmt_2 =
        "%.*s,{\"shm_name\":\"%.*s\",\"total\":%d,\"free\":%d,\"size\":%d}";
    const char *shm_fmt = "[%.*s]";
    const char *fmt = "{\"shm\":%.*s,\"enable\":%d}";

    part = &ngx_cycle->shared_memory.part;
    shm_zone = part->elts;

    size = 1 << ngx_pagesize_shift;
    res = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    tmp = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    m = 0;
    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }
        shpool = (ngx_slab_pool_t *)shm_zone[i].shm.addr;

        if (m == 0) {
            res->len =
                snprintf(NULL, 0, fmt_1, shm_zone[i].shm.name.len,
                        shm_zone[i].shm.name.data, shm_zone[i].shm.size / 1024,
                        shpool->pfree * size / 1024, size / 1024);
            res->len += 1;
            res->data = ngx_pcalloc(r->pool, res->len);
            snprintf((char *)res->data, res->len, fmt_1,
                    shm_zone[i].shm.name.len, shm_zone[i].shm.name.data,
                    shm_zone[i].shm.size / 1024, shpool->pfree * size / 1024,
                    size / 1024);
        } else {
            tmp->len = snprintf(
                    NULL, 0, fmt_2, res->len, res->data, shm_zone[i].shm.name.len,
                    shm_zone[i].shm.name.data, shm_zone[i].shm.size / 1024,
                    shpool->pfree * size / 1024, size / 1024);
            tmp->len += 1;
            tmp->data = ngx_pcalloc(r->pool, tmp->len);
            snprintf((char *)tmp->data, tmp->len, fmt_2, res->len, res->data,
                    shm_zone[i].shm.name.len, shm_zone[i].shm.name.data,
                    shm_zone[i].shm.size / 1024, shpool->pfree * size / 1024,
                    size / 1024);
            ngx_pfree(r->pool, res->data);
            res->data = tmp->data;
            res->len = tmp->len;
        }
        m++;
    }
    tmp->len = snprintf(NULL, 0, shm_fmt, res->len, res->data);
    tmp->len += 1;
    tmp->data = ngx_pcalloc(r->pool, tmp->len);
    snprintf((char *)tmp->data, tmp->len, shm_fmt, res->len, res->data);
    ngx_pfree(r->pool, res->data);
    res->data = tmp->data;
    res->len = tmp->len;

    tmp->len =
        snprintf(NULL, 0, fmt, res->len, res->data, lccf->etomc2_cc_enable);
    tmp->len += 1;
    tmp->data = ngx_pcalloc(r->pool, tmp->len);
    snprintf((char *)tmp->data, tmp->len, fmt, res->len, res->data,
            lccf->etomc2_cc_enable);

    return tmp;
} /* -----  end of function web_route_main_conf  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * web_route_domain_list Description:
 * =====================================================================================
 */
ngx_str_t *web_route_domain_list(ngx_http_request_t *r,
        ngx_http_etomc2_loc_conf_t *lccf) {
    ngx_http_core_srv_conf_t **cscfp;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_etomc2_loc_conf_t *loc_conf;
    ngx_http_conf_ctx_t *ctx;
    ngx_uint_t s;
    ngx_str_t *tmp;
    ngx_str_t *res;
    const char *fmt_1 =
        "{\"domain\":\"%.*s\",\"status\":%d,\"gt\":%d,\"itemize\":%d}";
    const char *fmt_2 =
        "%.*s,{\"domain\":\"%.*s\",\"status\":%d,\"gt\":%d,\"itemize\":%d}";
    const char *fmt = "[%.*s]";

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    res = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    tmp = ngx_pcalloc(r->pool, sizeof(ngx_str_t));

    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        ctx = cscfp[s]->ctx;
        loc_conf = (ngx_http_etomc2_loc_conf_t *)
            ctx->loc_conf[ngx_http_etomc2_cc_module.ctx_index];

        if (s == 0) {
            res->len =
                snprintf(NULL, 0, fmt_1, cscfp[s]->server_name.len,
                        cscfp[s]->server_name.data, loc_conf->cc_return_status,
                        loc_conf->cc_gt_level, loc_conf->cc_itemize);
            res->len += 1;
            res->data = ngx_pcalloc(r->pool, res->len);
            snprintf((char *)res->data, res->len, fmt_1,
                    cscfp[s]->server_name.len, cscfp[s]->server_name.data,
                    loc_conf->cc_return_status, loc_conf->cc_gt_level,
                    loc_conf->cc_itemize);
        } else {
            tmp->len = snprintf(
                    NULL, 0, fmt_2, res->len, res->data, cscfp[s]->server_name.len,
                    cscfp[s]->server_name.data, loc_conf->cc_return_status,
                    loc_conf->cc_gt_level, loc_conf->cc_itemize);
            tmp->len += 1;
            tmp->data = ngx_pcalloc(r->pool, tmp->len);
            snprintf((char *)tmp->data, tmp->len, fmt_2, res->len, res->data,
                    cscfp[s]->server_name.len, cscfp[s]->server_name.data,
                    loc_conf->cc_return_status, loc_conf->cc_gt_level,
                    loc_conf->cc_itemize);
            ngx_pfree(r->pool, res->data);
            /** ngx_pfree(r->pool,res); */
            res->data = tmp->data;
            res->len = tmp->len;
        }
    }
    tmp->len = snprintf(NULL, 0, fmt, res->len, res->data);
    tmp->len += 1;
    tmp->data = ngx_pcalloc(r->pool, tmp->len);
    snprintf((char *)tmp->data, tmp->len, fmt, res->len, res->data);
    return tmp;
} /* -----  end of function web_route_domain_list  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * web_route_update_conf Description:
 * =====================================================================================
 */
ngx_str_t *web_route_update_conf(ngx_http_request_t *r,
        ngx_http_etomc2_loc_conf_t *lccf) {
    ngx_http_core_srv_conf_t **cscfp;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_etomc2_loc_conf_t *loc_conf;
    ngx_http_conf_ctx_t *ctx;
    ngx_uint_t s;

    ngx_table_elt_t *dhv, *ihv, *ghv, *rhv;
    const char *domain = "domain", *itemize = "itemize", *glevel = "glevel",
          *rstatus = "rstatus";

    dhv = search_headers_in(r, (u_char *)domain, strlen(domain));

    if (dhv == NULL || dhv->value.len == 0) {
        /** NX_LOG("domain  dhv value is null"); */
        return NULL;
    }


    ihv = search_headers_in(r, (u_char *)itemize, strlen(itemize));

    if (ihv == NULL || ihv->value.len == 0) {
        /** NX_LOG("domain  ihv value is null"); */
        return NULL;
    }


    ghv = search_headers_in(r, (u_char *)glevel, strlen(glevel));

    if (ghv == NULL || ghv->value.len == 0) {
        NX_LOG("domain  ghv value is null");
        return NULL;
    }


    rhv = search_headers_in(r, (u_char *)rstatus, strlen(rstatus));

    if (rhv == NULL || rhv->value.len == 0) {
        NX_LOG("domain  rhv value is null");
        return NULL;
    }


    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        ctx = cscfp[s]->ctx;
        loc_conf = (ngx_http_etomc2_loc_conf_t *)
            ctx->loc_conf[ngx_http_etomc2_cc_module.ctx_index];

        if (ngx_strncmp(cscfp[s]->server_name.data, dhv->value.data,
                    cscfp[s]->server_name.len) == 0) {
            loc_conf->cc_return_status =
                ngx_atoi(rhv->value.data, rhv->value.len);
            loc_conf->cc_gt_level = ngx_atoi(ghv->value.data, ghv->value.len);
            loc_conf->cc_itemize = ngx_atoi(ihv->value.data, ihv->value.len);
            break;
        }
    }
    return NULL;
} /* -----  end of function web_route_update_conf  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * web_route_json_flow Description:
 * =====================================================================================
 */
ngx_str_t *web_route_json_flow(ngx_http_request_t *r,
        ngx_http_etomc2_loc_conf_t *lccf) {
    ngx_table_elt_t *dhv;
    const char *domain = "domain";
    ngx_str_t *res;
    dhv = search_headers_in(r, (u_char *)domain, strlen(domain));

    if (dhv == NULL || dhv->value.len == 0) {
        /** NX_LOG("domain  dhv value is null"); */
        return NULL;
    }

    res = flow_get(r, &dhv->value);

    return res;
} /* -----  end of function web_route_json_flow  ----- */

/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * web_route_waf_domain_ids Description:
 * =====================================================================================
 */
ngx_str_t *web_route_waf_domain_ids(ngx_http_request_t *r,
        ngx_http_etomc2_loc_conf_t *lccf) {
    ngx_str_t *data;
    ngx_shm_zone_t *shm_zone_list;
    Ngx_etomc2_aiwaf_list *list_ptr;
    ngx_table_elt_t *hv;
    const char *domain = "domain";
    uint32_t dm_hash = 0;
    /**
     * get  waf  domain ids
     */
    hv = search_headers_in(r, (u_char *)domain, strlen(domain));

    if (hv == NULL || hv->value.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "domain  hv value is null");
        return NULL;
    }
    shm_zone_list = lccf->shm_zone_list;
    list_ptr = (Ngx_etomc2_aiwaf_list *)shm_zone_list->data;

    dm_hash = to_hash((char *)hv->value.data, hv->value.len);
    data = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    if (data == NULL) {
        return NULL;
    }

    data->len = 0;
    data->data = NULL;

    list_json(r, list_ptr, &data, dm_hash);

    if (data->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "list_json data is null");
        return NULL;
    }

    return data;
} /* -----  end of function web_route_waf_domain_ids  ----- */

/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * web_route_waf_domain_rule Description:
 * =====================================================================================
 */
ngx_str_t *web_route_waf_domain_rule(ngx_http_request_t *r,
        ngx_http_etomc2_loc_conf_t *lccf) {
    Ngx_etomc2_shm_tree_data *nrule;
    ngx_table_elt_t *hv;
    ngx_shm_zone_t *shm_zone;
    Ngx_etomc2_shm_tree_data *ptr;
    uint32_t hashv = 0;
    u_char *tmp;
    const char *name = "hashv";
    uint32_t nhash = -1;

    /**
     * get  waf  id  rule
     */
    hv = search_headers_in(r, (u_char *)name, strlen(name));
    if (hv == NULL || hv->value.len == 0) {
        return NULL;
    }
    shm_zone = lccf->shm_zone_waf;
    ptr = ((Ngx_etomc2_shm_tree_data *)shm_zone->data);

    tmp = hv->value.data;
    hashv = strtol((char *)tmp, NULL, 10);

    if (hashv == nhash) {
        return NULL;
    }

    nrule = tree_search(&ptr, hashv);

    if (nrule == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "nrule is   null");

        return NULL;
    }

    return (ngx_str_t *)nrule->data;
} /* -----  end of function web_route_waf_domain_rule  ----- */

/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * web_route_set_gt_level Description:
 * =====================================================================================
 */
ngx_int_t web_route_set_gt_level(ngx_http_request_t *r,
        ngx_http_etomc2_loc_conf_t *lccf) {
    ngx_http_core_srv_conf_t **cscfp;
    ngx_uint_t s;
    ngx_http_core_main_conf_t *cmcf;
    ngx_slab_pool_t *shpool;
    ngx_table_elt_t *hv;
    uint32_t dm_hash = 0, server_hash;
    int is_server = -1;
    int ilevel = -1;
    const char *domain = "domain";
    const char *level = "level";
    ngx_shm_zone_t *shm_zone_cc_gt;

    Ngx_etomc2_shm_gt *cc_gt_ptr, *cc_new_ptr;
    /**
     *  set  shm_gt_level
     */
    hv = search_headers_in(r, (u_char *)domain, strlen(domain));
    if (hv == NULL || hv->value.len == 0) {
        return NGX_ERROR;
    }
    dm_hash = to_hash((char *)hv->value.data, hv->value.len);

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        /** ngx_cc_gt_init(cf,cscfp[s]->server_name); */
        server_hash = to_hash((char *)cscfp[s]->server_name.data,
                cscfp[s]->server_name.len);
        if (dm_hash == server_hash) {
            is_server = 0;
            break;
        }
    }
    if (is_server == -1) {
        return NGX_ERROR;
    }
    hv = search_headers_in(r, (u_char *)level, strlen(level));
    if (hv == NULL || hv->value.len == 0) {
        return NGX_ERROR;
    }
    ilevel = ngx_atoi(hv->value.data, hv->value.len);
    shm_zone_cc_gt = lccf->shm_zone_cc_gt;
    shpool = (ngx_slab_pool_t *)shm_zone_cc_gt->shm.addr;

    cc_gt_ptr = (Ngx_etomc2_shm_gt *)shm_zone_cc_gt->data;
    while (cc_gt_ptr) {
        if (cc_gt_ptr->hash_domain == 0) {
            cc_gt_ptr->hash_domain = dm_hash;
        }
        if (cc_gt_ptr->hash_domain == dm_hash) {
            ngx_shmtx_lock(&shpool->mutex);
            switch (ilevel) {
                case 1:
                    cc_gt_ptr->level = GTL_1;
                    break;
                case 2:
                    cc_gt_ptr->level = GTL_2;
                    break;
                case 3:
                    cc_gt_ptr->level = GTL_3;
                    break;
                case 4:
                    cc_gt_ptr->level = GTL_4;
                    break;
                case 5:
                    cc_gt_ptr->level = GTL_5;
                    break;
                default:
                    break;
            } /* -----  end switch  ----- */
            ngx_shmtx_unlock(&shpool->mutex);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "[server_name:new,level:%d]", cc_gt_ptr->level);

            break;
        }
        if (cc_gt_ptr->next == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "[server_name:new]");
            // new
            cc_new_ptr =
                ngx_slab_alloc_locked(shpool, sizeof(Ngx_etomc2_shm_gt));
            if (!cc_new_ptr) {
                break;
            }
            cc_new_ptr->hash_domain = dm_hash;
            cc_new_ptr->count = 0;
            cc_new_ptr->now = 0;
            switch (ilevel) {
                case 1:
                    cc_new_ptr->level = GTL_1;
                    break;
                case 2:
                    cc_new_ptr->level = GTL_2;
                    break;
                case 3:
                    cc_new_ptr->level = GTL_3;
                    break;
                case 4:
                    cc_new_ptr->level = GTL_4;
                    break;
                case 5:
                    cc_new_ptr->level = GTL_5;
                    break;
                default:
                    break;
            } /* -----  end switch  ----- */
            cc_new_ptr->next = NULL;
            ngx_shmtx_lock(&shpool->mutex);

            cc_gt_ptr->next = cc_new_ptr;
            ngx_shmtx_unlock(&shpool->mutex);
        }

        cc_gt_ptr = cc_gt_ptr->next;
    }

    return NGX_OK;
} /* -----  end of function web_route_set_gt_level  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * web_route_ip_blacklist Description:
 * =====================================================================================
 */
ngx_str_t web_route_ip_blacklist(ngx_http_request_t *r,
        ngx_http_etomc2_loc_conf_t *lccf) {
    const char *bip = "blackip";
    const char *wip = "whiteip";
    ngx_str_t badIp = ngx_string("bad ip!");
    ngx_table_elt_t *hv;
    CC_THIN_COOKIE_MARK mark;
    hv = search_headers_in(r, (u_char *)bip, strlen(bip));
    mark = M_RED;
    if (hv == NULL || hv->value.len == 0) {
        hv = search_headers_in(r, (u_char *)wip, strlen(wip));
        if (hv == NULL || hv->value.len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "domain  hv value is null");
            return badIp;
        }
        mark = M_GREEN;
    }

    int isip = isIp_v4((char *)hv->value.data);

    if (isip == -1) {
        return badIp;
    } else {
        uint32_t hash = to_hash((char *)hv->value.data, hv->value.len);
        /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"hv:[%s] len:%d
         * hash:%z",hv->value.data,hv->value.len,hash); */
        ngx_str_t path = hdcache_hash_to_dir_def(
                r, (char *)lccf->hdcache_path.data, hash, mark);
        hdcache_create_dir((char *)path.data, 0700);
        ngx_str_t file_path = hdcache_file_build(r, path, hv->value);
        hdcache_create_file((char *)file_path.data, 0, 0);
        return hv->value;
    }
} /* -----  end of function web_route_ip_blacklist  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * web_route_del_blackip Description:
 * =====================================================================================
 */
ngx_str_t web_route_del_blackip(ngx_http_request_t *r,
        ngx_http_etomc2_loc_conf_t *lccf) {
    const char *bip = "blackip";
    const char *wip = "whiteip";
    ngx_table_elt_t *hv;
    ngx_str_t badIp = ngx_string("bad ip!");
    CC_THIN_COOKIE_MARK mark;
    hv = search_headers_in(r, (u_char *)bip, strlen(bip));
    mark = M_RED;
    if (hv == NULL || hv->value.len == 0) {
        hv = search_headers_in(r, (u_char *)wip, strlen(wip));
        if (hv == NULL || hv->value.len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "domain  hv value is null");
            return badIp;
        }
        mark = M_GREEN;
    }

    int isip = isIp_v4((char *)hv->value.data);

    if (isip == -1) {
        return badIp;
    } else {
        uint32_t hash = to_hash((char *)hv->value.data, hv->value.len);
        /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"hv:[%s] len:%d
         * hash:%z",hv->value.data,hv->value.len,hash); */
        ngx_str_t path = hdcache_hash_to_dir_def(
                r, (char *)lccf->hdcache_path.data, hash, mark);
        ngx_str_t file_path = hdcache_file_build(r, path, hv->value);
        hdcache_unlink_file((char *)file_path.data);
        return hv->value;
    }
} /* -----  end of function web_route_del_blackip  ----- */

/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * web_route_get_uri_itemize Description:
 * =====================================================================================
 */
ngx_int_t web_route_get_uri_itemize(ngx_http_request_t *r,
        ngx_http_etomc2_loc_conf_t *lccf) {
    ngx_http_core_srv_conf_t **cscfp;
    ngx_uint_t s;
    ngx_http_core_main_conf_t *cmcf;
    ngx_slab_pool_t *shpool;
    ngx_table_elt_t *hv;
    uint32_t dm_hash = 0, server_hash;
    int is_server = -1, i;
    uint32_t hashv = 0;
    /** int ilevel = -1, itake = 0; */
    const char *domain = "domain";

    const char *cc_id = "ccid";
    ngx_shm_zone_t *shm_zone_cc_gt;

    Ngx_etomc2_shm_gt *cc_gt_ptr, *cc_new_ptr;
    /**
     *  set  shm_gt_uri_itemize
     */
    hv = search_headers_in(r, (u_char *)domain, strlen(domain));
    if (hv == NULL || hv->value.len == 0) {
        return NGX_ERROR;
    }
    dm_hash = to_hash((char *)hv->value.data, hv->value.len);

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        /** ngx_cc_gt_init(cf,cscfp[s]->server_name); */
        server_hash = to_hash((char *)cscfp[s]->server_name.data,
                cscfp[s]->server_name.len);
        if (dm_hash == server_hash) {
            is_server = 0;
            break;
        }
    }
    if (is_server == -1) {
        return NGX_ERROR;
    }
    hv = search_headers_in(r, (u_char *)cc_id, strlen(cc_id));
    if (hv == NULL || hv->value.len == 0) {
        return NGX_ERROR;
    }
    hashv = strtol((char *)hv->value.data, NULL, 10);

    shm_zone_cc_gt = lccf->shm_zone_cc_gt;
    shpool = (ngx_slab_pool_t *)shm_zone_cc_gt->shm.addr;

    cc_gt_ptr = (Ngx_etomc2_shm_gt *)shm_zone_cc_gt->data;
    while (cc_gt_ptr) {
        if (cc_gt_ptr->hash_domain == 0) {
            cc_gt_ptr->hash_domain = dm_hash;
        }
        if (cc_gt_ptr->hash_domain == dm_hash) {
            ngx_shmtx_lock(&shpool->mutex);
            for (i = 0; i < CC_GT_URI_MAX; i++) {
                if (cc_gt_ptr->uri_itemize[i] == 0) {
                    cc_gt_ptr->uri_itemize[i] = hashv;
                    break;
                }
            }
            ngx_shmtx_unlock(&shpool->mutex);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "[server_name:new,level:%d]", cc_gt_ptr->level);

            break;
        }
        if (cc_gt_ptr->next == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "[server_name:new]");
            // new
            cc_new_ptr = ngx_cc_gt_init(shpool);
            if (!cc_new_ptr) {
                break;
            }
            cc_new_ptr->hash_domain = dm_hash;
            cc_gt_ptr->uri_itemize[0] = hashv;

            ngx_shmtx_lock(&shpool->mutex);

            cc_gt_ptr->next = cc_new_ptr;
            ngx_shmtx_unlock(&shpool->mutex);
        }

        cc_gt_ptr = cc_gt_ptr->next;
    }
    return NGX_OK;
} /* -----  end of function web_route_get_uri_itemize  ----- */
