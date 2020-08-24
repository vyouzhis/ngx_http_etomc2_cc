/*
 * etomc2, a web application firewall for NGINX
 * Copyright (C) NBS System – All Rights Reserved
 * Licensed under GNU GPL v3.0 – See the LICENSE notice for details
 */

#include "etomc2.h"
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  chekc_uri
 *  Description:
 * =====================================================================================
 */
ngx_str_t get_uri(ngx_http_request_t *r) {
    ngx_str_t tmp_uri;

    if (r->uri.len >= (NGX_MAX_UINT32_VALUE / 4) - 1) {
        r->uri.len /= 4;
    }

    tmp_uri.len =
        r->uri.len +
        (2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len, NGX_ESCAPE_ARGS));
    tmp_uri.data = ngx_pcalloc(r->pool, tmp_uri.len + 1);
    if (!tmp_uri.data) {
        tmp_uri.len = 0;
        return tmp_uri;
    }
    ngx_escape_uri(tmp_uri.data, r->uri.data, r->uri.len, NGX_ESCAPE_ARGS);

    return tmp_uri;
} /* -----  end of function chekc_uri  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_enter
 *  Description:  front  enter
 * =====================================================================================
 */
ngx_int_t cc_thin_enter(ngx_http_request_t *r) {
    ngx_http_etomc2_loc_conf_t *lccf;
    ngx_table_elt_t *pem;

    ngx_shm_zone_t *shm_zone_cc_ub;
    Ngx_etomc2_cc_user_behavior *cc_ub_ptr, *behavior;

    ngx_rbtree_node_t *find_node;

    ngx_str_t *key;
    uint32_t time_space;
    time_t now;
    int timestamp = -1, uuid;

    /** ngx_cc_gt(r); */

    now = ngx_time();
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!lccf) {

        return (NGX_DECLINED);
    }
    if (lccf->cc_itemize == 0) {
        return NGX_OK;

    }
    if (lccf->hdcache_path.len > 0) {
        int black_ip = custom_ip_attack_exist(r,M_RED);

        if (black_ip == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "custom_ip_attack");
            return NGX_ERROR;
        }
    }

    key = ngx_cc_rbtree_hash_key(r);
    if (!key) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_cc_rbtree_hash_key is null");
        return NGX_DECLINED;
    }
    /**
     *  behavior cc  for hdcache M_RED
     *
     */
    int hb = hdcache_behavior(r, key, M_RED, &timestamp);

    if (hb != -1) {
       /**  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, */
                /** "hdcache_behavior:%d, timestamp:%d", hb, timestamp);        */
        time_space = (now - timestamp);
        if ((size_t)time_space < Intensity[hb]) {
            ngx_pfree(r->pool, key->data);
            ngx_pfree(r->pool, key);
            return NGX_ERROR;
        }
    }

    /**
     * rsa  pem
     */
    if (lccf->rsa_pem_pk.len > 0) {
        pem = search_headers_in(r, (u_char *)PEM_SECURE_TUNNEL,
                strlen(PEM_SECURE_TUNNEL));

        if (pem && pem->value.len > 0) {
            char *decrypt;
            rsa_decrypt(r, pem->value, lccf->rsa_pem, &decrypt);
        }
    }



    uuid = uuid4_data(r);
    int lou = lreq_operate_uri(r);
    if (lou == 0) {
        if (uuid != -1) {
            ngx_pfree(r->pool, key->data);
            ngx_pfree(r->pool, key);
            return NGX_OK;
        }
        /**
         *  new user for hatml
         *  cc_thin_user_behavior_search  app  user
         */
        shm_zone_cc_ub = lccf->shm_zone_cc_ub;
        if (!shm_zone_cc_ub) {
            ngx_pfree(r->pool, key->data);
            ngx_pfree(r->pool, key);
            return NGX_DECLINED;
        }

        cc_ub_ptr = (Ngx_etomc2_cc_user_behavior *)shm_zone_cc_ub->data;
        if (cc_ub_ptr) {
            find_node = cc_thin_user_behavior_search(
                    cc_ub_ptr->rbtree.root, cc_ub_ptr->rbtree.sentinel, key);
            if (find_node != cc_ub_ptr->rbtree.sentinel) {
                behavior = (Ngx_etomc2_cc_user_behavior *)find_node;
                if (behavior->mark == M_SMALL) {
                    // M_SMALL return busy 
                    ngx_pfree(r->pool, key->data);
                    ngx_pfree(r->pool, key);
                    return NGX_BUSY;
                }
            }
        } 
    }

    ngx_pfree(r->pool, key->data);
    ngx_pfree(r->pool, key);
    return NGX_OK;
} /* -----  end of function cc_thin_enter  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_create
 *  Description:
 * =====================================================================================
 */
Ngx_visit_cc_attack *cc_thin_create(ngx_slab_pool_t *shpool) {
    Ngx_visit_cc_attack *thin = NULL;
    if (shpool == NULL) {
        thin = (Ngx_visit_cc_attack *)malloc(sizeof(Ngx_visit_cc_attack));
    } else {
        thin = ngx_slab_alloc_locked(shpool, sizeof(Ngx_visit_cc_attack));
    }
    if (thin == NULL) {
        return NULL;
    }
    thin->next = NULL;
    thin->hash_uri = 0;
    thin->hash_domain = 0;
    thin->rise_level = 0;

    return thin;
} /* -----  end of function cc_thin_create  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_insert
 *  Description:
 * =====================================================================================
 */
void cc_thin_insert(ngx_slab_pool_t *shpool, Ngx_visit_cc_attack **thin_root,
        uint32_t hash_uri, uint32_t hash_domain,
        size_t rise_level) {
    Ngx_visit_cc_attack *tlist = NULL, *nlist = NULL;

    if (!(*thin_root)) {
        (*thin_root) = cc_thin_create(shpool);
    }

    tlist = (*thin_root);
    while (tlist) {
        if (tlist->hash_uri == 0) {
            tlist->hash_uri = hash_uri;
            tlist->hash_domain = hash_domain;
            tlist->rise_level = rise_level;
            break;
        }
        if (tlist->hash_domain == hash_domain && tlist->hash_uri == hash_uri) {
            if (tlist->rise_level < rise_level) {
                tlist->rise_level = rise_level;
            }
            break;
        }
        if (tlist->next == NULL) {
            nlist = cc_thin_create(shpool);
            nlist->hash_uri = hash_uri;
            nlist->hash_domain = hash_domain;
            nlist->rise_level = rise_level;

            tlist->next = nlist;
            break;
        }
        tlist = tlist->next;
    }

} /* -----  end of function cc_thin_insert  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_delete
 *  Description:
 * =====================================================================================
 */
void cc_thin_delete(Ngx_visit_cc_attack **thin_root, uint32_t hash_uri,
        uint32_t hash_domain) {
    Ngx_visit_cc_attack *tlist = (*thin_root);
    while (tlist) {
        if (tlist->hash_domain == hash_domain && tlist->hash_uri == hash_uri) {
            tlist->hash_uri = 0;
            tlist->hash_domain = 0;
            tlist->rise_level = 0;

            break;
        }
        tlist = tlist->next;
    }
} /* -----  end of function cc_thin_delete  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_search
 *  Description:
 * =====================================================================================
 */
size_t cc_thin_search(Ngx_visit_cc_attack **thin_root, uint32_t hash_uri,
        uint32_t hash_domain) {
    Ngx_visit_cc_attack *tlist = (*thin_root);
    size_t rise_level = -1;
    while (tlist) {
        if (tlist->hash_domain == hash_domain && tlist->hash_uri == hash_uri) {
            rise_level = tlist->rise_level;

            break;
        }
        tlist = tlist->next;
    }
    return rise_level;
} /* -----  end of function cc_thin_search  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_show
 *  Description:
 * =====================================================================================
 */
void cc_thin_show(ngx_http_request_t *r, Ngx_visit_cc_attack *thin_root) {
    Ngx_visit_cc_attack *tlist = thin_root;
    while (tlist) {
        /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"etomc2 visits cc
         * attack:%z,domain:%z,rise:%d",tlist->hash_uri,
         * tlist->hash_domain,tlist->rise_level); */
        tlist = tlist->next;
    }
} /* -----  end of function cc_thin_show  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_uri_create()
 *  Description:
 * =====================================================================================
 */
Ngx_etomc2_cc_uri *cc_uri_create(ngx_slab_pool_t *shpool) {
    Ngx_etomc2_cc_uri *cc_uri_data;
    int time_index = timeIndex();
    cc_uri_data = ngx_slab_alloc_locked(shpool, sizeof(Ngx_etomc2_cc_uri));
    if (!cc_uri_data) return NULL;
    memset(cc_uri_data->visits, 0, sizeof(cc_uri_data->visits));
    memset(cc_uri_data->visited, 0, sizeof(cc_uri_data->visited));

    cc_uri_data->visits[time_index] = 1;
    return cc_uri_data;
} /* -----  end of function cc_uri_create()  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  domain_uri_create
 *  Description:
 * =====================================================================================
 */
Ngx_etomc2_cc_domain *domain_uri_create(ngx_slab_pool_t *shpool) {
    Ngx_etomc2_cc_domain *ncd = NULL;

    ncd = ngx_slab_alloc_locked(shpool, sizeof(Ngx_etomc2_cc_domain));
    if (!ncd) return NULL;
    ncd->hash_domain = 0;
    ncd->next = NULL;
    ncd->tree_uri = tree_create(shpool);
    return ncd;
} /* -----  end of function domain_uri_create  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  domain_uri_add
 *  Description:
 * =====================================================================================
 */
void domain_uri_add(ngx_http_request_t *r) {
    ngx_http_headers_out_t out_t = r->headers_out;
    char *content_type[] = {"html", "xml", "json"};
    int istype = -1;
    int len, i;
    int time_index, pre_index;
    ngx_http_etomc2_loc_conf_t *lccf;
    ngx_shm_zone_t *shm_zone, *shm_zone_cc_thin;
    ngx_slab_pool_t *shpool;

    Ngx_etomc2_cc_domain *cc_domain, *tmp_domain;
    Ngx_etomc2_shm_tree_data *tree_cc_uri;
    Ngx_etomc2_shm_tree_data *tree_uri;
    Ngx_etomc2_cc_uri *cc_uri_data;
    Ngx_visit_cc_attack *cc_thin_ptr;
    uint32_t hash_domain, hash_uri;

    size_t visit_pre, visit_now;
    float rise;
    int fib_index;
    /** const char *fmt = */
    /** "[visite pre_index is 0 uri:%z,pre:%l,index:%d,time:%l, count:%d]"; */

    GET_ARRAY_LEN(content_type, len);

    for (i = 0; i < len; i++) {
        istype = findstring((char *)out_t.content_type.data, content_type[i]);
        if (istype != -1) {
            break;
        }
    }
    if (istype == -1) {
        return;
    }
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!lccf) return;

    if (lccf->shm_zone_uri == NULL) {
        return;
    }
    shm_zone = lccf->shm_zone_uri;
    shm_zone_cc_thin = lccf->shm_zone_cc_thin;

    shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    cc_domain = (Ngx_etomc2_cc_domain *)shm_zone->data;
    cc_thin_ptr = (Ngx_visit_cc_attack *)shm_zone_cc_thin->data;

    if (!cc_domain) {
        /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "cc_domain  is
         * null"); */

        ngx_shmtx_unlock(&shpool->mutex);

        return;
    }

    hash_domain =
        to_hash((char *)r->headers_in.server.data, r->headers_in.server.len);
    ngx_str_t uri = get_uri(r);
    if (uri.len == 0) return;
    hash_uri = to_hash((char *)uri.data, uri.len);

    time_index = timeIndex();

    /*
     * Ngx_etomc2_cc_domain init
     */

    if (cc_domain->hash_domain == 0) {
        cc_uri_data = cc_uri_create(shpool);
        if (!cc_uri_data) {
            ngx_shmtx_unlock(&shpool->mutex);

            return;
        }
        if (!cc_domain->tree_uri) {
            ngx_shmtx_unlock(&shpool->mutex);

            return;
        }

        tree_insert(r, &cc_domain->tree_uri, hash_uri, cc_uri_data, shpool);

        cc_domain->hash_domain = hash_domain;

        ngx_shmtx_unlock(&shpool->mutex);

        return;
    }

    /** ngx_shmtx_lock(&shpool->mutex); */

    while (cc_domain) {
        if (cc_domain->hash_domain == hash_domain) {
            tree_cc_uri = cc_domain->tree_uri;

            tree_uri = tree_search(&tree_cc_uri, hash_uri);
            if (!tree_uri) {
                /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                 * "tree_cc_uri is null %z tree
                 * hash:%z",hash_uri,cc_domain->tree_uri->hashkey); */

                cc_uri_data = cc_uri_create(shpool);
                if (!cc_uri_data) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            "cc_uri_data 1 is null");

                    ngx_shmtx_unlock(&shpool->mutex);

                    return;
                }
                tree_insert(r, &tree_cc_uri, hash_uri, cc_uri_data, shpool);

            } else {
                /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                 * "cc_uri_data where is null %z tree
                 * hash:%z",hash_uri,cc_domain->tree_uri->hashkey); */

                /** ngx_shmtx_lock(&shpool->mutex); */
                if (!tree_uri->data) {
                    /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                     * "cc_uri_data data is null"); */
                    ngx_shmtx_unlock(&shpool->mutex);

                    return;
                }
                cc_uri_data = (Ngx_etomc2_cc_uri *)tree_uri->data;

                cc_uri_data->visits[time_index] += 1;
                /** ngx_shmtx_unlock(&shpool->mutex); */

                if (time_index == 0) {
                    pre_index = 59;
                } else {
                    pre_index = time_index - 1;
                }

                visit_pre = cc_uri_data->visits[pre_index];
                cc_domain->count += 1;

                if (visit_pre != 0) {
                    visit_now = cc_uri_data->visits[time_index];
                    rise = (float)visit_now / (float)visit_pre;
                    fib_index = (int)rise;
                    if (fib_index > 3) {
                        fib_index = 3;
                    }

                    cc_thin_insert(shpool, &cc_thin_ptr, hash_uri, hash_domain,
                            fib_index);
                    /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                     * "[Fibonacci:%f, %l,%l
                     * uri:%z]",Fibonacci[fib_index][0],cc_uri_data->visits[pre_index],cc_uri_data->visits[time_index],hash_uri);
                     */
                } else {
                    /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                     * fmt,hash_uri,
                     * cc_uri_data->visits[pre_index],pre_index,cc_uri_data->visits[time_index],cc_domain->count);
                     */
                }
            }
            ngx_shmtx_unlock(&shpool->mutex);
            return;
        }
        if (!cc_domain->next) {
            break;
        }

        cc_domain = cc_domain->next;
    }

    // add new domain
    tmp_domain = domain_uri_create(shpool);
    if (!tmp_domain) {
        ngx_shmtx_unlock(&shpool->mutex);

        return;
    }
    tmp_domain->hash_domain = hash_domain;
    cc_uri_data = cc_uri_create(shpool);

    /** ngx_shmtx_lock(&shpool->mutex); */
    tree_insert(r, &tmp_domain->tree_uri, hash_uri, cc_uri_data, shpool);
    cc_domain->next = tmp_domain;

    ngx_shmtx_unlock(&shpool->mutex);

    ngx_log_error(
            NGX_LOG_ERR, r->connection->log, 0, "[domain:%s,uri status:%d,type:%s]",
            r->headers_in.server.data, out_t.status, out_t.content_type.data);
    return;
} /* -----  end of function domain_uri_add  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  domain_uri_show
 *  Description:
 * =====================================================================================
 */
void domain_uri_show(ngx_http_request_t *r) {
    ngx_http_etomc2_loc_conf_t *lccf;
    ngx_shm_zone_t *shm_zone;
    /** ngx_slab_pool_t *shpool; */
    /**    ngx_etomc2_shm_t *ptr; */

    Ngx_etomc2_cc_domain *cc_domain;

    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!lccf) return;

    if (lccf->shm_zone_uri == NULL) {
        return;
    }
    shm_zone = lccf->shm_zone_uri;
    /** shpool = (ngx_slab_pool_t *)shm_zone->shm.addr; */

    cc_domain = ((Ngx_etomc2_cc_domain *)shm_zone->data);
    /** cc_domain = ptr->list_domain_uri; */
    while (cc_domain && cc_domain->hash_domain != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[domain:%z]",
                cc_domain->hash_domain);
        visit_print(r, cc_domain->tree_uri);
        cc_domain = cc_domain->next;
    }
} /* -----  end of function domain_uri_show  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  findstring
 *  Description:
 * =====================================================================================
 */
int findstring(const char *rest, const char *dest) {
    size_t n = 0, m = 0;
    size_t l = strlen(rest);
    size_t i = strlen(dest);
    for (n = 0; n < l; n++) {
        if (m == i) break;
        if (*(rest + n) == *(dest + m)) {
            m++;
        } else {
            m = 0;
        }
    }
    if (m == i) {
        return (n - i);
    }
    return -1;

} /* -----  end of function findstring  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_cookie
 *  Description:
 * =====================================================================================
 */
void cc_cookie(ngx_http_request_t *r) {
    /** ngx_table_elt_t **cookies; */
    /** int exist = -1; */
    /** ngx_uint_t nelts; */
    /** char md5[32]; */
    /** cookies = r->headers_in.cookies.elts; */
    /** nelts = r->headers_in.cookies.nelts; */
    /**  */
    /** if (nelts == 0) return; */
    /**  */
    /** exist = findstring((char *)cookies[0]->value.data, COOKIE_GREEN_NAME);
    */
    /**  */
    /** if (exist != -1) { */
    /**     snprintf(md5, 32, "%s", cookies[0]->value.data + exist + */
    /**                                 strlen(COOKIE_GREEN_NAME) + 1); */
    /**  */
    /**     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, */
    /**                   "[cookies value:%s, exits:%d]", md5, exist); */
    /** } */

    /**     if (exist == -1) { */
    /** cc_setcookie(r); */
    /** } */

} /* -----  end of function cc_cookie  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_setcookie
 *  Description:
 * =====================================================================================
 */
void cc_setcookie(ngx_http_request_t *r, ngx_str_t key) {
    ngx_str_t cookie;
    const char *fmt = "%s=%s; path=/";

    cookie.len = snprintf(NULL, 0, fmt, COOKIE_GREEN_NAME, key.data);
    cookie.len += 1;
    cookie.data = ngx_pcalloc(r->pool, cookie.len);
    if (cookie.data == NULL) {
        return;
    }
    snprintf((char *)cookie.data, cookie.len, fmt, COOKIE_GREEN_NAME, key.data);

    setcookie(r, cookie);

} /* -----  end of function cc_setcookie  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_cookie_mark
 *  Description:
 * =====================================================================================
 */
ngx_int_t cc_cookie_mark(ngx_http_request_t *r) {
    ngx_table_elt_t **cookies;
    int exist = -1;
    ngx_uint_t nelts, cmp = -1;
    char md5[33];
    ngx_str_t *ower_md5;

    cookies = r->headers_in.cookies.elts;
    nelts = r->headers_in.cookies.nelts;

    if (nelts == 0) return -1;

    exist = findstring((char *)cookies[0]->value.data, COOKIE_GREEN_NAME);

    if (exist != -1) {
        snprintf(
                md5, 33, "%s",
                cookies[0]->value.data + exist + strlen(COOKIE_GREEN_NAME) + 1);

        ower_md5 = ngx_cc_rbtree_hash_key(r);
        if (ower_md5 == NULL || ower_md5->data == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "cc cookie_mark null");
            return -1;
        }

        cmp = ngx_memn2cmp(ower_md5->data, (u_char *)md5, 32, 32);
        ngx_pfree(r->pool, ower_md5->data);
        ngx_pfree(r->pool, ower_md5);

        if (cmp == 0) {
            return NGX_OK;
        }
    }

    return -1;
} /* -----  end of function cc_cookie_mark  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  setcookie
 *  Description:
 * =====================================================================================
 */
void setcookie(ngx_http_request_t *r, ngx_str_t cookie) {
    ngx_table_elt_t *set_cookie;
    u_char *p;
    if (cookie.len == 0 || cookie.data == NULL) {
        return;
    }
    p = cookie.data + cookie.len - 1;

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return;
    }

    set_cookie->hash = 1;
    set_cookie->key.len = sizeof("Set-Cookie") - 1;
    set_cookie->key.data = (u_char *)"Set-Cookie";
    set_cookie->value.len = p - cookie.data;
    set_cookie->value.data = cookie.data;

} /* -----  end of function setcookie  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  behavior_uuid_cookie
 *  Description:
 * =====================================================================================
 */
int behavior_uuid_cookie(ngx_http_request_t *r) {
    ngx_table_elt_t **cookies;
    int exist;
    ngx_uint_t nelts;

    cookies = r->headers_in.cookies.elts;
    nelts = r->headers_in.cookies.nelts;

    if (nelts == 0) return -1;

    exist =
        findstring((char *)cookies[0]->value.data, (char *)COOKIE_UUID_NAME);

    if (exist != -1) {
        return 0;
    }

    return -1;

} /* -----  end of function behavior_uuid_cookie  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_pagenotfound
 *  Description:  ip  connect to  uri  404
 * =====================================================================================
 */
void cc_thin_PageNotFound(ngx_http_request_t *r) {
    if (r->headers_out.status == 404) {
    }

    return;
} /* -----  end of function cc_thin_pagenotfound  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_user_agent
 *  Description:
 * =====================================================================================
 */
void cc_thin_user_agent(ngx_http_request_t *r) {
    /** ngx_table_elt_t **forwarded; */
    /** forwarded = r->headers_in.x_forwarded_for.elts; */
    /**     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[user_agent:%s
     * forwarded:%s]", */
    /** r->headers_in.user_agent->value.data,forwarded[0]->value.data); */

    return;
} /* -----  end of function cc_thin_user_agent  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_user_behavior_green
 *  Description:
 * =====================================================================================
 */
void cc_thin_user_behavior_green(ngx_http_request_t *r,
        Ngx_etomc2_cc_user_behavior *behavior,
        uint32_t hash) {
    ngx_str_t path;
    ngx_str_t file_path;
    int mh;
    time_t now = ngx_time();
    /**
     * client to M_GREEN
     * app  or  brower
     */

    if (behavior->BrowserOrBot == BB_BOT) {
        path = hdcache_hash_to_dir(r, hash, M_GREEN);

        mh = hdcache_create_dir((char *)path.data, 0700);
        if (mh == 0) {
            file_path = hdcache_file_build(r, path, behavior->hash_str);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "hdcache_file_build green  %s  %d", file_path.data,
                    behavior->BrowserOrBot);
            if (file_path.len > 0) {
                hdcache_create_file((char *)file_path.data, 0, now);
                ngx_pfree(r->pool, file_path.data);
            }
        }
    } else {
        cc_setcookie(r, behavior->hash_str);
    }

} /* -----  end of function cc_thin_user_behavior_green  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_user_behavior_redaction
 *  Description:
 * =====================================================================================
 */
int cc_thin_user_behavior_redaction(ngx_http_request_t *r,
        Ngx_etomc2_cc_user_behavior *behavior,
        uint32_t time_space, size_t maxVal,
        time_t now, uint32_t hash) {
    return 0;
} /* -----  end of function cc_thin_user_behavior_redaction  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_user_behavior_red
 *  Description:
 * =====================================================================================
 */
int cc_thin_user_behavior_red(ngx_http_request_t *r,
        Ngx_etomc2_cc_user_behavior *behavior, time_t now,
        uint32_t hash,uint32_t hash_uri) {
    uint32_t time_space;
    /** int l = 0; */
    int fib_index, maxIndex;
    int hb;
    size_t maxVal;
    float rise;
    int timestamp = -1, I_index;
    int increase;
    ngx_str_t file_path, path;
    ngx_str_t key;
    Ngx_etomc2_shm_gt *cc_gt_ptr;
    ngx_http_etomc2_loc_conf_t *lccf;
    /***
     *
     * MARK_READY_NEXT_TIME  or  check url is  app loop url
     */
    maxIndex = ArrayMax(behavior->uri_amount);
    maxVal = behavior->uri_amount[maxIndex];

    time_space = (now - behavior->rate_0);
    if (time_space > MARK_READY_NEXT_TIME_INVALID && behavior->mark == M_READY) {
        /**
         *  next  MARK_READY_NEXT_TIME  to check
         */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "M_READY status continue, now:%z, rate_0:%z,time_space:%di, maxVal:%d", now,
                behavior->rate_0, time_space, maxVal);

        behavior->rate_1 = behavior->rate_0;
        behavior->rate_0 = now;

        return -1;
    }
    if (time_space < MARK_READY_NEXT_TIME) {
        /**
         *  M_READY status continue
         * next  MARK_READY_NEXT_TIME  to check
         */
        return -1;
    }

    key = behavior->hash_str;
    file_path.len = 0;
    behavior->rate_1 = behavior->rate_0;
    behavior->rate_0 = now;
    if (behavior->mark == M_READY || behavior->mark == M_SMALL) {
        increase = maxVal - behavior->uri_amount[ROAD_MAP_URI_MAX - 1];
        rise =
            (float)maxVal / (float)behavior->uri_amount[ROAD_MAP_URI_MAX - 1];
        I_index = 0;

        behavior->uri_amount[ROAD_MAP_URI_MAX - 1] = maxVal;

        if (rise <= Fibonacci[1][0]) {
            rise = (float)increase / (float)ROAD_MAP_URI_MAX;

            if (rise <= Fibonacci[1][0]) {
                /**
                 * M_READY status continue
                 */

                return -1;
            }
        }
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "M_RED status  rise:%.5f,  increase:%d max:%d, amount:%d",
                rise, increase, maxVal,
                behavior->uri_amount[ROAD_MAP_URI_MAX - 1]);
        lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
        if (!lccf) return -1;

        /**
         *  itemize
         *
         */
        /**         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "cc_itemize:%d", */
        /** lccf->cc_itemize); */
        if (lccf->cc_itemize == 1) {

            cc_gt_ptr = NULL;
            ngx_cc_gt_search(r, &cc_gt_ptr);
            if(cc_gt_ptr){
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "[CC Attack check:%d  level:%d  cc_id:%z,take:%d]",
                        cc_gt_ptr->count, cc_gt_ptr->level,
                        hash_uri,cc_gt_ptr->take);
            }else{
                ngx_cc_gt(r);
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "[CC Attack  cc_id:%z]",
                        hash_uri);
            }
            if (cc_gt_ptr == NULL || cc_gt_ptr->take == 0) {
                return -1;
            }
        }

        /** lreq_status(r); */

        /**
         * fib_index = [2,3]
         *
         */
        behavior->mark = M_RED;
        fib_index = (int)rise;
        if (fib_index > 3) {
            I_index = 4;
        } else if (rise >= Fibonacci[fib_index][1]) {
            I_index = I_index + fib_index;
        } else {
            I_index = I_index + fib_index - 1;
        }

        if (I_index > 4) I_index = 4;
        behavior->uri_amount[ROAD_MAP_URI_MAX - 2] = I_index;
        ngx_cc_gt(r);

    } else if (behavior->mark == M_YELLOW) {
        rise = (float)maxVal / (float)ROAD_MAP_URI_MAX;
        fib_index = (int)rise;

        if (rise >= Fibonacci[2][0]) {
            /**
             * enter cc attacking
             */
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "M_READY status  rise:%.5f", rise);
            if (behavior->uri_amount[BEHAVIOR_URI_SMALL] == 0 &&
                    behavior->content_types[BEHAVIOR_URI_SMALL] == 0) {
                behavior->mark = M_SMALL;
            } else {
                behavior->mark = M_READY;
            }
            behavior->uri_amount[ROAD_MAP_URI_MAX - 1] = maxVal;
        }
    }

    if (behavior->mark == M_RED) {
        int gt = ngx_cc_gt_check(r,hash_uri);

        if (gt == -1) {
            return -1;
        }

        black_ip_log(r);
        path = hdcache_hash_to_dir(r, hash, behavior->mark);
        hb = hdcache_create_dir((char *)path.data, 0700);
        if (hb == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "hdcache_create_dir  error");
            return -1;
        }

        file_path = hdcache_file_build(r, path, key);
        if (file_path.len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "file_path  error");
            return -1;
        }
        I_index = hdcache_file_content((char *)file_path.data, &timestamp);

        if (I_index != -1) {
            I_index += 1;
            if (I_index > 4) I_index = 4;
        } else {
            I_index = behavior->uri_amount[ROAD_MAP_URI_MAX - 2];
        }

        hdcache_create_file((char *)file_path.data, I_index, behavior->rate_0);

        return 0;
    }
    return -1;
} /* -----  end of function cc_thin_user_behavior_red  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_user_behavior_lreq
 *  Description:
 * =====================================================================================
 */
void cc_thin_user_behavior_lreq(ngx_http_request_t *r,
        Ngx_etomc2_cc_user_behavior *behavior,
        time_t now) {
    int fib_index, maxIndex;
    size_t maxVal;
    float rise;

    uint32_t time_space;

    time_space = (now - behavior->rate_0);
    if (time_space < MARK_READY_NEXT_TIME) {
        /**
         *M_READY status continue
         */
        return;
    }

    behavior->rate_1 = behavior->rate_0;
    behavior->rate_0 = now;

    maxIndex = ArrayMax(behavior->uri_amount);
    maxVal = behavior->uri_amount[maxIndex];
    rise = (float)maxVal / (float)behavior->uri_amount[ROAD_MAP_URI_MAX - 1];
    fib_index = (int)rise;
    behavior->uri_amount[ROAD_MAP_URI_MAX - 1] = maxVal;
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "cc_thin_user_behavior_lreq, %.2f, %d", rise, fib_index);
    /**     if (fib_index <= Fibonacci[1][0] && fib_index > Fibonacci[0][0])
     * {
     */
    /** //  guess == 1 */
    /** lreq_ctrl_uri(r, 1); */
    /** } */
} /* -----  end of function cc_thin_user_behavior_lreq  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_user_behavior_check_node
 *  Description:
 * =====================================================================================
 */
int cc_thin_user_behavior_check_node(ngx_http_request_t *r,
        Ngx_etomc2_cc_user_behavior *cc_ub_ptr,
        ngx_str_t *key, uint32_t hash,
        uint32_t hash_uri, uint32_t hash_type,
        ngx_slab_pool_t *shpool) {
    ngx_rbtree_node_t *find_node;
    int m = 0, n = 0, rate0, rate1;
    size_t referer = 0;
    /** uint32_t time_space; */
    Ngx_etomc2_cc_user_behavior *behavior;
    int now = ngx_time();
    find_node = cc_thin_user_behavior_search(cc_ub_ptr->rbtree.root,
            cc_ub_ptr->rbtree.sentinel, key);
    if (find_node == cc_ub_ptr->rbtree.sentinel) {
        return -1;
    }

    behavior = (Ngx_etomc2_cc_user_behavior *)find_node;
    /**
     *  check uuid
     */
    int amount = behavior->uri_amount[0] + behavior->uri_amount[1] +
        behavior->uri_amount[2];
    if (behavior->BrowserOrBot == BB_DEFAULT && amount >= 3) {
        int bb = behavior_uuid_cookie(r);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "behavior_uuid_cookie:%d", bb);
        if (bb == -1) {
            behavior->BrowserOrBot = BB_BOT;
        } else if (bb == 0) {
            behavior->BrowserOrBot = BB_BROWSER;
        }
    }

    m = 0;
    while (behavior->road_maps[m] != 0) {
        if (behavior->road_maps[m] == hash_uri) {
            behavior->uri_amount[m] += 1;
            break;
        }
        m++;
        if (m == ROAD_MAP_URI_MAX) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ROAD_MAP_URI_MAX delete node:%s",
                    behavior->hash_str.data);
            goto green;
        }
        if (m < ROAD_MAP_URI_MAX && behavior->road_maps[m] == 0) {
            behavior->road_maps[m] = hash_uri;
            behavior->uri_amount[m] = 1;
        }
    }

    for (n = 0; n < CONTENT_SIZE; n++) {
        if (behavior->content_types[n] == 0) {
            behavior->content_types[n] = hash_type;
            break;
        }
        if (behavior->content_types[n] == hash_type) {
            break;
        }
    }
    if (behavior->content_types[CONTENT_SIZE - 1] != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "CONTENT_SIZE delete node:%s", behavior->hash_str.data);
        goto green;
    }
    /**
     *  not the same uri
     */
    if (behavior->rate_0 > 0 && behavior->rate_1 > 0 &&
            (behavior->uri_amount[3] != 0 || behavior->content_types[3] != 0)) {
        rate0 = behavior->rate_0 - behavior->rate_1;
        rate1 = now - behavior->rate_0;
        if (rate0 > TIME_RATE_INTERVAL && rate1 > TIME_RATE_INTERVAL &&
                behavior->referer == 1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "TIME_RATE_INTERVAL delete node:%s",
                    behavior->hash_str.data);

            goto green;
        }
    }

    if (referer == 1) {
        behavior->referer = 1;
    }
    /**
     *m = uri , n = content_type
     */
    if (behavior->uri_amount[BAD_BEHAVIOR] == 0 &&
            behavior->content_types[BAD_BEHAVIOR] == 0) {
        /**
         *  check  M_RED
         */

        int isred = cc_thin_user_behavior_red(r, behavior, now, hash,hash_uri);
        if (isred == 0) {
            cc_thin_user_behavior_delete(&cc_ub_ptr->rbtree, find_node, shpool);
        }
    }

    return 0;

green:
    cc_thin_user_behavior_green(r, behavior, hash);

    cc_thin_user_behavior_delete(&cc_ub_ptr->rbtree, find_node, shpool);

    return 0;
} /* -----  end of function cc_thin_user_behavior_check_node  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_user_behavior_add
 *  Description:
 * =====================================================================================
 */
int cc_thin_user_behavior_add(ngx_http_request_t *r, ngx_slab_pool_t *shpool,
        ngx_str_t *key, uint32_t hash_uri,
        uint32_t hash_type, uint32_t hash, size_t referer,
        Ngx_etomc2_cc_user_behavior *cc_ub_ptr) {
    ngx_rbtree_node_t *node;
    Ngx_etomc2_cc_user_behavior *behavior;

    node = ngx_slab_alloc_locked(shpool, sizeof(Ngx_etomc2_cc_user_behavior));
    if (!node) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "node ngx_slab_alloc_locked is null");

        return -1;
    }
    node->key = hash;

    behavior = (Ngx_etomc2_cc_user_behavior *)node;

    behavior->mark = M_YELLOW;
    memset(behavior->road_maps, 0, sizeof(behavior->road_maps));
    memset(behavior->uri_amount, 0, sizeof(behavior->uri_amount));
    memset(behavior->content_types, 0, sizeof(behavior->content_types));

    behavior->road_maps[0] = hash_uri;
    behavior->uri_amount[0] = 1;
    behavior->content_types[0] = hash_type;
    behavior->referer = referer;
    behavior->rate_0 = ngx_time();
    behavior->rate_1 = 0;
    behavior->method = 0;
    behavior->BrowserOrBot = BB_DEFAULT;
    behavior->hash_str.len = key->len;
    behavior->hash_str.data =
        ngx_slab_alloc_locked(shpool, behavior->hash_str.len);
    if (!behavior->hash_str.data) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "behavior ngx_slab_alloc_locked is null");

        ngx_slab_free_locked(shpool, node);

        return -1;
    }

    snprintf((char *)behavior->hash_str.data, behavior->hash_str.len, "%s",
            key->data);
    ngx_rbtree_insert(&cc_ub_ptr->rbtree, node);

    return 0;
} /* -----  end of function cc_thin_user_behavior_add  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_ub_queue
 *  Description:
 * =====================================================================================
 */
void cc_thin_ub_queue(ngx_http_request_t *r, ngx_http_etomc2_loc_conf_t *lccf,
        Ngx_etomc2_cc_user_behavior *cc_ub_ptr, ngx_str_t *key,
        int memory_free) {
    ngx_shm_zone_t *shm_zone_ub_queue;
    Ngx_ub_queue_ptr *ub_queue_ptr;
    Ngx_etomc2_ub_queue *th;
    time_t now = ngx_time();
    ngx_rbtree_node_t *find_node;
    ngx_slab_pool_t *shpool;

    if (lccf->shm_zone_ub_queue == NULL) {
        return;
    }
    shm_zone_ub_queue = lccf->shm_zone_ub_queue;

    ub_queue_ptr = (Ngx_ub_queue_ptr *)shm_zone_ub_queue->data;

    th = ub_queue_ptr->head;
    if (th && th->time_reckon != 0) {
        if (((uint32_t)now - th->time_reckon) > TIME_RECKON_OUT ||
                memory_free == -1) {
            find_node = cc_thin_user_behavior_search(cc_ub_ptr->rbtree.root,
                    cc_ub_ptr->rbtree.sentinel,
                    &th->hash_str);

            if (find_node != cc_ub_ptr->rbtree.sentinel) {
                shpool = (ngx_slab_pool_t *)lccf->shm_zone_cc_ub->shm.addr;

                cc_thin_user_behavior_delete(&cc_ub_ptr->rbtree, find_node,
                        shpool);
            }

            shpool = (ngx_slab_pool_t *)shm_zone_ub_queue->shm.addr;

            if (ub_queue_ptr->head->next) {
                ub_queue_ptr->head = ub_queue_ptr->head->next;
                ngx_slab_free_locked(shpool, th->hash_str.data);
                ngx_slab_free_locked(shpool, th);
            } else {
                ub_queue_ptr->head->time_reckon = 0;

                ngx_slab_free_locked(shpool, ub_queue_ptr->head->hash_str.data);
            }
        }
    }
    shpool = (ngx_slab_pool_t *)shm_zone_ub_queue->shm.addr;

    cc_thin_ub_queue_insert(ub_queue_ptr, shpool, key);

} /* -----  end of function cc_thin_ub_queue  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_user_behavior_lookup
 *  Description:
 * =====================================================================================
 */
void cc_thin_user_behavior_lookup(ngx_http_request_t *r, ngx_str_t *key) {
    ngx_shm_zone_t *shm_zone_cc_ub;

    ngx_http_etomc2_loc_conf_t *lccf;
    Ngx_etomc2_cc_user_behavior *cc_ub_ptr;

    uint32_t hash, hash_uri, hash_type;
    ngx_http_headers_out_t out_t = r->headers_out;

    ngx_slab_pool_t *shpool;

    size_t referer = 0;
    int exist;
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!lccf) return;

    if (lccf->shm_zone_cc_ub == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "shm_zone_cc_ub is null");
        return;
    }

    shm_zone_cc_ub = lccf->shm_zone_cc_ub;
    shpool = (ngx_slab_pool_t *)shm_zone_cc_ub->shm.addr;

    cc_ub_ptr = (Ngx_etomc2_cc_user_behavior *)shm_zone_cc_ub->data;
    if (!cc_ub_ptr) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "cc_ub_ptr is null");

        return;
    }

    hash = to_hash((char *)key->data, key->len);

    ngx_str_t uri = get_uri(r);
    if (uri.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "cc_thin_user_behavior_lookup uri is null");
        return;
    }

    hash_uri = to_hash((char *)uri.data, uri.len);

    hash_type =
        to_hash((char *)out_t.content_type.data, out_t.content_type.len);

    if (r->headers_in.referer != NULL) {
        referer = 1;
    }

    ngx_shmtx_lock(&shpool->mutex);

    exist = cc_thin_user_behavior_check_node(r, cc_ub_ptr, key, hash, hash_uri,
            hash_type, shpool);
    if (exist == 0) {
        /**
         * exist  client
         */

        ngx_shmtx_unlock(&shpool->mutex);

        return;
    }
    /**
     *
     * new client
     */
    int isok = cc_thin_user_behavior_add(r, shpool, key, hash_uri, hash_type,
            hash, referer, cc_ub_ptr);

    if (isok == -1) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "cc_thin_user_behavior_lookup share memory error");
        // return;
    }else{
        size_t size;
        size = 1 << ngx_pagesize_shift;
        int freesize = (shpool->pfree * size / 1024 - size / 1024);
        if (freesize < 0) {
            /**      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, */
            /** "free:%12z(KB)   isok:%d",shpool->pfree*size/1024-size/1024,isok */
            /** ); */
            isok = -1;
        }
    }
    /**
     * ub_queue
     */
    cc_thin_ub_queue(r, lccf, cc_ub_ptr, key, isok);

    ngx_shmtx_unlock(&shpool->mutex);

    return;
} /* -----  end of function cc_thin_user_behavior_lookup  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  ArrayMax
 *  Description:
 * =====================================================================================
 */
int ArrayMax(size_t array[]) {
    size_t i = 0;
    int step = 0;
    size_t maxVal = 0;
    while (i < (ROAD_MAP_URI_MAX - 2) && array[i] != 0) {
        if (maxVal < array[i]) {
            maxVal = array[i];
            step = i;
        }
        i++;
    }

    return step;
} /* -----  end of function ArrayMax  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_user_behavior_search
 *  Description:
 * =====================================================================================
 */
ngx_rbtree_node_t *cc_thin_user_behavior_search(ngx_rbtree_node_t *node,
        ngx_rbtree_node_t *sentinel,
        ngx_str_t *key) {
    uint32_t hash;
    ngx_int_t cmp;
    Ngx_etomc2_cc_user_behavior *lrn = NULL;

    hash = to_hash((char *)key->data, key->len);

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        } else if (hash > node->key) {
            node = node->right;
            continue;
        } else {
            lrn = (Ngx_etomc2_cc_user_behavior *)node;

            /*   lrn->hash_str.len == lrnt->hash_str.len  */
            cmp = ngx_memn2cmp(lrn->hash_str.data, key->data, lrn->hash_str.len,
                    key->len);
            /* only key */
            if (cmp == 0) {
                break;
            }

            node = (cmp < 0) ? node->left : node->right;
        }
    }
    return node;
} /* -----  end of function cc_thin_user_behavior_search  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_user_behavior_delete
 *  Description:
 * =====================================================================================
 */
void cc_thin_user_behavior_delete(ngx_rbtree_t *root, ngx_rbtree_node_t *node,
        ngx_slab_pool_t *shpool) {
    Ngx_etomc2_cc_user_behavior *behavior = (Ngx_etomc2_cc_user_behavior *)node;

    ngx_rbtree_delete(root, node);
    ngx_slab_free_locked(shpool, behavior->hash_str.data);
    ngx_slab_free_locked(shpool, behavior);

} /* -----  end of function cc_thin_user_behavior_delete  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  cc_thin_ub_queue_insert
 *  Description:
 * =====================================================================================
 */
void cc_thin_ub_queue_insert(Ngx_ub_queue_ptr *ub_queue_ptr,
        ngx_slab_pool_t *shpool, ngx_str_t *hash_str) {
    Ngx_etomc2_ub_queue *new_queue;

    time_t seconds;
    seconds = ngx_time();
    if (!ub_queue_ptr->head) {
        ub_queue_ptr->head =
            ngx_slab_alloc_locked(shpool, sizeof(Ngx_etomc2_ub_queue));
        if (!ub_queue_ptr->head) {
            return;
        }
    }

    if (ub_queue_ptr->head->time_reckon == 0) {
        ub_queue_ptr->head->hash_str.len = hash_str->len;

        ub_queue_ptr->head->hash_str.data =
            ngx_slab_alloc_locked(shpool, hash_str->len);
        if (!ub_queue_ptr->head->hash_str.data) return;
        snprintf((char *)ub_queue_ptr->head->hash_str.data,
                ub_queue_ptr->head->hash_str.len, "%s", hash_str->data);
        ub_queue_ptr->head->time_reckon = seconds;
        ub_queue_ptr->tail = ub_queue_ptr->head;

    } else {
        new_queue = ngx_slab_alloc_locked(shpool, sizeof(Ngx_etomc2_ub_queue));
        if (!new_queue) return;
        new_queue->hash_str.len = hash_str->len;
        new_queue->hash_str.data = ngx_slab_alloc_locked(shpool, hash_str->len);
        if (!new_queue->hash_str.data) {
            ngx_slab_free_locked(shpool, new_queue);
            return;
        }
        new_queue->time_reckon = seconds;

        snprintf((char *)new_queue->hash_str.data, new_queue->hash_str.len,
                "%s", hash_str->data);
        ub_queue_ptr->tail->next = new_queue;
        ub_queue_ptr->tail = ub_queue_ptr->tail->next;
    }

} /* -----  end of function cc_thin_ub_queue_insert  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  ngx_cc_rbtree_loop
 *  Description:
 * =====================================================================================
 */
void ngx_cc_rbtree_loop(ngx_http_request_t *r, ngx_rbtree_node_t *node,
        ngx_rbtree_node_t *sentinel) {
    Ngx_etomc2_cc_user_behavior *lrn;
    char str[256];
    char amount[256];
    char ctype[256];

    if (node != sentinel) {
        lrn = (Ngx_etomc2_cc_user_behavior *)node;

        int i = 0;
        int index = 0, ai = 0, ci = 0;
        for (i = 0; i < 13; i++) {
            index +=
                snprintf(&str[index], 256 - index, ",%d", lrn->road_maps[i]);
            ai += snprintf(&amount[ai], 256 - ai, ",%lx", lrn->uri_amount[i]);
            ci += snprintf(&ctype[ci], 256 - ci, ",%ld", lrn->content_types[i]);
            if (lrn->road_maps[i] == 0) {
                break;
            }
        }
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "[find  node road_maps:%s,= amount:%s= ctype:%s= "
                "rate_0:%d, rate_1:%d]",
                str, amount, ctype, lrn->rate_0, lrn->rate_1);

        ngx_cc_rbtree_loop(r, node->left, sentinel);
        ngx_cc_rbtree_loop(r, node->right, sentinel);
    }

} /* -----  end of function ngx_cc_rbtree_loop  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  ngx_cc_rbtree_showall
 *  Description:
 * =====================================================================================
 */
void ngx_cc_rbtree_showall(ngx_http_request_t *r) {
    ngx_http_etomc2_loc_conf_t *lccf;
    Ngx_etomc2_cc_user_behavior *cc_ub_ptr;
    ngx_rbtree_node_t *node, *sentinel;
    Ngx_etomc2_cc_user_behavior *lrn;
    ngx_shm_zone_t *shm_zone_cc_ub;
    char str[256];
    char amount[256];
    char ctype[256];

    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!lccf) return;

    if (lccf->shm_zone_cc_ub == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "shm_zone_cc_ub is null");
        return;
    }

    shm_zone_cc_ub = lccf->shm_zone_cc_ub;

    cc_ub_ptr = (Ngx_etomc2_cc_user_behavior *)shm_zone_cc_ub->data;
    node = cc_ub_ptr->rbtree.root;
    sentinel = cc_ub_ptr->rbtree.sentinel;
    if (node != sentinel) {
        lrn = (Ngx_etomc2_cc_user_behavior *)node;

        int i = 0;
        int index = 0, ai = 0, ci = 0;
        for (i = 0; i < 13; i++) {
            if (lrn->road_maps[i] == 0) {
                break;
            }
            index +=
                snprintf(&str[index], 256 - index, ",%d", lrn->road_maps[i]);
            ai += snprintf(&amount[ai], 256 - ai, ",%lx", lrn->uri_amount[i]);
            ci += snprintf(&ctype[ci], 256 - ci, ",%ld", lrn->content_types[i]);
        }
        ngx_log_error(
                NGX_LOG_ERR, r->connection->log, 0,
                "[find  node road_maps:%s,= amount:%s = ctype:%s,= referer:%s]",
                str, amount, ctype, lrn->hash_str.data);
        ngx_cc_rbtree_loop(r, node->left, sentinel);
        ngx_cc_rbtree_loop(r, node->right, sentinel);
    }

} /* -----  end of function ngx_cc_rbtree_showall  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  ngx_cc_rbtree_hash_key
 *  Description:
 * =====================================================================================
 */
ngx_str_t *ngx_cc_rbtree_hash_key(ngx_http_request_t *r) {
    /** ngx_http_etomc2_loc_conf_t *lccf; */

    ngx_str_t *key;
    const char *fmt = "%.*s,%.*s,%.*s,%s";
    ngx_md5_t ctx;
    u_char md5[16];
    char md5_32[32];
    int i = 0;
    ngx_str_t ip = client_forward_ip(r);

    if(ip.len == 0)return NULL;

    //  hash(server_name+ip+ua+key)   key: HASH_COOKIE_KEY  ...
    key = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    if (!key) return NULL;

    if (r->headers_in.user_agent == NULL) {
        /**         lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module); */
        /** if (!lccf || lccf->hdcache_path.len ==0) { */
        /**     return NULL; */
        /** } */
        /** uint32_t hash = to_hash((char *)ip.data, ip.len); */
        /**  */
        /** ngx_str_t path = hdcache_hash_to_dir_def( */
        /**         r, (char *)lccf->hdcache_path.data, hash, M_RED); */
        /** int  hb = hdcache_create_dir((char *)path.data, 0700); */
        /** if (hb == -1) { */
        /**     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, */
        /**             "hdcache_create_dir  error"); */
        /**     return NULL; */
        /** } */
        /** ngx_str_t file_path = hdcache_file_build(r, path, ip); */
        /** hdcache_create_file((char *)file_path.data, 0, 0); */
        /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, */
        /** "user_agent is null, %s",ip.data); */
        return NULL;
    }

    key->len = snprintf(NULL, 0, fmt, r->headers_in.server.len,
            r->headers_in.server.data, ip.len, ip.data,
            r->headers_in.user_agent->value.len,
            r->headers_in.user_agent->value.data, HASH_COOKIE_KEY);

    key->len += 1;
    key->data = ngx_pcalloc(r->pool, key->len);
    if (!key->data) return NULL;

    snprintf((char *)key->data, key->len, fmt, r->headers_in.server.len,
            r->headers_in.server.data, ip.len, ip.data,
            r->headers_in.user_agent->value.len,
            r->headers_in.user_agent->value.data, HASH_COOKIE_KEY);

    ngx_md5_init(&ctx);
    ngx_md5_update(&ctx, key->data, key->len);
    ngx_md5_final(md5, &ctx);

    for (i = 0; i < 16; i++) {
        sprintf(md5_32 + i * 2, "%02X", md5[i]);
    }
    ngx_pfree(r->pool, key->data);

    key->len = 33;
    key->data = ngx_pcalloc(r->pool, key->len);
    if (!key->data) return NULL;
    snprintf((char *)key->data, key->len, "%s", md5_32);

    return key;
} /* -----  end of function ngx_cc_rbtree_hash_key  ----- */


/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  black_ip_log
 *  Description:
 * =====================================================================================
 */
void black_ip_log(ngx_http_request_t *r) {
    ngx_str_t ip = client_forward_ip(r);
    char CARET_RETURN = '\n';
    if(cc_black_ip_file==NULL || !cc_black_ip_file->file) {
        return;
    }
    ngx_write_fd(cc_black_ip_file->file->fd, ip.data, ip.len);

    ngx_write_fd(cc_black_ip_file->file->fd, &CARET_RETURN, sizeof(char));

} /* -----  end of function black_ip_log  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  client_forward_ip
 *  Description:
 * =====================================================================================
 */
ngx_str_t client_forward_ip(ngx_http_request_t *r) {
    ngx_table_elt_t **forwarded;
    ngx_uint_t nelts;
    ngx_str_t ip;
    const char *fmt = "%s";

    forwarded = r->headers_in.x_forwarded_for.elts;
    nelts = r->headers_in.x_forwarded_for.nelts;
    if (nelts == 0) {
        ip.len = snprintf(NULL, 0, fmt, r->connection->addr_text.data);
    } else {
        ip.len = snprintf(NULL, 0, fmt, forwarded[0]->value.data);
    }
    /** ip.len +=1; */
    ip.data = ngx_pcalloc(r->pool, ip.len + 1);
    if (!ip.data) {
        ip.len = 0;
        return ip;
    }
    if (nelts == 0) {
        snprintf((char *)ip.data, ip.len + 1, fmt,
                r->connection->addr_text.data);
    } else {
        snprintf((char *)ip.data, ip.len + 1, fmt, forwarded[0]->value.data);
    }
    return ip;
} /* -----  end of function client_forward_ip  ----- */
