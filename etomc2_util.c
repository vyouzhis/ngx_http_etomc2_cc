/*
 * =====================================================================================
 *
 *       Filename:  etomc2_util.c
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  2020年08月24日 23时39分29秒
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
 * ======================================================================
 *         Name:  timeIndex
 *  Description:
 * =====================================================================================
 */
int timeIndex() {
    time_t rawtime = time(NULL);

    if (rawtime == -1) {
        return 0;
    }

    struct tm *ptm = localtime(&rawtime);

    if (ptm == NULL) {
        return 0;
    }
    return ptm->tm_min;
    /** return   ptm->tm_hour; */
} /* -----  end of function timeIndex  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  tree_create
 *  Description:
 * =====================================================================================
 */
Ngx_etomc2_shm_tree_data *tree_create(ngx_slab_pool_t *shpool) {
    Ngx_etomc2_shm_tree_data *temp = NULL;
    if (shpool == NULL) {
        temp = (Ngx_etomc2_shm_tree_data *)malloc(
            sizeof(Ngx_etomc2_shm_tree_data));
    } else {
        temp = ngx_slab_alloc_locked(shpool, sizeof(Ngx_etomc2_shm_tree_data));
    }
    if (temp == NULL) {
        return NULL;
    }
    temp->left = temp->right = NULL;
    temp->hashkey = 0;
    temp->data = NULL;
    return temp;
} /* -----  end of function tree_create  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  tree_insert
 *  Description:
 * =====================================================================================
 */
size_t tree_insert(ngx_http_request_t *r, Ngx_etomc2_shm_tree_data **tree,
                   uint32_t hashkey, void *data, ngx_slab_pool_t *shpool) {
    size_t res = -1;

    if (!(*tree)) {
        *tree = tree_create(shpool);

        if ((*tree) == NULL) {
            return res;
        }
        (*tree)->hashkey = hashkey;
        (*tree)->data = data;
        return 0;
    }
    if (!(*tree)->data) {
        (*tree)->hashkey = hashkey;
        (*tree)->data = data;
        return 0;
    }

    if (hashkey < (*tree)->hashkey) {
        res = tree_insert(r, &(*tree)->left, hashkey, data, shpool);
    } else if (hashkey > (*tree)->hashkey) {
        res = tree_insert(r, &(*tree)->right, hashkey, data, shpool);
    }
    return res;
} /* -----  end of function tree_insert  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * tree_search Description:
 * =====================================================================================
 */
Ngx_etomc2_shm_tree_data *tree_search(Ngx_etomc2_shm_tree_data **tree,
                                      uint32_t hashkey) {
    Ngx_etomc2_shm_tree_data *tmp = NULL;

    if (!(*tree)) {
        return NULL;
    }

    if (hashkey < (*tree)->hashkey) {
        tmp = tree_search(&((*tree)->left), hashkey);
    } else if (hashkey > (*tree)->hashkey) {
        tmp = tree_search(&((*tree)->right), hashkey);
    } else if (hashkey == (*tree)->hashkey) {
        tmp = *tree;
    }
    return tmp;
} /* -----  end of function tree_search  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * visit_print Description:
 * =====================================================================================
 */
void visit_print(ngx_http_request_t *r, Ngx_etomc2_shm_tree_data *tree) {
    /** char *pstr; */
    char str[128];
    if (tree) {
        Ngx_etomc2_cc_uri *data = (Ngx_etomc2_cc_uri *)tree->data;

        int i = 0;
        int index = 0;
        for (i = 0; i < 60; i++)
            index +=
                snprintf(&str[index], 128 - index, ",%ld", data->visits[i]);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      " hash:%z visits:[%s]", tree->hashkey, str);
        visit_print(r, tree->left);
        visit_print(r, tree->right);
    }

} /* -----  end of function visit_print  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * search_headers_in Description:
 * =====================================================================================
 */
ngx_table_elt_t *search_headers_in(ngx_http_request_t *r, u_char *name,
                                   size_t len) {
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_uint_t i;

    /*
       Get the first part of the list. There is usual only one part.
       */
    part = &r->headers_in.headers.part;
    h = part->elts;

    /*
       Headers list array may consist of more than one part,
       so loop through all of it
       */
    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                /* The last part, search is done. */
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        /*
           Just compare the lengths and then the names case insensitively.
           */
        if (len != h[i].key.len || ngx_strcasecmp(name, h[i].key.data) != 0) {
            /* This header doesn't match. */
            continue;
        }

        /*
           Ta-da, we got one!
           Note, we'v stop the search at the first matched header
           while more then one header may fit.
           */
        return &h[i];
    }

    /*
       No headers was found
       */
    return NULL;

} /* -----  end of function search_headers_in  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * to_hash Description:
 * =====================================================================================
 */
uint32_t to_hash(const char *key, size_t length) {
    size_t i = 0;

    uint32_t hash = 0;
    while (i != length) {
        hash += key[i++];
        hash += hash << 10;
        hash ^= hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    return hash;

} /* -----  end of function to_hash  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  get_uri
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
} /* -----  end of function get_uri  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * flow_update Description:
 * =====================================================================================
 */
void flow_update(ngx_http_request_t *r) {
    ngx_http_etomc2_loc_conf_t *lccf;
    ngx_shm_zone_t *shm_zone_cc_flow;
    ngx_slab_pool_t *shpool;
    Ngx_etomc2_cc_flow *cc_flow_ptr, *cc_flow_new;
    uint32_t hash_domain;
    time_t now;
    int index;

    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!lccf) {
        return;
    }
    shm_zone_cc_flow = lccf->shm_zone_cc_flow;
    if (!shm_zone_cc_flow) {
        return;
    }
    cc_flow_ptr = (Ngx_etomc2_cc_flow *)shm_zone_cc_flow->data;
    hash_domain =
        to_hash((char *)r->headers_in.server.data, r->headers_in.server.len);
    now = ngx_time();

    index = (int)(now % (60 * 60) / 60);
    NX_DEBUG("index:%d", index);
    shpool = (ngx_slab_pool_t *)shm_zone_cc_flow->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);
    while (cc_flow_ptr) {
        if (cc_flow_ptr->hash_domain == 0) {
            cc_flow_ptr->hash_domain = hash_domain;
        }
        if (cc_flow_ptr->hash_domain == hash_domain) {
            if (cc_flow_ptr->ptr == 0) {
                cc_flow_ptr->ptr = index;
            }
            if (cc_flow_ptr->ptr != index) {
                cc_flow_ptr->flow[index] = 0;
                cc_flow_ptr->ptr = index;
            }
            cc_flow_ptr->now[index] = now;
            cc_flow_ptr->flow[index] += 1;
            break;
        }
        if (cc_flow_ptr->next == NULL) {
            cc_flow_new = flow_init(shpool);
            cc_flow_ptr->next = cc_flow_new;
        }
        cc_flow_ptr = cc_flow_ptr->next;
    }
    ngx_shmtx_unlock(&shpool->mutex);
} /* -----  end of function flow_update  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * flow_init   Description:
 * =====================================================================================
 */
Ngx_etomc2_cc_flow *flow_init(ngx_slab_pool_t *shpool) {
    Ngx_etomc2_cc_flow *cc_flow_new;
    cc_flow_new = ngx_slab_alloc_locked(shpool, sizeof(Ngx_etomc2_cc_flow));
    if (!cc_flow_new) {
        return NULL;
    }
    cc_flow_new->hash_domain = 0;
    memset(cc_flow_new->flow, 0, (size_t)SHM_FLOW_FREQ * sizeof(size_t));
    memset(cc_flow_new->now, 0, (size_t)SHM_FLOW_FREQ * sizeof(time_t));
    cc_flow_new->ptr = 0;
    cc_flow_new->next = NULL;

    return cc_flow_new;
} /* -----  end of function flow_init  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * flow_get Description:
 * =====================================================================================
 */
ngx_str_t *flow_get(ngx_http_request_t *r, ngx_str_t *domain) {
    ngx_http_etomc2_loc_conf_t *lccf;
    ngx_shm_zone_t *shm_zone_cc_flow;
    /** ngx_slab_pool_t *shpool; */
    Ngx_etomc2_cc_flow *cc_flow_ptr;
    uint32_t hash_domain;
    ngx_str_t *fres, *ftmp, *dres, *dtmp, *data=NULL;
    int i = 0;
    const char *fmt_1 = "%d";
    const char *fmt_2 = "%.*s,%d";

    const char *fmt = "{\"flow\":[%.*s],\"date\":[%.*s]}";

    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!lccf) {
        return NULL;
    }
    shm_zone_cc_flow = lccf->shm_zone_cc_flow;
    if (!shm_zone_cc_flow) {
        return NULL;
    }
    cc_flow_ptr = (Ngx_etomc2_cc_flow *)shm_zone_cc_flow->data;
    hash_domain = to_hash((char *)domain->data, domain->len);
    fres = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    ftmp = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    dres = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    dtmp = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    while (cc_flow_ptr) {
        if (cc_flow_ptr->hash_domain == 0) {
            NX_DEBUG("CC_FLOW NULL");
            break;
        }
        if (cc_flow_ptr->hash_domain == hash_domain) {
            /** cc_flow_ptr->now; */
            for (i = 0; i < SHM_FLOW_FREQ; i++) {
                if (i == 0) {
                    fres->len = snprintf(NULL, 0, fmt_1, cc_flow_ptr->flow[i]);
                    fres->len += 1;
                    fres->data = ngx_pcalloc(r->pool, fres->len);
                    snprintf((char *)fres->data, fres->len, fmt_1,
                             cc_flow_ptr->flow[i]);

                    dres->len = snprintf(NULL, 0, fmt_1, cc_flow_ptr->now[i]);
                    dres->len += 1;
                    dres->data = ngx_pcalloc(r->pool, dres->len);
                    snprintf((char *)dres->data, dres->len, fmt_1,
                             cc_flow_ptr->now[i]);
                } else {
                    ftmp->len = snprintf(NULL, 0, fmt_2, fres->len, fres->data,
                                         cc_flow_ptr->flow[i]);
                    ftmp->len += 1;
                    ftmp->data = ngx_pcalloc(r->pool, ftmp->len);
                    snprintf((char *)ftmp->data, ftmp->len, fmt_2, fres->len,
                             fres->data, cc_flow_ptr->flow[i]);
                    ngx_pfree(r->pool, fres->data);
                    /** ngx_pfree(r->pool,res); */
                    fres->data = ftmp->data;
                    fres->len = ftmp->len;

                    dtmp->len = snprintf(NULL, 0, fmt_2, dres->len, dres->data,
                                         cc_flow_ptr->now[i]);
                    dtmp->len += 1;
                    dtmp->data = ngx_pcalloc(r->pool, dtmp->len);
                    snprintf((char *)dtmp->data, dtmp->len, fmt_2, dres->len,
                             dres->data, cc_flow_ptr->now[i]);
                    ngx_pfree(r->pool, dres->data);
                    /** ngx_pfree(r->pool,res); */
                    dres->data = dtmp->data;
                    dres->len = dtmp->len;
                }
            }
            NX_DEBUG("%V, %V", fres, dres);
            break;
        }
        cc_flow_ptr = cc_flow_ptr->next;
    }

    if(dres->len >0){
        data = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
        data->len = snprintf(NULL,0,fmt,fres->len,fres->data,dres->len,dres->data);
        data->len+=1;
        data->data = ngx_pcalloc(r->pool,data->len);
        snprintf((char*)data->data,data->len,fmt,fres->len,fres->data,dres->len,dres->data);
    }
    return data;
} /* -----  end of function flow_get  ----- */
