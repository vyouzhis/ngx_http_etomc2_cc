/*
 * =====================================================================================
 *
 *       Filename:  etomc2_gt.c
 *
 *    Description:  cc gt
 *
 *        Version:  1.0
 *        Created:  2020年05月27日 23时47分54秒
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
 *         Name:  ngx_cc_gt
 *  Description:
 * =====================================================================================
 */
void ngx_cc_gt(ngx_http_request_t *r) {
    ngx_http_dummy_loc_conf_t *lccf;
    ngx_slab_pool_t *shpool;

    Ngx_etomc2_shm_gt *cc_gt_ptr, *cc_new_ptr;
    ngx_shm_zone_t *shm_zone_cc_gt;
    time_t now;
    uint32_t hash_domain;

    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!lccf) return;

    if (lccf->shm_zone_cc_gt == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shm_zone_cc_ub is null");
        return;
    }

    shm_zone_cc_gt = lccf->shm_zone_cc_gt;

    cc_gt_ptr = (Ngx_etomc2_shm_gt *)shm_zone_cc_gt->data;
    now = ngx_time();
    hash_domain =
        to_hash((char *)r->headers_in.server.data, r->headers_in.server.len);
    int diff = now - cc_gt_ptr->now;

    while (cc_gt_ptr) {
        if (cc_gt_ptr->hash_domain == 0) {
            cc_gt_ptr->hash_domain = hash_domain;

            switch (lccf->cc_gt_level) {
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
                    cc_gt_ptr->level = GTL_5;

                    break;
            } /* -----  end switch  ----- */
        }

        if (cc_gt_ptr->hash_domain == hash_domain) {

            if (diff > SHM_GT_TIMEOUT) {
                cc_gt_ptr->count = 1;

            } else {
                cc_gt_ptr->count += 1;
            }
            cc_gt_ptr->now = now;
            return;
        }
        if (cc_gt_ptr->next == NULL) {
            shpool = (ngx_slab_pool_t *)shm_zone_cc_gt->shm.addr;

            // new
            cc_new_ptr = ngx_cc_gt_init(shpool);
            if (!cc_new_ptr) {
                return;
            }
            cc_new_ptr->hash_domain = hash_domain;
            cc_new_ptr->now = now;

            switch (lccf->cc_gt_level) {
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
                    cc_new_ptr->level = GTL_5;

                    break;
            } /* -----  end switch  ----- */
            cc_gt_ptr->next = cc_new_ptr;
            return;
        }

        cc_gt_ptr = cc_gt_ptr->next;
    }

} /* -----  end of function ngx_cc_gt  ----- */

/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_cc_gt_init Description:
 * =====================================================================================
 */
Ngx_etomc2_shm_gt *ngx_cc_gt_init(ngx_slab_pool_t *shpool) {
    Ngx_etomc2_shm_gt *cc_new_ptr;

    // new
    cc_new_ptr = ngx_slab_alloc_locked(shpool, sizeof(Ngx_etomc2_shm_gt));
    if (!cc_new_ptr) {
        return NULL;
    }
    cc_new_ptr->hash_domain = 0;
    cc_new_ptr->count = 1;
    cc_new_ptr->now = 0;
    cc_new_ptr->take = 0;
    memset(cc_new_ptr->uri_itemize, 0,(size_t) CC_GT_URI_MAX*sizeof(uint32_t));
    cc_new_ptr->level = GTL_5;

    cc_new_ptr->next = NULL;

    return cc_new_ptr;
} /* -----  end of function ngx_cc_gt_init  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  ngx_cc_gt_check
 *  Description:
 * =====================================================================================
 */
int ngx_cc_gt_check(ngx_http_request_t *r,uint32_t hash_uri) {
    Ngx_etomc2_shm_gt *cc_gt_ptr; 

    int i;
    SHM_GT_LEVEL uri_level;
    cc_gt_ptr = NULL;
    ngx_cc_gt_search(r, &cc_gt_ptr);

 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "[CC Attack check:%d  level:%d]",
                    cc_gt_ptr->count, cc_gt_ptr->level);
    if (cc_gt_ptr != NULL && cc_gt_ptr->count >= cc_gt_ptr->level) {
        for (i = 0; i < CC_GT_URI_MAX && cc_gt_ptr->uri_itemize[i]!=0; i++) {
            if (cc_gt_ptr->uri_itemize[i] == hash_uri) {
                uri_level = cc_gt_ptr->level;
                switch (uri_level) {
                    case GTL_1:
                        uri_level = GTL_2;
                        break;
                    case GTL_2:
                        uri_level = GTL_3;
                        break;
                    case GTL_3:
                        uri_level = GTL_4;
                        break;
                    case GTL_4:
                        uri_level = GTL_5;
                        break;
                    default:
                        uri_level = GTL_5;
                        break;
                } /* -----  end switch  ----- */
                if (cc_gt_ptr->count >= uri_level) {
                    return 0;
                } else {
                    return -1;
                }
            }
        }
        return 0;
    }
    return -1;
} /* -----  end of function ngx_cc_gt_check  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_cc_gt_search Description:
 * =====================================================================================
 */
void ngx_cc_gt_search(ngx_http_request_t *r, Ngx_etomc2_shm_gt **gt_node_ptr) {
    ngx_http_dummy_loc_conf_t *lccf;
    Ngx_etomc2_shm_gt *cc_gt_ptr;
    ngx_shm_zone_t *shm_zone_cc_gt;
    uint32_t hash_domain;
    /** ngx_str_t uri; */

    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!lccf) return;

    if (lccf->shm_zone_cc_gt == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shm_zone_cc_ub is null");
        return;
    }

    shm_zone_cc_gt = lccf->shm_zone_cc_gt;

    cc_gt_ptr = (Ngx_etomc2_shm_gt *)shm_zone_cc_gt->data;
    hash_domain =
        to_hash((char *)r->headers_in.server.data, r->headers_in.server.len);

    while (cc_gt_ptr) {
        if (cc_gt_ptr->hash_domain == hash_domain) {
            *gt_node_ptr = cc_gt_ptr;

            return;
        }
        cc_gt_ptr = cc_gt_ptr->next;
    }
    *gt_node_ptr = NULL;
} /* -----  end of function ngx_cc_gt_search  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  gt_index
 *  Description:
 * =====================================================================================
 */
int gt_index(SHM_GT_LEVEL gt) {
    switch (gt) {
        case GTL_1:
            return 1;
        case GTL_2:
            return 2;
        case GTL_3:
            return 3;
        case GTL_4:
            return 4;
        default:
            return 5;
    } /* -----  end switch  ----- */

} /* -----  end of function gt_index  ----- */
