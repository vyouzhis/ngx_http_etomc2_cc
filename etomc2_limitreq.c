/*
 * =====================================================================================
 *
 *       Filename:  etomc2_limitreq.c
 *
 *    Description:  limit  request
 *
 *        Version:  1.0
 *        Created:  2020年04月18日 22时13分49秒
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
 *         Name:  lreq_status
 *  Description:
 * =====================================================================================
 */
void lreq_status(ngx_http_request_t *r) {
    /** ngx_atomic_int_t ac, rd, wr, wa; */
    /** ac = *ngx_stat_active; */
    /** rd = *ngx_stat_reading; */
    /** wr = *ngx_stat_writing; */
    /** wa = *ngx_stat_waiting; */
    /** ngx_log_error( */
    /**     NGX_LOG_ERR, r->connection->log, 0, */
    /**     "Active connections: %uA Reading: %uA Writing: %uA Waiting: %uA ", ac, */
        /** rd, wr, wa); */

} /* -----  end of function lreq_status  ----- */
  /*
* ===  FUNCTION
* ======================================================================
*         Name:  lreq_header_time
*  Description:
* =====================================================================================
*/
ngx_msec_t lreq_header_time(ngx_http_request_t *r) {
    size_t m = 0;
    ngx_msec_t ntime = 0;
    ngx_http_upstream_state_t *state;
    if (!r->upstream_states) return 0;
    if (r->upstream_states->nelts == 0) return 0;
    state = r->upstream_states->elts;

    if (state) {
        for (m = 0; m < r->upstream_states->nelts; m++) {

            if (ntime < state[m].header_time) {
                ntime = state[m].header_time;
            }
        }
    }

    return ntime;
} /* -----  end of function lreq_header_time  ----- */
  /*
* ===  FUNCTION
* ======================================================================
*         Name:  lreq_uri_queue
*  Description:  only  for M_GREEN  use  the function
* =====================================================================================
*/
void lreq_uri_queue(ngx_http_request_t *r) {
    ngx_shm_zone_t *shm_zone_lreq_queue;
    ngx_slab_pool_t *shpool;
    Ngx_etomc2_lreq_queue *lreq_queue_ptr, *lreq_next;

    uint32_t hash_domain, hash_uri;
    ngx_str_t uri;
    time_t now = ngx_time();
    time_t old_time = now;
    int old_id, i;
    ngx_msec_t header_time;

    ngx_http_etomc2_loc_conf_t *lccf;
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!lccf) return;

    if (lccf->shm_zone_lreq_queue == NULL) {
        return;
    }

    shm_zone_lreq_queue = lccf->shm_zone_lreq_queue;
    shpool = (ngx_slab_pool_t *)shm_zone_lreq_queue->shm.addr;

    lreq_queue_ptr = (Ngx_etomc2_lreq_queue *)shm_zone_lreq_queue->data;
    if (!lreq_queue_ptr) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "lreq_queue_ptr is null");

        return;
    }

    hash_domain =
        to_hash((char *)r->headers_in.server.data, r->headers_in.server.len);
    uri = get_uri(r);
    if (uri.len == 0) return;
    hash_uri = to_hash((char *)uri.data, uri.len);
    header_time = lreq_header_time(r);

    ngx_shmtx_lock(&shpool->mutex);

    if (lreq_queue_ptr->hash_domain == 0) {
        lreq_queue_ptr->hash_domain = hash_domain;
    } else {
        while (lreq_queue_ptr->hash_domain != hash_domain) {

            if (lreq_queue_ptr->next == NULL) {
                // add new queue
                lreq_next =
                    ngx_slab_alloc_locked(shpool, sizeof(Ngx_etomc2_lreq_queue));
                if (!lreq_next) {
                    goto release_lreq;
                }
                memset(lreq_next->lreq, 0,
                       (size_t)LREQ_QUEUE_MAX * sizeof(Ngx_etomc2_lreq_uri));
                /** lreq_next->lreq[0]; */
                lreq_next->lreq[0].hash_uri = hash_uri;
                lreq_next->lreq[0].header_time = header_time;

                lreq_next->lreq[0].avgtime[0] = header_time;
                lreq_next->lreq[0].avgtime[1] = 0;
                lreq_next->lreq[0].avgtime[0] = header_time;
                lreq_next->lreq[0].avgtime[3] = 0;
                lreq_next->lreq[0].active = 0;

                lreq_next->lreq[0].stime = now;
                lreq_next->lreq[0].ltime = now;
                lreq_next->lreq[0].count = 1;
                lreq_next->lreq[0].lastTime = now;
                lreq_next->next = NULL;
                lreq_next->hash_domain = hash_domain;

                lreq_queue_ptr->next = lreq_next;

                goto release_lreq;
            }
            lreq_queue_ptr = lreq_queue_ptr->next;
        }
    }
    /**     if (lreq_queue_ptr == NULL) { */
    /** goto release_lreq; */
    /** } */

    old_id = 0;
    for (i = 0; i < LREQ_QUEUE_MAX; i++) {

        if (lreq_queue_ptr->lreq[i].hash_uri == 0) {
            // add new uri
            lreq_queue_ptr->lreq[i].hash_uri = hash_uri;

            lreq_queue_ptr->lreq[i].header_time = header_time;

            lreq_queue_ptr->lreq[i].avgtime[0] = header_time;
            lreq_queue_ptr->lreq[i].avgtime[1] = 0;
            lreq_queue_ptr->lreq[i].avgtime[0] = header_time;
            lreq_queue_ptr->lreq[i].avgtime[3] = 0;
            lreq_queue_ptr->lreq[i].active = 0;

            lreq_queue_ptr->lreq[i].stime = now;
            lreq_queue_ptr->lreq[i].ltime = now;
            lreq_queue_ptr->lreq[i].count = 1;
            lreq_queue_ptr->lreq[i].lastTime = now;

            goto release_lreq;
        }
        if (lreq_queue_ptr->lreq[i].hash_uri == hash_uri) {
            //  update old uri
            int stime = now - lreq_queue_ptr->lreq[i].stime;
            if (stime > STIME_SECOND) {
               
                lreq_queue_ptr->lreq[i].stime = now;
                lreq_queue_ptr->lreq[i].avgtime[1] =
                    lreq_queue_ptr->lreq[i].avgtime[0];
            }
            lreq_queue_ptr->lreq[i].avgtime[0] =
                (lreq_queue_ptr->lreq[i].avgtime[0] + (float)header_time) / 2.0;

            int ltime = now - lreq_queue_ptr->lreq[i].ltime;
            if (ltime > LTIME_SECOND) {
                lreq_queue_ptr->lreq[i].ltime = now;
                lreq_queue_ptr->lreq[i].avgtime[3] =
                    lreq_queue_ptr->lreq[i].avgtime[2];
            }
            lreq_queue_ptr->lreq[i].avgtime[2] =
                (lreq_queue_ptr->lreq[i].avgtime[2] + (float)header_time) / 2.0;

            lreq_queue_ptr->lreq[i].count += 1;
            lreq_queue_ptr->lreq[i].lastTime = now;

            lreq_queue_ptr->lreq[i].header_time = header_time;
/**             NX_DEBUG( */
                          /** "lreq " */
                          /** "avgtime_0:%.2f,avgtime_1:%.2f,avgtime_2:%.2f," */
                          /** "avgtime_3:%.2f, header_time:%d", */
                          /** lreq_queue_ptr->lreq[i].avgtime[0], */
                          /** lreq_queue_ptr->lreq[i].avgtime[1], */
                          /** lreq_queue_ptr->lreq[i].avgtime[2], */
                          /** lreq_queue_ptr->lreq[i].avgtime[3], */
                          /** (int)lreq_queue_ptr->lreq[i].header_time); */
            goto release_lreq;
        }

        if (old_time > lreq_queue_ptr->lreq[i].lastTime) {
            old_time = lreq_queue_ptr->lreq[i].lastTime;
            old_id = i;
        }
    }
    // push old  and  add new
    lreq_queue_ptr->lreq[old_id].hash_uri = hash_uri;
    /** memset(lreq_queue_ptr->lreq[old_id].avgtime, 0, 4); */
    lreq_queue_ptr->lreq[old_id].header_time = header_time;
    lreq_queue_ptr->lreq[old_id].avgtime[0] = header_time;
    lreq_queue_ptr->lreq[old_id].active = 0;

    lreq_queue_ptr->lreq[old_id].stime = now;
    lreq_queue_ptr->lreq[old_id].ltime = now;
    lreq_queue_ptr->lreq[old_id].count = 1;
    lreq_queue_ptr->lreq[old_id].lastTime = now;

release_lreq:
    ngx_shmtx_unlock(&shpool->mutex);
} /* -----  end of function lreq_uri_queue  ----- */
  /*
* ===  FUNCTION
* ======================================================================
*         Name:  lreq_operate_uri
*  Description:  return 400  599
* =====================================================================================
*/
int lreq_operate_uri(ngx_http_request_t *r) {

    ngx_shm_zone_t *shm_zone_lreq_queue;
    ngx_slab_pool_t *shpool;
    ngx_str_t uri;
    Ngx_etomc2_lreq_queue *lreq_queue_ptr;

    uint32_t hash_uri, hash_domain;
    float fib1, fib2;
    int i;
    /** time_t now = ngx_time(); */
    Ngx_etomc2_lreq_uri lreq_uri;
    ngx_http_etomc2_loc_conf_t *lccf;
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!lccf) return -1;

    if (lccf->shm_zone_lreq_queue == NULL) {
        return -1;
    }

    shm_zone_lreq_queue = lccf->shm_zone_lreq_queue;

    lreq_queue_ptr = (Ngx_etomc2_lreq_queue *)shm_zone_lreq_queue->data;
    if (!lreq_queue_ptr) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "lreq_queue_ptr is null");
        return -1;
    }

    hash_domain =
        to_hash((char *)r->headers_in.server.data, r->headers_in.server.len);
    uri = get_uri(r);
    if (uri.len == 0) return -1;
    hash_uri = to_hash((char *)uri.data, uri.len);

    shpool = (ngx_slab_pool_t *)shm_zone_lreq_queue->shm.addr;

    while (lreq_queue_ptr) {

        if (lreq_queue_ptr->hash_domain == hash_domain) {
            for (i = 0; i < LREQ_QUEUE_MAX; i++) {
                lreq_uri = lreq_queue_ptr->lreq[i];
                if (lreq_uri.hash_uri != hash_uri) {
                    continue;
                }
                if (lreq_uri.avgtime[3] == 0 &&
                    lreq_uri.header_time > LREQ_HEADER_TIME) {
                    // when avgtime[3] == 0 
                    return 0;
                }

                if (lreq_uri.avgtime[3] == 0) {
                    return -1;
                }

                if ((int)lreq_uri.header_time < LREQ_HEADER_TIME) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  " lreq_queue_ptri release active");
                    ngx_shmtx_lock(&shpool->mutex);
                    lreq_queue_ptr->lreq[i].active = 0;
                    ngx_shmtx_unlock(&shpool->mutex);
                    return -1;
                }

                fib1 = lreq_uri.avgtime[0] / lreq_uri.avgtime[3];
                fib2 = lreq_uri.avgtime[1] / lreq_uri.avgtime[3];
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              " lreq_queue_ptr error avgtime[0]:%.2f, "
                              "avgtime[3]:%.2f "
                              "fib1:%.2f  fib2:%.2f",
                              lreq_uri.avgtime[0], lreq_uri.avgtime[3], fib1,
                              fib2);
                if (fib1 > Fibonacci[1][0] || fib2 > Fibonacci[1][0]) {

                    ngx_shmtx_lock(&shpool->mutex);
                    lreq_queue_ptr->lreq[i].active = lreq_uri.avgtime[3];
                    ngx_shmtx_unlock(&shpool->mutex);

                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  " lreq_queue_ptr limit error");
                    return 0;
                }
                if (lreq_uri.active > 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  " lreq_queue_ptri error active:%.2f",
                                  lreq_uri.active);
                    return 0;
                }
            }
            return -1;
        }
        lreq_queue_ptr = lreq_queue_ptr->next;
    }

    return -1;
} /* -----  end of function lreq_operate_uri  ----- */
  /*
* ===  FUNCTION
* ======================================================================
*         Name:  lreq_queue_show
*  Description:
* =====================================================================================
*/
void lreq_queue_show(ngx_http_request_t *r) {
    ngx_shm_zone_t *shm_zone_lreq_queue;
    /** ngx_slab_pool_t *shpool; */
    /** ngx_str_t uri; */
    Ngx_etomc2_lreq_queue *lreq_queue_ptr;

    /** uint32_t hash_uri, hash_domain; */
    /** float fib1, fib2; */
    int i;
    Ngx_etomc2_lreq_uri lreq_uri;
    ngx_http_etomc2_loc_conf_t *lccf;
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!lccf) return;

    if (lccf->shm_zone_lreq_queue == NULL) {
        return;
    }

    shm_zone_lreq_queue = lccf->shm_zone_lreq_queue;

    lreq_queue_ptr = (Ngx_etomc2_lreq_queue *)shm_zone_lreq_queue->data;
    if (!lreq_queue_ptr) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "lreq_queue_ptr is null");
        return;
    }

    while (lreq_queue_ptr) {
        for (i = 0; i < LREQ_QUEUE_MAX; i++) {
            lreq_uri = lreq_queue_ptr->lreq[i];
            if (lreq_uri.count == 0) continue;
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "lreq_queue_ptr short time:%l, "
                          "count:%d,lasttime:%l,avgtime:%.4f, uri:%z",
                          lreq_uri.stime, lreq_uri.count, lreq_uri.lastTime,
                          lreq_uri.avgtime[0], lreq_uri.hash_uri);
        }
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "lreq_queue_ptr ----- ");
        lreq_queue_ptr = lreq_queue_ptr->next;
    }
} /* -----  end of function lreq_queue_show  ----- */
