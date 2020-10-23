/*
 * =====================================================================================
 *
 *       Filename:  etomc2_skeleton.c
 *
 *    Description:  etomc2  cc
 *
 *        Version:  1.0
 *        Created:  2020年08月10日 11时40分20秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  etomc2@etomc2.com (), etomc2@etomc2.com
 *   Organization:  etomc2.com
 *
 * =====================================================================================
 */

#include "etomc2.h"

/**
 *  ngx_http_limit_bandwidth_module_ctx function
 */
static ngx_int_t ngx_http_etomc2_dummy_init(ngx_conf_t *cf);
void *ngx_http_etomc2_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_etomc2_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_etomc2_merge_loc_conf(ngx_conf_t *cf, void *parent,
                                            void *child);
/** static ngx_int_t ngx_init_etomc2_shm_zone(ngx_shm_zone_t *shm_zone, void
 * *data);
 */
/*
 ** Module's registred function/handlers.
 */
static ngx_int_t ngx_http_etomc2_access_handler(ngx_http_request_t *r);

ngx_int_t ngx_http_etomc2_header_filter(ngx_http_request_t *r);
ngx_int_t ngx_http_etomc2_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

static char *ngx_http_etomc2_web(ngx_conf_t *cf, ngx_command_t *cmd,
                                 void *conf);
static ngx_int_t ngx_http_etomc2_web_handler(ngx_http_request_t *r);

/**
 *  commands  function
 */

static char *ngx_http_cc_set_shm_size(ngx_conf_t *cf, ngx_command_t *cmd,
                                      void *conf);

static ngx_int_t ngx_etomc2_init_shm_zone_cc_thin(ngx_shm_zone_t *shm_zone,
                                                  void *data);
static ngx_int_t ngx_etomc2_init_shm_zone_cc_ub(ngx_shm_zone_t *shm_zone,
                                                void *data);
static ngx_int_t ngx_etomc2_init_shm_zone_ub_queue(ngx_shm_zone_t *shm_zone,
                                                   void *data);
static ngx_int_t ngx_etomc2_init_shm_zone_lreq_queue(ngx_shm_zone_t *shm_zone,
                                                     void *data);
static ngx_int_t ngx_etomc2_init_shm_zone_cc_gt(ngx_shm_zone_t *shm_zone,
                                                void *data);
static ngx_int_t ngx_etomc2_init_shm_zone_cc_flow(ngx_shm_zone_t *shm_zone,
                                                  void *data);
static void ngx_cc_rbtree_insert_value(ngx_rbtree_node_t *temp,
                                       ngx_rbtree_node_t *node,
                                       ngx_rbtree_node_t *sentinel);

static char *ngx_http_etomc2_ctrl(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf);
static ngx_int_t ngx_http_etomc2_ctrl_handler(ngx_http_request_t *r);

ngx_str_t *web_route_domain_list(ngx_http_request_t *r,
                                 ngx_http_etomc2_loc_conf_t *lccf);
ngx_str_t *web_route_main_conf(ngx_http_request_t *r,
                               ngx_http_etomc2_loc_conf_t *lccf);
ngx_str_t *web_route_update_conf(ngx_http_request_t *r,
                                 ngx_http_etomc2_loc_conf_t *lccf);
ngx_str_t *web_route_json_flow(ngx_http_request_t *r,
                               ngx_http_etomc2_loc_conf_t *lccf);
ngx_str_t *web_route_waf_domain_ids(ngx_http_request_t *r,
                                    ngx_http_etomc2_loc_conf_t *lccf);
ngx_str_t *web_route_waf_domain_rule(ngx_http_request_t *r,
                                     ngx_http_etomc2_loc_conf_t *lccf);
ngx_int_t web_route_set_gt_level(ngx_http_request_t *r,
                                 ngx_http_etomc2_loc_conf_t *lccf);
ngx_str_t web_route_ip_blacklist(ngx_http_request_t *r,
                                 ngx_http_etomc2_loc_conf_t *lccf);
ngx_str_t web_route_del_blackip(ngx_http_request_t *r,
                                ngx_http_etomc2_loc_conf_t *lccf);
ngx_int_t web_route_get_gt_take(ngx_http_request_t *r,
                                ngx_http_etomc2_loc_conf_t *lccf);
ngx_int_t web_route_get_uri_itemize(ngx_http_request_t *r,
                                    ngx_http_etomc2_loc_conf_t *lccf);
static ngx_int_t ngx_http_slab_stat_buf(ngx_pool_t *pool, ngx_buf_t *b);
void list_json(ngx_http_request_t *r, Ngx_etomc2_aiwaf_list *nlist,
               ngx_str_t **data, uint32_t dmhash);
int isIp_v4(const char *ip);

static u_char ngx_web_etomc2[] = WEB_ETOMC2;
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_uint_t ngx_http_cc_shm_size;
static ngx_uint_t ngx_cc_run_check;

/**
 * This module provided directive: base print.
 *
 */
static ngx_command_t ngx_http_etomc2_cc_commands[] = {
    /**
     *  http
     */
    {ngx_string(ETOMC2_CC_ENABLE), NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_etomc2_loc_conf_t, etomc2_cc_enable), NULL},
    {ngx_string(ET2_SHM_SIZE), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_http_cc_set_shm_size, 0, 0, NULL},

    {ngx_string(ET2_NGX_CTRL),            /* directive */
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, /* location context and takes
                                             no arguments*/
     ngx_http_etomc2_ctrl,                /* configuration setup function */
     0, /* No offset. Only one context is supported. */
     0, /* No offset when storing the module configuration on struct. */
     NULL},

    {ngx_string(ETOMC2_WEB_API),          /* directive */
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, /* location context and takes
                                             no arguments*/
     ngx_http_etomc2_web,                 /* configuration setup function */
     0, /* No offset. Only one context is supported. */
     0, /* No offset when storing the module configuration on struct. */
     NULL},

    {ngx_string(HDCACHE_PATH), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_etomc2_loc_conf_t, hdcache_path), NULL},

    /**     {ngx_string(NAXSI_PEM_PK_FILE), */
    /** NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, */
    /** ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET, */
    /** offsetof(ngx_http_etomc2_loc_conf_t, rsa_pem_pk), NULL}, */
    {ngx_string(CC_GT_LEVEL),
     NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_etomc2_loc_conf_t, cc_gt_level), NULL},
    {ngx_string(CC_ITEMIZE),
     NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_etomc2_loc_conf_t, cc_itemize), NULL},
    {ngx_string(CC_RETURN_STATUS),
     NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_etomc2_loc_conf_t, cc_return_status), NULL},

    {ngx_string(CC_TRUST_STATUS),
     NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_etomc2_loc_conf_t, cc_trust_status), NULL},

    ngx_null_command /* command termination */
};

/* The module context. */
static ngx_http_module_t ngx_http_etomc2_cc_module_ctx = {
    NULL,                             /* preconfiguration */
    ngx_http_etomc2_dummy_init,       /* postconfiguration */
    ngx_http_etomc2_create_main_conf, /* create main configuration */
    NULL,                             /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_etomc2_create_loc_conf, /* create location configuration */
    ngx_http_etomc2_merge_loc_conf   /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_etomc2_cc_module = {
    NGX_MODULE_V1,
    &ngx_http_etomc2_cc_module_ctx, /* module context */
    ngx_http_etomc2_cc_commands,    /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    NULL,                           /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING};
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_http_etomc2_dummy_init Description:
 * =====================================================================================
 */
static ngx_int_t ngx_http_etomc2_dummy_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf == NULL) return (NGX_ERROR); /*LCOV_EXCL_LINE*/

    /* Register for rewrite phase */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) return (NGX_ERROR); /*LCOV_EXCL_LINE*/

    *h = ngx_http_etomc2_access_handler;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_etomc2_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_etomc2_body_filter;

    return (NGX_OK);
} /* -----  end of function ngx_http_etomc2_dummy_init  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_http_etomc2_create_main_conf Description:
 * =====================================================================================
 */
void *ngx_http_etomc2_create_main_conf(ngx_conf_t *cf) {
    ngx_http_etomc2_main_conf_t *mc;

    mc = ngx_pcalloc(cf->pool, sizeof(ngx_http_etomc2_main_conf_t));
    if (!mc) return (NGX_CONF_ERROR); /*LCOV_EXCL_LINE*/
    /** mc->bandwidth_size=0; */
    return (mc);
} /* -----  end of function ngx_http_etomc2_create_main_conf  ----- */

/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_http_etomc2_create_loc_conf Description:
 * =====================================================================================
 */
static void *ngx_http_etomc2_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_etomc2_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_etomc2_loc_conf_t));
    if (conf == NULL) return NULL;
    conf->etomc2_cc_enable = NGX_CONF_UNSET_UINT;
    conf->cc_gt_level = NGX_CONF_UNSET_UINT;
    conf->cc_return_status = NGX_CONF_UNSET_UINT;
    conf->cc_itemize = NGX_CONF_UNSET;

    return (conf);

} /* -----  end of function ngx_http_etomc2_create_loc_conf  ----- */

/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_http_etomc2_merge_loc_conf Description:
 * =====================================================================================
 */
static char *ngx_http_etomc2_merge_loc_conf(ngx_conf_t *cf, void *parent,
                                            void *child) {
    ngx_shm_zone_t *shm_zone_cc_thin, *shm_zone_cc_ub, *shm_zone_ub_queue,
        *shm_zone_lreq_queue, *shm_zone_cc_gt, *shm_zone_cc_flow;

    ngx_str_t *shm_cc_thin_name, *shm_cc_ub_name, *shm_ub_queue_name,
        *shm_lreq_queue_name, *shm_gt_name, *shm_flow_name;

    ngx_http_etomc2_loc_conf_t *prev = parent;
    ngx_http_etomc2_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->etomc2_cc_enable, prev->etomc2_cc_enable, 0);

    ngx_conf_merge_uint_value(conf->cc_gt_level, prev->cc_gt_level, 5);
    /** NX_CONF_DEBUG("CC_GT_LEVEL:%d,
     * server:%s",conf->cc_gt_level,cf->cycle->hostname.data); */
    ngx_conf_merge_value(conf->cc_itemize, prev->cc_itemize, 0);

    ngx_conf_merge_uint_value(conf->cc_return_status, prev->cc_return_status,
                              444);
    ngx_conf_merge_str_value(conf->cc_trust_status, prev->cc_trust_status, "");

    ngx_conf_merge_str_value(conf->hdcache_path, prev->hdcache_path,
                             "/var/cache/nginx/hdcache");

    /** NX_CONF_DEBUG("%s", conf->cc_path.data); */
    /** -------- cc thin ------ */
    shm_cc_thin_name = ngx_palloc(cf->pool, sizeof *shm_cc_thin_name);
    shm_cc_thin_name->len = sizeof("shared_memory_cc_thin") - 1;
    shm_cc_thin_name->data = (unsigned char *)"shared_memory_cc_thin";
    shm_zone_cc_thin = ngx_shared_memory_add(
        cf, shm_cc_thin_name, SHM_SIZE_MAX_COMMON, &ngx_http_etomc2_cc_module);

    if (shm_zone_cc_thin == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone_cc_thin->init = ngx_etomc2_init_shm_zone_cc_thin;
    conf->shm_zone_cc_thin = shm_zone_cc_thin;
    ngx_conf_merge_ptr_value(conf->shm_zone_cc_thin, prev->shm_zone_cc_thin,
                             NULL);

    /** -------- user  behavior cc attack ------ */
    if (ngx_http_cc_shm_size == 0) {
        ngx_http_cc_shm_size = SHM_SIZE_MAX_COMMON;
    }
    shm_cc_ub_name = ngx_palloc(cf->pool, sizeof *shm_cc_ub_name);
    shm_cc_ub_name->len = sizeof("shared_memory_cc_ub") - 1;
    shm_cc_ub_name->data = (unsigned char *)"shared_memory_cc_ub";
    shm_zone_cc_ub = ngx_shared_memory_add(
        cf, shm_cc_ub_name, ngx_http_cc_shm_size, &ngx_http_etomc2_cc_module);

    if (shm_zone_cc_ub == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone_cc_ub->init = ngx_etomc2_init_shm_zone_cc_ub;
    conf->shm_zone_cc_ub = shm_zone_cc_ub;
    ngx_conf_merge_ptr_value(conf->shm_zone_cc_ub, prev->shm_zone_cc_ub, NULL);

    /** -------- user  behavior cc queue ------ */

    shm_ub_queue_name = ngx_palloc(cf->pool, sizeof *shm_ub_queue_name);
    shm_ub_queue_name->len = sizeof("shared_memory_ub_queue") - 1;
    shm_ub_queue_name->data = (unsigned char *)"shared_memory_ub_queue";
    shm_zone_ub_queue = ngx_shared_memory_add(cf, shm_ub_queue_name,
                                              abs(ngx_http_cc_shm_size / 4),
                                              &ngx_http_etomc2_cc_module);

    if (shm_zone_ub_queue == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone_ub_queue->init = ngx_etomc2_init_shm_zone_ub_queue;
    conf->shm_zone_ub_queue = shm_zone_ub_queue;
    ngx_conf_merge_ptr_value(conf->shm_zone_ub_queue, prev->shm_zone_ub_queue,
                             NULL);

    /** ---------- queue ----------- */
    shm_lreq_queue_name = ngx_palloc(cf->pool, sizeof *shm_lreq_queue_name);
    shm_lreq_queue_name->len = sizeof("shared_memory_lreq_queue") - 1;
    shm_lreq_queue_name->data = (unsigned char *)"shared_memory_lreq_queue";
    shm_zone_lreq_queue =
        ngx_shared_memory_add(cf, shm_lreq_queue_name, SHM_SIZE_MAX_COMMON,
                              &ngx_http_etomc2_cc_module);

    if (shm_zone_lreq_queue == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone_lreq_queue->init = ngx_etomc2_init_shm_zone_lreq_queue;
    conf->shm_zone_lreq_queue = shm_zone_lreq_queue;
    ngx_conf_merge_ptr_value(conf->shm_zone_lreq_queue,
                             prev->shm_zone_lreq_queue, NULL);

    /** -------- gt global toggle  ----------------*/
    shm_gt_name = ngx_palloc(cf->pool, sizeof *shm_gt_name);
    shm_gt_name->len = sizeof("shared_memory_gt") - 1;
    shm_gt_name->data = (unsigned char *)"shared_memory_gt";
    shm_zone_cc_gt = ngx_shared_memory_add(
        cf, shm_gt_name, SHM_SIZE_DEFAULT_COMMON, &ngx_http_etomc2_cc_module);

    if (shm_zone_cc_gt == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone_cc_gt->init = ngx_etomc2_init_shm_zone_cc_gt;
    conf->shm_zone_cc_gt = shm_zone_cc_gt;
    ngx_conf_merge_ptr_value(conf->shm_zone_cc_gt, prev->shm_zone_cc_gt, NULL);

    /** -------- flow global toggle  ----------------*/
    shm_flow_name = ngx_palloc(cf->pool, sizeof *shm_flow_name);
    shm_flow_name->len = sizeof("shared_memory_flow") - 1;
    shm_flow_name->data = (unsigned char *)"shared_memory_flow";
    shm_zone_cc_flow = ngx_shared_memory_add(
        cf, shm_flow_name, SHM_SIZE_DEFAULT_COMMON, &ngx_http_etomc2_cc_module);

    if (shm_zone_cc_flow == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone_cc_flow->init = ngx_etomc2_init_shm_zone_cc_flow;
    conf->shm_zone_cc_flow = shm_zone_cc_flow;
    ngx_conf_merge_ptr_value(conf->shm_zone_cc_flow, prev->shm_zone_cc_flow,
                             NULL);

    return NGX_CONF_OK;
} /* -----  end of function ngx_http_etomc2_merge_loc_conf  ----- */

/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_http_etomc2_access_handler Description:
 * =====================================================================================
 */
static ngx_int_t ngx_http_etomc2_access_handler(ngx_http_request_t *r) {
    ngx_http_etomc2_loc_conf_t *lccf;
    ngx_int_t rc;
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!lccf) {
        NX_LOG("ngx_http_etomc2_access_handler lccf error");
        return NGX_DECLINED;
    }
    if (lccf->etomc2_cc_enable == 0) {
        return NGX_DECLINED;
    }

    initialize_uuid();

    if (ngx_cc_run_check == 0) {
        ngx_cc_run_check = 1;
    }

    rc = cc_thin_enter(r);

    if (rc == NGX_ERROR) {
        r->headers_out.status = lccf->cc_return_status;

        return rc;
    } else if (rc == NGX_BUSY) {
        r->headers_out.status = 503;

        return NGX_ERROR;
    }
    return NGX_DECLINED;

} /* -----  end of function ngx_http_etomc2_access_handler  ----- */

/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_http_etomc2_header_filter Description:
 * =====================================================================================
 */
ngx_int_t ngx_http_etomc2_header_filter(ngx_http_request_t *r) {
    ngx_http_etomc2_loc_conf_t *lccf;
    ngx_str_t *key;

    size_t m = 0, bad_status = 0;
    /** ngx_http_request_ctx_t *ctx; */
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!lccf) {
        return ngx_http_next_header_filter(r);
    }
    if (lccf->etomc2_cc_enable == 0) {
        return ngx_http_next_header_filter(r);
    }
    if (lccf->cc_itemize == 0) {
        return ngx_http_next_header_filter(r);
    }
    if (r->headers_out.status == 200) {
        lreq_uri_queue(r);
    }
    key = ngx_cc_rbtree_hash_key(r);
    if (!key) {
        NX_LOG("ngx_cc_rbtree_hash_key is null");
        return ngx_http_next_header_filter(r);
    }
    flow_update(r);
    /**
     *  M_GREEN
     */
    ngx_int_t cm = cc_cookie_mark(r, key);

    if (cm == NGX_OK) {
        return ngx_http_next_header_filter(r);
    }

    /**
     *
     *  hdcache  for app  green
     */

    int isexit = hdcache_behavior_exist(r, key, M_GREEN);
    if (isexit == 0) {
        return ngx_http_next_header_filter(r);
    }

    /**
     *  user behavior lookup
     */

    if (r->headers_out.status == 200) {
        if (ngx_cc_run_check == 1) {
            NX_DEBUG("cc_thin_end ok, time:%d", ngx_time());
            ngx_cc_run_check = 2;
        }
        /**
         * user behavior cc  attack;
         * update  struct subject
         */
        cc_thin_user_behavior_lookup(r, key);
    }
    if (lccf->cc_trust_status.len > 0) {
        NX_DEBUG("cc_trust_status:[%s] ", lccf->cc_trust_status.data);
        for (m = 0; m < (lccf->cc_trust_status.len - 1); m += 4) {
            ngx_uint_t status =
                ngx_atoi((u_char *)lccf->cc_trust_status.data + m, 3);

            NX_DEBUG("cc_trust_status:%d status:%d", status,
                     r->headers_out.status);
            if (r->headers_out.status == status) {
                bad_status = 1;
                break;
            }
        }
        if (bad_status == 0) {
            hdcache_behavior_add(r, key, M_RED, 0, ngx_time());
            return ngx_http_next_header_filter(r);
        }
    }
    return ngx_http_next_header_filter(r);

} /* -----  end of function ngx_http_etomc2_header_filter  ----- */

/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_http_etomc2_body_filter Description:
 * =====================================================================================
 */
ngx_int_t ngx_http_etomc2_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    ngx_http_etomc2_loc_conf_t *lccf;

    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (lccf->etomc2_cc_enable == 0) {
        return ngx_http_next_body_filter(r, in);
    }
    /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, */
    /** "ngx_http_etomc2_body_filter"); */
    return ngx_http_next_body_filter(r, in);
} /* -----  end of function ngx_http_etomc2_body_filter  ----- */

/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_http_etomc2_web Description:
 * =====================================================================================
 */
static char *ngx_http_etomc2_web(ngx_conf_t *cf, ngx_command_t *cmd,
                                 void *conf) {
    ngx_http_core_loc_conf_t *clcf; /* pointer to core location configuration */

    /* Install the hello world handler. */
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_etomc2_web_handler;

    return NGX_CONF_OK;
} /* -----  end of function ngx_http_etomc2_web  ----- */

/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_http_etomc2_web_handler Description:
 * =====================================================================================
 */
static ngx_int_t ngx_http_etomc2_web_handler(ngx_http_request_t *r) {
    ngx_buf_t *b;
    ngx_chain_t out;

    /* Set the Content-Type header. */
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *)"text/plain";

    /* Allocate a new buffer for sending out the reply. */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    /* Insertion in the buffer chain. */
    out.buf = b;
    out.next = NULL; /* just one buffer */

    b->pos = ngx_web_etomc2; /* first position in memory of the data */
    b->last = ngx_web_etomc2 + sizeof(ngx_web_etomc2) -
              1;     /* last position in memory of the data */
    b->memory = 1;   /* content is in read-only memory */
    b->last_buf = 1; /* there will be no more buffers in the request */

    /* Sending the headers for the reply. */
    r->headers_out.status = NGX_HTTP_OK; /* 200 status code */
    /* Get the content length of the body. */
    r->headers_out.content_length_n = sizeof(ngx_web_etomc2) - 1;
    ngx_http_send_header(r); /* Send the headers */

    /* Send the body, and return the status code of the output filter chain. */
    return ngx_http_output_filter(r, &out);

} /* -----  end of function ngx_http_etomc2_web_handler  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  ngx_http_cc_set_shm_size
 *  Description:
 * =====================================================================================
 */
static char *ngx_http_cc_set_shm_size(ngx_conf_t *cf, ngx_command_t *cmd,
                                      void *conf) {
    off_t new_shm_size;
    ngx_str_t *value;

    value = cf->args->elts;

    new_shm_size = ngx_parse_offset(&value[1]);
    if (new_shm_size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Invalid memory area size `%V'", &value[1]);
        return NGX_CONF_ERROR;
    }

    new_shm_size = ngx_align(new_shm_size, ngx_pagesize);

    if (new_shm_size < 8 * (ssize_t)ngx_pagesize) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "The cc_shm_size value must be at least %udKiB",
                           (8 * ngx_pagesize) >> 10);
        new_shm_size = 8 * ngx_pagesize;
    }

    if (ngx_http_cc_shm_size &&
        ngx_http_cc_shm_size != (ngx_uint_t)new_shm_size) {
        ngx_conf_log_error(
            NGX_LOG_WARN, cf, 0,
            "Cannot change memory area size without restart, ignoring change");
    } else {
        ngx_http_cc_shm_size = new_shm_size;
    }
    /** NX_CONF_DEBUG( */
    /**  "Using %d of shared memory , ubsize:%d", */
    /** ngx_http_cc_shm_size, */
    /** (ngx_http_cc_shm_size / (ngx_pagesize + sizeof(ngx_slab_page_t)))); */

    return NGX_CONF_OK;

} /* -----  end of function ngx_http_cc_set_shm_size  ----- */

/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_etomc2_init_shm_zone_cc_thin Description:
 * =====================================================================================
 */
static ngx_int_t ngx_etomc2_init_shm_zone_cc_thin(ngx_shm_zone_t *shm_zone,
                                                  void *data) {
    ngx_slab_pool_t *shpool;
    Ngx_visit_cc_attack *shm_etomc2;
    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }
    shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    shm_etomc2 = ngx_slab_alloc_locked(shpool, sizeof(Ngx_visit_cc_attack));
    if (!shm_etomc2) {
        ngx_shmtx_unlock(&shpool->mutex);

        return NGX_ERROR;
    }

    shm_etomc2->hash_uri = 0;
    shm_etomc2->hash_domain = 0;
    shm_etomc2->rise_level = 0;
    shm_etomc2->next = NULL;

    shm_zone->data = shm_etomc2;

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
} /* -----  end of function ngx_etomc2_init_shm_zone_cc_thin  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_etomc2_init_shm_zone_cc_ub Description:
 * =====================================================================================
 */
static ngx_int_t ngx_etomc2_init_shm_zone_cc_ub(ngx_shm_zone_t *shm_zone,
                                                void *data) {
    ngx_slab_pool_t *shpool;
    Ngx_etomc2_cc_user_behavior *shm_etomc2;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }
    shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    shm_etomc2 =
        ngx_slab_alloc_locked(shpool, sizeof(Ngx_etomc2_cc_user_behavior));
    if (!shm_etomc2) {
        ngx_shmtx_unlock(&shpool->mutex);

        return NGX_ERROR;
    }

    shm_zone->data = shm_etomc2;
    ngx_rbtree_init(&shm_etomc2->rbtree, &shm_etomc2->sentinel,
                    ngx_cc_rbtree_insert_value);
    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
} /* -----  end of function ngx_etomc2_init_shm_zone_cc_ub  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_etomc2_init_shm_zone_ub_queue Description:
 * =====================================================================================
 */
static ngx_int_t ngx_etomc2_init_shm_zone_ub_queue(ngx_shm_zone_t *shm_zone,
                                                   void *data) {
    ngx_slab_pool_t *shpool;
    Ngx_ub_queue_ptr *shm_etomc2;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }
    shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    shm_etomc2 = ngx_slab_alloc_locked(shpool, sizeof(Ngx_ub_queue_ptr));
    if (!shm_etomc2) {
        ngx_shmtx_unlock(&shpool->mutex);

        return NGX_ERROR;
    }
    /**     shm_etomc2->hash_str = 0; */
    shm_etomc2->head =
        ngx_slab_alloc_locked(shpool, sizeof(Ngx_etomc2_ub_queue));
    shm_etomc2->tail = NULL;

    shm_zone->data = shm_etomc2;

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;

} /* -----  end of function ngx_etomc2_init_shm_zone_ub_queue  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_etomc2_init_shm_zone_lreq_queue Description:
 * =====================================================================================
 */
static ngx_int_t ngx_etomc2_init_shm_zone_lreq_queue(ngx_shm_zone_t *shm_zone,
                                                     void *data) {
    ngx_slab_pool_t *shpool;
    Ngx_etomc2_lreq_queue *shm_etomc2;
    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }
    shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    shm_etomc2 = ngx_slab_alloc_locked(shpool, sizeof(Ngx_etomc2_lreq_queue));
    if (!shm_etomc2) {
        ngx_shmtx_unlock(&shpool->mutex);

        return NGX_ERROR;
    }
    memset(shm_etomc2->lreq, 0,
           (size_t)LREQ_QUEUE_MAX * sizeof(Ngx_etomc2_lreq_uri));

    shm_etomc2->next = NULL;

    shm_zone->data = shm_etomc2;

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;

} /* -----  end of function ngx_etomc2_init_shm_zone_lreq_queue  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_etomc2_init_shm_zone_cc_gt Description:
 * =====================================================================================
 */
static ngx_int_t ngx_etomc2_init_shm_zone_cc_gt(ngx_shm_zone_t *shm_zone,
                                                void *data) {
    ngx_slab_pool_t *shpool;
    Ngx_etomc2_shm_gt *shm_etomc2;
    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }
    shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    shm_etomc2 = ngx_slab_alloc_locked(shpool, sizeof(Ngx_etomc2_shm_gt));
    if (!shm_etomc2) {
        ngx_shmtx_unlock(&shpool->mutex);

        return NGX_ERROR;
    }
    shm_etomc2->hash_domain = 0;
    shm_etomc2->count = 0;
    shm_etomc2->now = 0;
    shm_etomc2->level = GTL_5;
    shm_etomc2->next = NULL;
    shm_zone->data = shm_etomc2;

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;

} /* -----  end of function ngx_etomc2_init_shm_zone_cc_gt  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_etomc2_init_shm_zone_cc_flow Description:
 * =====================================================================================
 */
static ngx_int_t ngx_etomc2_init_shm_zone_cc_flow(ngx_shm_zone_t *shm_zone,
                                                  void *data) {
    ngx_slab_pool_t *shpool;
    Ngx_etomc2_cc_flow *shm_etomc2;
    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }
    shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    shm_etomc2 = ngx_slab_alloc_locked(shpool, sizeof(Ngx_etomc2_cc_flow));
    if (!shm_etomc2) {
        ngx_shmtx_unlock(&shpool->mutex);

        return NGX_ERROR;
    }
    shm_etomc2->hash_domain = 0;
    memset(shm_etomc2->flow, 0, (size_t)SHM_FLOW_FREQ * sizeof(size_t));
    memset(shm_etomc2->now, 0, (size_t)SHM_FLOW_FREQ * sizeof(time_t));
    shm_etomc2->ptr = 0;
    shm_etomc2->next = NULL;
    shm_zone->data = shm_etomc2;

    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_OK;
} /* -----  end of function ngx_etomc2_init_shm_zone_cc_flow  ----- */
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  ngx_cc_rbtree_insert_value
 *  Description:
 * =====================================================================================
 */
static void ngx_cc_rbtree_insert_value(ngx_rbtree_node_t *temp,
                                       ngx_rbtree_node_t *node,
                                       ngx_rbtree_node_t *sentinel) {
    ngx_rbtree_node_t **p;
    Ngx_etomc2_cc_user_behavior *lrn, *lrnt;
    ngx_int_t cmp = -1;
    if (node == NULL) {
        return;
    }

    for (;;) {
        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else { /* node->key == temp->key */
            /** break; */
            lrn = (Ngx_etomc2_cc_user_behavior *)node;
            lrnt = (Ngx_etomc2_cc_user_behavior *)temp;

            /*   lrn->hash_str.len == lrnt->hash_str.len  */
            cmp = ngx_memn2cmp(lrn->hash_str.data, lrnt->hash_str.data,
                               lrn->hash_str.len, lrnt->hash_str.len);
            /* only key */
            /** if(cmp == 0)break; */

            p = (cmp < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }
    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);

} /* -----  end of function ngx_cc_rbtree_insert_value  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_http_etomc2_ctrl Description:
 * =====================================================================================
 */
static char *ngx_http_etomc2_ctrl(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf) {
    ngx_http_core_loc_conf_t *clcf; /* pointer to core location configuration */

    /* Install the hello world handler. */
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_etomc2_ctrl_handler;

    return NGX_CONF_OK;

} /* -----  end of function ngx_http_etomc2_ctrl  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_http_etomc2_ctrl_handler Description:
 * =====================================================================================
 */
static ngx_int_t ngx_http_etomc2_ctrl_handler(ngx_http_request_t *r) {
    ngx_buf_t *b;
    ngx_chain_t out;
    size_t html_json = 0;  // 0:html, 1:json
    u_char ngx_hello_world[] = "hello world";
    ngx_str_t *resData;
    ngx_str_t uri = get_uri(r);
    ngx_http_etomc2_loc_conf_t *lccf;
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);

    /** NX_DEBUG("uri:%s", uri.data); */
    /* Allocate a new buffer for sending out the reply. */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    /* Insertion in the buffer chain. */
    out.buf = b;
    out.next = NULL; /* just one buffer */
    resData = NULL;

    if (ngx_strcmp(uri.data, "/") == 0) {
        html_json = 0;
        resData = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
        resData->len = strlen((char *)ngx_hello_world) + 1;
        resData->data = ngx_pcalloc(r->pool, resData->len);
        snprintf((char *)resData->data, resData->len, "%s", ngx_hello_world);
    } else if (ngx_strcmp(uri.data, "/login") == 0) {
        html_json = 1;
        resData = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
        resData->len = strlen((char *)ngx_hello_world) + 1;
        resData->data = ngx_pcalloc(r->pool, resData->len);
        snprintf((char *)resData->data, resData->len, "%s", ngx_hello_world);
    } else if (ngx_strcmp(uri.data, "/domain_list") == 0) {
        html_json = 1;
        resData = web_route_domain_list(r, lccf);
    } else if (ngx_strcmp(uri.data, "/main_conf") == 0) {
        html_json = 1;
        resData = web_route_main_conf(r, lccf);
    } else if (ngx_strcmp(uri.data, "/update_conf") == 0) {
        html_json = 1;
        resData = web_route_update_conf(r, lccf);
    } else if (ngx_strcmp(uri.data, "/json_flow") == 0) {
        html_json = 1;
        resData = web_route_json_flow(r, lccf);
    }
    if (resData == NULL) {
        resData = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
        resData->len = strlen((char *)ngx_hello_world) + 1;
        resData->data = ngx_pcalloc(r->pool, resData->len);
        snprintf((char *)resData->data, resData->len, "%s", ngx_hello_world);
        NX_DEBUG("else");
    }

    b->pos = resData->data; /* first position in memory of the data */
    b->last = resData->data + resData->len -
              1;     /* last position in memory of the data */
    b->memory = 1;   /* content is in read-only memory */
    b->last_buf = 1; /* there will be no more buffers in the request */

    /* Set the Content-Type header. */
    if (html_json == 0) {
        r->headers_out.content_type.len = sizeof("text/html") - 1;
        r->headers_out.content_type.data = (u_char *)"text/html";
    } else {
        r->headers_out.content_type.len = sizeof("application/json") - 1;
        r->headers_out.content_type.data = (u_char *)"application/json";
    }
    /* Sending the headers for the reply. */
    r->headers_out.status = NGX_HTTP_OK; /* 200 status code */
    /* Get the content length of the body. */
    r->headers_out.content_length_n = resData->len - 1;
    ngx_http_send_header(r); /* Send the headers */

    /* Send the body, and return the status code of the output filter chain. */
    return ngx_http_output_filter(r, &out);
} /* -----  end of function ngx_http_etomc2_ctrl_handler  ----- */
/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_http_etomc2_ctrl_handler Description:
 * =====================================================================================
 */
ngx_int_t lngx_http_etomc2_ctrl_handler(ngx_http_request_t *r) {
    ngx_buf_t *b;
    ngx_chain_t out;
    ngx_table_elt_t *et;
    ngx_str_t *data;

    ngx_http_etomc2_loc_conf_t *lccf;

    ngx_int_t itype;

    const char *type = "type";

    et = search_headers_in(r, (u_char *)type, strlen(type));
    if (et == NULL || et->value.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "type value is null");
        return NGX_ERROR;
    }
    itype = ngx_atoi(et->value.data, et->value.len);

    /* Set the Content-Type header. */
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *)"text/plain";
    r->headers_out.content_length_n = 0;

    /* Allocate a new buffer for sending out the reply. */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    /* Insertion in the buffer chain. */
    out.buf = b;
    out.next = NULL; /* just one buffer */
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);

    if (lccf->shm_zone_list == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shm_zone_list is null");
        return NGX_ERROR;
    }
    if (itype == 0) {
        data = web_route_waf_domain_ids(r, lccf);

        b->pos = data->data; /* first position in memory of the data */
        // memory of the data */
        b->last = data->data + data->len - 1;

        /* Get the content length of the body. */
        r->headers_out.content_length_n = data->len - 1;

    } else if (itype == 1) {
        data = web_route_waf_domain_rule(r, lccf);
        b->pos = data->data; /* first position in memory of the data*/
        // memory of the data
        b->last = data->data + data->len - 1;

        // Get the content length of the body.
        r->headers_out.content_length_n = data->len - 1;
    } else if (itype == 2) {
        web_route_set_gt_level(r, lccf);
        ngx_str_t gt = ngx_string("ok");
        b->pos = gt.data; /* first position in memory of the data */
        // memory of the data */
        b->last = gt.data + gt.len;

        /* Get the content length of the body. */
        r->headers_out.content_length_n = gt.len;
    } else if (itype == 3) {
        ngx_str_t dd = web_route_ip_blacklist(r, lccf);
        b->pos = dd.data; /* first position in memory of the data*/
        // memory of the data
        b->last = dd.data + dd.len - 1;

        // Get the content length of the body.
        r->headers_out.content_length_n = dd.len - 1;
    } else if (itype == 4) {
        web_route_get_gt_take(r, lccf);
        ngx_str_t gt = ngx_string("ok");
        b->pos = gt.data; /* first position in memory of the data */
        // memory of the data */
        b->last = gt.data + gt.len;

        /* Get the content length of the body. */
        r->headers_out.content_length_n = gt.len;

    } else if (itype == 5) {
        web_route_get_uri_itemize(r, lccf);
        ngx_str_t gt = ngx_string("ok");
        b->pos = gt.data; /* first position in memory of the data */
        // memory of the data */
        b->last = gt.data + gt.len;

        /* Get the content length of the body. */
        r->headers_out.content_length_n = gt.len;
    } else if (itype == 6) {
        ngx_str_t dbl = web_route_del_blackip(r, lccf);
        b->pos = dbl.data; /* first position in memory of the data*/
        // memory of the data
        b->last = dbl.data + dbl.len - 1;

        // Get the content length of the body.
        r->headers_out.content_length_n = dbl.len - 1;
    } else if (itype == 7) {
        if (ngx_http_slab_stat_buf(r->pool, b) == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_out.content_length_n = b->last - b->pos;

    } else {
        lreq_queue_show(r);
        char *string = "123456";
        ngx_str_t count_str = ngx_string(string);
        b->pos = count_str.data;
        b->last = count_str.data + count_str.len - 1;
        r->headers_out.content_length_n = count_str.len - 1;
        // return (NGX_ERROR);
    }
    b->memory = 1;   /* content is in read-only memory */
    b->last_buf = 1; /* there will be no more buffers in the request */
    /* Sending the headers for the reply. */
    r->headers_out.status = NGX_HTTP_OK; /* 200 status code */

    ngx_http_send_header(r); /* Send the headers */

    /* Send the body, and return the status code of the output filter chain. */
    return ngx_http_output_filter(r, &out);

} /* -----  end of function ngx_http_etomc2_ctrl_handler  ----- */
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
        NX_LOG("domain  dhv value is null");
        return NULL;
    }

    NX_DEBUG("domain:%s, domain%d", dhv->value.data, dhv->value.len);

    ihv = search_headers_in(r, (u_char *)itemize, strlen(itemize));

    if (ihv == NULL || ihv->value.len == 0) {
        NX_LOG("domain  ihv value is null");
        return NULL;
    }

    NX_DEBUG("itemize:%s, itemize%d", ihv->value.data, ihv->value.len);

    ghv = search_headers_in(r, (u_char *)glevel, strlen(glevel));

    if (ghv == NULL || ghv->value.len == 0) {
        NX_LOG("domain  ghv value is null");
        return NULL;
    }

    NX_DEBUG("glevel:%s, glevel%d", ghv->value.data, ghv->value.len);

    rhv = search_headers_in(r, (u_char *)rstatus, strlen(rstatus));

    if (rhv == NULL || rhv->value.len == 0) {
        NX_LOG("domain  rhv value is null");
        return NULL;
    }

    NX_DEBUG("rstatus:%s, rstatus%d", rhv->value.data, rhv->value.len);

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
        NX_LOG("domain  dhv value is null");
        return NULL;
    }

    NX_DEBUG("domain:%s, domain%d", dhv->value.data, dhv->value.len);
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
   * web_route_get_gt_take Description:
   * =====================================================================================
   */
ngx_int_t web_route_get_gt_take(ngx_http_request_t *r,
                                ngx_http_etomc2_loc_conf_t *lccf) {
    /**         ngx_http_core_srv_conf_t **cscfp; */
    /** ngx_uint_t s; */
    /** ngx_http_core_main_conf_t *cmcf; */
    /** ngx_slab_pool_t *shpool; */
    /** ngx_table_elt_t *hv; */
    /** uint32_t dm_hash = 0, server_hash; */
    /** int is_server = -1; */
    /** int ilevel = -1, itake = 0; */
    /** const char *take = "take"; */
    /** const char *domain = "domain"; */
    /** ngx_shm_zone_t *shm_zone_cc_gt; */
    /**  */
    /** Ngx_etomc2_shm_gt *cc_gt_ptr, *cc_new_ptr; */
    /**  */
    /**  */
    /** [> set  shm_gt_take <] */
    /** hv = search_headers_in(r, (u_char *)domain, strlen(domain)); */
    /** if (hv == NULL || hv->value.len == 0) { */
    /**     return NGX_ERROR; */
    /** } */
    /** dm_hash = to_hash((char *)hv->value.data, hv->value.len); */
    /**  */
    /** cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module); */
    /**  */
    /** cscfp = cmcf->servers.elts; */
    /** for (s = 0; s < cmcf->servers.nelts; s++) { */
    /**     [> ngx_cc_gt_init(cf,cscfp[s]->server_name); <] */
    /**     server_hash = to_hash((char *)cscfp[s]->server_name.data, */
    /**                           cscfp[s]->server_name.len); */
    /**     if (dm_hash == server_hash) { */
    /**         is_server = 0; */
    /**         break; */
    /**     } */
    /** } */
    /** if (is_server == -1) { */
    /**     return NGX_ERROR; */
    /** } */
    /** hv = search_headers_in(r, (u_char *)take, strlen(take)); */
    /** if (hv == NULL || hv->value.len == 0) { */
    /**     return NGX_ERROR; */
    /** } */
    /** itake = ngx_atoi(hv->value.data, hv->value.len); */
    /** shm_zone_cc_gt = lccf->shm_zone_cc_gt; */
    /** shpool = (ngx_slab_pool_t *)shm_zone_cc_gt->shm.addr; */
    /**  */
    /** cc_gt_ptr = (Ngx_etomc2_shm_gt *)shm_zone_cc_gt->data; */
    /** while (cc_gt_ptr) { */
    /**     if (cc_gt_ptr->hash_domain == 0) { */
    /**         cc_gt_ptr->hash_domain = dm_hash; */
    /**     } */
    /**     if (cc_gt_ptr->hash_domain == dm_hash) { */
    /**         ngx_shmtx_lock(&shpool->mutex); */
    /**         cc_gt_ptr->take = itake; */
    /**         ngx_shmtx_unlock(&shpool->mutex); */
    /**         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, */
    /**                       "[server_name:new,level:%d]", cc_gt_ptr->level);
     */
    /**  */
    /**         break; */
    /**     } */
    /**     if (cc_gt_ptr->next == NULL) { */
    /**         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, */
    /**                       "[server_name:new]"); */
    /**         // new */
    /**         cc_new_ptr = */
    /**             ngx_slab_alloc_locked(shpool, sizeof(Ngx_etomc2_shm_gt)); */
    /**         if (!cc_new_ptr) { */
    /**             break; */
    /**         } */
    /**         cc_new_ptr->hash_domain = dm_hash; */
    /**         cc_new_ptr->take = itake; */
    /**         cc_new_ptr->count = 0; */
    /**         cc_new_ptr->now = 0; */
    /**         switch (ilevel) { */
    /**             case 1: */
    /**                 cc_new_ptr->level = GTL_1; */
    /**                 break; */
    /**             case 2: */
    /**                 cc_new_ptr->level = GTL_2; */
    /**                 break; */
    /**             case 3: */
    /**                 cc_new_ptr->level = GTL_3; */
    /**                 break; */
    /**             case 4: */
    /**                 cc_new_ptr->level = GTL_4; */
    /**                 break; */
    /**             case 5: */
    /**                 cc_new_ptr->level = GTL_5; */
    /**                 break; */
    /**             default: */
    /**                 break; */
    /** } */
    /* -----  end switch  ----- */
    /** cc_new_ptr->next = NULL; */
    /**     ngx_shmtx_lock(&shpool->mutex); */
    /**  */
    /**     cc_gt_ptr->next = cc_new_ptr; */
    /**     ngx_shmtx_unlock(&shpool->mutex); */
    /** } */
    /**  */
    /** cc_gt_ptr = cc_gt_ptr->next; */
    /** } */
    return NGX_OK;
} /* -----  end of function web_route_get_gt_take  ----- */
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

/*
 * ===  FUNCTION
 * ====================================================================== Name:
 * ngx_http_slab_stat_buf Description:
 * =====================================================================================
 */
static ngx_int_t ngx_http_slab_stat_buf(ngx_pool_t *pool, ngx_buf_t *b) {
    u_char *p;
    size_t pz, size;
    ngx_uint_t i, k, n;
    ngx_shm_zone_t *shm_zone;
    ngx_slab_pool_t *shpool;
    ngx_slab_page_t *page;
    ngx_slab_stat_t *stats;
    volatile ngx_list_part_t *part;

#define NGX_SLAB_SHM_SIZE (sizeof("* shared memory: \n") - 1)
#define NGX_SLAB_SHM_FORMAT "* shared memory: %V\n"
#define NGX_SLAB_SUMMARY_SIZE \
    (3 * 12 + sizeof("total:(KB) free:(KB) size:(KB)\n") - 1)
#define NGX_SLAB_SUMMARY_FORMAT "total:%12z(KB) free:%12z(KB) size:%12z(KB)\n"
#define NGX_SLAB_PAGE_ENTRY_SIZE \
    (12 + 2 * 16 + sizeof("pages:(KB) start: end:\n") - 1)
#define NGX_SLAB_PAGE_ENTRY_FORMAT "pages:%12z(KB) start:%p end:%p\n"
#define NGX_SLAB_SLOT_ENTRY_SIZE \
    (12 * 5 + sizeof("slot:(Bytes) total: used: reqs: fails:\n") - 1)
#define NGX_SLAB_SLOT_ENTRY_FORMAT \
    "slot:%12z(Bytes) total:%12z used:%12z reqs:%12z fails:%12z\n"
    pz = 0;

    /* query shared memory */

    part = &ngx_cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        pz += NGX_SLAB_SHM_SIZE + (size_t)shm_zone[i].shm.name.len;
        pz += NGX_SLAB_SUMMARY_SIZE;

        shpool = (ngx_slab_pool_t *)shm_zone[i].shm.addr;

        ngx_shmtx_lock(&shpool->mutex);

        for (page = shpool->free.next; page != &shpool->free;
             page = page->next) {
            pz += NGX_SLAB_PAGE_ENTRY_SIZE;
        }

        n = ngx_pagesize_shift - shpool->min_shift;
        ngx_shmtx_unlock(&shpool->mutex);

        for (k = 0; k < n; k++) {
            pz += NGX_SLAB_SLOT_ENTRY_SIZE;
        }
    }

    /* preallocate pz * 2 to make sure memory enough */
    p = ngx_palloc(pool, pz * 2);
    if (p == NULL) {
        return NGX_ERROR;
    }

    b->pos = p;

    size = 1 << ngx_pagesize_shift;

    part = &ngx_cycle->shared_memory.part;
    shm_zone = part->elts;

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

        p = ngx_snprintf(p, NGX_SLAB_SHM_SIZE + shm_zone[i].shm.name.len,
                         NGX_SLAB_SHM_FORMAT, &shm_zone[i].shm.name);

        ngx_shmtx_lock(&shpool->mutex);

        p = ngx_snprintf(p, NGX_SLAB_SUMMARY_SIZE, NGX_SLAB_SUMMARY_FORMAT,
                         shm_zone[i].shm.size / 1024,
                         shpool->pfree * size / 1024, size / 1024,
                         shpool->pfree);

        for (page = shpool->free.next; page != &shpool->free;
             page = page->next) {
            p = ngx_snprintf(
                p, NGX_SLAB_PAGE_ENTRY_SIZE, NGX_SLAB_PAGE_ENTRY_FORMAT,
                page->slab * size / 1024, shpool->start, shpool->end);
        }

        stats = shpool->stats;

        n = ngx_pagesize_shift - shpool->min_shift;

        for (k = 0; k < n; k++) {
            p = ngx_snprintf(p, NGX_SLAB_SLOT_ENTRY_SIZE,
                             NGX_SLAB_SLOT_ENTRY_FORMAT,
                             1 << (k + shpool->min_shift), stats[k].total,
                             stats[k].used, stats[k].reqs, stats[k].fails);
        }

        ngx_shmtx_unlock(&shpool->mutex);
    }
    b->last = p;
    b->memory = 1;
    b->last_buf = 1;

    return NGX_OK;
} /* -----  end of function ngx_http_slab_stat_buf  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  list_json
 *  Description:
 * =====================================================================================
 */
void list_json(ngx_http_request_t *r, Ngx_etomc2_aiwaf_list *nlist,
               ngx_str_t **data, uint32_t dmhash) {
    Ngx_etomc2_aiwaf_list *tlist = NULL;
    const char *fmt = "%u";
    const char *fmt_list = "%.*s,%u";

    ngx_str_t *tmp;

    tlist = nlist;

    while (tlist) {
        /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"hash_domain:%zu
         * dmhash:%zu hash_rule:%zu, domain:%s",tlist->hash_domain,
         * dmhash,tlist->hash_rule,tlist->domain); */

        if (tlist->hash_domain != dmhash) {
            tlist = tlist->next;
            continue;
        }
        tmp = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
        if (tmp == NULL) return;
        if ((*data)->len == 0) {
            tmp->len = snprintf(NULL, 0, fmt, tlist->hash_rule);
            tmp->len += 1;
            tmp->data = ngx_pcalloc(r->pool, tmp->len);
            if (tmp->data == NULL) return;
            snprintf((char *)tmp->data, tmp->len, fmt, tlist->hash_rule);

        } else {
            tmp->len = snprintf(NULL, 0, fmt_list, (*data)->len, (*data)->data,
                                tlist->hash_rule);
            tmp->len += 1;

            tmp->data = ngx_pcalloc(r->pool, tmp->len);
            if (tmp->data == NULL) return;
            snprintf((char *)tmp->data, tmp->len, fmt_list, (*data)->len,
                     (*data)->data, tlist->hash_rule);
            ngx_pfree(r->pool, (*data)->data);
        }

        (*data)->data = tmp->data;
        (*data)->len = tmp->len;

        tlist = tlist->next;
    }
} /* -----  end of function list_json  ----- */
  /*
   * ===  FUNCTION
   * ======================================================================
   *         Name:  isIp_v4
   *  Description:
   * =====================================================================================
   */
int isIp_v4(const char *ip) {
    int len = strlen(ip);
    int i;
    unsigned int d[4];
    char tail[16];
    int c;
    if (len < 7 || len > 15) return -1;

    tail[0] = 0;
    c = sscanf(ip, "%3u.%3u.%3u.%3u%s", &d[0], &d[1], &d[2], &d[3], tail);

    if (c != 4 || tail[0]) return -1;

    for (i = 0; i < 4; i++)
        if (d[i] > 255) return -1;
    return 0;
} /* -----  end of function isIp_v4  ----- */
