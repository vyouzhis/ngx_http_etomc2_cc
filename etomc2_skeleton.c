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
static char *ngx_conf_set_black_path(ngx_conf_t *cf, ngx_command_t *cmd,
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

static void ngx_cc_rbtree_insert_value(ngx_rbtree_node_t *temp,
                                       ngx_rbtree_node_t *node,
                                       ngx_rbtree_node_t *sentinel);


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
    {ngx_string(CC_SHM_SIZE), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_http_cc_set_shm_size, 0, 0, NULL},

    {ngx_string("etomc2_skeleton_api"),   /* directive */
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, /* location context and takes
                                             no arguments*/
     ngx_http_etomc2_web,                 /* configuration setup function */
     0, /* No offset. Only one context is supported. */
     0, /* No offset when storing the module configuration on struct. */
     NULL},
    {ngx_string(CC_BLACK_IP_FILE), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_black_path, 0, 0, NULL},
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
        *shm_zone_lreq_queue, *shm_zone_cc_gt;

    ngx_str_t *shm_cc_thin_name, *shm_cc_ub_name, *shm_ub_queue_name,
        *shm_lreq_queue_name, *shm_gt_name;

    ngx_http_etomc2_loc_conf_t *prev = parent;
    ngx_http_etomc2_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->etomc2_cc_enable, prev->etomc2_cc_enable, 0);

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

    /** ---------- aiwaf list ----------- */
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

    /** -------- global toggle  ----------------*/
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
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_top_header_filter error");
        return NGX_DECLINED;
    }
    if (lccf->etomc2_cc_enable == 0) {
        return NGX_DECLINED;
    }
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "etomc2_cc_enable:%d",
                  lccf->etomc2_cc_enable);
    initialize_uuid();
    /**     pem_auth = 0; */
    /**  */
    /** #ifdef RSA_AUTH */
    /**     pem_auth = rsa_auth(r, rsa_pem_auth_base64); */
    /** #endif */
    /** if (pem_auth == 0) { */
    if (ngx_cc_run_check == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "cc_thin_enter time:%d", ngx_time());

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
    /** } */
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
    uint32_t hash;
    ngx_str_t path;
    ngx_str_t file_path;
    size_t m = 0;
    /** ngx_http_request_ctx_t *ctx; */
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!lccf) {
        return ngx_http_next_header_filter(r);
    }
    if (lccf->etomc2_cc_enable == 0) {
        return ngx_http_next_header_filter(r);
    }
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "ngx_http_etomc2_header_filter");

    /** if (pem_auth == -1) { */
    /** return ngx_http_next_header_filter(r); */
    /** } */

    key = ngx_cc_rbtree_hash_key(r);
    if (!key) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_cc_rbtree_hash_key is null");
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.status != 200 && r->headers_out.status != 301 &&
        r->headers_out.status != 302) {
        /**         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, */
        /** "ill_return_status len:%d ", lccf->ill_return_status.len); */
        if (lccf->ill_return_status.len > 0) {
            for (m = 0; m < (lccf->ill_return_status.len - 1); m += 4) {
                ngx_uint_t status =
                    ngx_atoi((u_char *)lccf->ill_return_status.data + m, 3);

                /**             ngx_log_error(NGX_LOG_ERR, r->connection->log,
                 * 0, */
                /** "ill_return_status:%d status:%d", status, */
                /** r->headers_out.status); */
                if (r->headers_out.status == status) {
                    hash = to_hash((char *)key->data, key->len);
                    path = hdcache_hash_to_dir(r, hash, M_RED);
                    int hb = hdcache_create_dir((char *)path.data, 0700);
                    if (hb == -1) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "hdcache_create_dir  error");
                        break;
                    }
                    file_path = hdcache_file_build(r, path, *key);
                    if (file_path.len == 0) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "file_path  error");
                        break;
                    }
                    hdcache_create_file((char *)file_path.data, 0, ngx_time());
                    return ngx_http_next_header_filter(r);
                }
            }
        }
    }

    if (r->headers_out.status == 200) {
        lreq_uri_queue(r);
        /** lreq_queue_show(r); */
        /** lreq_status(r); */
    }

    /**             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, */
    /** "headers_out status:%d", r->headers_out.status); */
    /**
     *  M_GREEN
     */
    ngx_int_t cm = cc_cookie_mark(r);

    if (cm == NGX_OK) {
        return ngx_http_next_header_filter(r);
    }

    /**
     *  white_ip  exist
     */

    if (lccf->hdcache_path.len > 0) {
        int white_ip = custom_ip_attack_exist(r, M_GREEN);

        if (white_ip == 0) {
            return ngx_http_next_header_filter(r);
        }
    }

    /**
     *
     *  hdcache  for app  green
     */
    hash = to_hash((char *)key->data, key->len);
    path = hdcache_hash_to_dir(r, hash, M_GREEN);
    file_path = hdcache_file_build(r, path, *key);
    int isexit = hdcache_file_exist((char *)file_path.data);
    if (isexit == 0) {
        return ngx_http_next_header_filter(r);
    }

    /**
     *  user behavior lookup
     */

    if (r->headers_out.status == 200) {
        if (ngx_cc_run_check == 1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "cc_thin_end ok, time:%d", ngx_time());
            ngx_cc_run_check = 2;
        }
        /**
         * visits  cc attack
         * update  struct subject
         */
        /** domain_uri_add(r); */

        /**
         * user behavior cc  attack;
         * update  struct subject
         */
        cc_thin_user_behavior_lookup(r, key);
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
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "ngx_http_etomc2_body_filter");
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
    ssize_t new_shm_size;
    ngx_str_t *value;

    value = cf->args->elts;

    new_shm_size = ngx_parse_size(&value[1]);
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
    /**     ngx_conf_log_error(NGX_LOG_ERR, cf, 0, */
    /** "Using %d of shared memory , ubsize:%d", */
    /** ngx_http_cc_shm_size, (ngx_http_cc_shm_size / (ngx_pagesize +
     * sizeof(ngx_slab_page_t))) ); */

    return NGX_CONF_OK;

} /* -----  end of function ngx_http_cc_set_shm_size  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  ngx_conf_set_black_path
 *  Description:
 * =====================================================================================
 */
static char *ngx_conf_set_black_path(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf) {
    ngx_str_t *value;

    value = cf->args->elts;
    /**     ngx_conf_log_error( */
    /** NGX_LOG_ERR, cf, 0, */
    /** "black file:%s",value[1].data); */

    cc_black_ip_file = ngx_palloc(cf->pool, sizeof(ngx_log_t));
    if (!cc_black_ip_file) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "open black ip file file error, abort.");
        return (NGX_CONF_ERROR);
    }
    ngx_memzero(cc_black_ip_file, sizeof(ngx_log_t));

    cc_black_ip_file->log_level = NGX_LOG_NOTICE;
    cc_black_ip_file->file = ngx_conf_open_file(cf->cycle, &value[1]);
    if (!cc_black_ip_file->file) {
        ngx_pfree(cf->pool, cc_black_ip_file);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "open etomc2LogFile file error, abort.");
        return (NGX_CONF_ERROR);
    }
    return NGX_CONF_OK;
} /* -----  end of function ngx_conf_set_black_path  ----- */

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

