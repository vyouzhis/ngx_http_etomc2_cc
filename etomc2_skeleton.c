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
    ngx_http_etomc2_loc_conf_t *prev = parent;
    ngx_http_etomc2_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->etomc2_cc_enable, prev->etomc2_cc_enable, 0);

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

    lccf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (lccf->etomc2_cc_enable == 0) {
        return ngx_http_next_header_filter(r);
    }
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "ngx_http_etomc2_header_filter");
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

