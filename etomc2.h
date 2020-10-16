/*
 * =====================================================================================
 *
 *       Filename:  etomc2.h
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  2020年08月10日 11时50分24秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  etomc2@etomc2.com (), etomc2@etomc2.com
 *   Organization:  etomc2.com
 *
 * =====================================================================================
 */
#ifndef ETOMC2_INC
#define ETOMC2_INC

#define ETOMC2_VERSION "0.0.1"

#include <ctype.h>
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include <ngx_http_core_module.h>
#include <ngx_md5.h>
#include <pcre.h>
#include <sys/times.h>
#include <unistd.h>

/**
 *  define  function
 */

#define LFEATURE 1
#define DFEATURE 1
#ifndef __ETOMC2_LOG
#define __ETOMC2_LOG
#define NX_LOG(LOG, ...)                                           \
    do {                                                           \
        if (LFEATURE)                                              \
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, LOG, \
                          ##__VA_ARGS__);                          \
    } while (0)
#endif

#ifndef __ETOMC2_DEBUG
#define __ETOMC2_DEBUG
#define NX_DEBUG(LOG, ...)                                                \
    do {                                                                  \
        if (DFEATURE)                                                     \
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, LOG, \
                          ##__VA_ARGS__);                                 \
    } while (0)
#endif

#ifndef __ETOMC2_CONF_DEBUG
#define __ETOMC2_CONF_DEBUG
#define NX_CONF_DEBUG(LOG, ...)                                     \
    do {                                                                \
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, LOG, ##__VA_ARGS__); \
    } while (0)
#endif

#define GET_ARRAY_LEN(array, len) \
    { len = (sizeof(array) / sizeof(array[0])); }

/**
 * define  var
 */

/***
 * ctx command
 */
/**
 * config http
 */
#define ETOMC2_CC_ENABLE "ET2CCEnable"
#define ET2_SHM_SIZE "et2_shm_size"

/**
 * config  server
 */
#define CC_RETURN_STATUS "et2_cc_return_status"
#define CC_ITEMIZE "et2_cc_itemize"
#define CC_GT_LEVEL "et2_cc_level"

#define CC_TRUST_STATUS "et2_trust_status"
/**
 * web ctrl admin
 */
#define ET2_NGX_CTRL "et2_ctrl_admin"
#define ETOMC2_WEB_API "et2_web_api"

// #define CC_PATH "et2_root_path"

#define HDCACHE_PATH "et2_hdcache_path"

#define PEM_SECURE_TUNNEL "secure-tunnel"
#define etomc2_PEM_PK_FILE "Etomc2CCPemPrivateKey"

#define RSA_PEM_AUTH "rsa_pem_auth"

//  itemize behavior  and when  ngx found  itemize will write log
//  itemize_id for  uri

#define WEB_ETOMC2 "hello world!"

// share memory size;
#define SHM_SIZE_MAX_COMMON 128 * ngx_pagesize
#define SHM_SIZE_DEFAULT_COMMON 8 * ngx_pagesize

#define CC_GT_URI_MAX 8

//  10 < ROAD_MAP_URI_MAX
#define SHM_GT_TIMEOUT 10

// flow
#define SHM_FLOW_FREQ 60

//#define ITIME_SECOND 300
#define STIME_SECOND 30
#define LTIME_SECOND 120
/**
 *  header_time > 5  lreq limit
 */
#define LREQ_HEADER_TIME 5000
#define LREQ_QUEUE_MAX 8

#define TIME_RECKON_OUT 3600
#define TIME_RATE_INTERVAL 5
#define ROAD_MAP_URI_MAX 13  // Fibonacci  number
#define CONTENT_SIZE 8
#define BEHAVIOR_URI_SMALL 2
#define BAD_BEHAVIOR 4
#define HASH_COOKIE_KEY "d41d8cd98f00b204e9800998ecf8427e"
#define VISITS_RATE_SIZE 3

#define MARK_READY_NEXT_TIME 2
#define MARK_READY_NEXT_TIME_INVALID 4

#define COOKIE_GREEN_NAME "behavior_cc"
#define COOKIE_UUID_NAME "__secure-uuid"

static const float Fibonacci[4][2] = {
    {0.382, 0.5}, {1.13, 1.618}, {2.24, 2.618}, {3.14, 3.618}};

static const size_t Intensity[] = {5 * 60, 13 * 60, 60 * 60, 24 * 60 * 60,
                                   7 * 24 * 60 * 60};

/**
 *  define  global var
 */
/* The hello world string. */

extern ngx_module_t ngx_http_etomc2_cc_module;

// static int pem_auth;

/**
 *
 *  define  struct  enum
 */
enum CC_THIN_COOKIE_MARK {
    M_YELLOW = 0,  // init  new  client
    M_GREEN,       // green is  trust  client
    M_SMALL,       //  only  one  uri
    M_READY,       // checking  client
    M_RED          // block  client
};                 /* ----------  end of enum CC_THIN_COOKIE_MARK  ---------- */
typedef enum CC_THIN_COOKIE_MARK CC_THIN_COOKIE_MARK;

enum BROWSER_BOT {
    BB_DEFAULT = 0,
    BB_BROWSER,
    BB_BOT
}; /* ----------  end of enum BROWSER_BOT  ---------- */

typedef enum BROWSER_BOT BROWSER_BOT;

/**
 * aiwaf hash list
 */
struct ngx_etomc2_aiwaf_list {
    uint32_t hash_rule;
    uint32_t hash_domain;
    struct ngx_etomc2_aiwaf_list *next;
}; /* ----------  end of struct ngx_etomc2_aiwaf_list  ---------- */

typedef struct ngx_etomc2_aiwaf_list Ngx_etomc2_aiwaf_list;

struct ngx_etomc2_shm_tree_data {
    uint32_t hashkey;
    void *data;
    struct ngx_etomc2_shm_tree_data *right, *left;
}; /* ----------  end of struct ngx_etomc2_shm_tree_data  ---------- */

typedef struct ngx_etomc2_shm_tree_data Ngx_etomc2_shm_tree_data;

/* ---- etomc2 cc------ */
enum SHM_GT_LEVEL {
    GTL_1 = 1,
    GTL_2 = 5,
    GTL_3 = 13,
    GTL_4 = 55,
    GTL_5 = 233,
}; /* ----------  end of enum SHM_GT_LEVEL  ---------- */

typedef enum SHM_GT_LEVEL SHM_GT_LEVEL;

struct ngx_etomc2_shm_gt {
    uint32_t hash_domain;
    size_t count;
    time_t now;
    uint32_t uri_itemize[CC_GT_URI_MAX];  // uri  is loop  itemize level+1;
    // ngx_flag_t take;  // default 0 is  itemizeing,  1 is itemizeed
    SHM_GT_LEVEL level;
    struct ngx_etomc2_shm_gt *next;
}; /* ----------  end of struct ngx_etomc2_shm_gt  ---------- */

typedef struct ngx_etomc2_shm_gt Ngx_etomc2_shm_gt;

/*
 * one hour flow, one minute step
 */

struct ngx_etomc2_cc_flow {
    uint32_t hash_domain;
    size_t flow[SHM_FLOW_FREQ];
    time_t now[SHM_FLOW_FREQ];
    struct ngx_etomc2_cc_flow *next;
};				/* ----------  end of struct ngx_etomc2_cc_flow  ---------- */

typedef struct ngx_etomc2_cc_flow Ngx_etomc2_cc_flow;

/**
 * the step 0
 * use  Fibonacci to calculate increase
 */

/**
 *  二级防护，当量大于后端可承受阶段的时候，启用
 *  第二波纯数据流拦截
 *  只记录可疑的
 *  visit cc attack
 */
struct ngx_etomc2_cc_domain {
    int count;
    uint32_t hash_domain;
    Ngx_etomc2_shm_tree_data *tree_uri;
    struct ngx_etomc2_cc_domain *next;
}; /* ----------  end of struct ngx_etomc2_cc_domain  ---------- */

typedef struct ngx_etomc2_cc_domain Ngx_etomc2_cc_domain;

/**
 *  M_READY  URI
 */

struct ngx_etomc2_cc_uri {
    ngx_str_t *uri;
    size_t visits[60];   // 24 time uri visit
    size_t visited[60];  // 24 time uri visited
}; /* ----------  end of struct ngx_etomc2_cc_uri  ---------- */

typedef struct ngx_etomc2_cc_uri Ngx_etomc2_cc_uri;

/**
 *
 * the step 1
 * fine-grained for minute
 *
 */
struct ngx_visit_cc_attack {
    uint32_t hash_domain;
    uint32_t hash_uri;
    size_t rise_level;  // now rise level  visits/visited  from  Fibonacci
    struct ngx_visit_cc_attack *next;
}; /* ----------  end of struct ngx_visit_cc_attack  ---------- */

typedef struct ngx_visit_cc_attack Ngx_visit_cc_attack;

/* ---- visit  cc attack ----  */

/* ----------- visit lreq  uri  --------*/
/**
 * check hdcache is not,  run  10 minute and  stop
 * while do  limit  request
 *  M_LIMIT  status  and push
 *  ma(minTime[0],maxTime[0]) / ma(minTime[1],maxTime[1])
 *  Fibonacci[]
 */

struct ngx_etomc2_lreq_uri {
    // ngx_str_t uri_md5;
    uint32_t hash_uri;  ///   uri
    time_t stime;       // 5 minutes  average
    time_t ltime;       //  30  minute

    ngx_msec_t header_time;
    float avgtime[4];  // ma  value now  5 minutes  and  30 pre minutes
    // header_time
    float active;  // default 0  active>0,  agvTime[0]/active  < Fibonacci[0][1]
    uint32_t count;   // visit  count
    time_t lastTime;  // visit  last time
                      // struct ngx_etomc2_lreq_uri *next;
}; /* ----------  end of struct ngx_etomc2_lreq_uri  ---------- */

typedef struct ngx_etomc2_lreq_uri Ngx_etomc2_lreq_uri;

/**
 *  add new  queue  for M_GREEN
 */
struct ngx_etomc2_lreq_queue {
    uint32_t hash_domain;
    Ngx_etomc2_lreq_uri lreq[LREQ_QUEUE_MAX];  //  new  add  and  push last time

    struct ngx_etomc2_lreq_queue *next;
}; /* ----------  end of struct ngx_etomc2_lreq_queue  ---------- */

typedef struct ngx_etomc2_lreq_queue Ngx_etomc2_lreq_queue;

/* ----------- visit lreq  uri  --------*/

/*  ------ user behavior cc attack ---- */

/**
 * the step 2
 * request info record
 */

/* typedef struct ngx_etomc2_cc_info Ngx_etomc2_cc_attack; */

// time  out  60  second

/**
 * -----  time out 60 second   -----
 *
 * user behavior cc attack  struct
 * M_GREEN factor
 * 1. road_maps == ROAD_MAP_URI_MAX  or  content_types  == CONTENT_SIZE
 * 2. referer == 1  and  (rate_0 - rate_1)>TIME_RATE_INTERVAL
 *     and (now - rate_0) > TIME_RATE_INTERVAL
 *
 * M_RED  factor
 *   time out  60 second
 * 1. road_maps < BAD_BEHAVIOR  and  content_types < BAD_BEHAVIOR
 *    check amount  top / ROAD_MAP_URI_MAX  == Fibonacci
 *
 *   if   amount top/ROAD_MAP_URI_MAX   == Fibonacci[3]
 *      rate_0 - rate_1 = 10 second
 *      uri_amount[-1]  save rate_0  val
 *
 *      10 second  2 Fibonacci
 *      uri_amount top  / uri_amount[-1]  == Fibonacci[2]
 *
 *  mark  == M_RED  or M_READY
 *  uri_amount[-2]  the max road_maps  and  the Intensity val
 *
 *  M_YELLOW the next
 */
struct ngx_etomc2_cc_user_behavior {
    ngx_rbtree_t rbtree;
    ngx_rbtree_node_t sentinel;
    ngx_str_t hash_str;

    CC_THIN_COOKIE_MARK mark;  // first  is M_YELLOW  ,bad is M_RED clean
    // M_GREEN or time out
    uint32_t road_maps[ROAD_MAP_URI_MAX];  // uri  road maps;
    size_t uri_amount[ROAD_MAP_URI_MAX];   // uri  amount;

    size_t content_types[ROAD_MAP_URI_MAX];  //  how many content type;
    // header_in request file
    size_t referer;
    ngx_flag_t method;         // get and post  == 1, only get  or post  == 0
    BROWSER_BOT BrowserOrBot;  // Browser  bot (or app)  set uuid cookie  check
    // and  content_types

    time_t rate_0;  ///  timestamp　interval > TIME_RATE_INTERVAL
    time_t rate_1;

}; /* ----------  end of struct ngx_etomc2_cc_user_behavior  ---------- */

typedef struct ngx_etomc2_cc_user_behavior Ngx_etomc2_cc_user_behavior;

/**
 * all client queue info
 * do not use
 *
 */
struct ngx_etomc2_ub_queue {
    ngx_str_t hash_str;  //  hash(server_name+ip+ua+key)   key:
    // HASH_COOKIE_KEY  ...
    uint32_t time_reckon;  //( now time - time_reckon )> TIME_RECKON_OUT  to
    // nullify
    struct ngx_etomc2_ub_queue *next;
}; /* ----------  end of struct ngx_etomc2_ub_queue  ---------- */

typedef struct ngx_etomc2_ub_queue Ngx_etomc2_ub_queue;

struct ngx_ub_queue_ptr {
    Ngx_etomc2_ub_queue *head;
    Ngx_etomc2_ub_queue *tail;
}; /* ----------  end of struct ngx_ub_queue_ptr  ---------- */

typedef struct ngx_ub_queue_ptr Ngx_ub_queue_ptr;

/* #define cc_queue_init(h) \ */
/* ngx_slab_alloc_locked((ngx_slab_pool_t*)(p), sizeof(Ngx_etomc2_ub_queue)); */

#define cc_queue_insert_tail(h, x) \
    Ngx_etomc2_ub_queue *t = h;    \
    while (t->next) {              \
        t = t->next;               \
    }                              \
    t->next = x;

#define cc_queue_show(h, r)                                                    \
    Ngx_etomc2_ub_queue *t = h;                                                \
    while (t && t->time_reckon != 0) {                                         \
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,                      \
                      " {hash_str:%s}[%d]", t->hash_str.data, t->time_reckon); \
        t = t->next;                                                           \
    }

#define cc_queue_pop_head(h, p)                                          \
    time_t seconds = ngx_time();                                         \
    Ngx_etomc2_ub_queue *th = h;                                         \
    if ((th) && (th)->time_reckon != 0) {                                \
        if (((uint32_t)seconds - (th)->time_reckon) > TIME_RECKON_OUT) { \
            h = h->next;                                                 \
            ngx_slab_free((ngx_slab_pool_t *)(p), th);                   \
        }                                                                \
    }

/* ---- etomc2 cc------ */

typedef struct {
    ngx_log_t *log;

} ngx_http_etomc2_main_conf_t;

typedef struct {
    ngx_flag_t etomc2_cc_enable;

    // ngx_str_t cc_path;
    ngx_str_t hdcache_path;
    ngx_str_t rsa_pem_pk;
    ngx_str_t rsa_pem;

    ngx_str_t cc_trust_status;

    ngx_flag_t cc_itemize;
    ngx_uint_t cc_gt_level;
    ngx_uint_t cc_return_status;
    ngx_slab_pool_t *shpool;

    /**
     * waf shm  and  waf hash list
     */
    ngx_shm_zone_t *shm_zone_waf;
    ngx_shm_zone_t *shm_zone_list;

    /**
     * cc  uri  count
     */
    ngx_shm_zone_t *shm_zone_uri;

    /**
     *  cc uri drop
     */
    ngx_shm_zone_t *shm_zone_cc_thin;

    /**
     *  user behavior cc attack
     */
    ngx_shm_zone_t *shm_zone_cc_ub;
    /**
     * user behavior  cc queue
     */
    ngx_shm_zone_t *shm_zone_ub_queue;
    /**
     * limit request  uri queue;
     */
    ngx_shm_zone_t *shm_zone_lreq_queue;

    /**
     *  cc  global toggle
     */
    ngx_shm_zone_t *shm_zone_cc_gt;

     /**
     *  flow global toggle
     */
    ngx_shm_zone_t *shm_zone_cc_flow;
    
} ngx_http_etomc2_loc_conf_t; /* ----------  end of struct
                                ngx_http_lb_loc_conf_t  ---------- */

ngx_table_elt_t *search_headers_in(ngx_http_request_t *r, u_char *name,
                                   size_t len);

Ngx_etomc2_shm_tree_data *tree_create(ngx_slab_pool_t *shpool);
size_t tree_insert(ngx_http_request_t *r, Ngx_etomc2_shm_tree_data **tree,
                   uint32_t hashkey, void *data, ngx_slab_pool_t *shpool);
void tree_print(ngx_http_request_t *r, Ngx_etomc2_shm_tree_data *tree);
Ngx_etomc2_shm_tree_data *tree_search(Ngx_etomc2_shm_tree_data **tree,
                                      uint32_t hashkey);

Ngx_etomc2_aiwaf_list *list_create(ngx_slab_pool_t *shpool);
void list_insert(ngx_http_request_t *r, ngx_slab_pool_t *shpool,
                 Ngx_etomc2_aiwaf_list **list_root, uint32_t hash_rule);
int timeIndex();
int timeSecond();
int findstring(const char *rest, const char *dest);
void visit_print(ngx_http_request_t *r, Ngx_etomc2_shm_tree_data *tree);

// ---- cc function----

ngx_str_t get_uri(ngx_http_request_t *r);

void cc_thin_user_agent(ngx_http_request_t *r);
ngx_int_t cc_thin_enter(ngx_http_request_t *r);
Ngx_visit_cc_attack *cc_thin_create(ngx_slab_pool_t *shpool);
void cc_thin_insert(ngx_slab_pool_t *shpool, Ngx_visit_cc_attack **thin_root,
                    uint32_t hash_uri, uint32_t hash_domain, size_t rise_level);
void cc_thin_delete(Ngx_visit_cc_attack **thin_root, uint32_t hash_uri,
                    uint32_t hash_domain);
size_t cc_thin_search(Ngx_visit_cc_attack **thin_root, uint32_t hash_uri,
                      uint32_t hash_domain);
void cc_thin_show(ngx_http_request_t *r, Ngx_visit_cc_attack *thin_root);

void cc_setcookie(ngx_http_request_t *r, ngx_str_t key);
void cc_cookie(ngx_http_request_t *r);
void setcookie(ngx_http_request_t *r, ngx_str_t cookie);
ngx_int_t cc_cookie_mark(ngx_http_request_t *r, ngx_str_t *ower_md5);
int behavior_uuid_cookie(ngx_http_request_t *r);

Ngx_etomc2_cc_domain *domain_uri_create(ngx_slab_pool_t *shpool);
ngx_int_t domain_uri(ngx_http_request_t *r);
void domain_uri_add(ngx_http_request_t *r);
void domain_uri_show(ngx_http_request_t *r);

void cc_thin_user_behavior_lookup(ngx_http_request_t *r, ngx_str_t *key);
ngx_rbtree_node_t *cc_thin_user_behavior_search(ngx_rbtree_node_t *node,
                                                ngx_rbtree_node_t *sentinel,
                                                ngx_str_t *key);

void cc_thin_user_behavior_delete(ngx_rbtree_t *root, ngx_rbtree_node_t *node,
                                  ngx_slab_pool_t *shpool);
void cc_thin_ub_queue_insert(Ngx_ub_queue_ptr *ub_queue_ptr,
                             ngx_slab_pool_t *shpool, ngx_str_t *hash_str);

void ngx_cc_rbtree_loop(ngx_http_request_t *r, ngx_rbtree_node_t *node,
                        ngx_rbtree_node_t *sentinel);
void ngx_cc_rbtree_showall(ngx_http_request_t *r);

ngx_str_t *ngx_cc_rbtree_hash_key(ngx_http_request_t *r);

int ArrayMax(size_t array[]);

void ngx_cc_gt(ngx_http_request_t *r);
Ngx_etomc2_shm_gt *ngx_cc_gt_init(ngx_slab_pool_t *shpool);
int ngx_cc_gt_check(ngx_http_request_t *r, uint32_t hash_uri);
int gt_index(SHM_GT_LEVEL gt);
void ngx_cc_gt_search(ngx_http_request_t *r, Ngx_etomc2_shm_gt **gt_node_ptr);
ngx_str_t client_forward_ip(ngx_http_request_t *r);
// ---- cc function----

// -----  openssl  rsa  -----
void rsa_encrypt(ngx_http_request_t *r, const ngx_str_t from);
int rsa_decrypt(ngx_http_request_t *r, const ngx_str_t base64,
                const ngx_str_t pem, char **decrypt);
int rsa_auth(ngx_http_request_t *r, const ngx_str_t base64);
// -----  openssl  rsa function -----

// ----  uuid ---

ngx_int_t initialize_mt();
void initialize_uuid();
int uuid4_data(ngx_http_request_t *r);
// ----  uuid ---

// ------  hdcache ----
int hdcache_create_dir(const char *path, const mode_t mode);
void hdcache_create_file(const char *path, int inten, int timestamp);
int hdcache_unlink_file(const char *path);
int hdcache_file_exist(const char *file);

ngx_str_t hdcache_hash_to_dir(ngx_http_request_t *r, uint32_t num,
                              CC_THIN_COOKIE_MARK mark);
ngx_str_t hdcache_hash_to_dir_def(ngx_http_request_t *r, const char *path,
                                  uint32_t num, CC_THIN_COOKIE_MARK mark);
ngx_str_t hdcache_file_build(ngx_http_request_t *r, ngx_str_t path,
                             ngx_str_t file_name);
int hdcache_file_content(const char *file, int *timestamp);
int hdcache_behavior(ngx_http_request_t *r, ngx_str_t *key,
                     CC_THIN_COOKIE_MARK mark, int *timestamp);
int hdcache_behavior_exist(ngx_http_request_t *r, ngx_str_t *key,
                           CC_THIN_COOKIE_MARK mark);
void hdcache_behavior_add(ngx_http_request_t *r, ngx_str_t *key,
                          CC_THIN_COOKIE_MARK mark, int inten, int timestamp);
//-------- hdcache -----

// ------ limit request   ------
void lreq_status(ngx_http_request_t *r);
void lreq_uri_queue(ngx_http_request_t *r);
void lreq_queue_show(ngx_http_request_t *r);
/* void lreq_ctrl_uri(ngx_http_request_t *r, ngx_flag_t guess); */
/* int lreq_search_uri(ngx_http_request_t *r); */
int lreq_operate_uri(ngx_http_request_t *r);
// ------ limit request   ------

/**
 * util
 */
uint32_t to_hash(const char *key, size_t length);
int timeIndex();
Ngx_etomc2_shm_tree_data *tree_create(ngx_slab_pool_t *shpool);
size_t tree_insert(ngx_http_request_t *r, Ngx_etomc2_shm_tree_data **tree,
                   uint32_t hashkey, void *data, ngx_slab_pool_t *shpool);
Ngx_etomc2_shm_tree_data *tree_search(Ngx_etomc2_shm_tree_data **tree,
                                      uint32_t hashkey);
void visit_print(ngx_http_request_t *r, Ngx_etomc2_shm_tree_data *tree);
ngx_table_elt_t *search_headers_in(ngx_http_request_t *r, u_char *name,
                                   size_t len);
#endif /* ----- #ifndef ETOMC2_INC  ----- */

