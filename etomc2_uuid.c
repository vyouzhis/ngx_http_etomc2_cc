/*
 * =====================================================================================
 *
 *       Filename:  etomc2_uuid.c
 *
 *    Description:  uuid
 *
 *        Version:  1.0
 *        Created:  2020年04月19日 09时35分30秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  etomc2@etomc2.com (), etomc2@etomc2.com
 *   Organization:  etomc2.com
 *
 * =====================================================================================
 */
#include "etomc2.h"

#include "ext/mt19937/mt64.h"

static int mt_initialized = 0;

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  initialize_mt
 *  Description:
 * =====================================================================================
 */
ngx_int_t initialize_mt() {

    static const size_t SEED_LENGTH = 312;
    unsigned long long seed[SEED_LENGTH];
    size_t n;
    FILE *f;

    f = fopen("/dev/urandom", "r");
    if (f == NULL) {

        return -1;
    }
    n = fread(seed, sizeof(unsigned long long), SEED_LENGTH, f);
    if (n < SEED_LENGTH) {

        fclose(f);
        return -2;
    }
    fclose(f);
    init_by_array64(seed, SEED_LENGTH);

    return 0;
} /* -----  end of function initialize_mt  ----- */
  /*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  initialize_uuid
 *  Description:
 * =====================================================================================
 */
void initialize_uuid() {
    if (!mt_initialized) {
        if (initialize_mt() != 0) return;
        mt_initialized = 1;
    }

} /* -----  end of function initialize_uuid  ----- */
  /*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  uuid4_variable
 *  Description:
 * =====================================================================================
 */
int uuid4_data(ngx_http_request_t *r) {
    static const size_t UUID_STR_LENGTH = 36;
    ngx_str_t v, cookie;
    const char *fmt = "%s=%.*s; path=/";

    ngx_table_elt_t **cookies;
    int exist = -1;
    ngx_uint_t nelts;

    cookies = r->headers_in.cookies.elts;
    nelts = r->headers_in.cookies.nelts;

    if (nelts != 0) {

        /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[uuid: nelts
         * 0]"); */
        exist = findstring((char *)cookies[0]->value.data, COOKIE_UUID_NAME);

        if (exist != -1) {
            /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[uuid:
             * exist]"); */
            return exist;
        }
    }

    uint64_t upper = (uint64_t)genrand64_int64();
    uint64_t lower = (uint64_t)genrand64_int64();
    upper &= ~((1ULL << 12) | (1ULL << 13) | (1ULL << 15));
    upper |= (1ULL << 14);
    lower &= ~(1ULL << 62);
    lower |= (1ULL << 63);

    v.len = UUID_STR_LENGTH;
    v.data = ngx_pcalloc(r->pool, v.len);
    if (!v.data) {
        v.len = 0;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[uuid: v error]");

        return exist;
    }

    ngx_snprintf(v.data, v.len, "%08uxL-%04uxL-%04uxL-%04uxL-%012uxL",
                 upper >> 32, (upper >> 16) & 0xFFFFULL, upper & 0xFFFFULL,
                 lower >> 48, lower & 0xFFFFFFFFFFFFULL);

    cookie.len = snprintf(NULL, 0, fmt, COOKIE_UUID_NAME, v.len, v.data);
    cookie.len += 1;
    cookie.data = ngx_pcalloc(r->pool, cookie.len);
    if (cookie.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "[uuid: cookie data error]");

        return exist;
    }
    snprintf((char *)cookie.data, cookie.len, fmt, COOKIE_UUID_NAME, v.len,
             v.data);
    ngx_pfree(r->pool, v.data);

    /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[uuid:%s]",
     * cookie.data); */

    setcookie(r, cookie);

    return exist;
} /* -----  end of function uuid4_variable  ----- */

