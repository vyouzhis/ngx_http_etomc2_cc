/*
 * =====================================================================================
 *
 *       Filename:  etomc2_pem.c
 *
 *    Description:  etomc2, a web application firewall for NGINX
 *
 *        Version:  1.0
 *        Created:  2020年04月14日 09时40分48秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  etomc2@etomc2.com (), etomc2@etomc2.com
 *   Organization:  etomc2.com
 *
 * =====================================================================================
 */

#include "etomc2.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  rsa_encrypt
 *  Description:
 * =====================================================================================
 */
void rsa_encrypt(ngx_http_request_t *r, const ngx_str_t from) {
    /** ngx_file_t rsa_pem_pk_file; */
    FILE *file;
    ngx_http_dummy_loc_conf_t *cf;
    RSA *rsa = NULL;
    char *en = NULL;
    /** int len = 0; */
    int rsa_len = 0;
    cf = ngx_http_get_module_loc_conf(r, ngx_http_etomc2_cc_module);
    if (!cf) return;

    /** rsa_pem_pk_file.fd
     * =ngx_open_file(cf->rsa_pem_pk.data,NGX_FILE_RDONLY |
     * NGX_FILE_NONBLOCK, NGX_FILE_OPEN, 0); */
    if ((file = fopen((char *)cf->rsa_pem_pk.data, "r")) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "rsa_pem_pk :%s error", cf->rsa_pem_pk.data);
        return;
    }

    if ((rsa = PEM_read_RSAPublicKey(file, NULL, NULL, NULL)) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "rsa  error");

        return;
    }

    /** len = from.len; */
    rsa_len = RSA_size(rsa);

    en = (char *)malloc(rsa_len + 1);
    memset(en, 0, rsa_len + 1);

    if (RSA_public_encrypt(rsa_len, (unsigned char *)from.data,
                (unsigned char *)en, rsa, RSA_NO_PADDING) < 0) {
        return;
    }
    ngx_str_t dest, src;

    src.len = rsa_len + 1;
    src.data = ngx_pcalloc(r->pool, src.len);
    if (!src.data) {
        return;
    }
    snprintf((char *)src.data, src.len, "%s", en);
    dest.len = ngx_base64_encoded_length(src.len);
    dest.data = ngx_pcalloc(r->pool, dest.len);
    if (!dest.data) return;
    ngx_encode_base64(&dest, &src);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[en :%d,dcode:%s]",
            dest.len, dest.data);
    /**  en); */
    free(en);
    RSA_free(rsa);
    fclose(file);
    /** ngx_close_file(rsa_pem_pk_file.fd); */

    return;
} /* -----  end of function rsa_encrypt  ----- */

/*
 * ===  FUNCTION
 * ======================================================================
 *         Name:  rsa_decrypt
 *  Description:
 * =====================================================================================
 */
int rsa_decrypt(ngx_http_request_t *r, const ngx_str_t base64, const ngx_str_t  pem, char **decrypt) {

    RSA *rsa = NULL;
    BIO *bio;

    char *decrypt_msg = NULL;
    int rsa_len = 0;
    ngx_str_t dest, vary;
    int exist = -1, b64_part;

    const char *fmt = "=";

    vary.len = base64.len;
    vary.data = ngx_pcalloc(r->pool, vary.len);
    if (!vary.data) {
        return -1;
    }

    exist = findstring((char *)base64.data, fmt);
    if (exist == -1) {
        b64_part = abs(base64.len / 2);
        ngx_memcpy(vary.data, base64.data + b64_part, base64.len - b64_part);
        ngx_memcpy(vary.data + b64_part, base64.data, b64_part);

    } else {
        b64_part = abs(exist / 2);

        ngx_memcpy(vary.data, base64.data + b64_part, exist - b64_part);
        ngx_memcpy(vary.data + (exist-b64_part), base64.data, b64_part);
        ngx_memcpy(vary.data + exist, base64.data + exist, base64.len - exist);
    }

    dest.len = ngx_base64_decoded_length(base64.len);

    dest.data = ngx_pcalloc(r->pool, dest.len);
    if (!dest.data) {
        ngx_pfree(r->pool, vary.data);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_base64_decoded_length  error, base64:%s",base64.data);
        return -1;
    }
    ngx_decode_base64(&dest, &vary);

    bio = BIO_new_mem_buf((void*)pem.data,pem.len);
    /** bio = BIO_new_mem_buf((void*)cf->rsa_pem.data,cf->rsa_pem.len); */
    if(bio==NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "bio error");

        return -1;
    }
    rsa = PEM_read_bio_RSAPrivateKey(bio,NULL,NULL,NULL);
    if(rsa == NULL){
        BIO_free(bio);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "rsa error");

        return -1;
    }
    rsa_len = RSA_size(rsa);
    decrypt_msg = (char *)malloc(rsa_len + 1);
    if(decrypt_msg == NULL)return -1;

    memset(decrypt_msg, 0, rsa_len + 1);

    if (RSA_private_decrypt(rsa_len, (unsigned char *)dest.data,
                (unsigned char *)decrypt_msg, rsa,
                RSA_PKCS1_PADDING) < 0) {

        ngx_pfree(r->pool, vary.data);
        ngx_pfree(r->pool, dest.data);
        free(decrypt_msg);
        RSA_free(rsa);
        BIO_free(bio);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "decrypt error");
        return -1;
    }
    (*decrypt) = decrypt_msg;


    /** decrypt_msg timestamp  or  uuid */


    ngx_pfree(r->pool, vary.data);
    ngx_pfree(r->pool, dest.data);
    /** free(decrypt_msg); */
    RSA_free(rsa);
    BIO_free(bio);
    return 0;
} /* -----  end of function rsa_decrypt  ----- */
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  rsa_auth
 *  Description:  
 * =====================================================================================
 */
int  rsa_auth ( ngx_http_request_t *r,const ngx_str_t base64 ){
    /** const char *pub_buf="-----BEGIN RSA PUBLIC KEY-----\n\ */
    /** MIIBCgKCAQEAwFNRei15X1237scPwivmWKI5cRhQGb6FH6Gje2JJWk25u4p9qXQm\n\ */
    /** 0GirQswE/ofJpgPlbHwElJVfSKAhYQ5iZXtaRQvJ+vF5KA8swRFDfV9+lEvkjSeK\n\ */
    /** VwN/v0bHrFqKnYV+yG2Lb7U/S6PZWuoFwGRMzpwz48gfI9UY4VChxvFtPP+Hyin7\n\ */
    /** IyJa/bHaWgHEAeyWqu+2gH0SPv3lmkuSHLjQFH0DjJnEQxkGoQ1p8M+0ddQbRvFY\n\ */
    /** z4Q4U65fWyCzPkiRsuwYdggd1vAGtIpGpLtu0/H+YCxBckuQaYSFYdCKRnINfjx7\n\ */
    /** qJLAnmY+bkHkPSWfPceyfPcnGk+PatrmkQIDAQAB\n\ */
    /** -----END RSA PUBLIC KEY-----"; */
    const char *pub_buf="-----BEGIN RSA PRIVATE KEY-----\n\
MIIEowIBAAKCAQEAwFNRei15X1237scPwivmWKI5cRhQGb6FH6Gje2JJWk25u4p9\n\
qXQm0GirQswE/ofJpgPlbHwElJVfSKAhYQ5iZXtaRQvJ+vF5KA8swRFDfV9+lEvk\n\
jSeKVwN/v0bHrFqKnYV+yG2Lb7U/S6PZWuoFwGRMzpwz48gfI9UY4VChxvFtPP+H\n\
yin7IyJa/bHaWgHEAeyWqu+2gH0SPv3lmkuSHLjQFH0DjJnEQxkGoQ1p8M+0ddQb\n\
RvFYz4Q4U65fWyCzPkiRsuwYdggd1vAGtIpGpLtu0/H+YCxBckuQaYSFYdCKRnIN\n\
fjx7qJLAnmY+bkHkPSWfPceyfPcnGk+PatrmkQIDAQABAoIBAQCsISXYAqERYFCB\n\
jXmmICI+C5r7hHYURHbi84jcof/iqZPkrLOBGOqwNi2pT+3cXG12fyAzst9qmDG6\n\
T07wja41A2ysRTvVs47q8oHsneXYbMJeOXppdw0SiZgo+lE1CafsCZGKErjsFrx6\n\
lz+uZasWIO65MAYlBHQSXuOwrLjN0rAUjPS0CZUdRPaZ9EqGXmN0JjL52/jHW03s\n\
XReNVaeJk++q+VuJxt9aGkudooh/zhxSeqx4twaiqi+xPmwq6clmLMej8EbnOGQO\n\
+5Ey5EFz0jYFgRArqF9lEj2AdwxexSS7Wa7I8bTO6t5y2k5L42W9CiN0VU9yg2OG\n\
R46jmJ1dAoGBAPouoOnBpmlIGwCvRLP6mTGMWZUbVKHBn6FXqUDutzCD70KqSQV9\n\
4OELKlM+NhWIP1A0KlcbUclT48PfqSyNgXbMcGPv2NW5zWsk0zQKgh4trw2bbIjQ\n\
y8szci4J71ADDkhYPuhXN8PsJq1Mc3Y4a+J8pr+Pp99aghdLXsqkpU/PAoGBAMTM\n\
QqKnwYlMJKtxXnqMSf/hIVc8ZZCoImGrKVkEtwk0s+qehlA+se8x3geQiW50T4Rf\n\
T63EBVfzR8r0r3XYSx4ey76+S+UqtyaRPaOJ48GweT6JjWZQ6fy5ASawp81O3Yvt\n\
sRLWEnrmnYB7YJekKKwURLgMZO7qWi9aIgbcZJufAoGAOV86DYEYHWqorpaC5dch\n\
DGjIHlZ/KP0TE1fb+4UCw4Bt/Na6GiVMza7WzPImSvfMtSLRVtpv/gBb6g4/aHUm\n\
7ExjtbdJ/XE3d0uhl3yVbEBDtZYf5JwlL/sjQwWKOMoKm3KJMpTVt/tOv00Z6VF1\n\
BCJbxvA1qhXCYX8qRMRPGKcCgYAE4rlIxndkjDJg2zioPDFeG92zB7nRxIrN9+zX\n\
2+kbXmaVDYhyF4xdTtSfRXRT/Kk4tREKVFJ5o32FyVtNxqfewI74VksWDmBrobFx\n\
DOxNk67+4XVUM/ALKSChMEOKMkoHvkfmGtBsoqsIVIfKW/Xyh7JJC226DLFeeZNc\n\
rj4FKwKBgD3e2ZvtvNmjXgTiJXwDCTDn7pdnc2NaGOCOtjAu2LW4oPmcQw5P0nXs\n\
4hlhmK1GKXqjAWh9atHSdTjguh0GvTj1g1ytv0TXlp4x5VW1kBerB+qRW2YEmZ2Y\n\
O4YDHEUDZFj2n8uSoqIbJUT5AHnMVrei0rMDo0weZs6sHayKH8Ku\n\
-----END RSA PRIVATE KEY-----";
    ngx_str_t  pem;
    pem.len = strlen(pub_buf);
    pem.len +=1;
    pem.data = ngx_pcalloc(r->pool,pem.len);
    snprintf((char*)pem.data,pem.len,"%s",pub_buf);
    char *decrypt;
    uint32_t  month = 60*60*24*30;
    uint32_t  tip = 60*60*24*27;
    uint32_t  pem_time;
    time_t now =ngx_time();
    uint32_t expire;
    
    if(base64.len==0){
        return -1;
    }

    if(rsa_decrypt(r,base64, pem,&decrypt) == -1){
        return -1;
    }

/**     month = 1500; */
    /** tip =  1200; */
    pem_time = atoi(decrypt);
    expire = (uint32_t)now-pem_time;
    if(expire > month){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[etomc2 cc expire: time out]");
        return -1;
    }
    else if(expire>tip){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[etomc2 cc become expire]");
        return 0;
    }
/**     else{ */
        /** ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[decrypt str :%s, time:%d, expire:%d]", */
        /**         decrypt,pem_time,(expire )); */
    /** } */
    return 0;
}		/* -----  end of function rsa_auth  ----- */
