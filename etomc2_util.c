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
        temp =
            (Ngx_etomc2_shm_tree_data *)malloc(sizeof(Ngx_etomc2_shm_tree_data));
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
 * ===  FUNCTION  ======================================================================
 *         Name:  tree_search
 *  Description:  
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
}		/* -----  end of function tree_search  ----- */
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  visit_print
 *  Description:  
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

}		/* -----  end of function visit_print  ----- */
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  search_headers_in
 *  Description:  
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

}		/* -----  end of function search_headers_in  ----- */
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  to_hash
 *  Description:  
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
  
}		/* -----  end of function to_hash  ----- */
