#include <gnutls/gnutls.h>
#include <stdint.h>

#include "tlv.h"

/* Structure defining global parameters for the server */
struct server_opts
{
    gnutls_certificate_credentials_t xcred;
    gnutls_priority_t priority_cache;
    
    int port ;
    char pkcs12_f[1024] ;
    char pidfile_path[1024] ;
    
    uint32_t local_address ;

    struct tunnel_params params ;
} ;
