#include <gnutls/gnutls.h>

/* Structure defining global parameters for the server */
struct server_opts
{
    gnutls_certificate_credentials_t xcred;
    gnutls_priority_t priority_cache;
    
    uint32_t local_address ;

    struct tunnel_params params ;
} ;
