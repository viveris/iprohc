
#include <gnutls/gnutls.h>

int generate_dh_params (gnutls_dh_params_t* dh_params) ;
int load_p12(gnutls_certificate_credentials_t xcred, char* p12_file, char* password) ;
void gnutls_transport_set_ptr_nowarn(gnutls_session_t session, int ptr) ;
