#include <gnutls/gnutls.h>

int
generate_dh_params (gnutls_dh_params_t* dh_params)
{
  int bits = gnutls_sec_param_to_pk_bits (GNUTLS_PK_DH, GNUTLS_SEC_PARAM_LOW);

  /* Generate Diffie-Hellman parameters - for use with DHE
   * kx algorithms. When short bit length is used, it might
   * be wise to regenerate parameters often.
   */
  gnutls_dh_params_init(dh_params);
  gnutls_dh_params_generate2(*dh_params, bits);

  return 0;
}
