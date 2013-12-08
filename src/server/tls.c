/*
This file is part of iprohc.

iprohc is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
any later version.

iprohc is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with iprohc.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>


static bool tls_parse_pkcs12(gnutls_pkcs12_t *const p12,
									  const char *const password,
									  gnutls_x509_privkey_t *const key,
									  gnutls_x509_crt_t *const certs,
									  int *const certs_nr)
	__attribute__((nonnull(1, 3, 4, 5), warn_unused_result));

static int tls_get_bag_at_index(gnutls_pkcs12_t *const p12,
										  const int bag_index,
										  const char *const password,
										  gnutls_x509_privkey_t *const key,
										  gnutls_x509_crt_t *const certs,
										  int *const certs_nr)
	__attribute__((nonnull(1, 4, 5, 6), warn_unused_result));

static bool tls_get_item_from_bag_at(gnutls_pkcs12_bag_t *const bag,
												 const int index,
												 const char *const password,
												 gnutls_x509_privkey_t *const key,
												 gnutls_x509_crt_t *const cert)
	__attribute__((nonnull(1, 4, 5), warn_unused_result));


bool generate_dh_params(gnutls_dh_params_t *const dh_params)
{
	/* int bits = gnutls_sec_param_to_pk_bits (GNUTLS_PK_DH, GNUTLS_SEC_PARAM_LOW); */
	int bits = 1248; /* Equivalent, gnutls_sec_param_to_pk_bits is available since 2.12 */
	int ret;

	assert(dh_params != NULL);

	/* Generate Diffie-Hellman parameters - for use with DHE
	 * kx algorithms. When short bit length is used, it might
	 * be wise to regenerate parameters often. */
	ret = gnutls_dh_params_init(dh_params);
	if(ret != GNUTLS_E_SUCCESS)
	{
		trace(LOG_ERR, "failed to initialize Diffie-Hellman parameters");
		goto error;
	}
	ret = gnutls_dh_params_generate2(*dh_params, bits);
	if(ret != GNUTLS_E_SUCCESS)
	{
		trace(LOG_ERR, "failed to generate Diffie-Hellman parameters");
		goto free_dh;
	}

	return true;

free_dh:
	gnutls_dh_params_deinit(*dh_params);
error:
	return false;
}


#define MAX_CERTS 10

bool load_p12(gnutls_certificate_credentials_t xcred,
				  const char *const p12_file,
				  const char *const password)
{
	FILE*p12file;
	gnutls_datum_t p12blob;
	gnutls_pkcs12_t p12 = NULL;

	gnutls_x509_privkey_t key = NULL;
	gnutls_x509_crt_t certs[MAX_CERTS];
	int certs_nr;
	int id_cert;

	uint8_t key_id[20];
	size_t key_id_size;

	bool is_success = false;
	int ret;
	int i;

	assert(p12_file != NULL);

	/* Read file */
	p12file = fopen(p12_file, "rb");
	if(p12file == NULL)
	{
		trace(LOG_ERR, "failed to open PKCS#12 file '%s': %s (%d)", p12_file,
				strerror(errno), errno);
		ret = GNUTLS_E_FILE_ERROR;
		goto error;
	}
	p12blob.data = malloc(32768 * sizeof(char));
	p12blob.size = fread((void*) p12blob.data, sizeof(char), 32768, p12file);
	fclose(p12file);

	/* Init structure and import P12 */
	ret = gnutls_pkcs12_init(&p12);
	if(ret < 0)
	{
		trace(LOG_ERR, "failed to init PKCS#12 object (%d)", ret);
		goto free_blob;
	}

	ret = gnutls_pkcs12_import(p12, &p12blob, GNUTLS_X509_FMT_DER, 0);
	if(ret < 0)
	{
		trace(LOG_ERR, "failed to import PKCS#12 data (%d)", ret);
		goto deinit_pkcs12;
	}

	if(password)
	{
		ret = gnutls_pkcs12_verify_mac(p12, password);
		if(ret < 0)
		{
			trace(LOG_ERR, "failed to verify PKCS#12 MAC (%d)", ret);
			goto deinit_pkcs12;
		}
	}

	/* extract the private key and the certificates from PKCS#12 */
	if(!tls_parse_pkcs12(&p12, password, &key, certs, &certs_nr))
	{
		trace(LOG_ERR, "failed to parse PKCS#12 file '%s'", p12_file);
		goto deinit_pkcs12;
	}
	if(certs_nr < 2)
	{
		trace(LOG_ERR, "too few certificates in PKCS#12 file '%s'", p12_file);
		goto free_certs_key;
	}
	
	/* get the ID of private key */
	key_id_size = sizeof(key_id);
	ret = gnutls_x509_privkey_get_key_id(key, 0, key_id, &key_id_size);
	if(ret < 0)
	{
		trace(LOG_ERR, "failed to get key ID");
		goto free_certs_key;
	}

	id_cert = -1;
	for(i = 0; i < certs_nr; i++)
	{
		uint8_t cert_id[20];
		size_t cert_id_size;

		cert_id_size = sizeof(cert_id);
		ret = gnutls_x509_crt_get_key_id(certs[i], 0, cert_id, &cert_id_size);
		if(ret < 0)
		{
			trace(LOG_ERR, "failed to get key ID for certificate #%d (%d)", i, ret);
			goto free_certs_key;
		}

		if(key_id_size == cert_id_size &&
			memcmp(cert_id, key_id, cert_id_size) == 0)
		{
			/* it's the key certificate ! */
			if(id_cert != -1)
			{
				ret = GNUTLS_E_INTERRUPTED;
				trace(LOG_ERR, "Duplicate key certificate !\n");
				goto free_certs_key;
			}
			id_cert = i;
		}
	}

	if(id_cert == -1)
	{
		ret = GNUTLS_E_INTERRUPTED;
		trace(LOG_ERR, "Unable to find key certificate !\n");
		goto free_certs_key;
	}

	/* Now have fun with the key and certs ! */
	ret = gnutls_certificate_set_x509_key(xcred, &certs[id_cert], 1, key);
	if(ret < 0)
	{
		trace(LOG_ERR, "failed to set key for main certificate");
		goto free_certs_key;
	}

	for(i = 0; i < certs_nr; i++)
	{
		if(i != id_cert)
		{
			ret = gnutls_certificate_set_x509_trust(xcred, &certs[i], 1);
			if(ret < 0)
			{
				trace(LOG_ERR, "failed to trust certificate #%d", i + 1);
				goto free_certs_key;
			}
		}
	}

	is_success = true;

free_certs_key:
	gnutls_x509_privkey_deinit(key);
	for(i = 0; i < certs_nr; i++)
	{
		gnutls_x509_crt_deinit(certs[i]);
	}
deinit_pkcs12:
	gnutls_pkcs12_deinit(p12);
free_blob:
	free(p12blob.data);
error:
	return is_success;
}


static bool tls_parse_pkcs12(gnutls_pkcs12_t *const p12,
									  const char *const password,
									  gnutls_x509_privkey_t *const key,
									  gnutls_x509_crt_t *const certs,
									  int *const certs_nr)
{
	int bag_index;
	int ret;
	int i;

	assert(p12 != NULL);
	assert(key != NULL);
	assert(certs != NULL);
	assert(certs_nr != NULL);

	/* no key or certificate at the moment **/
	*key = NULL;
	for(i = 0; i < MAX_CERTS; i++)
	{
		certs[i] = NULL;
	}
	*certs_nr = 0;

	bag_index = 0;
	for(;;)
	{
		ret = tls_get_bag_at_index(p12, bag_index, password, key, certs, certs_nr);
		if(ret == 2)
		{
			break;
		}
		else if(ret != 1)
		{
			trace(LOG_ERR, "failed to get bag #%d", bag_index + 1);
			goto free_certs_key;
		}
		bag_index++;
	}

	if(!key)
	{
		trace(LOG_ERR, "Unable to find the private key\n");
		goto free_certs_key;
	}

	if((*certs_nr) >= MAX_CERTS)
	{
		trace(LOG_ERR, "Unable to find all certificates\n");
		goto free_certs_key;
	}

	if((*certs_nr) == 0)
	{
		trace(LOG_ERR, "no certificate found\n");
		goto free_certs_key;
	}

	return true;

free_certs_key:
	if(key)
	{
		gnutls_x509_privkey_deinit(*key);
	}
	for(i = 0; i < (*certs_nr); i++)
	{
		gnutls_x509_crt_deinit(certs[i]);
	}
	return false;
}


static int tls_get_bag_at_index(gnutls_pkcs12_t *const p12,
										  const int bag_index,
										  const char *const password,
										  gnutls_x509_privkey_t *const key,
										  gnutls_x509_crt_t *const certs,
										  int *const certs_nr)
{
	gnutls_pkcs12_bag_t bag = NULL;
	int bag_count;
	int status = 0;
	int ret;
	int i;

	assert(p12 != NULL);
	assert(key != NULL);
	assert(certs != NULL);
	assert(certs_nr != NULL);
	assert((*certs_nr) >= 0);
	assert((*certs_nr) <= MAX_CERTS);

	ret = gnutls_pkcs12_bag_init(&bag);
	if(ret < 0)
	{
		trace(LOG_ERR, "failed to init bag #%d", bag_index + 1);
		goto error;
	}

	ret = gnutls_pkcs12_get_bag(*p12, bag_index, bag);
	if(ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
	{
		/* ignore */
		status = 2;
		goto free_bag;
	}
	if(ret < 0)
	{
		trace(LOG_ERR, "failed to retrieve bag #%d", bag_index + 1);
		goto free_bag;
	}

	ret = gnutls_pkcs12_bag_get_type(bag, 0);
	if(ret == GNUTLS_BAG_ENCRYPTED)
	{
		ret = gnutls_pkcs12_bag_decrypt(bag, password);
		if(ret < 0)
		{
			trace(LOG_ERR, "failed to decrypt bag #%d", bag_index + 1);
			goto free_bag;
		}
	}

	bag_count = gnutls_pkcs12_bag_get_count(bag);
	trace(LOG_DEBUG, "bag count = %d\n", bag_count);

	/* first, find the key */
	for(i = 0; i < bag_count; i++)
	{
		gnutls_x509_privkey_t new_key;
		gnutls_x509_crt_t new_cert;

		if(!tls_get_item_from_bag_at(&bag, i, password, &new_key, &new_cert))
		{
			trace(LOG_ERR, "failed to load item #%d of bag #%d",
					i + 1, bag_index + 1);
			goto free_bag;
		}

		/* if we found a new key, store it */
		if(new_key != NULL)
		{
			if((*key) != NULL)
			{
				trace(LOG_ERR, "more than one key found in PKCS#12");
				goto free_bag;
			}
			*key = new_key;
		}

		/* if we found a new certificate, store it in the array */
		if(new_cert != NULL)
		{
			if((*certs_nr) >= MAX_CERTS)
			{
				trace(LOG_ERR, "too many certificates, abort");
				gnutls_x509_crt_deinit(new_cert);
				goto free_bag;
			}

			certs[*certs_nr] = new_cert;
			(*certs_nr)++;
		}
	}

	status = 1;

free_bag:
	gnutls_pkcs12_bag_deinit(bag);
error:
	return status;
}


static bool tls_get_item_from_bag_at(gnutls_pkcs12_bag_t *const bag,
												 const int index,
												 const char *const password,
												 gnutls_x509_privkey_t *const key,
												 gnutls_x509_crt_t *const cert)
{
	gnutls_pkcs12_bag_type_t type;
	gnutls_datum_t data;
	int ret;

	assert(bag != NULL);
	assert(index >= 0);
	assert(key != NULL);
	assert(cert != NULL);

	*key = NULL;
	*cert = NULL;

	type = gnutls_pkcs12_bag_get_type(*bag, index);
	ret = gnutls_pkcs12_bag_get_data(*bag, index, &data);
	if(ret < 0)
	{
		goto error;
	}

	switch(type)
	{
		case GNUTLS_BAG_PKCS8_KEY:
		case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:
		{
			unsigned int flags = (type == GNUTLS_BAG_PKCS8_KEY ? GNUTLS_PKCS_PLAIN : 0);

			trace(LOG_DEBUG, "key found!");

			ret = gnutls_pkcs12_bag_get_data(*bag, index, &data);
			if(ret < 0)
			{
				goto error;
			}

			ret = gnutls_x509_privkey_init(key); // TODO gnutls_x509_privkey_deinit 
			if(ret < 0)
			{
				goto error;
			}

			ret = gnutls_x509_privkey_import_pkcs8(*key, &data,
																GNUTLS_X509_FMT_DER,
																password, flags);
			if(ret < 0)
			{
				gnutls_x509_privkey_deinit(*key);
				goto error;
			}

			break;
		}

		case GNUTLS_BAG_CERTIFICATE:
		{
			trace(LOG_DEBUG, "certificate found!");

			gnutls_x509_crt_init(cert);
			if(ret < 0)
			{
				goto error;
			}

			ret = gnutls_x509_crt_import(*cert, &data, GNUTLS_X509_FMT_DER);
			if(ret < 0)
			{
				gnutls_x509_crt_deinit(*cert);
				goto error;
			}

			break;
		}

		default:
		{
			ret = GNUTLS_E_UNKNOWN_PKCS_CONTENT_TYPE;
			trace(LOG_ERR, "unknown element %d\n", type);
			goto error;
		}
	}

	return true;

error:
	return false;
}


#if defined __GNUC__
#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
#endif
void gnutls_transport_set_ptr_nowarn(gnutls_session_t session, int ptr)
{
	return gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) ptr);
}


#if defined __GNUC__
#pragma GCC diagnostic error "-Wint-to-pointer-cast"
#endif


