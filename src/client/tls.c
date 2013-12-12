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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>
#include <string.h>

#include "log.h"

int generate_dh_params (gnutls_dh_params_t*dh_params)
{
	/* int bits = gnutls_sec_param_to_pk_bits (GNUTLS_PK_DH, GNUTLS_SEC_PARAM_LOW); */
	int bits = 1248; /* Equivalent, gnutls_sec_param_to_pk_bits is available since 2.12 */
	/* Generate Diffie-Hellman parameters - for use with DHE
	 * kx algorithms. When short bit length is used, it might
	 * be wise to regenerate parameters often.
	 */
	gnutls_dh_params_init(dh_params);
	gnutls_dh_params_generate2(*dh_params, bits);

	return 0;
}


#define MAX_CERTS 2

int load_p12(gnutls_certificate_credentials_t xcred, char*p12_file, char*password)
{
	int ret;
	int i;
	int bag_idx;
	int cert_idx;

	FILE*p12file;
	gnutls_datum_t p12blob;

	gnutls_pkcs12_t p12 = NULL;
	gnutls_pkcs12_bag_t bag = NULL;
	int bag_count;

	gnutls_x509_privkey_t key = NULL;
	gnutls_x509_crt_t certs[MAX_CERTS];
	for(i = 0; i < MAX_CERTS; i++)
	{
		certs[i] = NULL;
	}
	int id_cert = -1;

	gnutls_datum_t data;
	int type;
	uint8_t key_id[20];
	size_t key_id_size = sizeof(key_id);
	uint8_t cert_id[20];
	size_t cert_id_size = sizeof(cert_id);


	/* Read file */
	p12file = fopen(p12_file, "rb");
	if(p12file == NULL)
	{
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
		goto error;
	}

	ret = gnutls_pkcs12_import(p12, &p12blob, GNUTLS_X509_FMT_DER, 0);
	if(ret < 0)
	{
		free(p12blob.data);
		goto error;
	}
	free(p12blob.data);

	if(password)
	{
		ret = gnutls_pkcs12_verify_mac (p12, password);
		if(ret < 0)
		{
			goto error;
		}
	}

	/* P12 parsing */
	bag_idx = 0;
	cert_idx = 0;
	for(;; )
	{
		ret = gnutls_pkcs12_bag_init (&bag);
		if(ret < 0)
		{
			goto error;
		}

		ret = gnutls_pkcs12_get_bag (p12, bag_idx, bag);
		if(ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
		{
			break;
		}
		if(ret < 0)
		{
			goto error;
		}

		ret = gnutls_pkcs12_bag_get_type(bag, 0);
		if(ret == GNUTLS_BAG_ENCRYPTED)
		{
			ret = gnutls_pkcs12_bag_decrypt (bag, password);
			if(ret < 0)
			{
				goto error;
			}
		}

		bag_count = gnutls_pkcs12_bag_get_count(bag);
		trace(LOG_DEBUG, "Bag count : %d\n", bag_count);
		/* First find the key */
		for(i = 0; i < bag_count; i++)
		{
			type = gnutls_pkcs12_bag_get_type(bag, i);
			ret = gnutls_pkcs12_bag_get_data(bag, i, &data);
			if(ret < 0)
			{
				goto error;
			}
			switch(type)
			{
				case GNUTLS_BAG_PKCS8_KEY:
				case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:
					trace(LOG_DEBUG, "Key found !\n");
					ret = gnutls_pkcs12_bag_get_data(bag, i, &data);
					if(ret < 0)
					{
						goto error;
					}

					ret = gnutls_x509_privkey_init(&key);
					if(ret < 0)
					{
						goto error;
					}

					ret = gnutls_x509_privkey_import_pkcs8(
					   key, &data, GNUTLS_X509_FMT_DER,
					   password, type ==
					   GNUTLS_BAG_PKCS8_KEY ? GNUTLS_PKCS_PLAIN : 0);
					if(ret < 0)
					{
						goto error;
					}

					ret = gnutls_x509_privkey_get_key_id(key, 0, key_id, &key_id_size);
					if(ret < 0)
					{
						goto error;
					}

					break;
				case GNUTLS_BAG_CERTIFICATE:
					trace(LOG_DEBUG,"Cert found !\n");
					if(cert_idx >= MAX_CERTS)
					{
						ret = GNUTLS_E_INTERRUPTED;
						trace(LOG_ERR, "Too much certificate, abort\n");
						goto error;
					}

					gnutls_x509_crt_init(&certs[cert_idx]);
					if(ret < 0)
					{
						goto error;
					}

					ret = gnutls_x509_crt_import(certs[cert_idx], &data, GNUTLS_X509_FMT_DER);
					if(ret < 0)
					{
						goto error;
					}

					cert_idx++;

					break;
				default:
					ret = GNUTLS_E_UNKNOWN_PKCS_CONTENT_TYPE;
					trace(LOG_ERR, "Unknown element : %d\n", type);
					goto error;
			}
		}
		bag_idx++;

		gnutls_pkcs12_bag_deinit(bag);
		bag = NULL;
	}

	if(!key)
	{
		ret = GNUTLS_E_INTERRUPTED;
		trace(LOG_ERR, "Unable to find the private key\n");
		goto error;
	}

	if(cert_idx != MAX_CERTS)
	{
		ret = GNUTLS_E_INTERRUPTED;
		trace(LOG_ERR, "Unable to find all certificates\n");
		goto error;
	}

	for(i = 0; i < MAX_CERTS; i++)
	{
		ret = gnutls_x509_crt_get_key_id(certs[i], 0, cert_id, &cert_id_size);
		if(ret < 0)
		{
			goto error;
		}

		if(memcmp(cert_id, key_id, cert_id_size) == 0)
		{
			/* it's the key certificate ! */
			if(id_cert != -1)
			{
				ret = GNUTLS_E_INTERRUPTED;
				trace(LOG_ERR, "Duplicate key certificate !\n");
				goto error;
			}
			id_cert = i;
		}
	}

	if(id_cert == -1)
	{
		ret = GNUTLS_E_INTERRUPTED;
		trace(LOG_ERR, "Unable to find key certificate !\n");
		goto error;
	}

	/* Now have fun with the key and certs ! */
	ret = gnutls_certificate_set_x509_key(xcred, &certs[id_cert], 1, key);
	if(ret < 0)
	{
		goto error;
	}

	for(i = 0; i < MAX_CERTS; i++)
	{
		if(i != id_cert)
		{
			ret = gnutls_certificate_set_x509_trust(xcred, &certs[i], 1);
		}
	}
	if(ret < 0)
	{
		goto error;
	}


	ret = 0;

error:
	if(key)
	{
		gnutls_x509_privkey_deinit(key);
	}
	for(i = 0; i < MAX_CERTS; i++)
	{
		if(certs[i])
		{
			gnutls_x509_crt_deinit(certs[i]);
		}
	}
	if(bag)
	{
		gnutls_pkcs12_bag_deinit(bag);
	}
	if(p12)
	{
		gnutls_pkcs12_deinit(p12);
	}
	return ret;
}

