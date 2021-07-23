/*
 *  Copyright (C) 2021 - This file is part of x509-parser-verif project
 *
 *  Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *      Ryad BENADJILA <ryadbenadjila@gmail.com>
 *
 *  This software is licensed under a dual GPLv2/BSD license. See
 *  LICENSE file at the root folder of the project.
 */

#include "cert-extract.h"
#include "../../x509-parser-libecc/src/x509-parser.h" /* FIXME use -I */

int x509_cert_get_tbs_sig(unsigned char *buf, unsigned int len,
			  unsigned char **tbs_start, unsigned int *tbs_len,
			  unsigned char **sig_alg_start, unsigned int *sig_alg_len,
			  unsigned char **sig_start, unsigned int *sig_len)
{
	int ret;

	if (buf == NULL || len == 0 || len > 65535 ||
	    tbs_start == NULL || tbs_len == NULL ||
	    sig_alg_start == NULL || sig_alg_len == NULL) {
		ret = -1;
		goto err;
	}

	ret = x509_cert_extract_tbs_and_sig(buf, len, tbs_start, (u16 *)tbs_len,
					    sig_alg_start, (u16 *)sig_alg_len,
					    sig_start, (u16 *)sig_len);

err:
	return ret;
}

int x509_cert_get_SPKI(unsigned char *buf, unsigned int len,
		       unsigned char **spki_alg_oid_start, unsigned int *spki_alg_oid_len,
		       unsigned char **spki_pub_key_start, unsigned int *spki_pub_key_len)
{
	int ret;

	if (buf == NULL || len == 0 || len > 65535 ||
	    spki_alg_oid_start == NULL || spki_alg_oid_len == NULL ||
	    spki_pub_key_start == NULL || spki_pub_key_len == NULL) {
		ret = -1;
		goto err;
	}

	ret = x509_cert_extract_SPKI(buf, len,
				     spki_alg_oid_start, (u16 *)spki_alg_oid_len,
				     spki_pub_key_start, (u16 *)spki_pub_key_len);

err:
	return ret;
}

