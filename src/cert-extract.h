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

#ifndef __X509_CERT_EXTRACT_H__
#define __X509_CERT_EXTRACT_H__

int x509_cert_get_tbs_sig(unsigned char *buf, unsigned int len,
			  unsigned char **tbs_start, unsigned int *tbs_len,
			  unsigned char **sig_alg_start, unsigned int *sig_alg_len,
			  unsigned char **sig_start, unsigned int *sig_len);

int x509_cert_get_SPKI(unsigned char *buf, unsigned int len,
		       unsigned char **spki_alg_oid_start, unsigned int *spki_alg_oid_len,
		       unsigned char **spki_pub_key_start, unsigned int *spki_pub_key_len);

#endif /* __X509_CERT_EXTRACT_H__ */
