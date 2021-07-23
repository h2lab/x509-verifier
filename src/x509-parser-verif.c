/*
 *  Copyright (C) 2021 - This file is part of x509-parser project
 *
 *  Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *      Ryad BENADJILA <ryadbenadjila@gmail.com>
 *
 *  This software is licensed under a dual GPLv2/BSD license. See
 *  LICENSE file at the root folder of the project.
 */

#include <stdio.h>
#include "cert-extract.h"
#include "sig-verif.h"

int x509_cert_verif(unsigned char *tbv_cert, unsigned short tbv_cert_len,
		    unsigned char *anchor_cert, unsigned short anchor_cert_len)
{
	unsigned char *tbs_start;
	unsigned int tbs_len, sig_alg_len;
	unsigned char *sig_start, *sig_alg_start;
	x509_sig_verify_ctx ctx;
	unsigned int sig_len;
	unsigned int i;
	int ret;
	unsigned char *spki_alg_oid_start;
	unsigned int spki_alg_oid_len;
	unsigned char *spki_pub_key_start;
	unsigned int spki_pub_key_len;

	ret = x509_cert_get_tbs_sig(tbv_cert, tbv_cert_len, &tbs_start, &tbs_len,
				   &sig_alg_start, &sig_alg_len,
				   &sig_start, &sig_len);
	if (ret) {
		goto err;
	}

	/* Get length of tbsCert */
	/* Get AKI */
	/* Lookup CA certificate */
	/* Get Signature Algorithm field */
	/* Get Signature field */
	/* Do signature verif */
	printf("tbsCertificate length: %d\n", tbs_len);

	printf("sig_alg: ");
	for (i = 0; i < sig_alg_len; i++) {
		printf("%02x", sig_alg_start[i]);
	}
	printf("\n");

	printf("Signature: ");
	for (i = 0; i < sig_len; i++) {
		printf("%02x", sig_start[i]);
	}
	printf("\n");


	ret = x509_cert_get_SPKI(anchor_cert, anchor_cert_len,
				 &spki_alg_oid_start, &spki_alg_oid_len,
				 &spki_pub_key_start, &spki_pub_key_len);
	if (ret) {
		printf("error %d\n", ret);
		goto err;
	}

	printf("pubkey : ");
	for (i = 0; i < spki_pub_key_len; i++) {
		printf("%02x", spki_pub_key_start[i]);
	}
	printf("\n");

	printf("pubkey alg oid : ");
	for (i = 0; i < spki_alg_oid_len; i++) {
		printf("%02x", spki_alg_oid_start[i]);
	}
	printf("\n");

	ctx.tbs = tbs_start;
	ctx.tbs_len = tbs_len;
	ctx.sig_alg_oid = sig_alg_start;
	ctx.sig_alg_oid_len = sig_alg_len;
	ctx.sig = sig_start;
	ctx.sig_len = sig_len;
	ctx.pub_key = spki_pub_key_start + 4; /* FIX shift in a better manner */
	ctx.pub_key_len = spki_pub_key_len - 4; /* FIX shift in a better manner */
	ctx.pub_key_alg_oid = spki_alg_oid_start;
	ctx.pub_key_alg_oid_len = spki_alg_oid_len;

	ret = x509_sig_verify(&ctx);

	printf("Signature verifation ");
	printf("%s\n", ret ? "FAILED" : "SUCCESS");

err:
	return ret;
}
