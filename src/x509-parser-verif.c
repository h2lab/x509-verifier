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
#include "x509_types.h"
#include <string.h>

static const unsigned char oid_ecdsa_sha256[] = {
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
};

static const unsigned char oid_ecdsa_sha384[] = {
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03
};


/*
 * From signature algorithm OID 'sig_alg_start' of length 'sig_alg_len', the
 * function returns associated signature and hash algorithm types. The
 * function returns 0 on success, -1 on error.
 */
static int sig_oid_to_sig_and_hash_types(unsigned char *sig_alg_start,
					 unsigned int sig_alg_len,
					 x509_ec_sig_alg *sig_alg_type,
					 x509_hash_alg *hash_alg_type)
{
	int ret;

	if ((sig_alg_start == NULL) || (sig_alg_len == 0) ||
	    (sig_alg_type == NULL) || (hash_alg_type == NULL)) {
		ret = -1;
		goto err;
	}

	/* XXX Make something more generic */
	if ((sig_alg_len == sizeof(oid_ecdsa_sha256)) &&
	    !memcmp(sig_alg_start, oid_ecdsa_sha256, sizeof(oid_ecdsa_sha256))) {
		*sig_alg_type = X509_ECDSA;
		*hash_alg_type = X509_SHA256;
		printf("Detected SHA256\n");
	} else if ((sig_alg_len == sizeof(oid_ecdsa_sha384)) &&
	    !memcmp(sig_alg_start, oid_ecdsa_sha384, sizeof(oid_ecdsa_sha384))) {
		*sig_alg_type = X509_ECDSA;
		*hash_alg_type = X509_SHA384;
		printf("Detected SHA384\n");
	} else {
		ret = -1;
		goto err;
	}

	ret = 0;

err:
	return ret;
}


static const unsigned char oid_ecPublicKey[] = { /* 1.2.840.10045.2.1 */
	0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01
};

static const unsigned char oid_secp384r1[] = { /* 1.3.132.0.34 */
	0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22
};

static const unsigned char oid_secp256r1[] = { /* 1.2.840.10045.3.1.7 */
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};

/*
 * From OID 'spki_alg_oid_start' of 'spki_alg_oid_len' length from subject
 * public key info, the function returns associated curve. The function
 * returns 0 on success, -1 on error.
 */
static int curve_oid_to_curve_type(unsigned char *spki_alg_oid_start,
				   unsigned int spki_alg_oid_len,
				   x509_curve *curve_type)
{
	const unsigned char *buf;
	unsigned int remain;
	int ret;

	if ((spki_alg_oid_start == NULL) || (spki_alg_oid_len == 0) ||
	    (curve_type == NULL)) {
		ret = -1;
		goto err;
	}

	/*
	 * We expect a sequence of 2 OID, e.g. 3010 06072a8648ce3d0201 06052b81040022.
	 * The first one being 06072a8648ce3d0201, i.e. ecPublicKey and the next one
	 * providing the curve OID.
	 */
	if (spki_alg_oid_len < (2 + sizeof(oid_ecPublicKey))) {
		ret = -1;
		goto err;
	}

	if (memcmp(spki_alg_oid_start + 2, oid_ecPublicKey, sizeof(oid_ecPublicKey))) {
		ret = -1;
		goto err;
	}

	buf = spki_alg_oid_start + 2 + sizeof(oid_ecPublicKey);
	remain = spki_alg_oid_len - (2 + sizeof(oid_ecPublicKey));
	if (remain == sizeof(oid_secp256r1) && !memcmp(buf, oid_secp256r1, remain)) {
		printf("X509_SECP256R1 %d\n", remain);
		*curve_type = X509_SECP256R1;
	} else if (remain == sizeof(oid_secp384r1) && !memcmp(buf, oid_secp384r1, remain)) {
		printf("X509_SECP384R1 %d\n", remain);
		*curve_type = X509_SECP384R1;
	} else {
		ret = -1;
		goto err;
	}

	ret = 0;

err:
	return ret;
}

int x509_cert_verif(unsigned char *tbv_cert, unsigned short tbv_cert_len,
		    unsigned char *anchor_cert, unsigned short anchor_cert_len)
{
	unsigned char *tbs_start;
	unsigned int tbs_len, sig_alg_len;
	unsigned char *sig_start, *sig_alg_start;
	x509_sig_verify_ctx ctx;
	unsigned int sig_len;
	unsigned int i;
	unsigned char *spki_alg_oid_start;
	unsigned int spki_alg_oid_len;
	unsigned char *spki_pub_key_start;
	unsigned int spki_pub_key_len;
	x509_ec_sig_alg sig_alg_type;
	x509_hash_alg hash_alg_type;
	x509_curve curve_type;
	int ret;

	/*
	 * First extract the three elements we need from the certificate to
	 * verify:
	 *
	 *  - tbsCertificate
	 *  - signature algorithm (alg + hash)
	 *  - signature value
	 *
	 */
	ret = x509_cert_get_tbs_sig(tbv_cert, tbv_cert_len, &tbs_start, &tbs_len,
				    &sig_alg_start, &sig_alg_len,
				    &sig_start, &sig_len);
	if (ret) {
		goto err;
	}

	/*
	 * Now, extract from anchor:
	 *
	 * - the public value
	 * - the algorithm identifier
	 *
	 * describing the curve.
	 */
	ret = x509_cert_get_SPKI(anchor_cert, anchor_cert_len,
				 &spki_alg_oid_start, &spki_alg_oid_len,
				 &spki_pub_key_start, &spki_pub_key_len);
	if (ret) {
		printf("error %d\n", ret);
		goto err;
	}

	/*
	 * We can now extract signature alg, hash alg and curve from the
	 * two OID we just extracted
	 */
	ret = sig_oid_to_sig_and_hash_types(sig_alg_start, sig_alg_len,
					    &sig_alg_type, &hash_alg_type);
	if (ret) {
		printf("Error handling sig OID\n");
		goto err;
	}

	ret = curve_oid_to_curve_type(spki_alg_oid_start, spki_alg_oid_len,
				      &curve_type);
	if (ret) {
		printf("Error handling SPKI alg OID\n");
		goto err;
	}



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
	ctx.pub_key = spki_pub_key_start;
	ctx.pub_key_len = spki_pub_key_len;
	ctx.pub_key_alg_oid = spki_alg_oid_start;
	ctx.pub_key_alg_oid_len = spki_alg_oid_len;

	ctx.sig_alg_type = sig_alg_type;
	ctx.hash_alg_type = hash_alg_type;
	ctx.curve_type = curve_type;

	ret = x509_sig_verify(&ctx);

	printf("Signature verifation ");
	printf("%s\n", ret ? "FAILED" : "SUCCESS");

err:
	return ret;
}
