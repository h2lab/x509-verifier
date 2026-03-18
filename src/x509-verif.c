/*
 *  Copyright (C) 2021 - This file is part of x509-verif project
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
#include "x509-types.h"

int memcmp(const void *s1, const void *s2, size_t n);

/* XXX FIXME
 * revisit that: at the momoent, we deal with a sequence encapsulating
 * the OID and not the OID itself. Clarify or revisit.
 */

static const unsigned char oid_ecdsa_sha224[] = { /* 1.2.840.10045.4.3.1 */
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x01
};

static const unsigned char oid_ecdsa_sha256[] = { /* 1.2.840.10045.4.3.2 */
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
};

static const unsigned char oid_ecdsa_sha384[] = { /* 1.2.840.10045.4.3.3 */
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03
};

static const unsigned char oid_ecdsa_sha512[] = { /* 1.2.840.10045.4.3.4 */
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04
};

static const unsigned char oid_sm2_with_sm3[] = { /* 1.2.156.10197.1.501 */
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x75
};

/* The same as above but with a NULL (0x05, 0x00) in the sequence just after
   the OID. XXX It is unclear if this should be treated as invalid.
   this has been seen on SM2 DER certificate with SHA256
   197bd11845b507deef64f59dd718142db7aa1ad89ae0000ee051f8343f13efdf
*/
static const unsigned char oid_sm2_with_sm3_bis[] = { /* 1.2.156.10197.1.501 */
	0x30, 0x0c, 0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x75,
	0x05, 0x00
};

static const unsigned char oid_ed25519[] = { /* "1.3.101.112" */
	0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70
};

static const unsigned char oid_ed448[] = { /* "1.3.101.113" */
	0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71
};

static const unsigned char oid_gostR3411_94_with_gostR3410_2001[] = { /* 1.2.643.2.2.3 */
	0x30, 0x08, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x03
};

static const unsigned char oid_gostR3411_94_with_gostR3410_2001_bis[] = { /* 1.2.643.2.2.3 followed by NULL */
	0x30, 0x0a, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x03, 0x05, 0x00
};

static const unsigned char oid_gostR3411_94_with_gostR3410_94[] = { /* 1.2.643.2.2.4 */
	0x30, 0x08, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x04
};

static const unsigned char oid_gostR3410_2001[] = { /* 1.2.643.2.2.19 */
	0x30, 0x08, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x13
};


static const unsigned char oid_gost3410_2012_256[] = { /* 1.2.643.7.1.1.3.2 */
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x02
};

static const unsigned char oid_gost3410_2012_512[] = { /* 1.2.643.7.1.1.3.3 */
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x03
};


/*
 * This is where current approach does not make sense: we have a sequence
 * containing 1.2.643.2.2.3 OID followed by 0500, i.e. NULL
 * XXX Revisit that ASAP
 */
// static const unsigned char oid_GOST_R_3411_94_GOST_R_3410_2001[] = { /* "1.2.643.2.2.3" */
//	0x30, 0x0a, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x03, 0x05, 0x00
//};

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
	if ((sig_alg_len == sizeof(oid_ecdsa_sha224)) &&
	    !memcmp(sig_alg_start, oid_ecdsa_sha224, sizeof(oid_ecdsa_sha224))) {
		*sig_alg_type = X509_ECDSA;
		*hash_alg_type = X509_SHA224;
		printf("Detected ECDSA w/ SHA224\n");
	} else if ((sig_alg_len == sizeof(oid_ecdsa_sha256)) &&
	    !memcmp(sig_alg_start, oid_ecdsa_sha256, sizeof(oid_ecdsa_sha256))) {
		*sig_alg_type = X509_ECDSA;
		*hash_alg_type = X509_SHA256;
		printf("Detected ECDSA w/ SHA256\n");
	} else if ((sig_alg_len == sizeof(oid_ecdsa_sha384)) &&
	    !memcmp(sig_alg_start, oid_ecdsa_sha384, sizeof(oid_ecdsa_sha384))) {
		*sig_alg_type = X509_ECDSA;
		*hash_alg_type = X509_SHA384;
		printf("Detected ECDSA w/ SHA384\n");
	} else if ((sig_alg_len == sizeof(oid_ecdsa_sha512)) &&
	    !memcmp(sig_alg_start, oid_ecdsa_sha512, sizeof(oid_ecdsa_sha512))) {
		*sig_alg_type = X509_ECDSA;
		*hash_alg_type = X509_SHA512;
		printf("Detected ECDSA w/ SHA512\n");
	} else if ((sig_alg_len == sizeof(oid_sm2_with_sm3)) &&
	    !memcmp(sig_alg_start, oid_sm2_with_sm3, sizeof(oid_sm2_with_sm3))) {
		*sig_alg_type = X509_SM2;
		*hash_alg_type = X509_SM3;
		printf("Detected SM2 w/ SM3\n");
	} else if ((sig_alg_len == sizeof(oid_sm2_with_sm3_bis)) &&
	    !memcmp(sig_alg_start, oid_sm2_with_sm3_bis, sizeof(oid_sm2_with_sm3_bis))) {
		*sig_alg_type = X509_SM2;
		*hash_alg_type = X509_SM3;
		printf("Detected SM2 w/ SM3 (weird OID)\n");
	} else if ((sig_alg_len == sizeof(oid_ed25519)) &&
	    !memcmp(sig_alg_start, oid_ed25519, sizeof(oid_ed25519))) {
		*sig_alg_type = X509_EDDSA25519;
		*hash_alg_type = X509_SHA512;
		printf("Detected EDDSA 25519\n");
	} else if ((sig_alg_len == sizeof(oid_ed448)) &&
	    !memcmp(sig_alg_start, oid_ed448, sizeof(oid_ed448))) {
		*sig_alg_type = X509_EDDSA448;
		*hash_alg_type = X509_SHAKE256;
		printf("Detected EDDSA 448\n");
	} else if ((sig_alg_len == sizeof(oid_gost3410_2012_256)) &&
	    !memcmp(sig_alg_start, oid_gost3410_2012_256, sizeof(oid_gost3410_2012_256))) {
		*sig_alg_type = X509_ECRDSA;
		*hash_alg_type = X509_STREEBOG256;
		printf("Detected ECRDSA w/ STREEBOG256\n");
	} else if ((sig_alg_len == sizeof(oid_gost3410_2012_512)) &&
	    !memcmp(sig_alg_start, oid_gost3410_2012_512, sizeof(oid_gost3410_2012_512))) {
		*sig_alg_type = X509_ECRDSA;
		*hash_alg_type = X509_STREEBOG512;
		printf("Detected ECRDSA w/ STREEBOG256\n");
	} else if ((sig_alg_len == sizeof(oid_gostR3411_94_with_gostR3410_2001)) &&
	    !memcmp(sig_alg_start, oid_gostR3411_94_with_gostR3410_2001,
		    sizeof(oid_gostR3411_94_with_gostR3410_2001))) {
		*sig_alg_type = X509_ECRDSA;
		*hash_alg_type = X509_STREEBOG256;
		printf("Unsupported GOST sig\n");
		ret = -1;
		goto err;
	} else if ((sig_alg_len == sizeof(oid_gostR3411_94_with_gostR3410_2001_bis)) &&
	    !memcmp(sig_alg_start, oid_gostR3411_94_with_gostR3410_2001_bis,
		    sizeof(oid_gostR3411_94_with_gostR3410_2001_bis))) {
		*sig_alg_type = X509_ECRDSA;
		*hash_alg_type = X509_STREEBOG256;
		printf("Unsupported GOST sig\n");
		ret = -1;
		goto err;
	} else if ((sig_alg_len == sizeof(oid_gostR3411_94_with_gostR3410_94)) &&
	    !memcmp(sig_alg_start, oid_gostR3411_94_with_gostR3410_94,
		    sizeof(oid_gostR3411_94_with_gostR3410_94))) {
		*sig_alg_type = X509_ECRDSA;
		*hash_alg_type = X509_STREEBOG256;
		printf("Unsupported GOST sig\n");
		ret = -1;
		goto err;
	} else if ((sig_alg_len == sizeof(oid_gostR3410_2001)) &&
	    !memcmp(sig_alg_start, oid_gostR3410_2001,
		    sizeof(oid_gostR3410_2001))) {
		*sig_alg_type = X509_ECRDSA;
		*hash_alg_type = X509_STREEBOG256;
		printf("Unsupported GOST sig\n");
		ret = -1;
		goto err;
	} else {
		unsigned int i;
		printf("Signature OID: ");
		for (i = 0; i < sig_alg_len; i++) {
			printf("%02x", sig_alg_start[i]);
		}
		printf("\n");
		printf("here XXX %d\n", sig_alg_len);
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

static const unsigned char oid_secp256r1[] = { /* 1.2.840.10045.3.1.7 */
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};

static const unsigned char oid_secp384r1[] = { /* 1.3.132.0.34 */
	0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22
};

static const unsigned char oid_secp521r1[] = { /* 1.3.132.0.35 */
	0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23
};

static const unsigned char oid_sm2p256v1[] = { /* 1.2.156.10197.1.301 */
	0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d
};

static const unsigned char oid_pubkey_gost3410_2012_256[] = { /* 1.2.643.7.1.1.1.1 */
	0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01
};

static const unsigned char oid_pubkey_gostR3410_2001[] = { /* 1.2.643.2.2.19 */
	0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x13
};

/*
 * From OID 'spki_alg_oid_start' of 'spki_alg_oid_len' length from subject
 * public key info, the function returns associated curve. The function
 * returns 0 on success, -1 on error.
 *
 * It currently support:
 *  - all ecPublicKey-based encoding which consists in a sequence containing
 *     ecPublicKey OID followed by the curve OID
 *  - Ed25519 and Ed448 curves which consists in a sequence containsing
 *    a single OID.
 *  - GOST curve which consists in a sequence containsing     a single OID.
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

	{
		unsigned int i;
		printf("PubKeyOID: ");
		for (i = 0; i < spki_alg_oid_len; i++) {
			printf("%02x", spki_alg_oid_start[i]);
		}
		printf("\n");
	}

	buf = spki_alg_oid_start;
	if ((spki_alg_oid_len == sizeof(oid_ed448)) &&
	    !memcmp(buf, oid_ed448, sizeof(oid_ed448))) {
		*curve_type = X509_WEI448;
		ret = 0;
		goto err;
	} else if ((spki_alg_oid_len == sizeof(oid_ed25519)) &&
	    !memcmp(buf, oid_ed25519, sizeof(oid_ed25519))) {
		*curve_type = X509_WEI25519;
		ret = 0;
		goto err;
	} else if ((spki_alg_oid_len >= (2 + sizeof(oid_ecPublicKey))) &&
		(!memcmp(spki_alg_oid_start + 2, oid_ecPublicKey, sizeof(oid_ecPublicKey)))) {
		/*
		 * We expect a sequence of 2 OID, e.g. 3010 06072a8648ce3d0201
		 * 06052b81040022. The first one being 06072a8648ce3d0201, i.e.
		 * ecPublicKey (the one that just matched) and the next one
		 * providing the curve OID.
		 */

		buf = spki_alg_oid_start + 2 + sizeof(oid_ecPublicKey);
		remain = spki_alg_oid_len - (2 + sizeof(oid_ecPublicKey));
		if (remain == sizeof(oid_secp256r1) &&
			!memcmp(buf, oid_secp256r1, remain)) {
			printf("X509_SECP256R1 %d\n", remain);
			*curve_type = X509_SECP256R1;
		} else if (remain == sizeof(oid_secp384r1) &&
			!memcmp(buf, oid_secp384r1, remain)) {
			printf("X509_SECP384R1 %d\n", remain);
			*curve_type = X509_SECP384R1;
		} else if (remain == sizeof(oid_secp521r1) &&
			!memcmp(buf, oid_secp521r1, remain)) {
			printf("X509_SECP521R1 %d\n", remain);
			*curve_type = X509_SECP521R1;
		} else if (remain == sizeof(oid_sm2p256v1) &&
			!memcmp(buf, oid_sm2p256v1, remain)) {
			printf("X509_SM2P256V1 %d\n", remain);
			*curve_type = X509_SM2P256V1;
		} else {
			ret = -1;
			goto err;
		}
	} else if ((spki_alg_oid_len >= (2 + sizeof(oid_pubkey_gost3410_2012_256))) &&
		(!memcmp(spki_alg_oid_start + 2, oid_pubkey_gost3410_2012_256, sizeof(oid_pubkey_gost3410_2012_256)))) {
		/* Then, we will find a sequence (?!?) */
		int found;

		buf = spki_alg_oid_start + 2 + sizeof(oid_pubkey_gost3410_2012_256);
		remain = spki_alg_oid_len - (2 + sizeof(oid_pubkey_gost3410_2012_256));

		if (remain < 2) {
			ret = -1;
			goto err;
		}
		buf += 2;
		remain -= 2;

		const unsigned char oid_cryptoproA[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 };
		const unsigned char oid_cryptoproAbis[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01, };
		const unsigned char oid_cryptoproXchA[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x24, 0x00 };
		const unsigned char oid_paramsetA[] = { 0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01, };
		const unsigned char oid_testparam256[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x00 };
		found = 0;
		while (remain) {
			if (remain >= sizeof(oid_cryptoproA) && !memcmp(buf, oid_cryptoproA, sizeof(oid_cryptoproA))) {
				printf("X509_GOST_CRYPTOPRO_A 1\n");
				*curve_type = X509_GOST_R3410_2001_CRYPTOPRO_A_PARAMSET;
				found = 1;
				break;
			}
			if (remain >= sizeof(oid_cryptoproAbis) && !memcmp(buf, oid_cryptoproAbis, sizeof(oid_cryptoproAbis))) {
				printf("X509_GOST_CRYPTOPRO_A 2\n");
				*curve_type = X509_GOST_R3410_2001_CRYPTOPRO_A_PARAMSET;
				found = 1;
				break;
			}
			if (remain >= sizeof(oid_cryptoproXchA) && !memcmp(buf, oid_cryptoproXchA, sizeof(oid_cryptoproXchA))) {
				printf("X509_GOST_CRYPTOPRO_A 3\n");
				*curve_type = X509_GOST_R3410_2001_CRYPTOPRO_XCHA_PARAMSET;
				found = 1;
				break;
			}
			if (remain >= sizeof(oid_paramsetA) && !memcmp(buf, oid_paramsetA, sizeof(oid_paramsetA))) {
				printf("X509_GOST_CRYPTOPRO_A 4 here\n");
				*curve_type = X509_GOST_R3410_2012_256_PARAMSETA;
				found = 1;
				break;
			}
			if (remain >= sizeof(oid_testparam256) && !memcmp(buf, oid_testparam256, sizeof(oid_testparam256))) {
				printf("X509_GOST_CRYPTOPRO_A 4 bis\n");
				*curve_type = X509_GOST256;
				found = 1;
				break;
			}
			/* not found */

			remain -= buf[1] + 2; /* skip to next OID */
			buf += buf[1] + 2;
		}

		ret = found ? 0 : -1;
		goto err;
	} else if ((spki_alg_oid_len >= (2 + sizeof(oid_pubkey_gostR3410_2001))) &&
		(!memcmp(spki_alg_oid_start + 2, oid_pubkey_gostR3410_2001, sizeof(oid_pubkey_gostR3410_2001)))) {
		/* Then, we will find a sequence (?!?) */
		int found;

		buf = spki_alg_oid_start + 2 + sizeof(oid_pubkey_gostR3410_2001);
		remain = spki_alg_oid_len - (2 + sizeof(oid_pubkey_gostR3410_2001));

		if (remain < 2) {
			ret = -1;
			goto err;
		}
		buf += 2;
		remain -= 2;

		const unsigned char oid_cryptoproA[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 };
		const unsigned char oid_cryptoproAbis[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01, };
		const unsigned char oid_cryptoproXchA[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x24, 0x00 };
		const unsigned char oid_paramsetA[] = { 0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01, };
		found = 0;
		while (remain) {
			if (remain >= sizeof(oid_cryptoproA) && !memcmp(buf, oid_cryptoproA, sizeof(oid_cryptoproA))) {
				printf(" X509_GOST_CRYPTOPRO_A 5\n");
				*curve_type = X509_GOST_R3410_2001_CRYPTOPRO_A_PARAMSET;
				found = 1;
				break;
			}
			if (remain >= sizeof(oid_cryptoproAbis) && !memcmp(buf, oid_cryptoproAbis, sizeof(oid_cryptoproAbis))) {
				printf(" X509_GOST_CRYPTOPRO_A 6\n");
				*curve_type = X509_GOST_R3410_2001_CRYPTOPRO_A_PARAMSET;
				found = 1;
				break;
			}
			if (remain >= sizeof(oid_cryptoproXchA) && !memcmp(buf, oid_cryptoproXchA, sizeof(oid_cryptoproXchA))) {
				printf(" X509_GOST_CRYPTOPRO_A 7\n");
				*curve_type = X509_GOST_R3410_2001_CRYPTOPRO_XCHA_PARAMSET;
				found = 1;
				break;
			}
			if (remain >= sizeof(oid_paramsetA) && !memcmp(buf, oid_paramsetA, sizeof(oid_paramsetA))) {
				printf(" X509_GOST_CRYPTOPRO_A 8\n");
				*curve_type = X509_GOST_R3410_2012_256_PARAMSETA;
				found = 1;
				break;
			}
			/* not found */

			remain -= buf[1] + 2; /* skip to next OID */
			buf += buf[1] + 2;
		}

		ret = found ? 0 : -1;
		goto err;
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

	{
		unsigned int i;
		printf("tbs: ");
		for(i = 0; i < tbs_len; i++) {
			printf("%02x", tbs_start[i]);
		}
		printf("\n");
	}

	printf("sig_alg_len %d\n", sig_alg_len);
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
		printf("Error handling sig OID %d\n", sig_alg_len);
		goto err;
	}

	ret = curve_oid_to_curve_type(spki_alg_oid_start, spki_alg_oid_len,
				      &curve_type);
	if (ret) {
		printf("Curve OID: ");
		for (i = 0; i < spki_alg_oid_len; i++) {
			printf("%02x", spki_alg_oid_start[i]);
		}
		printf("\n");
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

	printf("spki : ");
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

	printf("Signature verification ");
	printf("%s\n", ret ? "FAILED" : "SUCCESS");

err:
	return ret;
}
