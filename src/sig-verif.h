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

#ifndef __X509_SIG_VERIF_H__
#define __X509_SIG_VERIF_H__
#include "x509-types.h"

/*
 * The purpose of this header is to provide a type neutral definition for
 * certificate signature verification functions: the types used here are
 * pure C99 ones (i.e. no u8, uint8_t, ssize_t, etc). This provides a
 * clean abstratcion/limit/DMZ against the various derinitions used in
 * the associated .c file, that can safely use types defined in other
 * libraries.
 */

typedef struct {
	/* tbsCertificate and its length*/
	unsigned char *tbs;
	unsigned int tbs_len;

	/* signature algorithm OID and its length */
	unsigned char *sig_alg_oid;
	unsigned int sig_alg_oid_len;

	/* signature value (i.e. sig of tbs by previous alg) */
	unsigned char *sig;
	unsigned int sig_len;

	/* raw public key value */
	unsigned char *pub_key;
	unsigned int pub_key_len;

	/* algorithm OID for given public key above */
	unsigned char *pub_key_alg_oid;
	unsigned int pub_key_alg_oid_len;

	/* XXX remove oid entries */
	x509_ec_sig_alg sig_alg_type;
	x509_hash_alg hash_alg_type;
	x509_curve curve_type;
} x509_sig_verify_ctx;

/*
 * The function takes as inputs the *raw* elements extracted from a
 * certificate (Signature Algorithm OID, tbs and signature) along
 * with the public key. Those elements are passed using a
 * x509_sig_verify_ctx structure defined above. The functions returns
 * 0 on success (signature is valid) and a negative value on error
 * (invalid signature).
 */
int x509_sig_verify(const x509_sig_verify_ctx *ctx);

#endif /* __X509_SIG_VERIF_H__ */
