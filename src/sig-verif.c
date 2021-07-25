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

#include "sig-verif.h"
#include "../../libecc-eddsa-sm2-newapi/src/libsig.h" /* FIXME use -I */

static int x509_to_libecc_hash_alg_type(x509_ec_sig_alg in, ec_sig_alg_type *out)
{
	int ret;

	switch (in) {
	case X509_ECDSA:
		*out = ECDSA;
		break;
		/* XXX Add missing algs */
	default:
		ret = -1;
		goto err;
		break;
	}

	ret = 0;

err:
	return ret;
}

static int x509_to_libecc_sig_alg_type(x509_hash_alg in, hash_alg_type *out)
{
	int ret;

	switch (in) {
	case X509_SHA384:
		*out = SHA384;
		break;
		/* XXX Add missing algs */
	default:
		ret = -1;
		goto err;
		break;
	}

	ret = 0;

err:
	return ret;
}

static int import_curve_params_from_x509_curve_type(x509_curve curve_type,
						    ec_params *ecp)
{
	int ret;

	switch(curve_type) {
	case X509_SECP384R1:
		import_params(ecp, &secp384r1_str_params);
		break;
		/* XXX Add missing algs */
	default:
		ret = -1;
		goto err;
		break;
	}

	ret = 0;

err:
	return ret;
}



/*
 * Convert pub key from SPKI (an DER bitstring) to libecc expected
 * format, depneding on curve_type.


0362 bitstring 0x62 de long ... 
00 .. avec 0 bit unused dans l'octet de poids fort
04 uncompressed point, the only we support, followed by X and Y :
d4bc3d024275411323cd80048602512f6aa881620b65ccf6ca9d1e6f4a6651a203d99d91fab616b18c6ede7ccddb79a6
2fcebbce712fe5a5ab28ec63046699f8faf2931005e1812842e3c668f4e61b84604a89afed790f3bcef1f644f50178c0


 */
static int x509_to_libecc_pub_key(unsigned char *in_pub_key, unsigned int in_pub_key_len,
				  x509_curve curve_type,
				  u8 *out_pub, u16 *out_pub_len)
{
	int ret;

	if (in_pub_key == NULL || in_pub_key_len == 0) { /* XXX */
		ret = -1;
		goto err;
	}

	switch (curve_type) {
	case X509_SECP384R1:
		/* XXX Let's cheat a bit for now */
		local_memcpy(out_pub, in_pub_key + 4, 48*2);
		*out_pub_len = 48 * 2;
		break;
		/* XXX Add missing algs */
	default:
		ret = -1;
		goto err;
		break;
	}

	ret = 0;

err:
	return ret;
}


/*
 * Convert signature from X.509 certificate to the format expected by libecc.
 * this depends on the 


 */
static int x509_to_libecc_sig(unsigned char *in_sig, unsigned int in_sig_len,
			      x509_ec_sig_alg sig_type,
			      x509_hash_alg hash_type,
			      x509_curve curve_type,
			      u8 *out_sig, u16 *out_sig_len)
{
	int ret;

	if (in_sig == NULL || in_sig_len == 0) {
		ret = -1;
		goto err;
	}

	(void)hash_type; /* XXX silence */
	(void)curve_type; /* XXX silence */

	switch (sig_type) {
	case X509_ECDSA:
		/* Let's cheat a bit for now */
		/*
		 * For ECDSA, libecc expects a sig in raw format, i.e. concatenated
		 * R and S and not two integers as found in certs
		 */
		local_memcpy(out_sig, in_sig + 7, 48);
		local_memcpy(out_sig + 48, in_sig + 58, 48);
		*out_sig_len = 48 * 2;
		break;
		/* XXX Add missing algs */
	default:
		ret = -1;
		goto err;
		break;
	}

	ret = 0;

err:
	return ret;
}

int x509_sig_verify(const x509_sig_verify_ctx *ctx)
{
	ec_sig_alg_type sig_type;
	hash_alg_type hash_type;
	ec_params ecp;
	ec_pub_key pubkey;
	u8 pub[2*BYTECEIL(CURVES_MAX_P_BIT_LEN)];
	u16 pub_len;
	u8 sig[EC_MAX_SIGLEN];
	u16 sig_len;
	int ret;

	if (ctx == NULL) {
		ret = -1;
		goto err;
	}

	/* Let's first get libecc version of sig, hash and curve */
	ret  = x509_to_libecc_hash_alg_type(ctx->sig_alg_type, &sig_type);
	ret |= x509_to_libecc_sig_alg_type(ctx->hash_alg_type, &hash_type);
	ret |= import_curve_params_from_x509_curve_type(ctx->curve_type, &ecp);
	if (ret) {
		goto err;
	}

	/* Let's now convert public key to libecc format */
	pub_len = sizeof(sizeof(pub));
	ret = x509_to_libecc_pub_key(ctx->pub_key, ctx->pub_key_len,
				     ctx->curve_type,
				     pub, &pub_len);
	if (ret) {
		goto err;
	}

	/* And then import it */
	ret = ec_pub_key_import_from_aff_buf(&pubkey, &ecp,
					     pub, pub_len, sig_type);
	if (ret) {
		goto err;
	}

	sig_len = sizeof(sig);
	ret = x509_to_libecc_sig(ctx->sig, ctx->sig_len,
				 ctx->sig_alg_type,
				 ctx->hash_alg_type,
				 ctx->curve_type,
				 sig, &sig_len);

	/* verify tbs */
	ret = ec_verify(sig, sig_len, &pubkey,
			ctx->tbs, ctx->tbs_len,
			sig_type, hash_type, NULL, 0);

err:
	return ret;
}
