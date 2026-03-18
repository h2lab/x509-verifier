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

#include <libecc/libsig.h>

#include "sig-verif.h"
#include "cert-extract.h"


static int x509_to_libecc_sig_alg_type(x509_ec_sig_alg in, ec_alg_type *out)
{
	int ret;

	switch (in) {
	case X509_ECDSA:
		*out = ECDSA;
		break;
	case X509_ECKCDSA:
		*out = ECKCDSA;
		break;
	case X509_ECSDSA:
		*out = ECSDSA;
		break;
	case X509_ECOSDSA:
		*out = ECOSDSA;
		break;
	case X509_ECFSDSA:
		*out = ECFSDSA;
		break;
	case X509_ECGDSA:
		*out = ECGDSA;
		break;
	case X509_ECRDSA:
		*out = ECRDSA;
		break;
	case X509_SM2:
		*out = SM2;
		break;
	case X509_EDDSA25519:
		*out = EDDSA25519;
		break;
	case X509_EDDSA25519CTX:
		*out = EDDSA25519CTX;
		break;
	case X509_EDDSA25519PH:
		*out = EDDSA25519PH;
		break;
	case X509_EDDSA448:
		*out = EDDSA448;
		break;
	case X509_EDDSA448PH:
		*out = EDDSA448PH;
		break;
	case X509_DECDSA:
		*out = DECDSA;
		break;
	default:
		*out = UNKNOWN_ALG;
		ret = -1;
		goto err;
		break;
	}

	ret = 0;

err:
	return ret;
}

static int x509_to_libecc_hash_alg_type(x509_hash_alg in, hash_alg_type *out)
{
	int ret;

	switch (in) {
	case X509_SHA224:
		*out = SHA224;
		break;
	case X509_SHA256:
		*out = SHA256;
		break;
	case X509_SHA384:
		*out = SHA384;
		break;
	case X509_SHA512:
		*out = SHA512;
		break;
	case X509_SHA3_224:
		*out = SHA3_224;
		break;
	case X509_SHA3_256:
		*out = SHA3_256;
		break;
	case X509_SHA3_384:
		*out = SHA3_384;
		break;
	case X509_SHA3_512:
		*out = SHA3_512;
		break;
	case X509_SHA512_224:
		*out = SHA512_224;
		break;
	case X509_SHA512_256:
		*out = SHA512_256;
		break;
	case X509_SM3:
		*out = SM3;
		break;
	case X509_SHAKE256:
		*out = SHAKE256;
		break;
	case X509_STREEBOG256:
		*out = STREEBOG256;
		break;
	case X509_STREEBOG512:
		*out = STREEBOG512;
		break;
	default:
		*out = UNKNOWN_HASH_ALG;
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
	case X509_FRP256V1:
		import_params(ecp, &frp256v1_str_params);
		break;
	case X509_SECP192R1:
		import_params(ecp, &secp192r1_str_params);
		break;
	case X509_SECP224R1:
		import_params(ecp, &secp224r1_str_params);
		break;
	case X509_SECP256R1:
		import_params(ecp, &secp256r1_str_params);
		break;
	case X509_SECP384R1:
		import_params(ecp, &secp384r1_str_params);
		break;
	case X509_SECP521R1:
		import_params(ecp, &secp521r1_str_params);
		break;
	case X509_BRAINPOOLP224R1:
		import_params(ecp, &brainpoolp224r1_str_params);
		break;
	case X509_BRAINPOOLP256R1:
		import_params(ecp, &brainpoolp256r1_str_params);
		break;
	case X509_BRAINPOOLP512R1:
		import_params(ecp, &brainpoolp512r1_str_params);
		break;
	case X509_GOST256:
		import_params(ecp, &GOST_256bits_curve_str_params);
		break;
	case X509_GOST512:
		import_params(ecp, &GOST_512bits_curve_str_params);
		break;
	case X509_BRAINPOOLP384R1:
		import_params(ecp, &brainpoolp384r1_str_params);
		break;
	case X509_BRAINPOOLP192R1:
		import_params(ecp, &brainpoolp192r1_str_params);
		break;
	case X509_WEI25519:
		import_params(ecp, &wei25519_str_params);
		break;
	case X509_WEI448:
		import_params(ecp, &wei448_str_params);
		break;
	case X509_SM2P256V1:
		import_params(ecp, &sm2p256v1_str_params);
		break;
	case X509_GOST_R3410_2001_TESTPARAMSET:
		import_params(ecp, &gost_R3410_2001_TestParamSet_str_params);
		break;
	case X509_GOST_R3410_2001_CRYPTOPRO_A_PARAMSET:
		import_params(ecp, &gost_R3410_2001_CryptoPro_A_ParamSet_str_params);
		break;
	case X509_GOST_R3410_2001_CRYPTOPRO_B_PARAMSET:
		import_params(ecp, &gost_R3410_2001_CryptoPro_B_ParamSet_str_params);
		break;
	case X509_GOST_R3410_2001_CRYPTOPRO_C_PARAMSET:
		import_params(ecp, &gost_R3410_2001_CryptoPro_C_ParamSet_str_params);
		break;
	case X509_GOST_R3410_2001_CRYPTOPRO_XCHA_PARAMSET:
		import_params(ecp, &gost_R3410_2001_CryptoPro_XchA_ParamSet_str_params);
		break;
	case X509_GOST_R3410_2001_CRYPTOPRO_XCHB_PARAMSET:
		import_params(ecp, &gost_R3410_2001_CryptoPro_XchB_ParamSet_str_params);
		break;
	case X509_GOST_R3410_2012_256_PARAMSETA:
		import_params(ecp, &gost_R3410_2012_256_paramSetA_str_params);
		break;
	case X509_GOST_R3410_2012_256_PARAMSETB:
		import_params(ecp, &gost_R3410_2012_256_paramSetB_str_params);
		break;
	case X509_GOST_R3410_2012_256_PARAMSETC:
		import_params(ecp, &gost_R3410_2012_256_paramSetC_str_params);
		break;
	case X509_GOST_R3410_2012_256_PARAMSETD:
		import_params(ecp, &gost_R3410_2012_256_paramSetD_str_params);
		break;
	case X509_GOST_R3410_2012_512_PARAMSETTEST:
		import_params(ecp, &gost_R3410_2012_512_paramSetTest_str_params);
		break;
	case X509_GOST_R3410_2012_512_PARAMSETA:
		import_params(ecp, &gost_R3410_2012_512_paramSetA_str_params);
		break;
	case X509_GOST_R3410_2012_512_PARAMSETB:
		import_params(ecp, &gost_R3410_2012_512_paramSetB_str_params);
		break;
	case X509_GOST_R3410_2012_512_PARAMSETC:
		import_params(ecp, &gost_R3410_2012_512_paramSetC_str_params);
		break;
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
	case X509_SM2P256V1:
	case X509_SECP256R1:
		/* XXX Let's cheat a bit for now */
		local_memcpy(out_pub, in_pub_key + 4, 32*2);
		*out_pub_len = 32 * 2;
		break;
	case X509_SECP384R1:
		/* XXX Let's cheat a bit for now */
		local_memcpy(out_pub, in_pub_key + 4, 48*2);
		*out_pub_len = 48 * 2;
		break;
	case X509_SECP521R1:
		/* XXX Let's cheat a bit for now */
		local_memcpy(out_pub, in_pub_key + 5, 66*2);
		*out_pub_len = 66 * 2;
		break;
	case X509_WEI25519:
		/* XXX Let's cheat a bit for now */
		local_memcpy(out_pub, in_pub_key + 3, 64/2);
		*out_pub_len = 64/2;
		break;
	case X509_WEI448:
		/* XXX Let's cheat a bit for now */
		local_memcpy(out_pub, in_pub_key + 3, 114/2);
		*out_pub_len = 114/2;
		break;
	case X509_GOST256:
	case X509_GOST_R3410_2001_TESTPARAMSET:
	case X509_GOST_R3410_2001_CRYPTOPRO_A_PARAMSET:
	case X509_GOST_R3410_2001_CRYPTOPRO_B_PARAMSET:
	case X509_GOST_R3410_2001_CRYPTOPRO_C_PARAMSET:
	case X509_GOST_R3410_2001_CRYPTOPRO_XCHA_PARAMSET:
	case X509_GOST_R3410_2001_CRYPTOPRO_XCHB_PARAMSET:
	case X509_GOST_R3410_2012_256_PARAMSETA:
	case X509_GOST_R3410_2012_256_PARAMSETB:
	case X509_GOST_R3410_2012_256_PARAMSETC:
	case X509_GOST_R3410_2012_256_PARAMSETD:
		/* XXX Let's cheat a bit for now */
		local_memcpy(out_pub, in_pub_key + 5, 32 * 2);
		*out_pub_len = 32 * 2;
		/* the two components are LE encoded. Reverse
		   them here at the moment XXX make that more coherent */
		{
			u8 i, tmp;
			for (i = 0; i < 16; i++) {
				tmp = out_pub[i];
				out_pub[i] = out_pub[31 - i];
				out_pub[31 - i] = tmp;

				tmp = out_pub[i+32];
				out_pub[i + 32] = out_pub[63 - i];
				out_pub[63 - i] = tmp;
			}
		}
		break;
	case X509_GOST_R3410_2012_512_PARAMSETTEST:
	case X509_GOST_R3410_2012_512_PARAMSETA:
	case X509_GOST_R3410_2012_512_PARAMSETB:
	case X509_GOST_R3410_2012_512_PARAMSETC:
	case X509_GOST512:
		/* XXX Let's cheat a bit for now */
		local_memcpy(out_pub, in_pub_key + 7, 64 * 2);
		*out_pub_len = 64 * 2;
		/* the two components are LE encoded. Reverse
		   them here at the moment XXX make that more coherent */
		{
			u8 i, tmp;
			for (i = 0; i < 32; i++) {
				tmp = out_pub[i];
				out_pub[i] = out_pub[63 - i];
				out_pub[63 - i] = tmp;

				tmp = out_pub[i+64];
				out_pub[i + 64] = out_pub[127 - i];
				out_pub[127 - i] = tmp;
			}
		}
		break;
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
 * on success, returns the number of bytes on which curve order is
 * encoded, e.g. 32 for secp256r1, 66 for secp521r1, etc.
 */
static int curve_order_len(x509_curve curve_type, unsigned int *order_len)
{
	int ret;

	switch (curve_type) {
	case X509_SECP192R1:
	case X509_BRAINPOOLP192R1:
		*order_len = 24;
		break;
	case X509_FRP256V1:
	case X509_SECP256R1:
	case X509_BRAINPOOLP256R1:
	case X509_SM2P256V1:
		*order_len = 32;
		break;
	case X509_SECP224R1:
	case X509_BRAINPOOLP224R1:
		*order_len = 28;
		break;
	case X509_SECP384R1:
	case X509_BRAINPOOLP384R1:
		*order_len = 48;
		break;
	case X509_BRAINPOOLP512R1:
		*order_len = 64;
		break;
	case X509_SECP521R1:
		*order_len = 66;
		break;
	case X509_GOST256:
	case X509_GOST_R3410_2001_TESTPARAMSET:
	case X509_GOST_R3410_2001_CRYPTOPRO_A_PARAMSET:
	case X509_GOST_R3410_2001_CRYPTOPRO_B_PARAMSET:
	case X509_GOST_R3410_2001_CRYPTOPRO_C_PARAMSET:
	case X509_GOST_R3410_2001_CRYPTOPRO_XCHA_PARAMSET:
	case X509_GOST_R3410_2001_CRYPTOPRO_XCHB_PARAMSET:
	case X509_GOST_R3410_2012_256_PARAMSETA:
	case X509_GOST_R3410_2012_256_PARAMSETB:
	case X509_GOST_R3410_2012_256_PARAMSETC:
	case X509_GOST_R3410_2012_256_PARAMSETD:
		*order_len = 32;
		break;
	case X509_GOST_R3410_2012_512_PARAMSETTEST:
	case X509_GOST_R3410_2012_512_PARAMSETA:
	case X509_GOST_R3410_2012_512_PARAMSETB:
	case X509_GOST_R3410_2012_512_PARAMSETC:
	case X509_GOST512:
		*order_len = 64;
		break;
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
 * For ECDSA, libecc expects a sig in raw format, i.e. concatenated R and S with
 * each integer having a size on exactly the expected number of bytes which is
 * the order length (R and S are reduced modulo the order).
 *
 * When R and S are packaged in the certificate signature, they are put in a
 * bitstring which encapsulates a sequence of two integers. As seen in numerous
 * certificates, the integer values may have leading 0 which must be removed
 * during conversion.
 *
 * XXX Most of that function should be moved to the cert-extract module and
 * modified to work in a proper way. This is only a fragile PoC yet.
 *
 * Example of what we are dealing with (ECDSA sig on secp256r1):
 * 034800 bitstring
 * 3045 sequence
 * 02 21 00dc92a1a013a6cf03b0e6c4219790fa14572d03ecee3cd36ecaa86c76bca2debb  R
 * 02 20   27a88527359b56c6a3f247d2b76e1b020017aa67a61591defa94ec7b0bf89f84  S
 */

/*
secp521r1
03818b00
308187
02420119ebfcfccdfa5a00acae57cd072130f5e11e4f36f32142cfe164bb60bd48f0c835f10292430f02f07d1a417933804840fe76d3c7bd1a406abdd6ecd451f92c542d
0241706edc0d498f7a85352b5853bed5e16ffcc357e66d3d74edb9c32829889ef5bcb5421e8c4bd884a82de17060f969a86c593804404621ded4c41efb1240416ece9d
*/


static int x509_to_libecc_sig_ecdsa(unsigned char *in_sig,
				    unsigned int in_sig_len,
				    x509_curve curve_type,
				    u8 *out_sig, u16 *out_sig_len)
{
	unsigned int order_len;
	int ret;

	ret = curve_order_len(curve_type, &order_len);
	if (ret) {
		goto err;
	}

	ret = x509_sig_ecdsa_extract_r_s(in_sig, in_sig_len, order_len,
					 out_sig, out_sig + order_len);
	if (ret) {
		goto err;
	}

	*out_sig_len = 2 * order_len;

err:
	return ret;
}

static int x509_to_libecc_sig_eddsa(unsigned char *in_sig,
				    unsigned int in_sig_len,
				    x509_curve curve_type,
				    u8 *out_sig, u16 *out_sig_len)
{
	unsigned int hsize;
	int ret;

	switch (curve_type) {
	case X509_WEI25519:
		hsize = 64; /* SHA512 */
		break;
	case X509_WEI448:
		hsize = 114; /* SHAKE256 */
		break;
	default:
		ret = -1;
		goto err;
	}

	ret = x509_sig_eddsa_extract_r_s(in_sig, in_sig_len, hsize,
					 out_sig, out_sig + hsize/2);
	if (ret) {
		goto err;
	}

	*out_sig_len = hsize;

err:
	return ret;
}

static int x509_to_libecc_sig_ecrdsa(unsigned char *in_sig,
				    unsigned int in_sig_len,
				    x509_curve curve_type,
				    u8 *out_sig, u16 *out_sig_len)
{
	unsigned int order_len;
	u16 len;
	int ret;

	switch (curve_type) {
	case X509_GOST256:
	case X509_GOST_R3410_2001_TESTPARAMSET:
	case X509_GOST_R3410_2001_CRYPTOPRO_A_PARAMSET:
	case X509_GOST_R3410_2001_CRYPTOPRO_B_PARAMSET:
	case X509_GOST_R3410_2001_CRYPTOPRO_C_PARAMSET:
	case X509_GOST_R3410_2001_CRYPTOPRO_XCHA_PARAMSET:
	case X509_GOST_R3410_2001_CRYPTOPRO_XCHB_PARAMSET:
	case X509_GOST_R3410_2012_256_PARAMSETA:
	case X509_GOST_R3410_2012_256_PARAMSETB:
	case X509_GOST_R3410_2012_256_PARAMSETC:
	case X509_GOST_R3410_2012_256_PARAMSETD:
		order_len = 32;
		break;
	case X509_GOST_R3410_2012_512_PARAMSETTEST:
	case X509_GOST_R3410_2012_512_PARAMSETA:
	case X509_GOST_R3410_2012_512_PARAMSETB:
	case X509_GOST_R3410_2012_512_PARAMSETC:
	case X509_GOST512:
		order_len = 64;
		break;
	default:
		ret = -1;
		goto err;
		break;
	}

	if (in_sig_len != (2 * order_len + 3)) {
		ret = -1;
		goto err;
	}

	/* From draft-deremin-rfc4491-bis-06: GOST R 34.10-2012 signature
	   algorithm with 256-bit key length generates a digital signature
	   in the form of two 256-bit numbers, r and s.  Its octet string
	   representation consists of 64 octets, where the first 32 octets
	   contain the big-endian representation of s and the second 32
	   octets contain the big-endian representation of r. */
	len = in_sig_len - 3;
	*out_sig_len = len;

	local_memcpy(out_sig, in_sig + 3 + (len / 2) , len / 2);
	local_memcpy(out_sig + (len / 2), in_sig + 3 , len / 2);

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

	switch (sig_type) {
	case X509_SM2:
	case X509_ECDSA:
		ret = x509_to_libecc_sig_ecdsa(in_sig, in_sig_len, curve_type,
					       out_sig, out_sig_len);
		break;
	case X509_EDDSA25519:
	case X509_EDDSA448:
		ret = x509_to_libecc_sig_eddsa(in_sig, in_sig_len, curve_type,
					       out_sig, out_sig_len);
		break;
	case X509_ECRDSA:
		ret = x509_to_libecc_sig_ecrdsa(in_sig, in_sig_len, curve_type,
						out_sig, out_sig_len);
		break;
	default:
		ret = -1;
		goto err;
		break;
	}

err:
	return ret;
}

/*
  https://patchwork.kernel.org/project/linux-security-module/patch/20200920162103.83197-10-tianjia.zhang@linux.alibaba.com/
  The default user id as specified in GM/T 0009-2012
*/
const u8 sm2_default_user_id[] = "1234567812345678";
const u16 sm2_default_user_id_len = sizeof(sm2_default_user_id) - 1; /* 16 */

int x509_sig_verify(const x509_sig_verify_ctx *ctx)
{
	ec_alg_type sig_type;
	hash_alg_type hash_type;
	ec_params ecp;
	ec_pub_key pubkey;
	u8 pub[2*BYTECEIL(CURVES_MAX_P_BIT_LEN)];
	u16 pub_len;
	u8 sig[EC_MAX_SIGLEN];
	u16 sig_len;
	int ret;
	const u8 *adata;
	u16 adata_len;

	if (ctx == NULL) {
		ret = -1;
		goto err;
	}
	{
		extern int printf(const char *format, ...);
		printf("curve_type %d\n", ctx->curve_type);
	}
	/* Let's first get libecc version of sig, hash and curve */
	ret  = x509_to_libecc_sig_alg_type(ctx->sig_alg_type, &sig_type);
	if (ret) {
		goto err;
	}

	ret = x509_to_libecc_hash_alg_type(ctx->hash_alg_type, &hash_type);
	if (ret) {
		goto err;
	}

	ret = import_curve_params_from_x509_curve_type(ctx->curve_type, &ecp);
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
	if ((sig_type == EDDSA25519) || (sig_type == EDDSA448)) {
		ret = eddsa_import_pub_key(&pubkey, pub, pub_len, &ecp, sig_type);
		if (ret) {
			goto err;
		}
	} else { /* ECDSA, SM2, ECRDSA */
		ret = ec_pub_key_import_from_aff_buf(&pubkey, &ecp,
						    pub, pub_len, sig_type);
		if (ret) {
			goto err;
		}
	}

	sig_len = sizeof(sig);
	ret = x509_to_libecc_sig(ctx->sig, ctx->sig_len,
				 ctx->sig_alg_type,
				 ctx->hash_alg_type,
				 ctx->curve_type,
				 sig, &sig_len);
	if (ret) {
		goto err;
	}

	adata = NULL;
	adata_len = 0;
	if (sig_type == SM2) {
		/*
		 * SM2 is passed user id (required to compute ZA using)
		 * via ancillary data.
		 */
		adata = sm2_default_user_id;
		adata_len = sm2_default_user_id_len;
	}

	/* verify tbs */
	ret = ec_verify(sig, sig_len, &pubkey,
			ctx->tbs, ctx->tbs_len,
			sig_type, hash_type, adata, adata_len);

err:
	return ret;
}
