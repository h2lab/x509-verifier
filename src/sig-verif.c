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

int x509_sig_verify(const x509_sig_verify_ctx *ctx)
{
	ec_params ecp_secp384r1;
	ec_pub_key pubkey;
	u8 sig[48*2];
	int ret;

	if (ctx == NULL) {
		ret = -1;
		goto err;
	}

	import_params(&ecp_secp384r1, &secp384r1_str_params);

	/* Import pub key */
	ret = ec_pub_key_import_from_aff_buf(&pubkey, &ecp_secp384r1,
					     ctx->pub_key, ctx->pub_key_len,
					     ECDSA);
	if (ret) {
		goto err;
	}

	/*
	 * For ECDSA, libecc expects a sig in raw format, i.e. concatenated
	 * R and S and not two integers as found in certs
	 */
	local_memcpy(sig, ctx->sig + 7, 48);
	local_memcpy(sig+48, ctx->sig + 58, 48);

	/* verify tbs */
	ret = ec_verify(sig, 96, &pubkey,
			ctx->tbs, ctx->tbs_len,
			ECDSA, SHA384, NULL, 0);

err:
	return ret;
}
