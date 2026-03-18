/*
 * Compatibility layer for x509-parser API changes.
 *
 * The legacy helpers are implemented using the current parser APIs so callers
 * can keep using their former interface.
 */

#include <stdint.h>
#include <x509/x509-parser.h>

int x509_cert_extract_tbs_and_sig(uint8_t *buf, uint32_t len,
				  uint8_t **tbs_start, uint16_t *tbs_len,
				  uint8_t **sig_alg_start, uint16_t *sig_alg_len,
				  uint8_t **sig_start, uint16_t *sig_len)
{
	cert_parsing_ctx cert_ctx;

	if ((buf == NULL) || (len == 0) ||
	    (tbs_start == NULL) || (tbs_len == NULL) ||
	    (sig_alg_start == NULL) || (sig_alg_len == NULL) ||
	    (sig_start == NULL) || (sig_len == NULL)) {
		return -1;
	}

	if (parse_x509_cert(&cert_ctx, buf, len)) {
		return -1;
	}

	/* Sanity check for tbs range */
	if ((cert_ctx.tbs_start > len) || (cert_ctx.tbs_len > (len - cert_ctx.tbs_start)) ||
	    (cert_ctx.tbs_len > UINT16_MAX)) {
		return -1;
	}
	*tbs_start = buf + cert_ctx.tbs_start;
	*tbs_len = (uint16_t)cert_ctx.tbs_len;

	/* Sanity check for sig_alg range */
	if ((cert_ctx.sig_alg_start > len) || (cert_ctx.sig_alg_len > (len - cert_ctx.sig_alg_start)) ||
	    (cert_ctx.sig_alg_len > UINT16_MAX)) {
		return -1;
	}
	*sig_alg_start = buf + cert_ctx.sig_alg_start;
	*sig_alg_len = (uint16_t)cert_ctx.sig_alg_len;

	/* Sanity check for sig range */
	if ((cert_ctx.sig_start > len) || (cert_ctx.sig_len > (len - cert_ctx.sig_start)) ||
	    (cert_ctx.sig_len > UINT16_MAX)) {
		return -1;
	}
	*sig_start = buf + cert_ctx.sig_start;
	*sig_len = (uint16_t)cert_ctx.sig_len;

	return 0;
}

int x509_cert_extract_SPKI(uint8_t *buf, uint32_t len,
			   uint8_t **spki_alg_oid_start, uint16_t *spki_alg_oid_len,
			   uint8_t **spki_pub_key_start, uint16_t *spki_pub_key_len)
{
	cert_parsing_ctx cert_ctx;

	if ((buf == NULL) || (len == 0) ||
	    (spki_alg_oid_start == NULL) || (spki_alg_oid_len == NULL) ||
	    (spki_pub_key_start == NULL) || (spki_pub_key_len == NULL)) {
		return -1;
	}

	if (parse_x509_cert(&cert_ctx, buf, len)) {
		return -1;
	}

	/* Sanity check for spki_alg_oid range */
	if ((cert_ctx.spki_alg_oid_start > len) || (cert_ctx.spki_alg_oid_len > (len - cert_ctx.spki_alg_oid_start)) ||
	    (cert_ctx.spki_alg_oid_len > UINT16_MAX)) {
		return -1;
	}
	*spki_alg_oid_start = buf + cert_ctx.spki_alg_oid_start;
	*spki_alg_oid_len = (uint16_t)cert_ctx.spki_alg_oid_len;

	/* Sanity check for spki_pub_key range */
	if ((cert_ctx.spki_pub_key_start > len) || (cert_ctx.spki_pub_key_len > (len - cert_ctx.spki_pub_key_start)) ||
	    (cert_ctx.spki_pub_key_len > UINT16_MAX)) {
		return -1;
	}
	*spki_pub_key_start = buf + cert_ctx.spki_pub_key_start;
	*spki_pub_key_len = (uint16_t)cert_ctx.spki_pub_key_len;

	return 0;
}

int x509_cert_is_self_signed(uint8_t *buf, uint16_t len, int *self_signed)
{
	cert_parsing_ctx cert_ctx;

	if ((buf == NULL) || (len == 0) || (self_signed == NULL)) {
		return -1;
	}

	if (parse_x509_cert(&cert_ctx, buf, (uint32_t)len)) {
		return -1;
	}

	*self_signed = cert_ctx.subject_issuer_identical ? 1 : 0;
	return 0;
}

int parse_sig_ecdsa_export_r_s(uint8_t *in_sig, uint32_t in_sig_len,
			       uint16_t *r_start, uint16_t *r_len,
			       uint16_t *s_start, uint16_t *s_len,
			       uint16_t *eaten)
{
	sig_params params = { 0 };
	uint32_t parsed = 0;

	if ((in_sig == NULL) || (in_sig_len == 0) ||
	    (r_start == NULL) || (r_len == NULL) ||
	    (s_start == NULL) || (s_len == NULL) || (eaten == NULL)) {
		return -1;
	}

	if (parse_sig_ecdsa(&params, in_sig, 0, in_sig_len, &parsed)) {
		return -1;
	}

	/* Sanity check: all u32 values must fit in u16 */
	if ((params.ecdsa.r_raw_off > UINT16_MAX) || (params.ecdsa.r_raw_len > UINT16_MAX) ||
	    (params.ecdsa.s_raw_off > UINT16_MAX) || (params.ecdsa.s_raw_len > UINT16_MAX) ||
	    (parsed > UINT16_MAX)) {
		return -1;
	}

	*r_start = (uint16_t)params.ecdsa.r_raw_off;
	*r_len = (uint16_t)params.ecdsa.r_raw_len;
	*s_start = (uint16_t)params.ecdsa.s_raw_off;
	*s_len = (uint16_t)params.ecdsa.s_raw_len;
	*eaten = (uint16_t)parsed;

	return 0;
}

int parse_sig_eddsa_export_r_s(uint8_t *in_sig, uint32_t in_sig_len,
			       uint16_t *r_start, uint16_t *r_len,
			       uint16_t *s_start, uint16_t *s_len,
			       uint16_t *eaten)
{
	sig_params params = { 0 };
	uint32_t parsed = 0;
	int ret;

	if ((in_sig == NULL) || (in_sig_len == 0) ||
	    (r_start == NULL) || (r_len == NULL) ||
	    (s_start == NULL) || (s_len == NULL) || (eaten == NULL)) {
		return -1;
	}

	ret = parse_sig_ed25519(&params, in_sig, 0, in_sig_len, &parsed);
	if (ret == 0) {
		/* Sanity check: all u32 values must fit in u16 */
		if ((params.ed25519.r_raw_off > UINT16_MAX) || (params.ed25519.r_raw_len > UINT16_MAX) ||
		    (params.ed25519.s_raw_off > UINT16_MAX) || (params.ed25519.s_raw_len > UINT16_MAX) ||
		    (parsed > UINT16_MAX)) {
			return -1;
		}

		*r_start = (uint16_t)params.ed25519.r_raw_off;
		*r_len = (uint16_t)params.ed25519.r_raw_len;
		*s_start = (uint16_t)params.ed25519.s_raw_off;
		*s_len = (uint16_t)params.ed25519.s_raw_len;
		*eaten = (uint16_t)parsed;

		return 0;
	}

	ret = parse_sig_ed448(&params, in_sig, 0, in_sig_len, &parsed);
	if (ret) {
		return -1;
	}

	/* Sanity check: all u32 values must fit in u16 */
	if ((params.ed448.r_raw_off > UINT16_MAX) || (params.ed448.r_raw_len > UINT16_MAX) ||
	    (params.ed448.s_raw_off > UINT16_MAX) || (params.ed448.s_raw_len > UINT16_MAX) ||
	    (parsed > UINT16_MAX)) {
		return -1;
	}

	*r_start = (uint16_t)params.ed448.r_raw_off;
	*r_len = (uint16_t)params.ed448.r_raw_len;
	*s_start = (uint16_t)params.ed448.s_raw_off;
	*s_len = (uint16_t)params.ed448.s_raw_len;
	*eaten = (uint16_t)parsed;

	return 0;
}
