/*
 *  Copyright (C) 2021 - This file is part of x509-verif project
 *
 *  Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *      Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *
 *  This software is licensed under a dual GPLv2/BSD license. See
 *  LICENSE file at the root folder of the project.
 */

#include "cert-extract.h"
#include <x509/x509-parser.h>

/* External functions from prebuilt x509-parser.o that are not declared in headers */
extern int x509_cert_extract_tbs_and_sig(const unsigned char *buf, unsigned int len,
					unsigned char **tbs_start, unsigned short *tbs_len,
					unsigned char **sig_alg_start, unsigned short *sig_alg_len,
					unsigned char **sig_start, unsigned short *sig_len);

extern int x509_cert_extract_SPKI(const unsigned char *buf, unsigned int len,
				  unsigned char **spki_alg_oid_start, unsigned short *spki_alg_oid_len,
				  unsigned char **spki_pub_key_start, unsigned short *spki_pub_key_len);

extern int x509_cert_is_self_signed(const unsigned char *buf, unsigned short len, int *self_signed);

extern int parse_sig_ecdsa_export_r_s(const unsigned char *sig, unsigned int sig_len,
				     unsigned short *r_start, unsigned short *r_len,
				     unsigned short *s_start, unsigned short *s_len,
				     unsigned short *eaten);

extern int parse_sig_eddsa_export_r_s(const unsigned char *sig, unsigned int sig_len,
				     unsigned short *r_start, unsigned short *r_len,
				     unsigned short *s_start, unsigned short *s_len,
				     unsigned short *eaten);

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

	/*
	 * Caution: the function below will only set the 16 LSB of out parameter
	 * on return. For that reason, we MUST initialize the values to 0 before
	 * passing the variable if we do not want to get random garbage in MSB.
	 *
	 * XXXX we should revisit that and have an interface with homogenous
	 * types, for instance by using uint16_t here.
	 */
	*tbs_len = 0;
	*sig_alg_len = 0;
	*sig_len = 0;
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

	/*
	 * Caution: the function below will only set the 16 LSB of out parameter
	 * on return. For that reason, we MUST initialize the values to 0 before
	 * passing the variable if we do not want to get random garbage in MSB.
	 */
	*spki_alg_oid_len = 0;
	*spki_pub_key_len = 0;
	ret = x509_cert_extract_SPKI(buf, len,
				     spki_alg_oid_start, (u16 *)spki_alg_oid_len,
				     spki_pub_key_start, (u16 *)spki_pub_key_len);

err:
	return ret;
}

int x509_cert_self_signed(unsigned char *buf, unsigned int len, int *self_signed)
{
	return x509_cert_is_self_signed(buf, (u16)len, self_signed);
}

/* Extract R and S coordinates of ECDSA signature. */
int x509_sig_ecdsa_extract_r_s(unsigned char *in_sig, unsigned int in_sig_len,
			       unsigned int coord_len,
			       unsigned char *r, unsigned char *s)
{
	u16 r_start, r_len, s_start, s_len, eaten, shift;
	int ret;
	extern int printf(const char *format, ...);

	printf("%02x", in_sig[0]);
	printf("%02x", in_sig[1]);
	printf("%02x", in_sig[2]);
	printf("%02x", in_sig[3]);
	printf("\n");
	ret = parse_sig_ecdsa_export_r_s(in_sig, in_sig_len, &r_start, &r_len,
					 &s_start, &s_len, &eaten);
	if (ret) {
		goto err;
	}
	printf("%d %d %d %d\n", ret, s_len, r_len, coord_len);

	if (r_len == (coord_len + 1)) {
		if (in_sig[r_start] != 0) {
			ret = -1;
			goto err;
		}
		r_start += 1;
		r_len -= 1;
	}

	if (s_len == (coord_len + 1)) {
		if (in_sig[s_start] != 0) {
			ret = -1;
			goto err;
		}
		s_start += 1;
		s_len -= 1;
	}

	if ((r_len > coord_len) || (s_len > coord_len)) {
		printf("WE ARE DOOMED %d %d %d %d\n", r_len, coord_len, s_len, coord_len);
		ret = -1;
		goto err;
	}

	memset(r, 0, coord_len);
	shift = coord_len - r_len;
	memcpy(r + shift, in_sig + r_start, r_len);

	memset(s, 0, coord_len);
	shift = coord_len - s_len;
	memcpy(s + shift, in_sig + s_start, s_len);
	{
		unsigned int i;
		printf("R: ");
		for (i = 0; i < coord_len; i++) {
			printf("%02x", r[i]);
		}
		printf("\n");
		printf("S: ");
		for (i = 0; i < coord_len; i++) {
			printf("%02x", s[i]);
		}
		printf("\n");
	}

err:
	return ret;
}


/* Extract R and S from EDDSA (Ed25519 or Ed448) signature. */
int x509_sig_eddsa_extract_r_s(unsigned char *in_sig, unsigned int in_sig_len,
			       unsigned int hsize,
			       unsigned char *r, unsigned char *s)
{
	u16 r_start, r_len, s_start, s_len, eaten;
	int ret;
	extern int printf(const char *format, ...);

	printf("%02x", in_sig[0]);
	printf("%02x", in_sig[1]);
	printf("%02x", in_sig[2]);
	printf("%02x", in_sig[3]);
	printf("\n");
	ret = parse_sig_eddsa_export_r_s(in_sig, in_sig_len, &r_start, &r_len,
					 &s_start, &s_len, &eaten);
	if (ret) {
		goto err;
	}
	printf("%d %d %d %d\n", ret, s_len, r_len, hsize);

	if ((r_len != s_len) || ((r_len + s_len) != hsize)) {
		printf("WE ARE DOOMED %d %d %d\n", r_len, s_len, hsize);
		ret = -1;
		goto err;
	}

	memset(r, 0, hsize/2);
	memcpy(r, in_sig + r_start, r_len);

	memset(s, 0, hsize/2);
	memcpy(s, in_sig + s_start, s_len);

	{
		unsigned int i;
		printf("R: ");
		for (i = 0; i < (hsize / 2); i++) {
			printf("%02x", r[i]);
		}
		printf("\n");
		printf("S: ");
		for (i = 0; i < (hsize / 2); i++) {
			printf("%02x", s[i]);
		}
		printf("\n");
	}

err:
	return ret;
}
