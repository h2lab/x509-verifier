/*
 *  Copyright (C) 2021 - This file is part of x509-parser project
 *
 *  Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual GPLv2/BSD license. See
 *  LICENSE file at the root folder of the project.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include "x509-parser-verif.h"

typedef uint8_t   u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define ASN1_MAX_BUFFER_SIZE 65534

static void usage(char *argv0)
{
	printf("Usage: %s file.der anchor.der\n", argv0);
}

int fimport(u8 *buf, u16 *len, char *fname)
{
	u16 rem, copied;
	int fd, ret;

	fd = open(fname, O_RDONLY);
	if (fd == -1) {
		printf("Unable to open input file %s\n", fname);
		ret = -1;
		goto err;
	}

	rem = ASN1_MAX_BUFFER_SIZE;
	copied = 0;
	while (rem) {
		ret = (int)read(fd, buf + copied, rem);
		if (ret <= 0) {
			break;
		} else {
			rem -= (u16)ret;
			copied += (u16)ret;
		}
	}
	close(fd);

	*len = copied;
	if (ret >= 0) {
		ret = 0;
	}

err:
	return ret;
}

int main(int argc, char *argv[])
{
	u8 tbv_cert[ASN1_MAX_BUFFER_SIZE]; /* cert to be verifierd */
	u8 anc_cert[ASN1_MAX_BUFFER_SIZE]; /* anchor to verify cert */
	u16 tbv_cert_len, anc_cert_len;
	char *tbv_fname = argv[1];
	char *anc_fname = argv[2];
	int ret;

	if (argc != 3) {
		usage(argv[0]);
		ret = -1;
		goto err;
	}

	/* import cert */
	ret = fimport(tbv_cert, &tbv_cert_len, tbv_fname);
	if (ret) {
		goto err;
	}

	/* import anchor */
	ret = fimport(anc_cert, &anc_cert_len, anc_fname);
	if (ret) {
		goto err;
	}

	/* verify cert using anchor */
	ret = x509_cert_verif(tbv_cert, tbv_cert_len, anc_cert, anc_cert_len);

err:
	return ret;
}
