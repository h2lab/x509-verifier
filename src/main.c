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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include "x509-verif.h"
#include "cert-extract.h"

typedef uint8_t   u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define ASN1_MAX_BUFFER_SIZE 65534

static void usage(char *argv0)
{
	printf("Usage: %s file.der anchor.der\n", argv0);
}

/*
 * Import content of file pointed by 'fname' into buffer 'buf' of size provided
 * by 'len'. On success, size of file copied to 'buf' is given in 'len'. 0 is
 * returned on success, -1 on error.
 */
int fimport(u8 *buf, u16 *len, char *fname)
{
	u16 rem, copied;
	int ret = -1;
	int fd;

	fd = open(fname, O_RDONLY);
	if (fd == -1) {
		printf("Unable to open input file %s\n", fname);
		ret = -1;
		goto err;
	}

	rem = *len;
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

int main_tbv_anc(int argc, char *argv[])
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
	tbv_cert_len = sizeof(tbv_cert);
	ret = fimport(tbv_cert, &tbv_cert_len, tbv_fname);
	if (ret) {
		goto err;
	}

	/* import anchor */
	anc_cert_len = sizeof(anc_cert);
	ret = fimport(anc_cert, &anc_cert_len, anc_fname);
	if (ret) {
		goto err;
	}

	/* verify cert using anchor */
	ret = x509_cert_verif(tbv_cert, tbv_cert_len, anc_cert, anc_cert_len);

err:
	return ret;
}

extern int parse_x509_cert_relaxed(const u8 *buf, u16 len, u16 *eaten);

int main_self_signed_relaxed(int argc, char *argv[])
{
	u8 buf[ASN1_MAX_BUFFER_SIZE];
	off_t pos, offset = 0;
	char *path = argv[1];
	u16 rem, copied, eaten;
	int ret, eof = 0;
	int fd, num_certs, num_certs_ok;

	if (argc != 2) {
		usage(argv[0]);
		ret = -1;
		goto out;
	}

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		printf("Unable to open input file %s\n", path);
		return -1;
	}

	num_certs = 0;
	num_certs_ok = 0;
	while (1) {
		pos = lseek(fd, offset, SEEK_SET);
		if (pos == (off_t)-1) {
			printf("lseek failed %s\n", path);
			ret = -1;
			goto out;
		}
		rem = ASN1_MAX_BUFFER_SIZE;
		copied = 0;
		while (rem) {
			ret = (int)read(fd, buf + copied, rem);
			if (ret <= 0) {
				if (copied == 0) {
					eof = 1;
				}
				break;
			} else {
				rem -= (u16)ret;
				copied += (u16)ret;
			}
		}

		if (eof) {
			break;
		}

		num_certs += 1;
		eaten = 0;
		ret = parse_x509_cert_relaxed(buf, copied, &eaten);
		if (ret == 1) {
			eaten = 1;
			printf("not a sequence %ld %d\n", offset, num_certs);
		}
		if (ret == 0) {
			int self_signed;

			num_certs_ok += 1;
			ret = x509_cert_self_signed(buf, eaten, &self_signed);
			if (!ret) {
				if (self_signed) {
					/* verify cert using anchor */
					ret = x509_cert_verif(buf, eaten, buf, eaten);
					if (ret) {
						printf("Sig verif failed for %s %llu %d\n", path, offset, eaten);
					} else {
						printf("Sig verif OK for %s\n");
					}
				}
			}
		}

		offset += eaten;
	}
	close(fd);

	ret = 0;

	printf("num_certs OK %d/%d\n", num_certs_ok, num_certs);

out:
	return ret;
}




int main(int argc, char *argv[])
{
	int ret;

	if (argc == 3) {
		ret = main_tbv_anc(argc, argv);
	} else if (argc == 2) {
		ret = main_self_signed_relaxed(argc, argv);
	} else {
		usage(argv[0]);
		ret = -1;
	}

	return ret;
}

