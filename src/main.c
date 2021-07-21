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
	printf("Usage: %s file.der\n", argv0);
}

int main(int argc, char *argv[])
{
	u8 buf[ASN1_MAX_BUFFER_SIZE];
	char *path = argv[1];
	u16 rem, copied;
	int ret, fd;

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

	ret = x509_cert_verif(buf, copied);

out:
	return ret;
}
