/*
 *  Copyright (C) 2021 - This file is part of x509-verif project
 *
 *  Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual GPLv2/BSD license. See
 *  LICENSE file at the root folder of the project.
 */
#ifndef __X509_PARSER_VERIF_H__
#define __X509_PARSER_VERIF_H__

int x509_cert_verif(unsigned char *tbv_cert, unsigned short tbv_cert_len,
		    unsigned char *anchor_cert, unsigned short anchor_cert_len);

#endif /* __X509_PARSER_VERIF_H__ */
