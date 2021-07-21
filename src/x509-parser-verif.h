/*
 *  Copyright (C) 2021 - This file is part of x509-parser project
 *
 *  Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual GPLv2/BSD license. See
 *  LICENSE file at the root folder of the project.
 */
#ifndef __X509_PARSER_VERIF_H__
#define __X509_PARSER_VERIF_H__

// #include "x509-parser.h"

int x509_cert_verif(const unsigned char *buf, unsigned short len);

#endif /* __X509_PARSER_VERIF_H__ */
