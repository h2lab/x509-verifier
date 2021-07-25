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
#ifndef __X509_TYPES_H__
#define __X509_TYPES_H__

typedef enum {
	X509_UNKNOWN_SIG_ALG =  0,
	X509_ECDSA           =  1,
	X509_ECKCDSA         =  2,
	X509_ECSDSA          =  3,
	X509_ECOSDSA         =  4,
	X509_ECFSDSA         =  5,
	X509_ECGDSA          =  6,
	X509_ECRDSA          =  7,
	X509_SM2             =  8,
	X509_EDDSA25519      =  9,
	X509_EDDSA25519CTX   = 10,
	X509_EDDSA25519PH    = 11,
	X509_EDDSA448        = 12,
	X509_EDDSA448PH      = 13,
	X509_DECDSA          = 14
} x509_ec_sig_alg;

/* Hash algorithm types */
typedef enum {
	X509_UNKNOWN_HASH_ALG =  0,
	X509_SHA224           =  1,
	X509_SHA256           =  2,
	X509_SHA384           =  3,
	X509_SHA512           =  4,
	X509_SHA3_224         =  5,
	X509_SHA3_256         =  6,
	X509_SHA3_384         =  7,
	X509_SHA3_512         =  8,
	X509_SHA512_224       =  9,
	X509_SHA512_256       = 10,
	X509_SM3              = 11,
	X509_SHAKE256         = 12,
	X509_STREEBOG256      = 13,
	X509_STREEBOG512      = 14,
} x509_hash_alg;

/* All curves we support */
typedef enum {
	X509_UNKNOWN_CURVE    =  0,
	X509_FRP256V1         =  1,
	X509_SECP192R1        =  2,
	X509_SECP224R1        =  3,
	X509_SECP256R1        =  4,
	X509_SECP384R1        =  5,
	X509_SECP521R1        =  6,
	X509_BRAINPOOLP224R1  =  7,
	X509_BRAINPOOLP256R1  =  8,
	X509_BRAINPOOLP512R1  =  9,
	X509_GOST256          = 10,
	X509_GOST512          = 11,
	X509_BRAINPOOLP384R1  = 12,
	X509_BRAINPOOLP192R1  = 13,
	X509_WEI25519         = 14,
	X509_WEI448           = 15,
	X509_SM2P256V1        = 17,
} x509_curve;

#endif /* __X509_TYPES_H__ */
