/* $OpenBSD: dh.h,v 1.19 2021/03/12 04:08:19 dtucker Exp $ */

/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ DH_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DH_H

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL

ਬਣਤਰ dhgroup {
	ਪੂਰਨ ਮਾਪ;
	BIGNUM *g;
	BIGNUM *p;
};

DH	*ਚੁਣੋ_dh(ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ);
DH	*dh_new_ਸਮੂਹ_asc(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
DH	*dh_new_ਸਮੂਹ(BIGNUM *, BIGNUM *);
DH	*dh_new_group1(ਖਾਲੀ);
DH	*dh_new_group14(ਖਾਲੀ);
DH	*dh_new_group16(ਖਾਲੀ);
DH	*dh_new_group18(ਖਾਲੀ);
DH	*dh_new_ਸਮੂਹ_fallback(ਪੂਰਨ);

ਪੂਰਨ	 dh_gen_ਕੁੰਜੀ(DH *, ਪੂਰਨ);
ਪੂਰਨ	 dh_pub_is_valid(ਅਚਲ DH *, ਅਚਲ BIGNUM *);

u_int	 dh_estimate(ਪੂਰਨ);
ਖਾਲੀ	 dh_ਸੈੱਟ_moduli_file(ਅਚਲ ਅੱਖਰ *);

/*
 * Max value from RFC4419.
 * Min value from RFC8270.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DH_GRP_MIN	2048
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DH_GRP_MAX	8192

/*
 * Values for "type" field of moduli(5)
 * Specifies the internal structure of the prime modulus.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MODULI_TYPE_UNKNOWN		(0)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MODULI_TYPE_UNSTRUCTURED	(1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MODULI_TYPE_ਸੁਰੱਖਿਅਤ		(2)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MODULI_TYPE_SCHNORR		(3)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MODULI_TYPE_SOPHIE_GERMAIN	(4)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MODULI_TYPE_STRONG		(5)

/*
 * Values for "tests" field of moduli(5)
 * Specifies the methods used in checking for primality.
 * Usually, more than one test is used.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MODULI_TESTS_UNTESTED		(0x00)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MODULI_TESTS_ਸੰਯੁਕਤ		(0x01)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MODULI_TESTS_SIEVE		(0x02)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MODULI_TESTS_MILLER_RABIN	(0x04)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MODULI_TESTS_JACOBI		(0x08)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MODULI_TESTS_ELLIPTIC		(0x10)

#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

#ਜੇ_ਅੰਤ /* DH_H */
