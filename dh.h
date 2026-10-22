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
#که_نه_تعریف_شوی DH_H
#تعریف_کړه DH_H

#که_تعریف_شوی WITH_OPENSSL

بنية dhgroup {
	صحيح اندازه;
	BIGNUM *g;
	BIGNUM *p;
};

DH	*ټاکنه_dh(صحيح, صحيح, صحيح);
DH	*dh_new_ډله_asc(ثابت حرف *, ثابت حرف *);
DH	*dh_new_ډله(BIGNUM *, BIGNUM *);
DH	*dh_new_group1(فراغ);
DH	*dh_new_group14(فراغ);
DH	*dh_new_group16(فراغ);
DH	*dh_new_group18(فراغ);
DH	*dh_new_ډله_fallback(صحيح);

صحيح	 dh_gen_کلی(DH *, صحيح);
صحيح	 dh_pub_is_valid(ثابت DH *, ثابت BIGNUM *);

u_int	 dh_estimate(صحيح);
فراغ	 dh_سېټ_moduli_file(ثابت حرف *);

/*
 * Max value from RFC4419.
 * Min value from RFC8270.
 */
#تعریف_کړه DH_GRP_MIN	2048
#تعریف_کړه DH_GRP_MAX	8192

/*
 * Values for "type" field of moduli(5)
 * Specifies the internal structure of the prime modulus.
 */
#تعریف_کړه MODULI_TYPE_UNKNOWN		(0)
#تعریف_کړه MODULI_TYPE_UNSTRUCTURED	(1)
#تعریف_کړه MODULI_TYPE_خوندي		(2)
#تعریف_کړه MODULI_TYPE_SCHNORR		(3)
#تعریف_کړه MODULI_TYPE_SOPHIE_GERMAIN	(4)
#تعریف_کړه MODULI_TYPE_STRONG		(5)

/*
 * Values for "tests" field of moduli(5)
 * Specifies the methods used in checking for primality.
 * Usually, more than one test is used.
 */
#تعریف_کړه MODULI_TESTS_UNTESTED		(0x00)
#تعریف_کړه MODULI_TESTS_مرکب		(0x01)
#تعریف_کړه MODULI_TESTS_SIEVE		(0x02)
#تعریف_کړه MODULI_TESTS_MILLER_RABIN	(0x04)
#تعریف_کړه MODULI_TESTS_JACOBI		(0x08)
#تعریف_کړه MODULI_TESTS_ELLIPTIC		(0x10)

#د_که_پای /* WITH_OPENSSL */

#د_که_پای /* DH_H */
