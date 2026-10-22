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
#جيڪڏهن_وصف_نه_ٿيل DH_H
#وصف_ڪريو DH_H

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL

بنية dhgroup {
	صحيح سائيز;
	BIGNUM *g;
	BIGNUM *p;
};

DH	*چونڊيو_dh(صحيح, صحيح, صحيح);
DH	*dh_new_گروهه_asc(ثابت حرف *, ثابت حرف *);
DH	*dh_new_گروهه(BIGNUM *, BIGNUM *);
DH	*dh_new_group1(فراغ);
DH	*dh_new_group14(فراغ);
DH	*dh_new_group16(فراغ);
DH	*dh_new_group18(فراغ);
DH	*dh_new_گروهه_fallback(صحيح);

صحيح	 dh_gen_ڪنجي(DH *, صحيح);
صحيح	 dh_pub_is_valid(ثابت DH *, ثابت BIGNUM *);

u_int	 dh_estimate(صحيح);
فراغ	 dh_سيٽ_moduli_file(ثابت حرف *);

/*
 * Max value from RFC4419.
 * Min value from RFC8270.
 */
#وصف_ڪريو DH_GRP_MIN	2048
#وصف_ڪريو DH_GRP_MAX	8192

/*
 * Values for "type" field of moduli(5)
 * Specifies the internal structure of the prime modulus.
 */
#وصف_ڪريو MODULI_TYPE_UNKNOWN		(0)
#وصف_ڪريو MODULI_TYPE_UNSTRUCTURED	(1)
#وصف_ڪريو MODULI_TYPE_محفوظ		(2)
#وصف_ڪريو MODULI_TYPE_SCHNORR		(3)
#وصف_ڪريو MODULI_TYPE_SOPHIE_GERMAIN	(4)
#وصف_ڪريو MODULI_TYPE_STRONG		(5)

/*
 * Values for "tests" field of moduli(5)
 * Specifies the methods used in checking for primality.
 * Usually, more than one test is used.
 */
#وصف_ڪريو MODULI_TESTS_UNTESTED		(0x00)
#وصف_ڪريو MODULI_TESTS_مرکب		(0x01)
#وصف_ڪريو MODULI_TESTS_SIEVE		(0x02)
#وصف_ڪريو MODULI_TESTS_MILLER_RABIN	(0x04)
#وصف_ڪريو MODULI_TESTS_JACOBI		(0x08)
#وصف_ڪريو MODULI_TESTS_ELLIPTIC		(0x10)

#جيڪڏهن_پورو /* WITH_OPENSSL */

#جيڪڏهن_پورو /* DH_H */
