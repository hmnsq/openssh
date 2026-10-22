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
#यदि_अपरिभाषितम् DH_H
#परिभाषय DH_H

#यदि_परिभाषितम् WITH_OPENSSL

संरचना dhgroup {
	पूर्णाङ्क आकार;
	BIGNUM *g;
	BIGNUM *p;
};

DH	*वृणु_dh(पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क);
DH	*dh_new_गणः_asc(ध्रुव वर्ण *, ध्रुव वर्ण *);
DH	*dh_new_गणः(BIGNUM *, BIGNUM *);
DH	*dh_new_group1(शून्य);
DH	*dh_new_group14(शून्य);
DH	*dh_new_group16(शून्य);
DH	*dh_new_group18(शून्य);
DH	*dh_new_गणः_fallback(पूर्णाङ्क);

पूर्णाङ्क	 dh_gen_कुञ्चिका(DH *, पूर्णाङ्क);
पूर्णाङ्क	 dh_pub_is_valid(ध्रुव DH *, ध्रुव BIGNUM *);

u_int	 dh_estimate(पूर्णाङ्क);
शून्य	 dh_समुच्चयः_moduli_file(ध्रुव वर्ण *);

/*
 * Max value from RFC4419.
 * Min value from RFC8270.
 */
#परिभाषय DH_GRP_MIN	2048
#परिभाषय DH_GRP_MAX	8192

/*
 * Values for "type" field of moduli(5)
 * Specifies the internal structure of the prime modulus.
 */
#परिभाषय MODULI_TYPE_UNKNOWN		(0)
#परिभाषय MODULI_TYPE_UNSTRUCTURED	(1)
#परिभाषय MODULI_TYPE_SAFE		(2)
#परिभाषय MODULI_TYPE_SCHNORR		(3)
#परिभाषय MODULI_TYPE_SOPHIE_GERMAIN	(4)
#परिभाषय MODULI_TYPE_STRONG		(5)

/*
 * Values for "tests" field of moduli(5)
 * Specifies the methods used in checking for primality.
 * Usually, more than one test is used.
 */
#परिभाषय MODULI_TESTS_UNTESTED		(0x00)
#परिभाषय MODULI_TESTS_संयुक्त		(0x01)
#परिभाषय MODULI_TESTS_SIEVE		(0x02)
#परिभाषय MODULI_TESTS_MILLER_RABIN	(0x04)
#परिभाषय MODULI_TESTS_JACOBI		(0x08)
#परिभाषय MODULI_TESTS_ELLIPTIC		(0x10)

#यदि_अन्तः /* WITH_OPENSSL */

#यदि_अन्तः /* DH_H */
