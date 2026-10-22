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
#अगर_अघोषित DH_H
#घोषणा DH_H

#अगर_घोषित WITH_OPENSSL

काष्ठा dhgroup {
	पूर्णांक आकार;
	BIGNUM *g;
	BIGNUM *p;
};

DH	*choose_dh(पूर्णांक, पूर्णांक, पूर्णांक);
DH	*dh_new_group_asc(स्थिर अक्षर *, स्थिर अक्षर *);
DH	*dh_new_group(BIGNUM *, BIGNUM *);
DH	*dh_new_group1(व्योम);
DH	*dh_new_group14(व्योम);
DH	*dh_new_group16(व्योम);
DH	*dh_new_group18(व्योम);
DH	*dh_new_group_fallback(पूर्णांक);

पूर्णांक	 dh_gen_कुंजी(DH *, पूर्णांक);
पूर्णांक	 dh_pub_is_valid(स्थिर DH *, स्थिर BIGNUM *);

u_int	 dh_estimate(पूर्णांक);
व्योम	 dh_set_moduli_file(स्थिर अक्षर *);

/*
 * Max value from RFC4419.
 * Min value from RFC8270.
 */
#घोषणा DH_GRP_MIN	2048
#घोषणा DH_GRP_MAX	8192

/*
 * Values for "type" field of moduli(5)
 * Specifies the internal structure of the prime modulus.
 */
#घोषणा MODULI_TYPE_UNKNOWN		(0)
#घोषणा MODULI_TYPE_UNSTRUCTURED	(1)
#घोषणा MODULI_TYPE_SAFE		(2)
#घोषणा MODULI_TYPE_SCHNORR		(3)
#घोषणा MODULI_TYPE_SOPHIE_GERMAIN	(4)
#घोषणा MODULI_TYPE_STRONG		(5)

/*
 * Values for "tests" field of moduli(5)
 * Specifies the methods used in checking for primality.
 * Usually, more than one test is used.
 */
#घोषणा MODULI_TESTS_UNTESTED		(0x00)
#घोषणा MODULI_TESTS_COMPOSITE		(0x01)
#घोषणा MODULI_TESTS_SIEVE		(0x02)
#घोषणा MODULI_TESTS_MILLER_RABIN	(0x04)
#घोषणा MODULI_TESTS_JACOBI		(0x08)
#घोषणा MODULI_TESTS_ELLIPTIC		(0x10)

#पूर्ण_अगर /* WITH_OPENSSL */

#पूर्ण_अगर /* DH_H */
