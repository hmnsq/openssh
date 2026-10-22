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
#నిర్వచితం_కాకపోతే DH_H
#నిర్వచించు DH_H

#నిర్వచితమైతే WITH_OPENSSL

నిర్మాణం dhgroup {
	పూర్ణాంకం కొలత;
	BIGNUM *g;
	BIGNUM *p;
};

DH	*ఎంచుకో_dh(పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం);
DH	*dh_new_సమూహం_asc(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
DH	*dh_new_సమూహం(BIGNUM *, BIGNUM *);
DH	*dh_new_group1(శూన్య);
DH	*dh_new_group14(శూన్య);
DH	*dh_new_group16(శూన్య);
DH	*dh_new_group18(శూన్య);
DH	*dh_new_సమూహం_fallback(పూర్ణాంకం);

పూర్ణాంకం	 dh_gen_కీలకం(DH *, పూర్ణాంకం);
పూర్ణాంకం	 dh_pub_is_valid(స్థిరరాశి DH *, స్థిరరాశి BIGNUM *);

u_int	 dh_estimate(పూర్ణాంకం);
శూన్య	 dh_సమితి_moduli_file(స్థిరరాశి అక్షరం *);

/*
 * Max value from RFC4419.
 * Min value from RFC8270.
 */
#నిర్వచించు DH_GRP_MIN	2048
#నిర్వచించు DH_GRP_MAX	8192

/*
 * Values for "type" field of moduli(5)
 * Specifies the internal structure of the prime modulus.
 */
#నిర్వచించు MODULI_TYPE_UNKNOWN		(0)
#నిర్వచించు MODULI_TYPE_UNSTRUCTURED	(1)
#నిర్వచించు MODULI_TYPE_సురక్షిత		(2)
#నిర్వచించు MODULI_TYPE_SCHNORR		(3)
#నిర్వచించు MODULI_TYPE_SOPHIE_GERMAIN	(4)
#నిర్వచించు MODULI_TYPE_STRONG		(5)

/*
 * Values for "tests" field of moduli(5)
 * Specifies the methods used in checking for primality.
 * Usually, more than one test is used.
 */
#నిర్వచించు MODULI_TESTS_UNTESTED		(0x00)
#నిర్వచించు MODULI_TESTS_సంయుక్త		(0x01)
#నిర్వచించు MODULI_TESTS_SIEVE		(0x02)
#నిర్వచించు MODULI_TESTS_MILLER_RABIN	(0x04)
#నిర్వచించు MODULI_TESTS_JACOBI		(0x08)
#నిర్వచించు MODULI_TESTS_ELLIPTIC		(0x10)

#అయితే_ముగింపు /* WITH_OPENSSL */

#అయితే_ముగింపు /* DH_H */
