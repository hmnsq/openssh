/* $OpenBSD: dns.h,v 1.21 2025/08/29 03:50:38 djm Exp $ */

/*
 * Copyright (c) 2003 Wesley Griffin. All rights reserved.
 * Copyright (c) 2003 Jakob Schlyter. All rights reserved.
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

#నిర్వచితం_కాకపోతే DNS_H
#నిర్వచించు DNS_H

గణన sshfp_types {
	SSHFP_కీలకం_RESERVED = 0,
	SSHFP_కీలకం_RSA = 1,
	SSHFP_కీలకం_DSA = 2,
	SSHFP_కీలకం_ECDSA = 3,
	SSHFP_కీలకం_ED25519 = 4
};

గణన sshfp_hashes {
	SSHFP_HASH_RESERVED = 0,
	SSHFP_HASH_SHA1 = 1,
	SSHFP_HASH_SHA256 = 2,
	SSHFP_HASH_MAX = 3
};

#నిర్వచించు DNS_RDATACLASS_లోపల	1
#నిర్వచించు DNS_RDATATYPE_SSHFP	44

#నిర్వచించు DNS_VERIFY_దొరికింది	0x00000001
#నిర్వచించు DNS_VERIFY_సరిపోలిక	0x00000002
#నిర్వచించు DNS_VERIFY_SECURE	0x00000004
#నిర్వచించు DNS_VERIFY_FAILED	0x00000008

పూర్ణాంకం	verify_host_కీలకం_dns(స్థిరరాశి అక్షరం *, నిర్మాణం sockaddr *,
    నిర్మాణం sshkey *, పూర్ణాంకం *);
పూర్ణాంకం	export_dns_rr(స్థిరరాశి అక్షరం *, నిర్మాణం sshkey *, FILE *, పూర్ణాంకం, పూర్ణాంకం);

#అయితే_ముగింపు /* DNS_H */
