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

#جيڪڏهن_وصف_نه_ٿيل DNS_H
#وصف_ڪريو DNS_H

تعداد sshfp_types {
	SSHFP_ڪنجي_RESERVED = 0,
	SSHFP_ڪنجي_RSA = 1,
	SSHFP_ڪنجي_DSA = 2,
	SSHFP_ڪنجي_ECDSA = 3,
	SSHFP_ڪنجي_ED25519 = 4
};

تعداد sshfp_hashes {
	SSHFP_HASH_RESERVED = 0,
	SSHFP_HASH_SHA1 = 1,
	SSHFP_HASH_SHA256 = 2,
	SSHFP_HASH_MAX = 3
};

#وصف_ڪريو DNS_RDATACLASS_اندريون	1
#وصف_ڪريو DNS_RDATATYPE_SSHFP	44

#وصف_ڪريو DNS_VERIFY_مليو	0x00000001
#وصف_ڪريو DNS_VERIFY_ميلاپ	0x00000002
#وصف_ڪريو DNS_VERIFY_SECURE	0x00000004
#وصف_ڪريو DNS_VERIFY_FAILED	0x00000008

صحيح	verify_host_ڪنجي_dns(ثابت حرف *, بنية sockaddr *,
    بنية sshkey *, صحيح *);
صحيح	export_dns_rr(ثابت حرف *, بنية sshkey *, FILE *, صحيح, صحيح);

#جيڪڏهن_پورو /* DNS_H */
