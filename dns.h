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

#که_نه_تعریف_شوی DNS_H
#تعریف_کړه DNS_H

تعداد sshfp_types {
	SSHFP_کلی_RESERVED = 0,
	SSHFP_کلی_RSA = 1,
	SSHFP_کلی_DSA = 2,
	SSHFP_کلی_ECDSA = 3,
	SSHFP_کلی_ED25519 = 4
};

تعداد sshfp_hashes {
	SSHFP_HASH_RESERVED = 0,
	SSHFP_HASH_SHA1 = 1,
	SSHFP_HASH_SHA256 = 2,
	SSHFP_HASH_MAX = 3
};

#تعریف_کړه DNS_RDATACLASS_دننه	1
#تعریف_کړه DNS_RDATATYPE_SSHFP	44

#تعریف_کړه DNS_VERIFY_وموندل	0x00000001
#تعریف_کړه DNS_VERIFY_سمون	0x00000002
#تعریف_کړه DNS_VERIFY_SECURE	0x00000004
#تعریف_کړه DNS_VERIFY_FAILED	0x00000008

صحيح	verify_host_کلی_dns(ثابت حرف *, بنية sockaddr *,
    بنية sshkey *, صحيح *);
صحيح	export_dns_rr(ثابت حرف *, بنية sshkey *, FILE *, صحيح, صحيح);

#د_که_پای /* DNS_H */
