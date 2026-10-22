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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ DNS_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DNS_H

ਗਿਣਤੀ sshfp_types {
	SSHFP_ਕੁੰਜੀ_RESERVED = 0,
	SSHFP_ਕੁੰਜੀ_RSA = 1,
	SSHFP_ਕੁੰਜੀ_DSA = 2,
	SSHFP_ਕੁੰਜੀ_ECDSA = 3,
	SSHFP_ਕੁੰਜੀ_ED25519 = 4
};

ਗਿਣਤੀ sshfp_hashes {
	SSHFP_HASH_RESERVED = 0,
	SSHFP_HASH_SHA1 = 1,
	SSHFP_HASH_SHA256 = 2,
	SSHFP_HASH_MAX = 3
};

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DNS_RDATACLASS_ਵਿੱਚ	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DNS_RDATATYPE_SSHFP	44

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DNS_VERIFY_ਮਿਲਿਆ	0x00000001
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DNS_VERIFY_ਮੇਲ	0x00000002
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DNS_VERIFY_SECURE	0x00000004
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DNS_VERIFY_FAILED	0x00000008

ਪੂਰਨ	verify_host_ਕੁੰਜੀ_dns(ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sockaddr *,
    ਬਣਤਰ sshkey *, ਪੂਰਨ *);
ਪੂਰਨ	export_dns_rr(ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sshkey *, FILE *, ਪੂਰਨ, ਪੂਰਨ);

#ਜੇ_ਅੰਤ /* DNS_H */
