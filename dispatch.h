/* $OpenBSD: dispatch.h,v 1.16 2026/03/03 09:57:25 dtucker Exp $ */

/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ DISPATCH_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DISPATCH_H

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DISPATCH_MAX	255

ਗਿਣਤੀ {
	DISPATCH_ਖੰਡ,
	DISPATCH_NONBLOCK
};

ਬਣਤਰ ssh;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਪੂਰਨ dispatch_fn(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);

ਪੂਰਨ	dispatch_protocol_error(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਪੂਰਨ	dispatch_protocol_ignore(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਖਾਲੀ	ssh_dispatch_init(ਬਣਤਰ ssh *, dispatch_fn *);
ਖਾਲੀ	ssh_dispatch_ਸੈੱਟ(ਬਣਤਰ ssh *, ਪੂਰਨ, dispatch_fn *);
ਖਾਲੀ	ssh_dispatch_range(ਬਣਤਰ ssh *, u_int, u_int, dispatch_fn *);
ਪੂਰਨ	ssh_dispatch_ਲੜੀਵਾਰ(ਬਣਤਰ ssh *, ਪੂਰਨ, ਅਸਥਿਰ sig_atomic_t *);
ਖਾਲੀ	ssh_dispatch_ਲੜੀਵਾਰ_fatal(ਬਣਤਰ ssh *, ਪੂਰਨ, ਅਸਥਿਰ sig_atomic_t *);

#ਜੇ_ਅੰਤ
