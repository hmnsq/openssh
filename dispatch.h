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

#ifndef DISPATCH_H
#define DISPATCH_H

#define DISPATCH_MAX	255

شمارش {
	DISPATCH_BLOCK,
	DISPATCH_NONBLOCK
};

ساختار ssh;

تعریفنوع صحیح dispatch_fn(صحیح, uint32_t, ساختار ssh *);

صحیح	dispatch_protocol_error(صحیح, uint32_t, ساختار ssh *);
صحیح	dispatch_protocol_ignore(صحیح, uint32_t, ساختار ssh *);
تهی	ssh_dispatch_init(ساختار ssh *, dispatch_fn *);
تهی	ssh_dispatch_set(ساختار ssh *, صحیح, dispatch_fn *);
تهی	ssh_dispatch_range(ساختار ssh *, u_int, u_int, dispatch_fn *);
صحیح	ssh_dispatch_run(ساختار ssh *, صحیح, فرار sig_atomic_t *);
تهی	ssh_dispatch_run_fatal(ساختار ssh *, صحیح, فرار sig_atomic_t *);

#endif
