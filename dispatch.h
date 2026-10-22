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

ಗಣನಾ {
	DISPATCH_BLOCK,
	DISPATCH_NONBLOCK
};

ಸಂರಚನಾ ssh;

ಪ್ರಕಾರನಿರ್ದೇಶ ಪೂರ್ಣಾಙ್ಕ dispatch_fn(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);

ಪೂರ್ಣಾಙ್ಕ	dispatch_protocol_error(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	dispatch_protocol_ignore(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ	ssh_dispatch_init(ಸಂರಚನಾ ssh *, dispatch_fn *);
ಶೂನ್ಯ	ssh_dispatch_set(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, dispatch_fn *);
ಶೂನ್ಯ	ssh_dispatch_range(ಸಂರಚನಾ ssh *, u_int, u_int, dispatch_fn *);
ಪೂರ್ಣಾಙ್ಕ	ssh_dispatch_run(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಚಞ್ಚಲ sig_atomic_t *);
ಶೂನ್ಯ	ssh_dispatch_run_fatal(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಚಞ್ಚಲ sig_atomic_t *);

#endif
