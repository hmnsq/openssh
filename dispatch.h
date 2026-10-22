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

ଗଣନା {
	DISPATCH_BLOCK,
	DISPATCH_NONBLOCK
};

ସଂରଚନା ssh;

ପ୍ରକାରବ୍ୟାଖ୍ୟା ପୂର୍ଣ୍ଣସଂଖ୍ୟା dispatch_fn(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	dispatch_protocol_error(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	dispatch_protocol_ignore(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ଶୂନ୍ୟ	ssh_dispatch_init(ସଂରଚନା ssh *, dispatch_fn *);
ଶୂନ୍ୟ	ssh_dispatch_set(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, dispatch_fn *);
ଶୂନ୍ୟ	ssh_dispatch_range(ସଂରଚନା ssh *, u_int, u_int, dispatch_fn *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_dispatch_run(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅସ୍ଥିର sig_atomic_t *);
ଶୂନ୍ୟ	ssh_dispatch_run_fatal(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅସ୍ଥିର sig_atomic_t *);

#endif
