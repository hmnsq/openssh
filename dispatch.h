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

#నిర్వచితం_కాకపోతే DISPATCH_H
#నిర్వచించు DISPATCH_H

#నిర్వచించు DISPATCH_MAX	255

గణన {
	DISPATCH_ఖండం,
	DISPATCH_NONBLOCK
};

నిర్మాణం ssh;

రకనిర్వచనం పూర్ణాంకం dispatch_fn(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);

పూర్ణాంకం	dispatch_protocol_error(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
పూర్ణాంకం	dispatch_protocol_ignore(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
శూన్య	ssh_dispatch_init(నిర్మాణం ssh *, dispatch_fn *);
శూన్య	ssh_dispatch_సమితి(నిర్మాణం ssh *, పూర్ణాంకం, dispatch_fn *);
శూన్య	ssh_dispatch_range(నిర్మాణం ssh *, u_int, u_int, dispatch_fn *);
పూర్ణాంకం	ssh_dispatch_నిరంతరం(నిర్మాణం ssh *, పూర్ణాంకం, అస్థిర sig_atomic_t *);
శూన్య	ssh_dispatch_నిరంతరం_fatal(నిర్మాణం ssh *, పూర్ణాంకం, అస్థిర sig_atomic_t *);

#అయితే_ముగింపు
