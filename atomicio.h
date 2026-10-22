/* $OpenBSD: atomicio.h,v 1.12 2018/12/27 03:25:25 djm Exp $ */

/*
 * Copyright (c) 2006 Damien Miller.  All rights reserved.
 * Copyright (c) 1995,1999 Theo de Raadt.  All rights reserved.
 * All rights reserved.
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

#నిర్వచితం_కాకపోతే _ATOMICIO_H
#నిర్వచించు _ATOMICIO_H

నిర్మాణం iovec;

/*
 * Ensure all of data on socket comes through. f==read || f==vwrite
 */
కొలత_t
atomicio6(ssize_t (*f) (పూర్ణాంకం, శూన్య *, కొలత_t), పూర్ణాంకం fd, శూన్య *_s, కొలత_t n,
    పూర్ణాంకం (*cb)(శూన్య *, కొలత_t), శూన్య *);
కొలత_t	atomicio(ssize_t (*)(పూర్ణాంకం, శూన్య *, కొలత_t), పూర్ణాంకం, శూన్య *, కొలత_t);

#నిర్వచించు vwrite (ssize_t (*)(పూర్ణాంకం, శూన్య *, కొలత_t))లిఖ

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
కొలత_t
atomiciov6(ssize_t (*f) (పూర్ణాంకం, స్థిరరాశి నిర్మాణం iovec *, పూర్ణాంకం), పూర్ణాంకం fd,
    స్థిరరాశి నిర్మాణం iovec *_iov, పూర్ణాంకం iovcnt, పూర్ణాంకం (*cb)(శూన్య *, కొలత_t), శూన్య *);
కొలత_t	atomiciov(ssize_t (*)(పూర్ణాంకం, స్థిరరాశి నిర్మాణం iovec *, పూర్ణాంకం),
    పూర్ణాంకం, స్థిరరాశి నిర్మాణం iovec *, పూర్ణాంకం);

#అయితే_ముగింపు /* _ATOMICIO_H */
