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

#ifndef _ATOMICIO_H
#define _ATOMICIO_H

সংরচনা iovec;

/*
 * Ensure all of data on socket comes through. f==read || f==vwrite
 */
size_t
atomicio6(ssize_t (*f) (পূর্ণাঙ্ক, শূন্য *, size_t), পূর্ণাঙ্ক fd, শূন্য *_s, size_t n,
    পূর্ণাঙ্ক (*cb)(শূন্য *, size_t), শূন্য *);
size_t	atomicio(ssize_t (*)(পূর্ণাঙ্ক, শূন্য *, size_t), পূর্ণাঙ্ক, শূন্য *, size_t);

#define vwrite (ssize_t (*)(পূর্ণাঙ্ক, শূন্য *, size_t))লিখ

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
size_t
atomiciov6(ssize_t (*f) (পূর্ণাঙ্ক, ধ্রুব সংরচনা iovec *, পূর্ণাঙ্ক), পূর্ণাঙ্ক fd,
    ধ্রুব সংরচনা iovec *_iov, পূর্ণাঙ্ক iovcnt, পূর্ণাঙ্ক (*cb)(শূন্য *, size_t), শূন্য *);
size_t	atomiciov(ssize_t (*)(পূর্ণাঙ্ক, ধ্রুব সংরচনা iovec *, পূর্ণাঙ্ক),
    পূর্ণাঙ্ক, ধ্রুব সংরচনা iovec *, পূর্ণাঙ্ক);

#endif /* _ATOMICIO_H */
