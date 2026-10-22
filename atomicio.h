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

संरचना iovec;

/*
 * Ensure all of data on socket comes through. f==read || f==vwrite
 */
माप_प्रकार
atomicio6(ssize_t (*f) (पूर्णाङ्क, शून्य *, माप_प्रकार), पूर्णाङ्क fd, शून्य *_s, माप_प्रकार n,
    पूर्णाङ्क (*cb)(शून्य *, माप_प्रकार), शून्य *);
माप_प्रकार	atomicio(ssize_t (*)(पूर्णाङ्क, शून्य *, माप_प्रकार), पूर्णाङ्क, शून्य *, माप_प्रकार);

#define vwrite (ssize_t (*)(पूर्णाङ्क, शून्य *, माप_प्रकार))लिख

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
माप_प्रकार
atomiciov6(ssize_t (*f) (पूर्णाङ्क, अचर संरचना iovec *, पूर्णाङ्क), पूर्णाङ्क fd,
    अचर संरचना iovec *_iov, पूर्णाङ्क iovcnt, पूर्णाङ्क (*cb)(शून्य *, माप_प्रकार), शून्य *);
माप_प्रकार	atomiciov(ssize_t (*)(पूर्णाङ्क, अचर संरचना iovec *, पूर्णाङ्क),
    पूर्णाङ्क, अचर संरचना iovec *, पूर्णाङ्क);

#endif /* _ATOMICIO_H */
