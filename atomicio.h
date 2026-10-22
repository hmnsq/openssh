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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _ATOMICIO_H
#ವ್ಯಾಖ್ಯಾನಿಸು _ATOMICIO_H

ರಚನೆ iovec;

/*
 * Ensure all of data on socket comes through. f==read || f==vwrite
 */
ಗಾತ್ರ_t
atomicio6(ssize_t (*f) (ಪೂರ್ಣಾಂಕ, ಶೂನ್ಯ *, ಗಾತ್ರ_t), ಪೂರ್ಣಾಂಕ fd, ಶೂನ್ಯ *_s, ಗಾತ್ರ_t n,
    ಪೂರ್ಣಾಂಕ (*cb)(ಶೂನ್ಯ *, ಗಾತ್ರ_t), ಶೂನ್ಯ *);
ಗಾತ್ರ_t	atomicio(ssize_t (*)(ಪೂರ್ಣಾಂಕ, ಶೂನ್ಯ *, ಗಾತ್ರ_t), ಪೂರ್ಣಾಂಕ, ಶೂನ್ಯ *, ಗಾತ್ರ_t);

#ವ್ಯಾಖ್ಯಾನಿಸು vwrite (ssize_t (*)(ಪೂರ್ಣಾಂಕ, ಶೂನ್ಯ *, ಗಾತ್ರ_t))ಲಿಖ

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
ಗಾತ್ರ_t
atomiciov6(ssize_t (*f) (ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ರಚನೆ iovec *, ಪೂರ್ಣಾಂಕ), ಪೂರ್ಣಾಂಕ fd,
    ಸ್ಥಿರಾಂಕ ರಚನೆ iovec *_iov, ಪೂರ್ಣಾಂಕ iovcnt, ಪೂರ್ಣಾಂಕ (*cb)(ಶೂನ್ಯ *, ಗಾತ್ರ_t), ಶೂನ್ಯ *);
ಗಾತ್ರ_t	atomiciov(ssize_t (*)(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ರಚನೆ iovec *, ಪೂರ್ಣಾಂಕ),
    ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ರಚನೆ iovec *, ಪೂರ್ಣಾಂಕ);

#ಆದರೆ_ಅಂತ್ಯ /* _ATOMICIO_H */
