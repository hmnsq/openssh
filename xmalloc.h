/* $OpenBSD: xmalloc.h,v 1.20 2021/04/03 06:18:41 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Created: Mon Mar 20 22:09:17 1995 ylo
 *
 * Versions of malloc and friends that check their results, and never return
 * failure (they call fatal if they encounter an error).
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

ശൂന്യം	*xmalloc(size_t);
ശൂന്യം	*xcalloc(size_t, size_t);
ശൂന്യം	*xreallocarray(ശൂന്യം *, size_t, size_t);
ശൂന്യം	*xrecallocarray(ശൂന്യം *, size_t, size_t, size_t);
അക്ഷരം	*xstrdup(സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 xasprintf(അക്ഷരം **, സ്ഥിരം അക്ഷരം *, ...)
    __attribute__((__format__ (printf, 2, 3))) __attribute__((__nonnull__ (2)));
പൂർണ്ണസംഖ്യ	 xvasprintf(അക്ഷരം **, സ്ഥിരം അക്ഷരം *, va_list)
    __attribute__((__nonnull__ (2)));
