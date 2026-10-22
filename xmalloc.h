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

शून्य	*xmalloc(माप_प्रकार);
शून्य	*xcalloc(माप_प्रकार, माप_प्रकार);
शून्य	*xreallocarray(शून्य *, माप_प्रकार, माप_प्रकार);
शून्य	*xrecallocarray(शून्य *, माप_प्रकार, माप_प्रकार, माप_प्रकार);
वर्ण	*xstrdup(अचर वर्ण *);
पूर्णाङ्क	 xasprintf(वर्ण **, अचर वर्ण *, ...)
    __attribute__((__format__ (म_लिखो, 2, 3))) __attribute__((__nonnull__ (2)));
पूर्णाङ्क	 xvasprintf(वर्ण **, अचर वर्ण *, बहु_सूची)
    __attribute__((__nonnull__ (2)));
