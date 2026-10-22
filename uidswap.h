/* $OpenBSD: uidswap.h,v 1.14 2018/07/18 11:34:05 dtucker Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

व्योम	 temporarily_use_uid(काष्ठा passwd *);
व्योम	 restore_uid(व्योम);
व्योम	 permanently_set_uid(काष्ठा passwd *);
