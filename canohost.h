/* $OpenBSD: canohost.h,v 1.12 2016/03/07 19:02:43 djm Exp $ */

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

#اگر_تعریف_نشده _CANOHOST_H
#تعریف_کن _CANOHOST_H

حرف		*get_peer_ipaddr(صحيح);
صحيح		 get_peer_پورت(صحيح);
حرف		*get_local_ipaddr(صحيح);
حرف		*get_local_name(صحيح);
صحيح		get_local_پورت(صحيح);

#پایان_اگر /* _CANOHOST_H */

فراغ		 ipv64_normalise_mapped(بنية sockaddr_storage *, socklen_t *);
