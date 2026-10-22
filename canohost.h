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

#اگر_غیر_تعریف_شدہ _CANOHOST_H
#تعریف_کرو _CANOHOST_H

حرف		*get_peer_ipaddr(صحیح);
صحیح		 get_peer_پورٹ(صحیح);
حرف		*get_local_ipaddr(صحیح);
حرف		*get_local_name(صحیح);
صحیح		get_local_پورٹ(صحیح);

#اگر_ختم /* _CANOHOST_H */

خالی		 ipv64_normalise_mapped(ساخت sockaddr_storage *, socklen_t *);
