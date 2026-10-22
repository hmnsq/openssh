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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _CANOHOST_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _CANOHOST_H

ਅੱਖਰ		*get_peer_ipaddr(ਪੂਰਨ);
ਪੂਰਨ		 get_peer_ਪੋਰਟ(ਪੂਰਨ);
ਅੱਖਰ		*get_local_ipaddr(ਪੂਰਨ);
ਅੱਖਰ		*get_local_name(ਪੂਰਨ);
ਪੂਰਨ		get_local_ਪੋਰਟ(ਪੂਰਨ);

#ਜੇ_ਅੰਤ /* _CANOHOST_H */

ਖਾਲੀ		 ipv64_normalise_mapped(ਬਣਤਰ sockaddr_storage *, socklen_t *);
