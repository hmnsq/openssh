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

#ifndef _CANOHOST_H
#define _CANOHOST_H

ವರ್ಣ		*get_peer_ipaddr(ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ		 get_peer_port(ಪೂರ್ಣಾಙ್ಕ);
ವರ್ಣ		*get_local_ipaddr(ಪೂರ್ಣಾಙ್ಕ);
ವರ್ಣ		*get_local_name(ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ		get_local_port(ಪೂರ್ಣಾಙ್ಕ);

#endif /* _CANOHOST_H */

ಶೂನ್ಯ		 ipv64_normalise_mapped(ಸಂರಚನಾ sockaddr_storage *, socklen_t *);
