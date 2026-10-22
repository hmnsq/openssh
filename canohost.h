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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _CANOHOST_H
#ವ್ಯಾಖ್ಯಾನಿಸು _CANOHOST_H

ಅಕ್ಷರ		*get_peer_ipaddr(ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ		 get_peer_ಪೋರ್ಟ್(ಪೂರ್ಣಾಂಕ);
ಅಕ್ಷರ		*get_local_ipaddr(ಪೂರ್ಣಾಂಕ);
ಅಕ್ಷರ		*get_local_name(ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ		get_local_ಪೋರ್ಟ್(ಪೂರ್ಣಾಂಕ);

#ಆದರೆ_ಅಂತ್ಯ /* _CANOHOST_H */

ಶೂನ್ಯ		 ipv64_normalise_mapped(ರಚನೆ sockaddr_storage *, socklen_t *);
