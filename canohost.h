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

അക്ഷരം		*get_peer_ipaddr(പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ		 get_peer_port(പൂർണ്ണസംഖ്യ);
അക്ഷരം		*get_local_ipaddr(പൂർണ്ണസംഖ്യ);
അക്ഷരം		*get_local_name(പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ		get_local_port(പൂർണ്ണസംഖ്യ);

#endif /* _CANOHOST_H */

ശൂന്യം		 ipv64_normalise_mapped(ഘടന sockaddr_storage *, socklen_t *);
