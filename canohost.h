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

অক্ষর		*get_peer_ipaddr(পূর্ণসংখ্যা);
পূর্ণসংখ্যা		 get_peer_port(পূর্ণসংখ্যা);
অক্ষর		*get_local_ipaddr(পূর্ণসংখ্যা);
অক্ষর		*get_local_name(পূর্ণসংখ্যা);
পূর্ণসংখ্যা		get_local_port(পূর্ণসংখ্যা);

#endif /* _CANOHOST_H */

শূন্য		 ipv64_normalise_mapped(কাঠামো sockaddr_storage *, socklen_t *);
