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

#నిర్వచితం_కాకపోతే _CANOHOST_H
#నిర్వచించు _CANOHOST_H

అక్షరం		*get_peer_ipaddr(పూర్ణాంకం);
పూర్ణాంకం		 get_peer_పోర్టు(పూర్ణాంకం);
అక్షరం		*get_local_ipaddr(పూర్ణాంకం);
అక్షరం		*get_local_name(పూర్ణాంకం);
పూర్ణాంకం		get_local_పోర్టు(పూర్ణాంకం);

#అయితే_ముగింపు /* _CANOHOST_H */

శూన్య		 ipv64_normalise_mapped(నిర్మాణం sockaddr_storage *, socklen_t *);
