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

#अगर_अघोषित _CANOHOST_H
#घोषणा _CANOHOST_H

अक्षर		*get_peer_ipaddr(पूर्णांक);
पूर्णांक		 get_peer_port(पूर्णांक);
अक्षर		*get_local_ipaddr(पूर्णांक);
अक्षर		*get_local_name(पूर्णांक);
पूर्णांक		get_local_port(पूर्णांक);

#पूर्ण_अगर /* _CANOHOST_H */

व्योम		 ipv64_normalise_mapped(काष्ठा sockaddr_storage *, socklen_t *);
