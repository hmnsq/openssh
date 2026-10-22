/* $OpenBSD: match.h,v 1.20 2020/07/05 23:59:45 djm Exp $ */

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
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਮੇਲ_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਮੇਲ_H

ਪੂਰਨ	 ਮੇਲ_ਨਮੂਨਾ(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 ਮੇਲ_ਨਮੂਨਾ_list(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);
ਪੂਰਨ	 ਮੇਲ_usergroup_ਨਮੂਨਾ_list(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 ਮੇਲ_hostname(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 ਮੇਲ_host_and_ip(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 ਮੇਲ_user(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਅੱਖਰ	*ਮੇਲ_list(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, u_int *);
ਅੱਖਰ	*ਮੇਲ_filter_denylist(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਅੱਖਰ	*ਮੇਲ_filter_allowlist(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);

/* addrmatch.c */
ਪੂਰਨ	 addr_ਮੇਲ_list(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 addr_ਮੇਲ_cidr_list(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
#ਜੇ_ਅੰਤ
