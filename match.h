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
#ifndef MATCH_H
#define MATCH_H

صحيح	 match_pattern(ثابت حرف *, ثابت حرف *);
صحيح	 match_pattern_list(ثابت حرف *, ثابت حرف *, صحيح);
صحيح	 match_usergroup_pattern_list(ثابت حرف *, ثابت حرف *);
صحيح	 match_hostname(ثابت حرف *, ثابت حرف *);
صحيح	 match_host_and_ip(ثابت حرف *, ثابت حرف *, ثابت حرف *);
صحيح	 match_user(ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *);
حرف	*match_list(ثابت حرف *, ثابت حرف *, u_int *);
حرف	*match_filter_denylist(ثابت حرف *, ثابت حرف *);
حرف	*match_filter_allowlist(ثابت حرف *, ثابت حرف *);

/* addrmatch.c */
صحيح	 addr_match_list(ثابت حرف *, ثابت حرف *);
صحيح	 addr_match_cidr_list(ثابت حرف *, ثابت حرف *);
#endif
