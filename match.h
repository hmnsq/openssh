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

صحیح	 match_pattern(ثابت نویسه *, ثابت نویسه *);
صحیح	 match_pattern_list(ثابت نویسه *, ثابت نویسه *, صحیح);
صحیح	 match_usergroup_pattern_list(ثابت نویسه *, ثابت نویسه *);
صحیح	 match_hostname(ثابت نویسه *, ثابت نویسه *);
صحیح	 match_host_and_ip(ثابت نویسه *, ثابت نویسه *, ثابت نویسه *);
صحیح	 match_user(ثابت نویسه *, ثابت نویسه *, ثابت نویسه *, ثابت نویسه *);
نویسه	*match_list(ثابت نویسه *, ثابت نویسه *, u_int *);
نویسه	*match_filter_denylist(ثابت نویسه *, ثابت نویسه *);
نویسه	*match_filter_allowlist(ثابت نویسه *, ثابت نویسه *);

/* addrmatch.c */
صحیح	 addr_match_list(ثابت نویسه *, ثابت نویسه *);
صحیح	 addr_match_cidr_list(ثابت نویسه *, ثابت نویسه *);
#endif
