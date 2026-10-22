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

ចំនួនគត់	 match_pattern(const var_na *, const var_na *);
ចំនួនគត់	 match_pattern_list(const var_na *, const var_na *, ចំនួនគត់);
ចំនួនគត់	 match_usergroup_pattern_list(const var_na *, const var_na *);
ចំនួនគត់	 match_hostname(const var_na *, const var_na *);
ចំនួនគត់	 match_host_and_ip(const var_na *, const var_na *, const var_na *);
ចំនួនគត់	 match_user(const var_na *, const var_na *, const var_na *, const var_na *);
var_na	*match_list(const var_na *, const var_na *, u_int *);
var_na	*match_filter_denylist(const var_na *, const var_na *);
var_na	*match_filter_allowlist(const var_na *, const var_na *);

/* addrmatch.c */
ចំនួនគត់	 addr_match_list(const var_na *, const var_na *);
ចំនួនគត់	 addr_match_cidr_list(const var_na *, const var_na *);
#endif
