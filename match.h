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

પૂર્ણાંક	 match_pattern(અચલ અક્ષર *, અચલ અક્ષર *);
પૂર્ણાંક	 match_pattern_list(અચલ અક્ષર *, અચલ અક્ષર *, પૂર્ણાંક);
પૂર્ણાંક	 match_usergroup_pattern_list(અચલ અક્ષર *, અચલ અક્ષર *);
પૂર્ણાંક	 match_hostname(અચલ અક્ષર *, અચલ અક્ષર *);
પૂર્ણાંક	 match_host_and_ip(અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *);
પૂર્ણાંક	 match_user(અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *);
અક્ષર	*match_list(અચલ અક્ષર *, અચલ અક્ષર *, u_int *);
અક્ષર	*match_filter_denylist(અચલ અક્ષર *, અચલ અક્ષર *);
અક્ષર	*match_filter_allowlist(અચલ અક્ષર *, અચલ અક્ષર *);

/* addrmatch.c */
પૂર્ણાંક	 addr_match_list(અચલ અક્ષર *, અચલ અક્ષર *);
પૂર્ણાંક	 addr_match_cidr_list(અચલ અક્ષર *, અચલ અક્ષર *);
#endif
