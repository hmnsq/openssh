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

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 match_pattern(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 match_pattern_list(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 match_usergroup_pattern_list(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 match_hostname(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 match_host_and_ip(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 match_user(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ଅକ୍ଷର	*match_list(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, u_int *);
ଅକ୍ଷର	*match_filter_denylist(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ଅକ୍ଷର	*match_filter_allowlist(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);

/* addrmatch.c */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 addr_match_list(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 addr_match_cidr_list(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
#endif
