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

ಪೂರ್ಣಾಙ್ಕ	 match_pattern(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 match_pattern_list(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 match_usergroup_pattern_list(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 match_hostname(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 match_host_and_ip(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 match_user(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
ವರ್ಣ	*match_list(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, u_int *);
ವರ್ಣ	*match_filter_denylist(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
ವರ್ಣ	*match_filter_allowlist(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);

/* addrmatch.c */
ಪೂರ್ಣಾಙ್ಕ	 addr_match_list(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 addr_match_cidr_list(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
#endif
