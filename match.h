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

पूर्णांक	 match_pattern(स्थिरांक अक्षर *, स्थिरांक अक्षर *);
पूर्णांक	 match_pattern_list(स्थिरांक अक्षर *, स्थिरांक अक्षर *, पूर्णांक);
पूर्णांक	 match_usergroup_pattern_list(स्थिरांक अक्षर *, स्थिरांक अक्षर *);
पूर्णांक	 match_hostname(स्थिरांक अक्षर *, स्थिरांक अक्षर *);
पूर्णांक	 match_host_and_ip(स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *);
पूर्णांक	 match_user(स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *);
अक्षर	*match_list(स्थिरांक अक्षर *, स्थिरांक अक्षर *, u_int *);
अक्षर	*match_filter_denylist(स्थिरांक अक्षर *, स्थिरांक अक्षर *);
अक्षर	*match_filter_allowlist(स्थिरांक अक्षर *, स्थिरांक अक्षर *);

/* addrmatch.c */
पूर्णांक	 addr_match_list(स्थिरांक अक्षर *, स्थिरांक अक्षर *);
पूर्णांक	 addr_match_cidr_list(स्थिरांक अक्षर *, स्थिरांक अक्षर *);
#endif
