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

পূর্ণসংখ্যা	 match_pattern(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 match_pattern_list(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 match_usergroup_pattern_list(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 match_hostname(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 match_host_and_ip(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 match_user(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
অক্ষর	*match_list(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, u_int *);
অক্ষর	*match_filter_denylist(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
অক্ষর	*match_filter_allowlist(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);

/* addrmatch.c */
পূর্ণসংখ্যা	 addr_match_list(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 addr_match_cidr_list(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
#endif
