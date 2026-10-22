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

পূর্ণাঙ্ক	 match_pattern(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);
পূর্ণাঙ্ক	 match_pattern_list(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 match_usergroup_pattern_list(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);
পূর্ণাঙ্ক	 match_hostname(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);
পূর্ণাঙ্ক	 match_host_and_ip(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);
পূর্ণাঙ্ক	 match_user(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);
বর্ণ	*match_list(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, u_int *);
বর্ণ	*match_filter_denylist(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);
বর্ণ	*match_filter_allowlist(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);

/* addrmatch.c */
পূর্ণাঙ্ক	 addr_match_list(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);
পূর্ণাঙ্ক	 addr_match_cidr_list(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);
#endif
