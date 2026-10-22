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

முழு	 match_pattern(மாறிலி எழுத்து *, மாறிலி எழுத்து *);
முழு	 match_pattern_list(மாறிலி எழுத்து *, மாறிலி எழுத்து *, முழு);
முழு	 match_usergroup_pattern_list(மாறிலி எழுத்து *, மாறிலி எழுத்து *);
முழு	 match_hostname(மாறிலி எழுத்து *, மாறிலி எழுத்து *);
முழு	 match_host_and_ip(மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *);
முழு	 match_user(மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *);
எழுத்து	*match_list(மாறிலி எழுத்து *, மாறிலி எழுத்து *, u_int *);
எழுத்து	*match_filter_denylist(மாறிலி எழுத்து *, மாறிலி எழுத்து *);
எழுத்து	*match_filter_allowlist(மாறிலி எழுத்து *, மாறிலி எழுத்து *);

/* addrmatch.c */
முழு	 addr_match_list(மாறிலி எழுத்து *, மாறிலி எழுத்து *);
முழு	 addr_match_cidr_list(மாறிலி எழுத்து *, மாறிலி எழுத்து *);
#endif
