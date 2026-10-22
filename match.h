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
#جے_بنا_تعریف میل_H
#تعریف_کرو میل_H

صحيح	 میل_نمونہ(ثابت حرف *, ثابت حرف *);
صحيح	 میل_نمونہ_list(ثابت حرف *, ثابت حرف *, صحيح);
صحيح	 میل_usergroup_نمونہ_list(ثابت حرف *, ثابت حرف *);
صحيح	 میل_hostname(ثابت حرف *, ثابت حرف *);
صحيح	 میل_host_and_ip(ثابت حرف *, ثابت حرف *, ثابت حرف *);
صحيح	 میل_user(ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *);
حرف	*میل_list(ثابت حرف *, ثابت حرف *, u_int *);
حرف	*میل_filter_denylist(ثابت حرف *, ثابت حرف *);
حرف	*میل_filter_allowlist(ثابت حرف *, ثابت حرف *);

/* addrmatch.c */
صحيح	 addr_میل_list(ثابت حرف *, ثابت حرف *);
صحيح	 addr_میل_cidr_list(ثابت حرف *, ثابت حرف *);
#جے_انت
