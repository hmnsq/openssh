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
#اگر_تعریف_نشده تطابق_H
#تعریف_کن تطابق_H

صحيح	 تطابق_الگو(ثابت حرف *, ثابت حرف *);
صحيح	 تطابق_الگو_list(ثابت حرف *, ثابت حرف *, صحيح);
صحيح	 تطابق_usergroup_الگو_list(ثابت حرف *, ثابت حرف *);
صحيح	 تطابق_hostname(ثابت حرف *, ثابت حرف *);
صحيح	 تطابق_host_and_ip(ثابت حرف *, ثابت حرف *, ثابت حرف *);
صحيح	 تطابق_user(ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *);
حرف	*تطابق_list(ثابت حرف *, ثابت حرف *, u_int *);
حرف	*تطابق_filter_denylist(ثابت حرف *, ثابت حرف *);
حرف	*تطابق_filter_allowlist(ثابت حرف *, ثابت حرف *);

/* addrmatch.c */
صحيح	 addr_تطابق_list(ثابت حرف *, ثابت حرف *);
صحيح	 addr_تطابق_cidr_list(ثابت حرف *, ثابت حرف *);
#پایان_اگر
