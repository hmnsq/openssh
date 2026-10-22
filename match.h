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
#اگر_غیر_تعریف_شدہ مطابقت_H
#تعریف_کرو مطابقت_H

صحیح	 مطابقت_نمونہ(ثابت حرف *, ثابت حرف *);
صحیح	 مطابقت_نمونہ_list(ثابت حرف *, ثابت حرف *, صحیح);
صحیح	 مطابقت_usergroup_نمونہ_list(ثابت حرف *, ثابت حرف *);
صحیح	 مطابقت_hostname(ثابت حرف *, ثابت حرف *);
صحیح	 مطابقت_host_and_ip(ثابت حرف *, ثابت حرف *, ثابت حرف *);
صحیح	 مطابقت_user(ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *);
حرف	*مطابقت_list(ثابت حرف *, ثابت حرف *, u_int *);
حرف	*مطابقت_filter_denylist(ثابت حرف *, ثابت حرف *);
حرف	*مطابقت_filter_allowlist(ثابت حرف *, ثابت حرف *);

/* addrmatch.c */
صحیح	 addr_مطابقت_list(ثابت حرف *, ثابت حرف *);
صحیح	 addr_مطابقت_cidr_list(ثابت حرف *, ثابت حرف *);
#اگر_ختم
