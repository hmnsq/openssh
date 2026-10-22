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
#که_نه_تعریف_شوی سمون_H
#تعریف_کړه سمون_H

صحيح	 سمون_نمونه(ثابت حرف *, ثابت حرف *);
صحيح	 سمون_نمونه_list(ثابت حرف *, ثابت حرف *, صحيح);
صحيح	 سمون_usergroup_نمونه_list(ثابت حرف *, ثابت حرف *);
صحيح	 سمون_hostname(ثابت حرف *, ثابت حرف *);
صحيح	 سمون_host_and_ip(ثابت حرف *, ثابت حرف *, ثابت حرف *);
صحيح	 سمون_user(ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *);
حرف	*سمون_list(ثابت حرف *, ثابت حرف *, u_int *);
حرف	*سمون_filter_denylist(ثابت حرف *, ثابت حرف *);
حرف	*سمون_filter_allowlist(ثابت حرف *, ثابت حرف *);

/* addrmatch.c */
صحيح	 addr_سمون_list(ثابت حرف *, ثابت حرف *);
صحيح	 addr_سمون_cidr_list(ثابت حرف *, ثابت حرف *);
#د_که_پای
