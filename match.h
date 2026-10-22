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

पूर्णाङ्क	 match_pattern(अचर वर्ण *, अचर वर्ण *);
पूर्णाङ्क	 match_pattern_list(अचर वर्ण *, अचर वर्ण *, पूर्णाङ्क);
पूर्णाङ्क	 match_usergroup_pattern_list(अचर वर्ण *, अचर वर्ण *);
पूर्णाङ्क	 match_hostname(अचर वर्ण *, अचर वर्ण *);
पूर्णाङ्क	 match_host_and_ip(अचर वर्ण *, अचर वर्ण *, अचर वर्ण *);
पूर्णाङ्क	 match_user(अचर वर्ण *, अचर वर्ण *, अचर वर्ण *, अचर वर्ण *);
वर्ण	*match_list(अचर वर्ण *, अचर वर्ण *, u_int *);
वर्ण	*match_filter_denylist(अचर वर्ण *, अचर वर्ण *);
वर्ण	*match_filter_allowlist(अचर वर्ण *, अचर वर्ण *);

/* addrmatch.c */
पूर्णाङ्क	 addr_match_list(अचर वर्ण *, अचर वर्ण *);
पूर्णाङ्क	 addr_match_cidr_list(अचर वर्ण *, अचर वर्ण *);
#endif
