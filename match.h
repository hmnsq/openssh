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
#यदि_अपरिभाषितम् मेलनम्_H
#परिभाषय मेलनम्_H

पूर्णाङ्क	 मेलनम्_आदर्शः(ध्रुव वर्ण *, ध्रुव वर्ण *);
पूर्णाङ्क	 मेलनम्_आदर्शः_list(ध्रुव वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क);
पूर्णाङ्क	 मेलनम्_usergroup_आदर्शः_list(ध्रुव वर्ण *, ध्रुव वर्ण *);
पूर्णाङ्क	 मेलनम्_hostname(ध्रुव वर्ण *, ध्रुव वर्ण *);
पूर्णाङ्क	 मेलनम्_host_and_ip(ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *);
पूर्णाङ्क	 मेलनम्_user(ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *);
वर्ण	*मेलनम्_list(ध्रुव वर्ण *, ध्रुव वर्ण *, u_int *);
वर्ण	*मेलनम्_filter_denylist(ध्रुव वर्ण *, ध्रुव वर्ण *);
वर्ण	*मेलनम्_filter_allowlist(ध्रुव वर्ण *, ध्रुव वर्ण *);

/* addrmatch.c */
पूर्णाङ्क	 addr_मेलनम्_list(ध्रुव वर्ण *, ध्रुव वर्ण *);
पूर्णाङ्क	 addr_मेलनम्_cidr_list(ध्रुव वर्ण *, ध्रुव वर्ण *);
#यदि_अन्तः
