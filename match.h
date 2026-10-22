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
#నిర్వచితం_కాకపోతే సరిపోలిక_H
#నిర్వచించు సరిపోలిక_H

పూర్ణాంకం	 సరిపోలిక_నమూనా(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 సరిపోలిక_నమూనా_list(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం);
పూర్ణాంకం	 సరిపోలిక_usergroup_నమూనా_list(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 సరిపోలిక_hostname(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 సరిపోలిక_host_and_ip(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 సరిపోలిక_user(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
అక్షరం	*సరిపోలిక_list(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, u_int *);
అక్షరం	*సరిపోలిక_filter_denylist(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
అక్షరం	*సరిపోలిక_filter_allowlist(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);

/* addrmatch.c */
పూర్ణాంకం	 addr_సరిపోలిక_list(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 addr_సరిపోలిక_cidr_list(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
#అయితే_ముగింపు
