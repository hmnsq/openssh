/*	$OpenBSD: getopt.h,v 1.2 2008/06/26 05:42:04 ray Exp $	*/
/*	$NetBSD: getopt.h,v 1.4 2000/07/07 10:43:54 ad Exp $	*/

/*-
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Dieter Baron and Thomas Klausner.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#నిర్వచితం_కాకపోతే _GETOPT_H_
#నిర్వచించు _GETOPT_H_

#నిర్వచితం_కాకపోతే __THROW
# ఒకవేళ defined __cplusplus
#  define __THROW throw()
# లేకపోతే
#  define __THROW
# endif
#అయితే_ముగింపు

/*
 * GNU-like getopt_long() and 4.4BSD getsubopt()/optreset extensions
 */
#నిర్వచించు no_argument        0
#నిర్వచించు required_argument  1
#నిర్వచించు optional_argument  2

#ఒకవేళ 0
నిర్మాణం option {
	/* name of long option */
	స్థిరరాశి అక్షరం *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	పూర్ణాంకం has_arg;
	/* if not NULL, set *flag to val when option found */
	పూర్ణాంకం *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	పూర్ణాంకం val;
};

పూర్ణాంకం	 getopt_long(పూర్ణాంకం, అక్షరం * స్థిరరాశి *, స్థిరరాశి అక్షరం *,
	    స్థిరరాశి నిర్మాణం option *, పూర్ణాంకం *);
పూర్ణాంకం	 getopt_long_only(పూర్ణాంకం, అక్షరం * స్థిరరాశి *, స్థిరరాశి అక్షరం *,
	    స్థిరరాశి నిర్మాణం option *, పూర్ణాంకం *);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే _GETOPT_DEFINED_
#నిర్వచించు _GETOPT_DEFINED_
పూర్ణాంకం	 getopt(పూర్ణాంకం, అక్షరం * స్థిరరాశి *, స్థిరరాశి అక్షరం *) __THROW;
పూర్ణాంకం	 getsubopt(అక్షరం **, అక్షరం * స్థిరరాశి *, అక్షరం **) __THROW;

బాహ్య   అక్షరం *optarg;                  /* getopt(3) external variables */
బాహ్య   పూర్ణాంకం opterr;
బాహ్య   పూర్ణాంకం optind;
బాహ్య   పూర్ణాంకం optopt;
బాహ్య   పూర్ణాంకం optreset;
బాహ్య   అక్షరం *suboptarg;               /* getsubopt(3) external variable */
#అయితే_ముగింపు
 
#అయితే_ముగింపు /* !_GETOPT_H_ */
