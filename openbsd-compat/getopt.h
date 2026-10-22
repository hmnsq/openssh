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

#ifndef _GETOPT_H_
#define _GETOPT_H_

#ifndef __THROW
# නම් defined __cplusplus
#  define __THROW throw()
# නැතහොත්
#  define __THROW
# endif
#endif

/*
 * GNU-like getopt_long() and 4.4BSD getsubopt()/optreset extensions
 */
#define no_argument        0
#define required_argument  1
#define optional_argument  2

#නම් 0
sa_nracanaa option {
	/* name of long option */
	const var_na *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	පූර්ණ_සංඛ්‍යා has_arg;
	/* if not NULL, set *flag to val when option found */
	පූර්ණ_සංඛ්‍යා *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	පූර්ණ_සංඛ්‍යා val;
};

පූර්ණ_සංඛ්‍යා	 getopt_long(පූර්ණ_සංඛ්‍යා, var_na * const *, const var_na *,
	    const sa_nracanaa option *, පූර්ණ_සංඛ්‍යා *);
පූර්ණ_සංඛ්‍යා	 getopt_long_only(පූර්ණ_සංඛ්‍යා, var_na * const *, const var_na *,
	    const sa_nracanaa option *, පූර්ණ_සංඛ්‍යා *);
#endif

#ifndef _GETOPT_DEFINED_
#define _GETOPT_DEFINED_
පූර්ණ_සංඛ්‍යා	 getopt(පූර්ණ_සංඛ්‍යා, var_na * const *, const var_na *) __THROW;
පූර්ණ_සංඛ්‍යා	 getsubopt(var_na **, var_na * const *, var_na **) __THROW;

extern   var_na *optarg;                  /* getopt(3) external variables */
extern   පූර්ණ_සංඛ්‍යා opterr;
extern   පූර්ණ_සංඛ්‍යා optind;
extern   පූර්ණ_සංඛ්‍යා optopt;
extern   පූර්ණ_සංඛ්‍යා optreset;
extern   var_na *suboptarg;               /* getsubopt(3) external variable */
#endif
 
#endif /* !_GETOPT_H_ */
