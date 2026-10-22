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
# જો defined __cplusplus
#  define __THROW throw()
# નહીંતર
#  define __THROW
# endif
#endif

/*
 * GNU-like getopt_long() and 4.4BSD getsubopt()/optreset extensions
 */
#define no_argument        0
#define required_argument  1
#define optional_argument  2

#જો 0
સંરચના option {
	/* name of long option */
	અચલ અક્ષર *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	પૂર્ણાંક has_arg;
	/* if not NULL, set *flag to val when option found */
	પૂર્ણાંક *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	પૂર્ણાંક val;
};

પૂર્ણાંક	 getopt_long(પૂર્ણાંક, અક્ષર * અચલ *, અચલ અક્ષર *,
	    અચલ સંરચના option *, પૂર્ણાંક *);
પૂર્ણાંક	 getopt_long_only(પૂર્ણાંક, અક્ષર * અચલ *, અચલ અક્ષર *,
	    અચલ સંરચના option *, પૂર્ણાંક *);
#endif

#ifndef _GETOPT_DEFINED_
#define _GETOPT_DEFINED_
પૂર્ણાંક	 getopt(પૂર્ણાંક, અક્ષર * અચલ *, અચલ અક્ષર *) __THROW;
પૂર્ણાંક	 getsubopt(અક્ષર **, અક્ષર * અચલ *, અક્ષર **) __THROW;

બાહ્ય   અક્ષર *optarg;                  /* getopt(3) external variables */
બાહ્ય   પૂર્ણાંક opterr;
બાહ્ય   પૂર્ણાંક optind;
બાહ્ય   પૂર્ણાંક optopt;
બાહ્ય   પૂર્ણાંક optreset;
બાહ્ય   અક્ષર *suboptarg;               /* getsubopt(3) external variable */
#endif
 
#endif /* !_GETOPT_H_ */
