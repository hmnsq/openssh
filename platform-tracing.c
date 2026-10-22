/*
 * Copyright (c) 2016 Darren Tucker.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#अगर_घोषित HAVE_SYS_PROCCTL_H
#समावेश <sys/procctl.h>
#पूर्ण_अगर
#अगर defined(HAVE_SYS_PRCTL_H)
#समावेश <sys/prctl.h>	/* For prctl() and PR_SET_DUMPABLE */
#पूर्ण_अगर
#अगर_घोषित HAVE_SYS_PTRACE_H
#समावेश <sys/ptrace.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_PRIV_H
#समावेश <priv.h> /* For setpflags() and __PROC_PROTECT  */
#पूर्ण_अगर
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "log.h"

व्योम
platform_disable_tracing(पूर्णांक strict)
{
#अगर defined(HAVE_PROCCTL) && defined(PROC_TRACE_CTL)
	/* On FreeBSD, we should make this process untraceable */
	पूर्णांक disable_trace = PROC_TRACE_CTL_DISABLE;

	/*
	 * On FreeBSD, we should make this process untraceable.
	 * pid=0 means "this process" but some older kernels do not
	 * understand that so retry with our own pid before failing.
	 */
	अगर (procctl(P_PID, 0, PROC_TRACE_CTL, &disable_trace) == 0)
		वापस;
	अगर (procctl(P_PID, getpid(), PROC_TRACE_CTL, &disable_trace) == 0)
		वापस;
	अगर (strict)
		fatal("unable to make the process untraceable: %s",
		    म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर
#अगर defined(HAVE_PRCTL) && defined(PR_SET_DUMPABLE)
	/* Disable ptrace on Linux without sgid bit */
	अगर (prctl(PR_SET_DUMPABLE, 0) != 0 && strict)
		fatal("unable to make the process undumpable: %s",
		    म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर
#अगर defined(HAVE_SETPFLAGS) && defined(__PROC_PROTECT)
	/* On Solaris, we should make this process untraceable */
	अगर (setpflags(__PROC_PROTECT, 1) != 0 && strict)
		fatal("unable to make the process untraceable: %s",
		    म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर
#अगर_घोषित PT_DENY_ATTACH
	/* Mac OS X */
	अगर (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1 && strict)
		fatal("unable to set PT_DENY_ATTACH: %s", म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर
}
