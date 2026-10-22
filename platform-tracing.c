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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#నిర్వచితమైతే HAVE_SYS_PROCCTL_H
#అన్తర్భావ <sys/procctl.h>
#అయితే_ముగింపు
#ఒకవేళ defined(HAVE_SYS_PRCTL_H)
#అన్తర్భావ <sys/prctl.h>	/* For prctl() and PR_SET_DUMPABLE */
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_SYS_PTRACE_H
#అన్తర్భావ <sys/ptrace.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_PRIV_H
#అన్తర్భావ <priv.h> /* For setpflags() and __PROC_PROTECT  */
#అయితే_ముగింపు
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "log.h"

శూన్య
platform_disable_tracing(పూర్ణాంకం strict)
{
#ఒకవేళ defined(HAVE_PROCCTL) && defined(PROC_TRACE_CTL)
	/* On FreeBSD, we should make this process untraceable */
	పూర్ణాంకం disable_trace = PROC_TRACE_CTL_DISABLE;

	/*
	 * On FreeBSD, we should make this process untraceable.
	 * pid=0 means "this process" but some older kernels do not
	 * understand that so retry with our own pid before failing.
	 */
	ఒకవేళ (procctl(P_PID, 0, PROC_TRACE_CTL, &disable_trace) == 0)
		తిరిగి;
	ఒకవేళ (procctl(P_PID, getpid(), PROC_TRACE_CTL, &disable_trace) == 0)
		తిరిగి;
	ఒకవేళ (strict)
		fatal("unable to make the process untraceable: %s",
		    strerror(errno));
#అయితే_ముగింపు
#ఒకవేళ defined(HAVE_PRCTL) && defined(PR_సమితి_DUMPABLE)
	/* Disable ptrace on Linux without sgid bit */
	ఒకవేళ (prctl(PR_సమితి_DUMPABLE, 0) != 0 && strict)
		fatal("unable to make the process undumpable: %s",
		    strerror(errno));
#అయితే_ముగింపు
#ఒకవేళ defined(HAVE_SETPFLAGS) && defined(__PROC_PROTECT)
	/* On Solaris, we should make this process untraceable */
	ఒకవేళ (setpflags(__PROC_PROTECT, 1) != 0 && strict)
		fatal("unable to make the process untraceable: %s",
		    strerror(errno));
#అయితే_ముగింపు
#నిర్వచితమైతే PT_DENY_ATTACH
	/* Mac OS X */
	ఒకవేళ (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1 && strict)
		fatal("unable to set PT_DENY_ATTACH: %s", strerror(errno));
#అయితే_ముగింపు
}
