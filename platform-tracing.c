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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ifdef HAVE_SYS_PROCCTL_H
#ଅନ୍ତର୍ଭାଵ <sys/procctl.h>
#endif
#ଯଦି defined(HAVE_SYS_PRCTL_H)
#ଅନ୍ତର୍ଭାଵ <sys/prctl.h>	/* For prctl() and PR_SET_DUMPABLE */
#endif
#ifdef HAVE_SYS_PTRACE_H
#ଅନ୍ତର୍ଭାଵ <sys/ptrace.h>
#endif
#ifdef HAVE_PRIV_H
#ଅନ୍ତର୍ଭାଵ <priv.h> /* For setpflags() and __PROC_PROTECT  */
#endif
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "log.h"

ଶୂନ୍ୟ
platform_disable_tracing(ପୂର୍ଣ୍ଣସଂଖ୍ୟା strict)
{
#ଯଦି defined(HAVE_PROCCTL) && defined(PROC_TRACE_CTL)
	/* On FreeBSD, we should make this process untraceable */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା disable_trace = PROC_TRACE_CTL_DISABLE;

	/*
	 * On FreeBSD, we should make this process untraceable.
	 * pid=0 means "this process" but some older kernels do not
	 * understand that so retry with our own pid before failing.
	 */
	ଯଦି (procctl(P_PID, 0, PROC_TRACE_CTL, &disable_trace) == 0)
		ଫେରନ୍ତୁ;
	ଯଦି (procctl(P_PID, getpid(), PROC_TRACE_CTL, &disable_trace) == 0)
		ଫେରନ୍ତୁ;
	ଯଦି (strict)
		fatal("unable to make the process untraceable: %s",
		    strerror(errno));
#endif
#ଯଦି defined(HAVE_PRCTL) && defined(PR_SET_DUMPABLE)
	/* Disable ptrace on Linux without sgid bit */
	ଯଦି (prctl(PR_SET_DUMPABLE, 0) != 0 && strict)
		fatal("unable to make the process undumpable: %s",
		    strerror(errno));
#endif
#ଯଦି defined(HAVE_SETPFLAGS) && defined(__PROC_PROTECT)
	/* On Solaris, we should make this process untraceable */
	ଯଦି (setpflags(__PROC_PROTECT, 1) != 0 && strict)
		fatal("unable to make the process untraceable: %s",
		    strerror(errno));
#endif
#ifdef PT_DENY_ATTACH
	/* Mac OS X */
	ଯଦି (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1 && strict)
		fatal("unable to set PT_DENY_ATTACH: %s", strerror(errno));
#endif
}
