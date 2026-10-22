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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#ifdef HAVE_SYS_PROCCTL_H
#અન્તર્ભાવ <sys/procctl.h>
#endif
#જો defined(HAVE_SYS_PRCTL_H)
#અન્તર્ભાવ <sys/prctl.h>	/* For prctl() and PR_SET_DUMPABLE */
#endif
#ifdef HAVE_SYS_PTRACE_H
#અન્તર્ભાવ <sys/ptrace.h>
#endif
#ifdef HAVE_PRIV_H
#અન્તર્ભાવ <priv.h> /* For setpflags() and __PROC_PROTECT  */
#endif
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "log.h"

શૂન્ય
platform_disable_tracing(પૂર્ણાંક strict)
{
#જો defined(HAVE_PROCCTL) && defined(PROC_TRACE_CTL)
	/* On FreeBSD, we should make this process untraceable */
	પૂર્ણાંક disable_trace = PROC_TRACE_CTL_DISABLE;

	/*
	 * On FreeBSD, we should make this process untraceable.
	 * pid=0 means "this process" but some older kernels do not
	 * understand that so retry with our own pid before failing.
	 */
	જો (procctl(P_PID, 0, PROC_TRACE_CTL, &disable_trace) == 0)
		પાછા;
	જો (procctl(P_PID, getpid(), PROC_TRACE_CTL, &disable_trace) == 0)
		પાછા;
	જો (strict)
		fatal("unable to make the process untraceable: %s",
		    strerror(errno));
#endif
#જો defined(HAVE_PRCTL) && defined(PR_SET_DUMPABLE)
	/* Disable ptrace on Linux without sgid bit */
	જો (prctl(PR_SET_DUMPABLE, 0) != 0 && strict)
		fatal("unable to make the process undumpable: %s",
		    strerror(errno));
#endif
#જો defined(HAVE_SETPFLAGS) && defined(__PROC_PROTECT)
	/* On Solaris, we should make this process untraceable */
	જો (setpflags(__PROC_PROTECT, 1) != 0 && strict)
		fatal("unable to make the process untraceable: %s",
		    strerror(errno));
#endif
#ifdef PT_DENY_ATTACH
	/* Mac OS X */
	જો (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1 && strict)
		fatal("unable to set PT_DENY_ATTACH: %s", strerror(errno));
#endif
}
