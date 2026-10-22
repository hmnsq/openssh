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

#شامل "includes.h"

#شامل <sys/types.h>
#اگر_تعریف_شدہ HAVE_SYS_PROCCTL_H
#شامل <sys/procctl.h>
#اگر_ختم
#اگر defined(HAVE_SYS_PRCTL_H)
#شامل <sys/prctl.h>	/* For prctl() and PR_SET_DUMPABLE */
#اگر_ختم
#اگر_تعریف_شدہ HAVE_SYS_PTRACE_H
#شامل <sys/ptrace.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_PRIV_H
#شامل <priv.h> /* For setpflags() and __PROC_PROTECT  */
#اگر_ختم
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "log.h"

خالی
platform_disable_tracing(صحیح strict)
{
#اگر defined(HAVE_PROCCTL) && defined(PROC_TRACE_CTL)
	/* On FreeBSD, we should make this process untraceable */
	صحیح disable_trace = PROC_TRACE_CTL_DISABLE;

	/*
	 * On FreeBSD, we should make this process untraceable.
	 * pid=0 means "this process" but some older kernels do not
	 * understand that so retry with our own pid before failing.
	 */
	اگر (procctl(P_PID, 0, PROC_TRACE_CTL, &disable_trace) == 0)
		واپس;
	اگر (procctl(P_PID, getpid(), PROC_TRACE_CTL, &disable_trace) == 0)
		واپس;
	اگر (strict)
		fatal("unable to make the process untraceable: %s",
		    strerror(errno));
#اگر_ختم
#اگر defined(HAVE_PRCTL) && defined(PR_سیٹ_DUMPABLE)
	/* Disable ptrace on Linux without sgid bit */
	اگر (prctl(PR_سیٹ_DUMPABLE, 0) != 0 && strict)
		fatal("unable to make the process undumpable: %s",
		    strerror(errno));
#اگر_ختم
#اگر defined(HAVE_SETPFLAGS) && defined(__PROC_PROTECT)
	/* On Solaris, we should make this process untraceable */
	اگر (setpflags(__PROC_PROTECT, 1) != 0 && strict)
		fatal("unable to make the process untraceable: %s",
		    strerror(errno));
#اگر_ختم
#اگر_تعریف_شدہ PT_DENY_ATTACH
	/* Mac OS X */
	اگر (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1 && strict)
		fatal("unable to set PT_DENY_ATTACH: %s", strerror(errno));
#اگر_ختم
}
