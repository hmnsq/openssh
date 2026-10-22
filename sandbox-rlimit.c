/* $OpenBSD: sandbox-rlimit.c,v 1.5 2020/10/18 11:32:01 djm Exp $ */
/*
 * Copyright (c) 2011 Damien Miller <djm@mindrot.org>
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

#اگر_تعریف_شدہ SANDBOX_RLIMIT

#شامل <sys/types.h>
#شامل <sys/time.h>
#شامل <sys/resource.h>

#شامل <errno.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "log.h"
#شامل "ssh-sandbox.h"
#شامل "xmalloc.h"

/* Minimal sandbox that sets zero nfiles, nprocs and filesize rlimits */

ساخت ssh_sandbox {
	صحیح junk;
};

ساخت ssh_sandbox *
ssh_sandbox_init(ساخت monitor *monitor)
{
	ساخت ssh_sandbox *box;

	/*
	 * Strictly, we don't need to maintain any state here but we need
	 * to return non-NULL to satisfy the API.
	 */
	debug3_f("preparing rlimit sandbox");
	box = xcalloc(1, حجم(*box));
	واپس box;
}

خالی
ssh_sandbox_بچہ(ساخت ssh_sandbox *box)
{
	ساخت rlimit rl_zero;

	rl_zero.rlim_cur = rl_zero.rlim_max = 0;

#اگر_غیر_تعریف_شدہ SANDBOX_SKIP_RLIMIT_FSIZE
	اگر (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal_f("setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			strerror(errno));
#اگر_ختم
#اگر_غیر_تعریف_شدہ SANDBOX_SKIP_RLIMIT_NOFILE
	اگر (setrlimit(RLIMIT_NOFILE, &rl_zero) == -1)
		fatal_f("setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			strerror(errno));
#اگر_ختم
#اگر_تعریف_شدہ HAVE_RLIMIT_NPROC
	اگر (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal_f("setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			strerror(errno));
#اگر_ختم
}

#اگر_ختم /* SANDBOX_RLIMIT */
