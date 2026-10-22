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

#ضمن "includes.h"

#جيڪڏهن_وصف_ٿيل SANDBOX_RLIMIT

#ضمن <sys/types.h>
#ضمن <sys/time.h>
#ضمن <sys/resource.h>

#ضمن <errno.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "log.h"
#ضمن "ssh-sandbox.h"
#ضمن "xmalloc.h"

/* Minimal sandbox that sets zero nfiles, nprocs and filesize rlimits */

بنية ssh_sandbox {
	صحيح junk;
};

بنية ssh_sandbox *
ssh_sandbox_init(بنية monitor *monitor)
{
	بنية ssh_sandbox *box;

	/*
	 * Strictly, we don't need to maintain any state here but we need
	 * to return non-NULL to satisfy the API.
	 */
	debug3_f("preparing rlimit sandbox");
	box = xcalloc(1, حجم(*box));
	أرجع box;
}

فراغ
ssh_sandbox_ٻار(بنية ssh_sandbox *box)
{
	بنية rlimit rl_zero;

	rl_zero.rlim_cur = rl_zero.rlim_max = 0;

#جيڪڏهن_وصف_نه_ٿيل SANDBOX_SKIP_RLIMIT_FSIZE
	إذا (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal_f("setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			strerror(errno));
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل SANDBOX_SKIP_RLIMIT_NOFILE
	إذا (setrlimit(RLIMIT_NOFILE, &rl_zero) == -1)
		fatal_f("setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			strerror(errno));
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_RLIMIT_NPROC
	إذا (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal_f("setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			strerror(errno));
#جيڪڏهن_پورو
}

#جيڪڏهن_پورو /* SANDBOX_RLIMIT */
