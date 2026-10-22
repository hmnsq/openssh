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

#અન્તર્ભાવ "includes.h"

#ifdef SANDBOX_RLIMIT

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/time.h>
#અન્તર્ભાવ <sys/resource.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "ssh-sandbox.h"
#અન્તર્ભાવ "xmalloc.h"

/* Minimal sandbox that sets zero nfiles, nprocs and filesize rlimits */

સંરચના ssh_sandbox {
	પૂર્ણાંક junk;
};

સંરચના ssh_sandbox *
ssh_sandbox_init(સંરચના monitor *monitor)
{
	સંરચના ssh_sandbox *box;

	/*
	 * Strictly, we don't need to maintain any state here but we need
	 * to return non-NULL to satisfy the API.
	 */
	debug3_f("preparing rlimit sandbox");
	box = xcalloc(1, કદ(*box));
	પાછા box;
}

શૂન્ય
ssh_sandbox_child(સંરચના ssh_sandbox *box)
{
	સંરચના rlimit rl_zero;

	rl_zero.rlim_cur = rl_zero.rlim_max = 0;

#ifndef SANDBOX_SKIP_RLIMIT_FSIZE
	જો (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal_f("setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			strerror(errno));
#endif
#ifndef SANDBOX_SKIP_RLIMIT_NOFILE
	જો (setrlimit(RLIMIT_NOFILE, &rl_zero) == -1)
		fatal_f("setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			strerror(errno));
#endif
#ifdef HAVE_RLIMIT_NPROC
	જો (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal_f("setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			strerror(errno));
#endif
}

#endif /* SANDBOX_RLIMIT */
