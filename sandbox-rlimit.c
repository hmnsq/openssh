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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే SANDBOX_RLIMIT

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/time.h>
#అన్తర్భావ <sys/resource.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "ssh-sandbox.h"
#అన్తర్భావ "xmalloc.h"

/* Minimal sandbox that sets zero nfiles, nprocs and filesize rlimits */

నిర్మాణం ssh_sandbox {
	పూర్ణాంకం junk;
};

నిర్మాణం ssh_sandbox *
ssh_sandbox_init(నిర్మాణం monitor *monitor)
{
	నిర్మాణం ssh_sandbox *box;

	/*
	 * Strictly, we don't need to maintain any state here but we need
	 * to return non-NULL to satisfy the API.
	 */
	debug3_f("preparing rlimit sandbox");
	box = xcalloc(1, పరిమాణం(*box));
	తిరిగి box;
}

శూన్య
ssh_sandbox_బిడ్డ(నిర్మాణం ssh_sandbox *box)
{
	నిర్మాణం rlimit rl_zero;

	rl_zero.rlim_cur = rl_zero.rlim_max = 0;

#నిర్వచితం_కాకపోతే SANDBOX_SKIP_RLIMIT_FSIZE
	ఒకవేళ (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal_f("setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			strerror(errno));
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే SANDBOX_SKIP_RLIMIT_NOFILE
	ఒకవేళ (setrlimit(RLIMIT_NOFILE, &rl_zero) == -1)
		fatal_f("setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			strerror(errno));
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_RLIMIT_NPROC
	ఒకవేళ (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal_f("setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			strerror(errno));
#అయితే_ముగింపు
}

#అయితే_ముగింపు /* SANDBOX_RLIMIT */
