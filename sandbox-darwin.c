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

#جے_تعریف_شدہ SANDBOX_DARWIN

#ضمن <sys/types.h>

#ضمن <sandbox.h>

#ضمن <errno.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "log.h"
#ضمن "ssh-sandbox.h"
#ضمن "monitor.h"
#ضمن "xmalloc.h"

/* Darwin/OS X sandbox */

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
	debug3_f("preparing Darwin sandbox");
	box = xcalloc(1, حجم(*box));
	أرجع box;
}

فراغ
ssh_sandbox_بچہ(بنية ssh_sandbox *box)
{
	حرف *errmsg;
	بنية rlimit rl_zero;

	debug3_f("starting Darwin sandbox");
	إذا (sandbox_init(k_SBXProfile_خالص_Computation, SANDBOX_NAMED,
	    &errmsg) == -1)
		fatal_f("sandbox_init: %s", errmsg);

	/*
	 * The kSBXProfilePureComputation still allows sockets, so
	 * we must disable these using rlimit.
	 */
	rl_zero.rlim_cur = rl_zero.rlim_max = 0;
	إذا (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, strerror(errno));
	إذا (setrlimit(RLIMIT_NOFILE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, strerror(errno));
	إذا (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, strerror(errno));
}

#جے_انت /* SANDBOX_DARWIN */
