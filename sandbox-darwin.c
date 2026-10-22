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

#समावेश "includes.h"

#अगर_घोषित SANDBOX_DARWIN

#समावेश <sys/types.h>

#समावेश <sandbox.h>

#समावेश <errno.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "log.h"
#समावेश "ssh-sandbox.h"
#समावेश "monitor.h"
#समावेश "xmalloc.h"

/* Darwin/OS X sandbox */

काष्ठा ssh_sandbox {
	पूर्णांक junk;
};

काष्ठा ssh_sandbox *
ssh_sandbox_init(काष्ठा monitor *monitor)
{
	काष्ठा ssh_sandbox *box;

	/*
	 * Strictly, we don't need to maintain any state here but we need
	 * to return non-NULL to satisfy the API.
	 */
	debug3_f("preparing Darwin sandbox");
	box = xcalloc(1, माप(*box));
	वापस box;
}

व्योम
ssh_sandbox_child(काष्ठा ssh_sandbox *box)
{
	अक्षर *errmsg;
	काष्ठा rlimit rl_zero;

	debug3_f("starting Darwin sandbox");
	अगर (sandbox_init(kSBXProfilePureComputation, SANDBOX_NAMED,
	    &errmsg) == -1)
		fatal_f("sandbox_init: %s", errmsg);

	/*
	 * The kSBXProfilePureComputation still allows sockets, so
	 * we must disable these using rlimit.
	 */
	rl_zero.rlim_cur = rl_zero.rlim_max = 0;
	अगर (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, म_त्रुटि(त्रुटि_सं));
	अगर (setrlimit(RLIMIT_NOFILE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, म_त्रुटि(त्रुटि_सं));
	अगर (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, म_त्रुटि(त्रुटि_सं));
}

#पूर्ण_अगर /* SANDBOX_DARWIN */
