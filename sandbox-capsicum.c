/*
 * Copyright (c) 2011 Dag-Erling Smorgrav
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

#अगर_घोषित SANDBOX_CAPSICUM

#समावेश <sys/types.h>
#समावेश <sys/time.h>
#समावेश <sys/resource.h>
#समावेश <sys/capsicum.h>

#समावेश <errno.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#अगर_घोषित HAVE_CAPSICUM_HELPERS_H
#समावेश <capsicum_helpers.h>
#पूर्ण_अगर

#समावेश "log.h"
#समावेश "monitor.h"
#समावेश "ssh-sandbox.h"
#समावेश "xmalloc.h"

/*
 * Capsicum sandbox that sets zero nfiles, nprocs and filesize rlimits,
 * limits rights on stdout, stdin, stderr, monitor and switches to
 * capability mode.
 */

काष्ठा ssh_sandbox {
	पूर्णांक m_recvfd;
	पूर्णांक m_log_sendfd;
};

काष्ठा ssh_sandbox *
ssh_sandbox_init(काष्ठा monitor *monitor)
{
	काष्ठा ssh_sandbox *box;

	debug3_f("preparing capsicum sandbox");
	box = xcalloc(1, माप(*box));
	box->m_recvfd = monitor->m_recvfd;
	box->m_log_sendfd = monitor->m_log_sendfd;
	वापस box;
}

व्योम
ssh_sandbox_child(काष्ठा ssh_sandbox *box)
{
	काष्ठा rlimit rl_zero;
	cap_rights_t rights;

#अगर_घोषित HAVE_CAPH_CACHE_TZDATA
	caph_cache_tzdata();
#पूर्ण_अगर

	rl_zero.rlim_cur = rl_zero.rlim_max = 0;

	अगर (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, म_त्रुटि(त्रुटि_सं));
#अगर_अघोषित SANDBOX_SKIP_RLIMIT_NOFILE
	अगर (setrlimit(RLIMIT_NOFILE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर
	अगर (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, म_त्रुटि(त्रुटि_सं));

	cap_rights_init(&rights);

	अगर (cap_rights_limit(STDIN_FILENO, &rights) < 0 && त्रुटि_सं != ENOSYS)
		fatal("can't limit stdin: %m");
	अगर (cap_rights_limit(STDOUT_FILENO, &rights) < 0 && त्रुटि_सं != ENOSYS)
		fatal("can't limit stdout: %m");
	अगर (cap_rights_limit(STDERR_FILENO, &rights) < 0 && त्रुटि_सं != ENOSYS)
		fatal("can't limit stderr: %m");

	cap_rights_init(&rights, CAP_READ, CAP_WRITE);
	अगर (cap_rights_limit(box->m_recvfd, &rights) < 0 &&
	    त्रुटि_सं != ENOSYS)
		fatal_f("failed to limit the network socket");
	cap_rights_init(&rights, CAP_WRITE);
	अगर (cap_rights_limit(box->m_log_sendfd, &rights) < 0 &&
	    त्रुटि_सं != ENOSYS)
		fatal_f("failed to limit the logging socket");
	अगर (cap_enter() < 0 && त्रुटि_सं != ENOSYS)
		fatal_f("failed to enter capability mode");

}

#पूर्ण_अगर /* SANDBOX_CAPSICUM */
