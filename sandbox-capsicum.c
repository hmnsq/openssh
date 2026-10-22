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

#ضمن "includes.h"

#ifdef SANDBOX_CAPSICUM

#ضمن <sys/types.h>
#ضمن <sys/time.h>
#ضمن <sys/resource.h>
#ضمن <sys/capsicum.h>

#ضمن <errno.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ifdef HAVE_CAPSICUM_HELPERS_H
#ضمن <capsicum_helpers.h>
#endif

#ضمن "log.h"
#ضمن "monitor.h"
#ضمن "ssh-sandbox.h"
#ضمن "xmalloc.h"

/*
 * Capsicum sandbox that sets zero nfiles, nprocs and filesize rlimits,
 * limits rights on stdout, stdin, stderr, monitor and switches to
 * capability mode.
 */

بنية ssh_sandbox {
	صحيح m_recvfd;
	صحيح m_log_sendfd;
};

بنية ssh_sandbox *
ssh_sandbox_init(بنية monitor *monitor)
{
	بنية ssh_sandbox *box;

	debug3_f("preparing capsicum sandbox");
	box = xcalloc(1, حجم(*box));
	box->m_recvfd = monitor->m_recvfd;
	box->m_log_sendfd = monitor->m_log_sendfd;
	החזר box;
}

فراغ
ssh_sandbox_child(بنية ssh_sandbox *box)
{
	بنية rlimit rl_zero;
	cap_rights_t rights;

#ifdef HAVE_CAPH_CACHE_TZDATA
	caph_cache_tzdata();
#endif

	rl_zero.rlim_cur = rl_zero.rlim_max = 0;

	אם (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, strerror(errno));
#ifndef SANDBOX_SKIP_RLIMIT_NOFILE
	אם (setrlimit(RLIMIT_NOFILE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, strerror(errno));
#endif
	אם (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, strerror(errno));

	cap_rights_init(&rights);

	אם (cap_rights_limit(STDIN_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stdin: %m");
	אם (cap_rights_limit(STDOUT_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stdout: %m");
	אם (cap_rights_limit(STDERR_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stderr: %m");

	cap_rights_init(&rights, CAP_READ, CAP_WRITE);
	אם (cap_rights_limit(box->m_recvfd, &rights) < 0 &&
	    errno != ENOSYS)
		fatal_f("failed to limit the network socket");
	cap_rights_init(&rights, CAP_WRITE);
	אם (cap_rights_limit(box->m_log_sendfd, &rights) < 0 &&
	    errno != ENOSYS)
		fatal_f("failed to limit the logging socket");
	אם (cap_enter() < 0 && errno != ENOSYS)
		fatal_f("failed to enter capability mode");

}

#endif /* SANDBOX_CAPSICUM */
