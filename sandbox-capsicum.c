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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SANDBOX_CAPSICUM

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/resource.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/capsicum.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CAPSICUM_HELPERS_H
#ਅਨ੍ਤਰ੍ਭਾਵ <capsicum_helpers.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-sandbox.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

/*
 * Capsicum sandbox that sets zero nfiles, nprocs and filesize rlimits,
 * limits rights on stdout, stdin, stderr, monitor and switches to
 * capability mode.
 */

ਬਣਤਰ ssh_sandbox {
	ਪੂਰਨ m_recvfd;
	ਪੂਰਨ m_log_sendfd;
};

ਬਣਤਰ ssh_sandbox *
ssh_sandbox_init(ਬਣਤਰ monitor *monitor)
{
	ਬਣਤਰ ssh_sandbox *box;

	debug3_f("preparing capsicum sandbox");
	box = xcalloc(1, ਆਕਾਰ(*box));
	box->m_recvfd = monitor->m_recvfd;
	box->m_log_sendfd = monitor->m_log_sendfd;
	ਵਾਪਸ box;
}

ਖਾਲੀ
ssh_sandbox_ਬੱਚਾ(ਬਣਤਰ ssh_sandbox *box)
{
	ਬਣਤਰ rlimit rl_zero;
	cap_rights_t rights;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CAPH_CACHE_TZDATA
	caph_cache_tzdata();
#ਜੇ_ਅੰਤ

	rl_zero.rlim_cur = rl_zero.rlim_max = 0;

	ਜੇ (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, strerror(errno));
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SANDBOX_SKIP_RLIMIT_NOFILE
	ਜੇ (setrlimit(RLIMIT_NOFILE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, strerror(errno));
#ਜੇ_ਅੰਤ
	ਜੇ (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, strerror(errno));

	cap_rights_init(&rights);

	ਜੇ (cap_rights_ਹੱਦਬੰਦੀ(STDIN_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stdin: %m");
	ਜੇ (cap_rights_ਹੱਦਬੰਦੀ(STDOUT_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stdout: %m");
	ਜੇ (cap_rights_ਹੱਦਬੰਦੀ(STDERR_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stderr: %m");

	cap_rights_init(&rights, CAP_READ, CAP_WRITE);
	ਜੇ (cap_rights_ਹੱਦਬੰਦੀ(box->m_recvfd, &rights) < 0 &&
	    errno != ENOSYS)
		fatal_f("failed to limit the network socket");
	cap_rights_init(&rights, CAP_WRITE);
	ਜੇ (cap_rights_ਹੱਦਬੰਦੀ(box->m_log_sendfd, &rights) < 0 &&
	    errno != ENOSYS)
		fatal_f("failed to limit the logging socket");
	ਜੇ (cap_enter() < 0 && errno != ENOSYS)
		fatal_f("failed to enter capability mode");

}

#ਜੇ_ਅੰਤ /* SANDBOX_CAPSICUM */
