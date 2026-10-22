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

#شامل "includes.h"

#اگر_تعریف_شدہ SANDBOX_CAPSICUM

#شامل <sys/types.h>
#شامل <sys/time.h>
#شامل <sys/resource.h>
#شامل <sys/capsicum.h>

#شامل <errno.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#اگر_تعریف_شدہ HAVE_CAPSICUM_HELPERS_H
#شامل <capsicum_helpers.h>
#اگر_ختم

#شامل "log.h"
#شامل "monitor.h"
#شامل "ssh-sandbox.h"
#شامل "xmalloc.h"

/*
 * Capsicum sandbox that sets zero nfiles, nprocs and filesize rlimits,
 * limits rights on stdout, stdin, stderr, monitor and switches to
 * capability mode.
 */

ساخت ssh_sandbox {
	صحیح m_recvfd;
	صحیح m_log_sendfd;
};

ساخت ssh_sandbox *
ssh_sandbox_init(ساخت monitor *monitor)
{
	ساخت ssh_sandbox *box;

	debug3_f("preparing capsicum sandbox");
	box = xcalloc(1, حجم(*box));
	box->m_recvfd = monitor->m_recvfd;
	box->m_log_sendfd = monitor->m_log_sendfd;
	واپس box;
}

خالی
ssh_sandbox_بچہ(ساخت ssh_sandbox *box)
{
	ساخت rlimit rl_zero;
	cap_rights_t rights;

#اگر_تعریف_شدہ HAVE_CAPH_CACHE_TZDATA
	caph_cache_tzdata();
#اگر_ختم

	rl_zero.rlim_cur = rl_zero.rlim_max = 0;

	اگر (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, strerror(errno));
#اگر_غیر_تعریف_شدہ SANDBOX_SKIP_RLIMIT_NOFILE
	اگر (setrlimit(RLIMIT_NOFILE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, strerror(errno));
#اگر_ختم
	اگر (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, strerror(errno));

	cap_rights_init(&rights);

	اگر (cap_rights_حد_بندی(STDIN_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stdin: %m");
	اگر (cap_rights_حد_بندی(STDOUT_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stdout: %m");
	اگر (cap_rights_حد_بندی(STDERR_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stderr: %m");

	cap_rights_init(&rights, CAP_READ, CAP_WRITE);
	اگر (cap_rights_حد_بندی(box->m_recvfd, &rights) < 0 &&
	    errno != ENOSYS)
		fatal_f("failed to limit the network socket");
	cap_rights_init(&rights, CAP_WRITE);
	اگر (cap_rights_حد_بندی(box->m_log_sendfd, &rights) < 0 &&
	    errno != ENOSYS)
		fatal_f("failed to limit the logging socket");
	اگر (cap_enter() < 0 && errno != ENOSYS)
		fatal_f("failed to enter capability mode");

}

#اگر_ختم /* SANDBOX_CAPSICUM */
