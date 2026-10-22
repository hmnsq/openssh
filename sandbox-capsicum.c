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

#جيڪڏهن_وصف_ٿيل SANDBOX_CAPSICUM

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
#جيڪڏهن_وصف_ٿيل HAVE_CAPSICUM_HELPERS_H
#ضمن <capsicum_helpers.h>
#جيڪڏهن_پورو

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
	أرجع box;
}

فراغ
ssh_sandbox_ٻار(بنية ssh_sandbox *box)
{
	بنية rlimit rl_zero;
	cap_rights_t rights;

#جيڪڏهن_وصف_ٿيل HAVE_CAPH_CACHE_TZDATA
	caph_cache_tzdata();
#جيڪڏهن_پورو

	rl_zero.rlim_cur = rl_zero.rlim_max = 0;

	إذا (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, strerror(errno));
#جيڪڏهن_وصف_نه_ٿيل SANDBOX_SKIP_RLIMIT_NOFILE
	إذا (setrlimit(RLIMIT_NOFILE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, strerror(errno));
#جيڪڏهن_پورو
	إذا (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, strerror(errno));

	cap_rights_init(&rights);

	إذا (cap_rights_حد_بندي(STDIN_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stdin: %m");
	إذا (cap_rights_حد_بندي(STDOUT_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stdout: %m");
	إذا (cap_rights_حد_بندي(STDERR_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stderr: %m");

	cap_rights_init(&rights, CAP_READ, CAP_WRITE);
	إذا (cap_rights_حد_بندي(box->m_recvfd, &rights) < 0 &&
	    errno != ENOSYS)
		fatal_f("failed to limit the network socket");
	cap_rights_init(&rights, CAP_WRITE);
	إذا (cap_rights_حد_بندي(box->m_log_sendfd, &rights) < 0 &&
	    errno != ENOSYS)
		fatal_f("failed to limit the logging socket");
	إذا (cap_enter() < 0 && errno != ENOSYS)
		fatal_f("failed to enter capability mode");

}

#جيڪڏهن_پورو /* SANDBOX_CAPSICUM */
