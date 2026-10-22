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

#அந்தர்பாவ "includes.h"

#ifdef SANDBOX_CAPSICUM

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/time.h>
#அந்தர்பாவ <sys/resource.h>
#அந்தர்பாவ <sys/capsicum.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#ifdef HAVE_CAPSICUM_HELPERS_H
#அந்தர்பாவ <capsicum_helpers.h>
#endif

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "monitor.h"
#அந்தர்பாவ "ssh-sandbox.h"
#அந்தர்பாவ "xmalloc.h"

/*
 * Capsicum sandbox that sets zero nfiles, nprocs and filesize rlimits,
 * limits rights on stdout, stdin, stderr, monitor and switches to
 * capability mode.
 */

கட்டமைப்பு ssh_sandbox {
	முழு m_recvfd;
	முழு m_log_sendfd;
};

கட்டமைப்பு ssh_sandbox *
ssh_sandbox_init(கட்டமைப்பு monitor *monitor)
{
	கட்டமைப்பு ssh_sandbox *box;

	debug3_f("preparing capsicum sandbox");
	box = xcalloc(1, அளவு(*box));
	box->m_recvfd = monitor->m_recvfd;
	box->m_log_sendfd = monitor->m_log_sendfd;
	திரும்பு box;
}

வெறுமை
ssh_sandbox_child(கட்டமைப்பு ssh_sandbox *box)
{
	கட்டமைப்பு rlimit rl_zero;
	cap_rights_t rights;

#ifdef HAVE_CAPH_CACHE_TZDATA
	caph_cache_tzdata();
#endif

	rl_zero.rlim_cur = rl_zero.rlim_max = 0;

	எனில் (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, strerror(errno));
#ifndef SANDBOX_SKIP_RLIMIT_NOFILE
	எனில் (setrlimit(RLIMIT_NOFILE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, strerror(errno));
#endif
	எனில் (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, strerror(errno));

	cap_rights_init(&rights);

	எனில் (cap_rights_limit(STDIN_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stdin: %m");
	எனில் (cap_rights_limit(STDOUT_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stdout: %m");
	எனில் (cap_rights_limit(STDERR_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stderr: %m");

	cap_rights_init(&rights, CAP_READ, CAP_WRITE);
	எனில் (cap_rights_limit(box->m_recvfd, &rights) < 0 &&
	    errno != ENOSYS)
		fatal_f("failed to limit the network socket");
	cap_rights_init(&rights, CAP_WRITE);
	எனில் (cap_rights_limit(box->m_log_sendfd, &rights) < 0 &&
	    errno != ENOSYS)
		fatal_f("failed to limit the logging socket");
	எனில் (cap_enter() < 0 && errno != ENOSYS)
		fatal_f("failed to enter capability mode");

}

#endif /* SANDBOX_CAPSICUM */
