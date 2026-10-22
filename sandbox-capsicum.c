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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే SANDBOX_CAPSICUM

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/time.h>
#అన్తర్భావ <sys/resource.h>
#అన్తర్భావ <sys/capsicum.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#నిర్వచితమైతే HAVE_CAPSICUM_HELPERS_H
#అన్తర్భావ <capsicum_helpers.h>
#అయితే_ముగింపు

#అన్తర్భావ "log.h"
#అన్తర్భావ "monitor.h"
#అన్తర్భావ "ssh-sandbox.h"
#అన్తర్భావ "xmalloc.h"

/*
 * Capsicum sandbox that sets zero nfiles, nprocs and filesize rlimits,
 * limits rights on stdout, stdin, stderr, monitor and switches to
 * capability mode.
 */

నిర్మాణం ssh_sandbox {
	పూర్ణాంకం m_recvfd;
	పూర్ణాంకం m_log_sendfd;
};

నిర్మాణం ssh_sandbox *
ssh_sandbox_init(నిర్మాణం monitor *monitor)
{
	నిర్మాణం ssh_sandbox *box;

	debug3_f("preparing capsicum sandbox");
	box = xcalloc(1, పరిమాణం(*box));
	box->m_recvfd = monitor->m_recvfd;
	box->m_log_sendfd = monitor->m_log_sendfd;
	తిరిగి box;
}

శూన్య
ssh_sandbox_బిడ్డ(నిర్మాణం ssh_sandbox *box)
{
	నిర్మాణం rlimit rl_zero;
	cap_rights_t rights;

#నిర్వచితమైతే HAVE_CAPH_CACHE_TZDATA
	caph_cache_tzdata();
#అయితే_ముగింపు

	rl_zero.rlim_cur = rl_zero.rlim_max = 0;

	ఒకవేళ (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, strerror(errno));
#నిర్వచితం_కాకపోతే SANDBOX_SKIP_RLIMIT_NOFILE
	ఒకవేళ (setrlimit(RLIMIT_NOFILE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, strerror(errno));
#అయితే_ముగింపు
	ఒకవేళ (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, strerror(errno));

	cap_rights_init(&rights);

	ఒకవేళ (cap_rights_హద్దు(STDIN_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stdin: %m");
	ఒకవేళ (cap_rights_హద్దు(STDOUT_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stdout: %m");
	ఒకవేళ (cap_rights_హద్దు(STDERR_FILENO, &rights) < 0 && errno != ENOSYS)
		fatal("can't limit stderr: %m");

	cap_rights_init(&rights, CAP_READ, CAP_WRITE);
	ఒకవేళ (cap_rights_హద్దు(box->m_recvfd, &rights) < 0 &&
	    errno != ENOSYS)
		fatal_f("failed to limit the network socket");
	cap_rights_init(&rights, CAP_WRITE);
	ఒకవేళ (cap_rights_హద్దు(box->m_log_sendfd, &rights) < 0 &&
	    errno != ENOSYS)
		fatal_f("failed to limit the logging socket");
	ఒకవేళ (cap_enter() < 0 && errno != ENOSYS)
		fatal_f("failed to enter capability mode");

}

#అయితే_ముగింపు /* SANDBOX_CAPSICUM */
