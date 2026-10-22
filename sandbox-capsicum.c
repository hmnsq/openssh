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

#अन्तर्भाव "includes.h"

#ifdef SANDBOX_CAPSICUM

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/resource.h>
#अन्तर्भाव <sys/capsicum.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#ifdef HAVE_CAPSICUM_HELPERS_H
#अन्तर्भाव <capsicum_helpers.h>
#endif

#अन्तर्भाव "log.h"
#अन्तर्भाव "monitor.h"
#अन्तर्भाव "ssh-sandbox.h"
#अन्तर्भाव "xmalloc.h"

/*
 * Capsicum sandbox that sets zero nfiles, nprocs and filesize rlimits,
 * limits rights on stdout, stdin, stderr, monitor and switches to
 * capability mode.
 */

संरचना ssh_sandbox {
	पूर्णांक m_recvfd;
	पूर्णांक m_log_sendfd;
};

संरचना ssh_sandbox *
ssh_sandbox_init(संरचना monitor *monitor)
{
	संरचना ssh_sandbox *box;

	debug3_f("preparing capsicum sandbox");
	box = xcalloc(1, आकार(*box));
	box->m_recvfd = monitor->m_recvfd;
	box->m_log_sendfd = monitor->m_log_sendfd;
	परत box;
}

शून्य
ssh_sandbox_child(संरचना ssh_sandbox *box)
{
	संरचना rlimit rl_zero;
	cap_rights_t rights;

#ifdef HAVE_CAPH_CACHE_TZDATA
	caph_cache_tzdata();
#endif

	rl_zero.rlim_cur = rl_zero.rlim_max = 0;

	जर (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, म_त्रुटि(त्रुटि_सं));
#ifndef SANDBOX_SKIP_RLIMIT_NOFILE
	जर (setrlimit(RLIMIT_NOFILE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, म_त्रुटि(त्रुटि_सं));
#endif
	जर (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, म_त्रुटि(त्रुटि_सं));

	cap_rights_init(&rights);

	जर (cap_rights_limit(STDIN_FILENO, &rights) < 0 && त्रुटि_सं != ENOSYS)
		fatal("can't limit stdin: %m");
	जर (cap_rights_limit(STDOUT_FILENO, &rights) < 0 && त्रुटि_सं != ENOSYS)
		fatal("can't limit stdout: %m");
	जर (cap_rights_limit(STDERR_FILENO, &rights) < 0 && त्रुटि_सं != ENOSYS)
		fatal("can't limit stderr: %m");

	cap_rights_init(&rights, CAP_READ, CAP_WRITE);
	जर (cap_rights_limit(box->m_recvfd, &rights) < 0 &&
	    त्रुटि_सं != ENOSYS)
		fatal_f("failed to limit the network socket");
	cap_rights_init(&rights, CAP_WRITE);
	जर (cap_rights_limit(box->m_log_sendfd, &rights) < 0 &&
	    त्रुटि_सं != ENOSYS)
		fatal_f("failed to limit the logging socket");
	जर (cap_enter() < 0 && त्रुटि_सं != ENOSYS)
		fatal_f("failed to enter capability mode");

}

#endif /* SANDBOX_CAPSICUM */
