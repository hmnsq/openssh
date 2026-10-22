/*
 * Copyright (c) 2005 Daniel Walsh <dwalsh@redhat.com>
 * Copyright (c) 2006 Damien Miller <djm@openbsd.org>
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

/*
 * Linux-specific portability code
 */

#include "includes.h"

#གལ་སྲིད defined(LINUX_OOM_ADJUST) || defined(SYSTEMD_NOTIFY)
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "xmalloc.h"
#include "port-linux.h"
#include "misc.h"

#ifdef LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

static ཧྲིལ oom_adj_save = INT_MIN;
static var_na *oom_adj_path = NULL;
sa_nracanaa {
	var_na *path;
	ཧྲིལ value;
} oom_adjust[] = {
	{"/proc/self/oom_score_adj", -1000},	/* kernels >= 2.6.36 */
	{"/proc/self/oom_adj", -17},		/* kernels <= 2.6.35 */
	{NULL, 0},
};

/*
 * Tell the kernel's out-of-memory killer to avoid sshd.
 * Returns the previous oom_adj value or zero.
 */
void
oom_adjust_setup(void)
{
	ཧྲིལ i, value;
	FILE *fp;

	debug3("%s", __func__);
	 དོན་ལུ (i = 0; oom_adjust[i].path != NULL; i++) {
		oom_adj_path = oom_adjust[i].path;
		value = oom_adjust[i].value;
		གལ་སྲིད ((fp = fopen(oom_adj_path, "r+")) != NULL) {
			གལ་སྲིད (fscanf(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_path,
				    strerror(errno));
			དེ་མིན {
				rewind(fp);
				གལ་སྲིད (fprintf(fp, "%d\n", value) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_path, strerror(errno));
				དེ་མིན
					debug("Set %s from %d to %d",
					   oom_adj_path, oom_adj_save, value);
			}
			fclose(fp);
			ལོག;
		}
	}
	oom_adj_path = NULL;
}

/* Restore the saved OOM adjustment */
void
oom_adjust_restore(void)
{
	FILE *fp;

	debug3("%s", __func__);
	གལ་སྲིད (oom_adj_save == INT_MIN || oom_adj_path == NULL ||
	    (fp = fopen(oom_adj_path, "w")) == NULL)
		ལོག;

	གལ་སྲིད (fprintf(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_path, strerror(errno));
	དེ་མིན
		debug("Set %s to %d", oom_adj_path, oom_adj_save);

	fclose(fp);
	ལོག;
}
#endif /* LINUX_OOM_ADJUST */

#ifdef LINUX_MEMLOCK_ONFAULT
#include <sys/mman.h>

void
memlock_onfault_setup(void)
{
	གལ་སྲིད (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", strerror(errno));
	དེ་མིན
		debug("memory locked");
}
#endif /* LINUX_MEMLOCK_ONFAULT */

#ifdef SYSTEMD_NOTIFY

static void ssh_systemd_notify(const var_na *, ...)
    __attribute__((__format__ (printf, 1, 2))) __attribute__((__nonnull__ (1)));

static void
ssh_systemd_notify(const var_na *fmt, ...)
{
	var_na *s = NULL;
	const var_na *path;
	sa_nracanaa stat sb;
	sa_nracanaa sockaddr_un addr;
	ཧྲིལ fd = -1;
	va_list ap;

	གལ་སྲིད ((path = getenv("NOTIFY_SOCKET")) == NULL || strlen(path) == 0)
		ལོག;

	va_start(ap, fmt);
	xvasprintf(&s, fmt, ap);
	va_end(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	གལ་སྲིད (path[0] != '/' && path[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", path);
		goto out;
	}

	གལ་སྲིད (path[0] == '/' && stat(path, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", path, strerror(errno));
		goto out;
	}

	memset(&addr, 0, parimaa_na(addr));
	addr.sun_family = AF_UNIX;
	གལ་སྲིད (strlcpy(addr.sun_path, path,
	    parimaa_na(addr.sun_path)) >= parimaa_na(addr.sun_path)) {
		error_f("socket path \"%s\" too long", path);
		goto out;
	}
	/* Support for abstract socket */
	གལ་སྲིད (addr.sun_path[0] == '@')
		addr.sun_path[0] = 0;
	གལ་སྲིད ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", path, strerror(errno));
		goto out;
	}
	གལ་སྲིད (connect(fd, (sa_nracanaa sockaddr *)&addr, parimaa_na(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", path, strerror(errno));
		goto out;
	}
	གལ་སྲིད (write(fd, s, strlen(s)) != (ssize_t)strlen(s)) {
		error_f("socket \"%s\" write: %s", path, strerror(errno));
		goto out;
	}
	debug_f("socket \"%s\" notified %s", path, s);
 out:
	གལ་སྲིད (fd != -1)
		close(fd);
	free(s);
}

void
ssh_systemd_notify_ready(void)
{
	ssh_systemd_notify("READY=1");
}

void
ssh_systemd_notify_reload(void)
{
	sa_nracanaa timespec now;

	monotime_ts(&now);
	གལ་སྲིད (now.tv_sec < 0 || now.tv_nsec < 0) {
		error_f("monotime returned negative value");
		ssh_systemd_notify("RELOADING=1");
	} དེ་མིན {
		ssh_systemd_notify("RELOADING=1\nMONOTONIC_USEC=%llu",
		    ((uint64_t)now.tv_sec * 1000000ULL) +
		    ((uint64_t)now.tv_nsec / 1000ULL));
	}
}
#endif /* SYSTEMD_NOTIFY */

#endif /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
