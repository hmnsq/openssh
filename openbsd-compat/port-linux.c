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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಯದಿ defined(LINUX_OOM_ADJUST) || defined(SYSTEMD_NOTIFY)
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/un.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <inttypes.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "port-linux.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

#ifdef LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ oom_adj_save = INT_MIN;
ಸ್ಥಿರ ವರ್ಣ *oom_adj_path = ರಿಕ್ತ;
ಸಂರಚನಾ {
	ವರ್ಣ *path;
	ಪೂರ್ಣಾಙ್ಕ ಮೌಲ್ಯ;
} oom_adjust[] = {
	{"/proc/self/oom_score_adj", -1000},	/* kernels >= 2.6.36 */
	{"/proc/self/oom_adj", -17},		/* kernels <= 2.6.35 */
	{ರಿಕ್ತ, 0},
};

/*
 * Tell the kernel's out-of-memory killer to avoid sshd.
 * Returns the previous oom_adj value or zero.
 */
ಶೂನ್ಯ
oom_adjust_setup(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ i, ಮೌಲ್ಯ;
	FILE *fp;

	debug3("%s", __func__);
	 ಪ್ರತಿ (i = 0; oom_adjust[i].path != ರಿಕ್ತ; i++) {
		oom_adj_path = oom_adjust[i].path;
		ಮೌಲ್ಯ = oom_adjust[i].ಮೌಲ್ಯ;
		ಯದಿ ((fp = fopen(oom_adj_path, "r+")) != ರಿಕ್ತ) {
			ಯದಿ (fscanf(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_path,
				    strerror(errno));
			ಅನ್ಯಥಾ {
				rewind(fp);
				ಯದಿ (fprintf(fp, "%d\n", ಮೌಲ್ಯ) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_path, strerror(errno));
				ಅನ್ಯಥಾ
					debug("Set %s from %d to %d",
					   oom_adj_path, oom_adj_save, ಮೌಲ್ಯ);
			}
			fclose(fp);
			ಪ್ರತ್ಯಾಗಮ;
		}
	}
	oom_adj_path = ರಿಕ್ತ;
}

/* Restore the saved OOM adjustment */
ಶೂನ್ಯ
oom_adjust_restore(ಶೂನ್ಯ)
{
	FILE *fp;

	debug3("%s", __func__);
	ಯದಿ (oom_adj_save == INT_MIN || oom_adj_path == ರಿಕ್ತ ||
	    (fp = fopen(oom_adj_path, "w")) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	ಯದಿ (fprintf(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_path, strerror(errno));
	ಅನ್ಯಥಾ
		debug("Set %s to %d", oom_adj_path, oom_adj_save);

	fclose(fp);
	ಪ್ರತ್ಯಾಗಮ;
}
#endif /* LINUX_OOM_ADJUST */

#ifdef LINUX_MEMLOCK_ONFAULT
#ಅನ್ತರ್ಭಾವ <sys/mman.h>

ಶೂನ್ಯ
memlock_onfault_setup(ಶೂನ್ಯ)
{
	ಯದಿ (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", strerror(errno));
	ಅನ್ಯಥಾ
		debug("memory locked");
}
#endif /* LINUX_MEMLOCK_ONFAULT */

#ifdef SYSTEMD_NOTIFY

ಸ್ಥಿರ ಶೂನ್ಯ ssh_systemd_notify(ಧ್ರುವ ವರ್ಣ *, ...)
    __attribute__((__format__ (printf, 1, 2))) __attribute__((__nonnull__ (1)));

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_systemd_notify(ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	ವರ್ಣ *s = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *path;
	ಸಂರಚನಾ stat sb;
	ಸಂರಚನಾ sockaddr_un addr;
	ಪೂರ್ಣಾಙ್ಕ fd = -1;
	va_list ap;

	ಯದಿ ((path = getenv("NOTIFY_SOCKET")) == ರಿಕ್ತ || strlen(path) == 0)
		ಪ್ರತ್ಯಾಗಮ;

	va_start(ap, fmt);
	xvasprintf(&s, fmt, ap);
	va_end(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	ಯದಿ (path[0] != '/' && path[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", path);
		ಗಚ್ಛ out;
	}

	ಯದಿ (path[0] == '/' && stat(path, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", path, strerror(errno));
		ಗಚ್ಛ out;
	}

	memset(&addr, 0, ಪರಿಮಾಣ(addr));
	addr.sun_family = AF_UNIX;
	ಯದಿ (strlcpy(addr.sun_path, path,
	    ಪರಿಮಾಣ(addr.sun_path)) >= ಪರಿಮಾಣ(addr.sun_path)) {
		error_f("socket path \"%s\" too long", path);
		ಗಚ್ಛ out;
	}
	/* Support for abstract socket */
	ಯದಿ (addr.sun_path[0] == '@')
		addr.sun_path[0] = 0;
	ಯದಿ ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", path, strerror(errno));
		ಗಚ್ಛ out;
	}
	ಯದಿ (connect(fd, (ಸಂರಚನಾ sockaddr *)&addr, ಪರಿಮಾಣ(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", path, strerror(errno));
		ಗಚ್ಛ out;
	}
	ಯದಿ (ಲಿಖ(fd, s, strlen(s)) != (ssize_t)strlen(s)) {
		error_f("socket \"%s\" write: %s", path, strerror(errno));
		ಗಚ್ಛ out;
	}
	debug_f("socket \"%s\" notified %s", path, s);
 out:
	ಯದಿ (fd != -1)
		close(fd);
	ಮುಕ್ತ(s);
}

ಶೂನ್ಯ
ssh_systemd_notify_ready(ಶೂನ್ಯ)
{
	ssh_systemd_notify("READY=1");
}

ಶೂನ್ಯ
ssh_systemd_notify_reload(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ timespec now;

	monotime_ts(&now);
	ಯದಿ (now.tv_sec < 0 || now.tv_nsec < 0) {
		error_f("monotime returned negative value");
		ssh_systemd_notify("RELOADING=1");
	} ಅನ್ಯಥಾ {
		ssh_systemd_notify("RELOADING=1\nMONOTONIC_USEC=%llu",
		    ((uint64_t)now.tv_sec * 1000000ULL) +
		    ((uint64_t)now.tv_nsec / 1000ULL));
	}
}
#endif /* SYSTEMD_NOTIFY */

#endif /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
