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

#ಆದರೆ defined(LINUX_OOM_ADJUST) || defined(SYSTEMD_NOTIFY)
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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ oom_adj_save = INT_MIN;
ಸ್ಥಿರ ಅಕ್ಷರ *oom_adj_ಮಾರ್ಗ = ಖಾಲಿ;
ರಚನೆ {
	ಅಕ್ಷರ *ಮಾರ್ಗ;
	ಪೂರ್ಣಾಂಕ ಮೌಲ್ಯ;
} oom_adjust[] = {
	{"/proc/self/oom_score_adj", -1000},	/* kernels >= 2.6.36 */
	{"/proc/self/oom_adj", -17},		/* kernels <= 2.6.35 */
	{ಖಾಲಿ, 0},
};

/*
 * Tell the kernel's out-of-memory killer to avoid sshd.
 * Returns the previous oom_adj value or zero.
 */
ಶೂನ್ಯ
oom_adjust_ಸಿದ್ಧತೆ(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ i, ಮೌಲ್ಯ;
	FILE *fp;

	debug3("%s", __func__);
	 ಗಾಗಿ (i = 0; oom_adjust[i].ಮಾರ್ಗ != ಖಾಲಿ; i++) {
		oom_adj_ಮಾರ್ಗ = oom_adjust[i].ಮಾರ್ಗ;
		ಮೌಲ್ಯ = oom_adjust[i].ಮೌಲ್ಯ;
		ಆದರೆ ((fp = fopen(oom_adj_ಮಾರ್ಗ, "r+")) != ಖಾಲಿ) {
			ಆದರೆ (fscanf(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_ಮಾರ್ಗ,
				    strerror(errno));
			ಇಲ್ಲದಿದ್ದರೆ {
				rewind(fp);
				ಆದರೆ (fprintf(fp, "%d\n", ಮೌಲ್ಯ) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_ಮಾರ್ಗ, strerror(errno));
				ಇಲ್ಲದಿದ್ದರೆ
					debug("Set %s from %d to %d",
					   oom_adj_ಮಾರ್ಗ, oom_adj_save, ಮೌಲ್ಯ);
			}
			fclose(fp);
			ಹಿಂತಿರುಗಿ;
		}
	}
	oom_adj_ಮಾರ್ಗ = ಖಾಲಿ;
}

/* Restore the saved OOM adjustment */
ಶೂನ್ಯ
oom_adjust_restore(ಶೂನ್ಯ)
{
	FILE *fp;

	debug3("%s", __func__);
	ಆದರೆ (oom_adj_save == INT_MIN || oom_adj_ಮಾರ್ಗ == ಖಾಲಿ ||
	    (fp = fopen(oom_adj_ಮಾರ್ಗ, "w")) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	ಆದರೆ (fprintf(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_ಮಾರ್ಗ, strerror(errno));
	ಇಲ್ಲದಿದ್ದರೆ
		debug("Set %s to %d", oom_adj_ಮಾರ್ಗ, oom_adj_save);

	fclose(fp);
	ಹಿಂತಿರುಗಿ;
}
#ಆದರೆ_ಅಂತ್ಯ /* LINUX_OOM_ADJUST */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ LINUX_MEMLOCK_ONFAULT
#ಅನ್ತರ್ಭಾವ <sys/mman.h>

ಶೂನ್ಯ
memlock_onfault_ಸಿದ್ಧತೆ(ಶೂನ್ಯ)
{
	ಆದರೆ (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", strerror(errno));
	ಇಲ್ಲದಿದ್ದರೆ
		debug("memory locked");
}
#ಆದರೆ_ಅಂತ್ಯ /* LINUX_MEMLOCK_ONFAULT */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SYSTEMD_NOTIFY

ಸ್ಥಿರ ಶೂನ್ಯ ssh_systemd_notify(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...)
    __attribute__((__format__ (ಬರೆ, 1, 2))) __attribute__((__nonnull__ (1)));

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_systemd_notify(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	ಅಕ್ಷರ *s = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ;
	ರಚನೆ stat sb;
	ರಚನೆ sockaddr_un addr;
	ಪೂರ್ಣಾಂಕ fd = -1;
	va_list ap;

	ಆದರೆ ((ಮಾರ್ಗ = getenv("NOTIFY_SOCKET")) == ಖಾಲಿ || ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ) == 0)
		ಹಿಂತಿರುಗಿ;

	va_start(ap, fmt);
	xvasprintf(&s, fmt, ap);
	va_end(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	ಆದರೆ (ಮಾರ್ಗ[0] != '/' && ಮಾರ್ಗ[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", ಮಾರ್ಗ);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (ಮಾರ್ಗ[0] == '/' && stat(ಮಾರ್ಗ, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", ಮಾರ್ಗ, strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}

	memset(&addr, 0, ಗಾತ್ರ(addr));
	addr.sun_family = AF_UNIX;
	ಆದರೆ (strlcpy(addr.sun_ಮಾರ್ಗ, ಮಾರ್ಗ,
	    ಗಾತ್ರ(addr.sun_ಮಾರ್ಗ)) >= ಗಾತ್ರ(addr.sun_ಮಾರ್ಗ)) {
		error_f("socket path \"%s\" too long", ಮಾರ್ಗ);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Support for abstract socket */
	ಆದರೆ (addr.sun_ಮಾರ್ಗ[0] == '@')
		addr.sun_ಮಾರ್ಗ[0] = 0;
	ಆದರೆ ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", ಮಾರ್ಗ, strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (connect(fd, (ರಚನೆ sockaddr *)&addr, ಗಾತ್ರ(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", ಮಾರ್ಗ, strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (ಲಿಖ(fd, s, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(s)) != (ssize_t)ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(s)) {
		error_f("socket \"%s\" write: %s", ಮಾರ್ಗ, strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	debug_f("socket \"%s\" notified %s", ಮಾರ್ಗ, s);
 ಹೊರಹೋಗು:
	ಆದರೆ (fd != -1)
		close(fd);
	ಬಿಡುಗಡೆ(s);
}

ಶೂನ್ಯ
ssh_systemd_notify_ready(ಶೂನ್ಯ)
{
	ssh_systemd_notify("READY=1");
}

ಶೂನ್ಯ
ssh_systemd_notify_reload(ಶೂನ್ಯ)
{
	ರಚನೆ timespec now;

	monotime_ts(&now);
	ಆದರೆ (now.tv_sec < 0 || now.tv_nsec < 0) {
		error_f("monotime returned negative value");
		ssh_systemd_notify("RELOADING=1");
	} ಇಲ್ಲದಿದ್ದರೆ {
		ssh_systemd_notify("RELOADING=1\nMONOTONIC_USEC=%llu",
		    ((uint64_t)now.tv_sec * 1000000ULL) +
		    ((uint64_t)now.tv_nsec / 1000ULL));
	}
}
#ಆದರೆ_ಅಂತ್ಯ /* SYSTEMD_NOTIFY */

#ಆದರೆ_ಅಂತ್ಯ /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
