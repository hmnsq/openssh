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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ defined(LINUX_OOM_ADJUST) || defined(SYSTEMD_NOTIFY)
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/un.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <inttypes.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "port-linux.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

ਸਥਿਰ ਪੂਰਨ oom_adj_save = INT_MIN;
ਸਥਿਰ ਅੱਖਰ *oom_adj_ਰਸਤਾ = ਨਿਰਾ;
ਬਣਤਰ {
	ਅੱਖਰ *ਰਸਤਾ;
	ਪੂਰਨ ਮੁੱਲ;
} oom_adjust[] = {
	{"/proc/self/oom_score_adj", -1000},	/* kernels >= 2.6.36 */
	{"/proc/self/oom_adj", -17},		/* kernels <= 2.6.35 */
	{ਨਿਰਾ, 0},
};

/*
 * Tell the kernel's out-of-memory killer to avoid sshd.
 * Returns the previous oom_adj value or zero.
 */
ਖਾਲੀ
oom_adjust_ਤਿਆਰੀ(ਖਾਲੀ)
{
	ਪੂਰਨ i, ਮੁੱਲ;
	FILE *fp;

	debug3("%s", __func__);
	 ਲਈ (i = 0; oom_adjust[i].ਰਸਤਾ != ਨਿਰਾ; i++) {
		oom_adj_ਰਸਤਾ = oom_adjust[i].ਰਸਤਾ;
		ਮੁੱਲ = oom_adjust[i].ਮੁੱਲ;
		ਜੇ ((fp = fopen(oom_adj_ਰਸਤਾ, "r+")) != ਨਿਰਾ) {
			ਜੇ (fscanf(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_ਰਸਤਾ,
				    strerror(errno));
			ਨਹੀਂਤਾਂ {
				rewind(fp);
				ਜੇ (fprintf(fp, "%d\n", ਮੁੱਲ) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_ਰਸਤਾ, strerror(errno));
				ਨਹੀਂਤਾਂ
					debug("Set %s from %d to %d",
					   oom_adj_ਰਸਤਾ, oom_adj_save, ਮੁੱਲ);
			}
			fclose(fp);
			ਵਾਪਸ;
		}
	}
	oom_adj_ਰਸਤਾ = ਨਿਰਾ;
}

/* Restore the saved OOM adjustment */
ਖਾਲੀ
oom_adjust_restore(ਖਾਲੀ)
{
	FILE *fp;

	debug3("%s", __func__);
	ਜੇ (oom_adj_save == INT_MIN || oom_adj_ਰਸਤਾ == ਨਿਰਾ ||
	    (fp = fopen(oom_adj_ਰਸਤਾ, "w")) == ਨਿਰਾ)
		ਵਾਪਸ;

	ਜੇ (fprintf(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_ਰਸਤਾ, strerror(errno));
	ਨਹੀਂਤਾਂ
		debug("Set %s to %d", oom_adj_ਰਸਤਾ, oom_adj_save);

	fclose(fp);
	ਵਾਪਸ;
}
#ਜੇ_ਅੰਤ /* LINUX_OOM_ADJUST */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LINUX_MEMLOCK_ONFAULT
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/mman.h>

ਖਾਲੀ
memlock_onfault_ਤਿਆਰੀ(ਖਾਲੀ)
{
	ਜੇ (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", strerror(errno));
	ਨਹੀਂਤਾਂ
		debug("memory locked");
}
#ਜੇ_ਅੰਤ /* LINUX_MEMLOCK_ONFAULT */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SYSTEMD_NOTIFY

ਸਥਿਰ ਖਾਲੀ ssh_systemd_notify(ਅਚਲ ਅੱਖਰ *, ...)
    __attribute__((__format__ (ਲਿਖੋ, 1, 2))) __attribute__((__nonnull__ (1)));

ਸਥਿਰ ਖਾਲੀ
ssh_systemd_notify(ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	ਅੱਖਰ *s = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *ਰਸਤਾ;
	ਬਣਤਰ stat sb;
	ਬਣਤਰ sockaddr_un addr;
	ਪੂਰਨ fd = -1;
	va_list ap;

	ਜੇ ((ਰਸਤਾ = getenv("NOTIFY_SOCKET")) == ਨਿਰਾ || ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ) == 0)
		ਵਾਪਸ;

	va_start(ap, fmt);
	xvasprintf(&s, fmt, ap);
	va_end(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	ਜੇ (ਰਸਤਾ[0] != '/' && ਰਸਤਾ[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", ਰਸਤਾ);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (ਰਸਤਾ[0] == '/' && stat(ਰਸਤਾ, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", ਰਸਤਾ, strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	memset(&addr, 0, ਆਕਾਰ(addr));
	addr.sun_family = AF_UNIX;
	ਜੇ (strlcpy(addr.sun_ਰਸਤਾ, ਰਸਤਾ,
	    ਆਕਾਰ(addr.sun_ਰਸਤਾ)) >= ਆਕਾਰ(addr.sun_ਰਸਤਾ)) {
		error_f("socket path \"%s\" too long", ਰਸਤਾ);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Support for abstract socket */
	ਜੇ (addr.sun_ਰਸਤਾ[0] == '@')
		addr.sun_ਰਸਤਾ[0] = 0;
	ਜੇ ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", ਰਸਤਾ, strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (connect(fd, (ਬਣਤਰ sockaddr *)&addr, ਆਕਾਰ(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", ਰਸਤਾ, strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (ਲਿਖ(fd, s, ਲੜੀ_ਲੰਬਾਈ(s)) != (ssize_t)ਲੜੀ_ਲੰਬਾਈ(s)) {
		error_f("socket \"%s\" write: %s", ਰਸਤਾ, strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	debug_f("socket \"%s\" notified %s", ਰਸਤਾ, s);
 ਬਾਹਰਲਾ:
	ਜੇ (fd != -1)
		close(fd);
	ਮੁਕਤ(s);
}

ਖਾਲੀ
ssh_systemd_notify_ready(ਖਾਲੀ)
{
	ssh_systemd_notify("READY=1");
}

ਖਾਲੀ
ssh_systemd_notify_reload(ਖਾਲੀ)
{
	ਬਣਤਰ timespec now;

	monotime_ts(&now);
	ਜੇ (now.tv_sec < 0 || now.tv_nsec < 0) {
		error_f("monotime returned negative value");
		ssh_systemd_notify("RELOADING=1");
	} ਨਹੀਂਤਾਂ {
		ssh_systemd_notify("RELOADING=1\nMONOTONIC_USEC=%llu",
		    ((uint64_t)now.tv_sec * 1000000ULL) +
		    ((uint64_t)now.tv_nsec / 1000ULL));
	}
}
#ਜੇ_ਅੰਤ /* SYSTEMD_NOTIFY */

#ਜੇ_ਅੰਤ /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
