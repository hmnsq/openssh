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

#അന്തര്ഭാവ "includes.h"

#എങ്കിൽ defined(LINUX_OOM_ADJUST) || defined(SYSTEMD_NOTIFY)
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/un.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <inttypes.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "port-linux.h"
#അന്തര്ഭാവ "misc.h"

#ifdef LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

സ്ഥിതം പൂർണ്ണസംഖ്യ oom_adj_save = INT_MIN;
സ്ഥിതം അക്ഷരം *oom_adj_path = ശൂന്യ;
ഘടന {
	അക്ഷരം *path;
	പൂർണ്ണസംഖ്യ മൂല്യം;
} oom_adjust[] = {
	{"/proc/self/oom_score_adj", -1000},	/* kernels >= 2.6.36 */
	{"/proc/self/oom_adj", -17},		/* kernels <= 2.6.35 */
	{ശൂന്യ, 0},
};

/*
 * Tell the kernel's out-of-memory killer to avoid sshd.
 * Returns the previous oom_adj value or zero.
 */
ശൂന്യം
oom_adjust_setup(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ i, മൂല്യം;
	FILE *fp;

	debug3("%s", __func__);
	 വേണ്ടി (i = 0; oom_adjust[i].path != ശൂന്യ; i++) {
		oom_adj_path = oom_adjust[i].path;
		മൂല്യം = oom_adjust[i].മൂല്യം;
		എങ്കിൽ ((fp = fopen(oom_adj_path, "r+")) != ശൂന്യ) {
			എങ്കിൽ (fscanf(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_path,
				    strerror(errno));
			അല്ലെങ്കിൽ {
				rewind(fp);
				എങ്കിൽ (fprintf(fp, "%d\n", മൂല്യം) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_path, strerror(errno));
				അല്ലെങ്കിൽ
					debug("Set %s from %d to %d",
					   oom_adj_path, oom_adj_save, മൂല്യം);
			}
			fclose(fp);
			തിരികെ;
		}
	}
	oom_adj_path = ശൂന്യ;
}

/* Restore the saved OOM adjustment */
ശൂന്യം
oom_adjust_restore(ശൂന്യം)
{
	FILE *fp;

	debug3("%s", __func__);
	എങ്കിൽ (oom_adj_save == INT_MIN || oom_adj_path == ശൂന്യ ||
	    (fp = fopen(oom_adj_path, "w")) == ശൂന്യ)
		തിരികെ;

	എങ്കിൽ (fprintf(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_path, strerror(errno));
	അല്ലെങ്കിൽ
		debug("Set %s to %d", oom_adj_path, oom_adj_save);

	fclose(fp);
	തിരികെ;
}
#endif /* LINUX_OOM_ADJUST */

#ifdef LINUX_MEMLOCK_ONFAULT
#അന്തര്ഭാവ <sys/mman.h>

ശൂന്യം
memlock_onfault_setup(ശൂന്യം)
{
	എങ്കിൽ (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", strerror(errno));
	അല്ലെങ്കിൽ
		debug("memory locked");
}
#endif /* LINUX_MEMLOCK_ONFAULT */

#ifdef SYSTEMD_NOTIFY

സ്ഥിതം ശൂന്യം ssh_systemd_notify(സ്ഥിരം അക്ഷരം *, ...)
    __attribute__((__format__ (printf, 1, 2))) __attribute__((__nonnull__ (1)));

സ്ഥിതം ശൂന്യം
ssh_systemd_notify(സ്ഥിരം അക്ഷരം *fmt, ...)
{
	അക്ഷരം *s = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *path;
	ഘടന stat sb;
	ഘടന sockaddr_un addr;
	പൂർണ്ണസംഖ്യ fd = -1;
	va_list ap;

	എങ്കിൽ ((path = getenv("NOTIFY_SOCKET")) == ശൂന്യ || strlen(path) == 0)
		തിരികെ;

	va_start(ap, fmt);
	xvasprintf(&s, fmt, ap);
	va_end(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	എങ്കിൽ (path[0] != '/' && path[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", path);
		പോകുക out;
	}

	എങ്കിൽ (path[0] == '/' && stat(path, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", path, strerror(errno));
		പോകുക out;
	}

	memset(&addr, 0, വലുപ്പം(addr));
	addr.sun_family = AF_UNIX;
	എങ്കിൽ (strlcpy(addr.sun_path, path,
	    വലുപ്പം(addr.sun_path)) >= വലുപ്പം(addr.sun_path)) {
		error_f("socket path \"%s\" too long", path);
		പോകുക out;
	}
	/* Support for abstract socket */
	എങ്കിൽ (addr.sun_path[0] == '@')
		addr.sun_path[0] = 0;
	എങ്കിൽ ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", path, strerror(errno));
		പോകുക out;
	}
	എങ്കിൽ (connect(fd, (ഘടന sockaddr *)&addr, വലുപ്പം(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", path, strerror(errno));
		പോകുക out;
	}
	എങ്കിൽ (ലിഖ(fd, s, strlen(s)) != (ssize_t)strlen(s)) {
		error_f("socket \"%s\" write: %s", path, strerror(errno));
		പോകുക out;
	}
	debug_f("socket \"%s\" notified %s", path, s);
 out:
	എങ്കിൽ (fd != -1)
		close(fd);
	സ്വതന്ത്രം(s);
}

ശൂന്യം
ssh_systemd_notify_ready(ശൂന്യം)
{
	ssh_systemd_notify("READY=1");
}

ശൂന്യം
ssh_systemd_notify_reload(ശൂന്യം)
{
	ഘടന timespec now;

	monotime_ts(&now);
	എങ്കിൽ (now.tv_sec < 0 || now.tv_nsec < 0) {
		error_f("monotime returned negative value");
		ssh_systemd_notify("RELOADING=1");
	} അല്ലെങ്കിൽ {
		ssh_systemd_notify("RELOADING=1\nMONOTONIC_USEC=%llu",
		    ((uint64_t)now.tv_sec * 1000000ULL) +
		    ((uint64_t)now.tv_nsec / 1000ULL));
	}
}
#endif /* SYSTEMD_NOTIFY */

#endif /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
