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

#અન્તર્ભાવ "includes.h"

#જો defined(LINUX_OOM_ADJUST) || defined(SYSTEMD_NOTIFY)
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/un.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <inttypes.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "port-linux.h"
#અન્તર્ભાવ "misc.h"

#ifdef LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

સ્થિર પૂર્ણાંક oom_adj_save = INT_MIN;
સ્થિર અક્ષર *oom_adj_path = ખાલી;
સંરચના {
	અક્ષર *path;
	પૂર્ણાંક કિંમત;
} oom_adjust[] = {
	{"/proc/self/oom_score_adj", -1000},	/* kernels >= 2.6.36 */
	{"/proc/self/oom_adj", -17},		/* kernels <= 2.6.35 */
	{ખાલી, 0},
};

/*
 * Tell the kernel's out-of-memory killer to avoid sshd.
 * Returns the previous oom_adj value or zero.
 */
શૂન્ય
oom_adjust_setup(શૂન્ય)
{
	પૂર્ણાંક i, કિંમત;
	FILE *fp;

	debug3("%s", __func__);
	 માટે (i = 0; oom_adjust[i].path != ખાલી; i++) {
		oom_adj_path = oom_adjust[i].path;
		કિંમત = oom_adjust[i].કિંમત;
		જો ((fp = fopen(oom_adj_path, "r+")) != ખાલી) {
			જો (fscanf(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_path,
				    strerror(errno));
			નહીંતર {
				rewind(fp);
				જો (fprintf(fp, "%d\n", કિંમત) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_path, strerror(errno));
				નહીંતર
					debug("Set %s from %d to %d",
					   oom_adj_path, oom_adj_save, કિંમત);
			}
			fclose(fp);
			પાછા;
		}
	}
	oom_adj_path = ખાલી;
}

/* Restore the saved OOM adjustment */
શૂન્ય
oom_adjust_restore(શૂન્ય)
{
	FILE *fp;

	debug3("%s", __func__);
	જો (oom_adj_save == INT_MIN || oom_adj_path == ખાલી ||
	    (fp = fopen(oom_adj_path, "w")) == ખાલી)
		પાછા;

	જો (fprintf(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_path, strerror(errno));
	નહીંતર
		debug("Set %s to %d", oom_adj_path, oom_adj_save);

	fclose(fp);
	પાછા;
}
#endif /* LINUX_OOM_ADJUST */

#ifdef LINUX_MEMLOCK_ONFAULT
#અન્તર્ભાવ <sys/mman.h>

શૂન્ય
memlock_onfault_setup(શૂન્ય)
{
	જો (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", strerror(errno));
	નહીંતર
		debug("memory locked");
}
#endif /* LINUX_MEMLOCK_ONFAULT */

#ifdef SYSTEMD_NOTIFY

સ્થિર શૂન્ય ssh_systemd_notify(અચલ અક્ષર *, ...)
    __attribute__((__format__ (printf, 1, 2))) __attribute__((__nonnull__ (1)));

સ્થિર શૂન્ય
ssh_systemd_notify(અચલ અક્ષર *fmt, ...)
{
	અક્ષર *s = ખાલી;
	અચલ અક્ષર *path;
	સંરચના stat sb;
	સંરચના sockaddr_un addr;
	પૂર્ણાંક fd = -1;
	va_list ap;

	જો ((path = getenv("NOTIFY_SOCKET")) == ખાલી || strlen(path) == 0)
		પાછા;

	va_start(ap, fmt);
	xvasprintf(&s, fmt, ap);
	va_end(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	જો (path[0] != '/' && path[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", path);
		જાઓ out;
	}

	જો (path[0] == '/' && stat(path, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", path, strerror(errno));
		જાઓ out;
	}

	memset(&addr, 0, કદ(addr));
	addr.sun_family = AF_UNIX;
	જો (strlcpy(addr.sun_path, path,
	    કદ(addr.sun_path)) >= કદ(addr.sun_path)) {
		error_f("socket path \"%s\" too long", path);
		જાઓ out;
	}
	/* Support for abstract socket */
	જો (addr.sun_path[0] == '@')
		addr.sun_path[0] = 0;
	જો ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", path, strerror(errno));
		જાઓ out;
	}
	જો (connect(fd, (સંરચના sockaddr *)&addr, કદ(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", path, strerror(errno));
		જાઓ out;
	}
	જો (લિખ(fd, s, strlen(s)) != (ssize_t)strlen(s)) {
		error_f("socket \"%s\" write: %s", path, strerror(errno));
		જાઓ out;
	}
	debug_f("socket \"%s\" notified %s", path, s);
 out:
	જો (fd != -1)
		close(fd);
	મુક્ત(s);
}

શૂન્ય
ssh_systemd_notify_ready(શૂન્ય)
{
	ssh_systemd_notify("READY=1");
}

શૂન્ય
ssh_systemd_notify_reload(શૂન્ય)
{
	સંરચના timespec now;

	monotime_ts(&now);
	જો (now.tv_sec < 0 || now.tv_nsec < 0) {
		error_f("monotime returned negative value");
		ssh_systemd_notify("RELOADING=1");
	} નહીંતર {
		ssh_systemd_notify("RELOADING=1\nMONOTONIC_USEC=%llu",
		    ((uint64_t)now.tv_sec * 1000000ULL) +
		    ((uint64_t)now.tv_nsec / 1000ULL));
	}
}
#endif /* SYSTEMD_NOTIFY */

#endif /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
