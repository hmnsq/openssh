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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଯଦି defined(LINUX_OOM_ADJUST) || defined(SYSTEMD_NOTIFY)
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/un.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <inttypes.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "port-linux.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"

#ifdef LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା oom_adj_save = INT_MIN;
ସ୍ଥିର ଅକ୍ଷର *oom_adj_path = ଖାଲି;
ସଂରଚନା {
	ଅକ୍ଷର *path;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ମୂଲ୍ୟ;
} oom_adjust[] = {
	{"/proc/self/oom_score_adj", -1000},	/* kernels >= 2.6.36 */
	{"/proc/self/oom_adj", -17},		/* kernels <= 2.6.35 */
	{ଖାଲି, 0},
};

/*
 * Tell the kernel's out-of-memory killer to avoid sshd.
 * Returns the previous oom_adj value or zero.
 */
ଶୂନ୍ୟ
oom_adjust_setup(ଶୂନ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, ମୂଲ୍ୟ;
	FILE *fp;

	debug3("%s", __func__);
	 ପାଇଁ (i = 0; oom_adjust[i].path != ଖାଲି; i++) {
		oom_adj_path = oom_adjust[i].path;
		ମୂଲ୍ୟ = oom_adjust[i].ମୂଲ୍ୟ;
		ଯଦି ((fp = fopen(oom_adj_path, "r+")) != ଖାଲି) {
			ଯଦି (fscanf(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_path,
				    strerror(errno));
			ଅନ୍ୟଥା {
				rewind(fp);
				ଯଦି (fprintf(fp, "%d\n", ମୂଲ୍ୟ) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_path, strerror(errno));
				ଅନ୍ୟଥା
					debug("Set %s from %d to %d",
					   oom_adj_path, oom_adj_save, ମୂଲ୍ୟ);
			}
			fclose(fp);
			ଫେରନ୍ତୁ;
		}
	}
	oom_adj_path = ଖାଲି;
}

/* Restore the saved OOM adjustment */
ଶୂନ୍ୟ
oom_adjust_restore(ଶୂନ୍ୟ)
{
	FILE *fp;

	debug3("%s", __func__);
	ଯଦି (oom_adj_save == INT_MIN || oom_adj_path == ଖାଲି ||
	    (fp = fopen(oom_adj_path, "w")) == ଖାଲି)
		ଫେରନ୍ତୁ;

	ଯଦି (fprintf(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_path, strerror(errno));
	ଅନ୍ୟଥା
		debug("Set %s to %d", oom_adj_path, oom_adj_save);

	fclose(fp);
	ଫେରନ୍ତୁ;
}
#endif /* LINUX_OOM_ADJUST */

#ifdef LINUX_MEMLOCK_ONFAULT
#ଅନ୍ତର୍ଭାଵ <sys/mman.h>

ଶୂନ୍ୟ
memlock_onfault_setup(ଶୂନ୍ୟ)
{
	ଯଦି (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", strerror(errno));
	ଅନ୍ୟଥା
		debug("memory locked");
}
#endif /* LINUX_MEMLOCK_ONFAULT */

#ifdef SYSTEMD_NOTIFY

ସ୍ଥିର ଶୂନ୍ୟ ssh_systemd_notify(ଅଚଳ ଅକ୍ଷର *, ...)
    __attribute__((__format__ (printf, 1, 2))) __attribute__((__nonnull__ (1)));

ସ୍ଥିର ଶୂନ୍ୟ
ssh_systemd_notify(ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	ଅକ୍ଷର *s = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *path;
	ସଂରଚନା stat sb;
	ସଂରଚନା sockaddr_un addr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd = -1;
	va_list ap;

	ଯଦି ((path = getenv("NOTIFY_SOCKET")) == ଖାଲି || strlen(path) == 0)
		ଫେରନ୍ତୁ;

	va_start(ap, fmt);
	xvasprintf(&s, fmt, ap);
	va_end(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	ଯଦି (path[0] != '/' && path[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", path);
		ଯାଅ out;
	}

	ଯଦି (path[0] == '/' && stat(path, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", path, strerror(errno));
		ଯାଅ out;
	}

	memset(&addr, 0, ଆକାର(addr));
	addr.sun_family = AF_UNIX;
	ଯଦି (strlcpy(addr.sun_path, path,
	    ଆକାର(addr.sun_path)) >= ଆକାର(addr.sun_path)) {
		error_f("socket path \"%s\" too long", path);
		ଯାଅ out;
	}
	/* Support for abstract socket */
	ଯଦି (addr.sun_path[0] == '@')
		addr.sun_path[0] = 0;
	ଯଦି ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", path, strerror(errno));
		ଯାଅ out;
	}
	ଯଦି (connect(fd, (ସଂରଚନା sockaddr *)&addr, ଆକାର(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", path, strerror(errno));
		ଯାଅ out;
	}
	ଯଦି (ଲିଖ(fd, s, strlen(s)) != (ssize_t)strlen(s)) {
		error_f("socket \"%s\" write: %s", path, strerror(errno));
		ଯାଅ out;
	}
	debug_f("socket \"%s\" notified %s", path, s);
 out:
	ଯଦି (fd != -1)
		close(fd);
	ମୁକ୍ତ(s);
}

ଶୂନ୍ୟ
ssh_systemd_notify_ready(ଶୂନ୍ୟ)
{
	ssh_systemd_notify("READY=1");
}

ଶୂନ୍ୟ
ssh_systemd_notify_reload(ଶୂନ୍ୟ)
{
	ସଂରଚନା timespec now;

	monotime_ts(&now);
	ଯଦି (now.tv_sec < 0 || now.tv_nsec < 0) {
		error_f("monotime returned negative value");
		ssh_systemd_notify("RELOADING=1");
	} ଅନ୍ୟଥା {
		ssh_systemd_notify("RELOADING=1\nMONOTONIC_USEC=%llu",
		    ((uint64_t)now.tv_sec * 1000000ULL) +
		    ((uint64_t)now.tv_nsec / 1000ULL));
	}
}
#endif /* SYSTEMD_NOTIFY */

#endif /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
