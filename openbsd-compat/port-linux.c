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

#অন্তর্ভাব "includes.h"

#যদি defined(LINUX_OOM_ADJUST) || defined(SYSTEMD_NOTIFY)
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/un.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <inttypes.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "port-linux.h"
#অন্তর্ভাব "misc.h"

#ifdef LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

স্থির পূর্ণাঙ্ক oom_adj_save = INT_MIN;
স্থির বর্ণ *oom_adj_path = রিক্ত;
সংরচনা {
	বর্ণ *path;
	পূর্ণাঙ্ক মান;
} oom_adjust[] = {
	{"/proc/self/oom_score_adj", -1000},	/* kernels >= 2.6.36 */
	{"/proc/self/oom_adj", -17},		/* kernels <= 2.6.35 */
	{রিক্ত, 0},
};

/*
 * Tell the kernel's out-of-memory killer to avoid sshd.
 * Returns the previous oom_adj value or zero.
 */
শূন্য
oom_adjust_setup(শূন্য)
{
	পূর্ণাঙ্ক i, মান;
	FILE *fp;

	debug3("%s", __func__);
	 প্রতি (i = 0; oom_adjust[i].path != রিক্ত; i++) {
		oom_adj_path = oom_adjust[i].path;
		মান = oom_adjust[i].মান;
		যদি ((fp = fopen(oom_adj_path, "r+")) != রিক্ত) {
			যদি (fscanf(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_path,
				    strerror(errno));
			অন্যথা {
				rewind(fp);
				যদি (fprintf(fp, "%d\n", মান) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_path, strerror(errno));
				অন্যথা
					debug("Set %s from %d to %d",
					   oom_adj_path, oom_adj_save, মান);
			}
			fclose(fp);
			প্রত্যাগম;
		}
	}
	oom_adj_path = রিক্ত;
}

/* Restore the saved OOM adjustment */
শূন্য
oom_adjust_restore(শূন্য)
{
	FILE *fp;

	debug3("%s", __func__);
	যদি (oom_adj_save == INT_MIN || oom_adj_path == রিক্ত ||
	    (fp = fopen(oom_adj_path, "w")) == রিক্ত)
		প্রত্যাগম;

	যদি (fprintf(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_path, strerror(errno));
	অন্যথা
		debug("Set %s to %d", oom_adj_path, oom_adj_save);

	fclose(fp);
	প্রত্যাগম;
}
#endif /* LINUX_OOM_ADJUST */

#ifdef LINUX_MEMLOCK_ONFAULT
#অন্তর্ভাব <sys/mman.h>

শূন্য
memlock_onfault_setup(শূন্য)
{
	যদি (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", strerror(errno));
	অন্যথা
		debug("memory locked");
}
#endif /* LINUX_MEMLOCK_ONFAULT */

#ifdef SYSTEMD_NOTIFY

স্থির শূন্য ssh_systemd_notify(ধ্রুব বর্ণ *, ...)
    __attribute__((__format__ (printf, 1, 2))) __attribute__((__nonnull__ (1)));

স্থির শূন্য
ssh_systemd_notify(ধ্রুব বর্ণ *fmt, ...)
{
	বর্ণ *s = রিক্ত;
	ধ্রুব বর্ণ *path;
	সংরচনা stat sb;
	সংরচনা sockaddr_un addr;
	পূর্ণাঙ্ক fd = -1;
	va_list ap;

	যদি ((path = getenv("NOTIFY_SOCKET")) == রিক্ত || strlen(path) == 0)
		প্রত্যাগম;

	va_start(ap, fmt);
	xvasprintf(&s, fmt, ap);
	va_end(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	যদি (path[0] != '/' && path[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", path);
		গচ্ছ out;
	}

	যদি (path[0] == '/' && stat(path, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", path, strerror(errno));
		গচ্ছ out;
	}

	memset(&addr, 0, পরিমাণ(addr));
	addr.sun_family = AF_UNIX;
	যদি (strlcpy(addr.sun_path, path,
	    পরিমাণ(addr.sun_path)) >= পরিমাণ(addr.sun_path)) {
		error_f("socket path \"%s\" too long", path);
		গচ্ছ out;
	}
	/* Support for abstract socket */
	যদি (addr.sun_path[0] == '@')
		addr.sun_path[0] = 0;
	যদি ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", path, strerror(errno));
		গচ্ছ out;
	}
	যদি (connect(fd, (সংরচনা sockaddr *)&addr, পরিমাণ(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", path, strerror(errno));
		গচ্ছ out;
	}
	যদি (লিখ(fd, s, strlen(s)) != (ssize_t)strlen(s)) {
		error_f("socket \"%s\" write: %s", path, strerror(errno));
		গচ্ছ out;
	}
	debug_f("socket \"%s\" notified %s", path, s);
 out:
	যদি (fd != -1)
		close(fd);
	মুক্ত(s);
}

শূন্য
ssh_systemd_notify_ready(শূন্য)
{
	ssh_systemd_notify("READY=1");
}

শূন্য
ssh_systemd_notify_reload(শূন্য)
{
	সংরচনা timespec now;

	monotime_ts(&now);
	যদি (now.tv_sec < 0 || now.tv_nsec < 0) {
		error_f("monotime returned negative value");
		ssh_systemd_notify("RELOADING=1");
	} অন্যথা {
		ssh_systemd_notify("RELOADING=1\nMONOTONIC_USEC=%llu",
		    ((uint64_t)now.tv_sec * 1000000ULL) +
		    ((uint64_t)now.tv_nsec / 1000ULL));
	}
}
#endif /* SYSTEMD_NOTIFY */

#endif /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
