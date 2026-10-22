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

#شامل "includes.h"

#اگر defined(LINUX_OOM_ADJUST) || defined(SYSTEMD_NOTIFY)
#شامل <sys/socket.h>
#شامل <sys/un.h>

#شامل <errno.h>
#شامل <inttypes.h>
#شامل <stdarg.h>
#شامل <string.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <time.h>
#شامل <unistd.h>

#شامل "log.h"
#شامل "xmalloc.h"
#شامل "port-linux.h"
#شامل "misc.h"

#ifdef LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

ایستا صحیح oom_adj_save = INT_MIN;
ایستا نویسه *oom_adj_path = پوچ;
ساختار {
	نویسه *path;
	صحیح مقدار;
} oom_adjust[] = {
	{"/proc/self/oom_score_adj", -1000},	/* kernels >= 2.6.36 */
	{"/proc/self/oom_adj", -17},		/* kernels <= 2.6.35 */
	{پوچ, 0},
};

/*
 * Tell the kernel's out-of-memory killer to avoid sshd.
 * Returns the previous oom_adj value or zero.
 */
تهی
oom_adjust_setup(تهی)
{
	صحیح i, مقدار;
	FILE *fp;

	debug3("%s", __func__);
	 برای (i = 0; oom_adjust[i].path != پوچ; i++) {
		oom_adj_path = oom_adjust[i].path;
		مقدار = oom_adjust[i].مقدار;
		اگر ((fp = fopen(oom_adj_path, "r+")) != پوچ) {
			اگر (fscanf(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_path,
				    strerror(errno));
			وگرنه {
				rewind(fp);
				اگر (fprintf(fp, "%d\n", مقدار) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_path, strerror(errno));
				وگرنه
					debug("Set %s from %d to %d",
					   oom_adj_path, oom_adj_save, مقدار);
			}
			fclose(fp);
			بازگشت;
		}
	}
	oom_adj_path = پوچ;
}

/* Restore the saved OOM adjustment */
تهی
oom_adjust_restore(تهی)
{
	FILE *fp;

	debug3("%s", __func__);
	اگر (oom_adj_save == INT_MIN || oom_adj_path == پوچ ||
	    (fp = fopen(oom_adj_path, "w")) == پوچ)
		بازگشت;

	اگر (fprintf(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_path, strerror(errno));
	وگرنه
		debug("Set %s to %d", oom_adj_path, oom_adj_save);

	fclose(fp);
	بازگشت;
}
#endif /* LINUX_OOM_ADJUST */

#ifdef LINUX_MEMLOCK_ONFAULT
#شامل <sys/mman.h>

تهی
memlock_onfault_setup(تهی)
{
	اگر (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", strerror(errno));
	وگرنه
		debug("memory locked");
}
#endif /* LINUX_MEMLOCK_ONFAULT */

#ifdef SYSTEMD_NOTIFY

ایستا تهی ssh_systemd_notify(ثابت نویسه *, ...)
    __attribute__((__format__ (printf, 1, 2))) __attribute__((__nonnull__ (1)));

ایستا تهی
ssh_systemd_notify(ثابت نویسه *fmt, ...)
{
	نویسه *s = پوچ;
	ثابت نویسه *path;
	ساختار stat sb;
	ساختار sockaddr_un addr;
	صحیح fd = -1;
	va_list ap;

	اگر ((path = getenv("NOTIFY_SOCKET")) == پوچ || strlen(path) == 0)
		بازگشت;

	va_start(ap, fmt);
	xvasprintf(&s, fmt, ap);
	va_end(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	اگر (path[0] != '/' && path[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", path);
		برو out;
	}

	اگر (path[0] == '/' && stat(path, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", path, strerror(errno));
		برو out;
	}

	memset(&addr, 0, اندازه(addr));
	addr.sun_family = AF_UNIX;
	اگر (strlcpy(addr.sun_path, path,
	    اندازه(addr.sun_path)) >= اندازه(addr.sun_path)) {
		error_f("socket path \"%s\" too long", path);
		برو out;
	}
	/* Support for abstract socket */
	اگر (addr.sun_path[0] == '@')
		addr.sun_path[0] = 0;
	اگر ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", path, strerror(errno));
		برو out;
	}
	اگر (connect(fd, (ساختار sockaddr *)&addr, اندازه(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", path, strerror(errno));
		برو out;
	}
	اگر (اكتب(fd, s, strlen(s)) != (ssize_t)strlen(s)) {
		error_f("socket \"%s\" write: %s", path, strerror(errno));
		برو out;
	}
	debug_f("socket \"%s\" notified %s", path, s);
 out:
	اگر (fd != -1)
		close(fd);
	آزاد(s);
}

تهی
ssh_systemd_notify_ready(تهی)
{
	ssh_systemd_notify("READY=1");
}

تهی
ssh_systemd_notify_reload(تهی)
{
	ساختار timespec now;

	monotime_ts(&now);
	اگر (now.tv_sec < 0 || now.tv_nsec < 0) {
		error_f("monotime returned negative value");
		ssh_systemd_notify("RELOADING=1");
	} وگرنه {
		ssh_systemd_notify("RELOADING=1\nMONOTONIC_USEC=%llu",
		    ((uint64_t)now.tv_sec * 1000000ULL) +
		    ((uint64_t)now.tv_nsec / 1000ULL));
	}
}
#endif /* SYSTEMD_NOTIFY */

#endif /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
