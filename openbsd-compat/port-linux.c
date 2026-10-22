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

#ضمن "includes.h"

#إذا defined(LINUX_OOM_ADJUST) || defined(SYSTEMD_NOTIFY)
#ضمن <sys/socket.h>
#ضمن <sys/un.h>

#ضمن <errno.h>
#ضمن <inttypes.h>
#ضمن <stdarg.h>
#ضمن <string.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <time.h>
#ضمن <unistd.h>

#ضمن "log.h"
#ضمن "xmalloc.h"
#ضمن "port-linux.h"
#ضمن "misc.h"

#اگر_تعریف_شده LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

ساكن صحيح oom_adj_save = INT_MIN;
ساكن حرف *oom_adj_مسیر = عدم;
بنية {
	حرف *مسیر;
	صحيح مقدار;
} oom_adjust[] = {
	{"/proc/self/oom_score_adj", -1000},	/* kernels >= 2.6.36 */
	{"/proc/self/oom_adj", -17},		/* kernels <= 2.6.35 */
	{عدم, 0},
};

/*
 * Tell the kernel's out-of-memory killer to avoid sshd.
 * Returns the previous oom_adj value or zero.
 */
فراغ
oom_adjust_راهاندازی(فراغ)
{
	صحيح i, مقدار;
	FILE *fp;

	debug3("%s", __func__);
	 لكل (i = 0; oom_adjust[i].مسیر != عدم; i++) {
		oom_adj_مسیر = oom_adjust[i].مسیر;
		مقدار = oom_adjust[i].مقدار;
		إذا ((fp = fopen(oom_adj_مسیر, "r+")) != عدم) {
			إذا (fscanf(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_مسیر,
				    strerror(errno));
			وإلا {
				rewind(fp);
				إذا (fprintf(fp, "%d\n", مقدار) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_مسیر, strerror(errno));
				وإلا
					debug("Set %s from %d to %d",
					   oom_adj_مسیر, oom_adj_save, مقدار);
			}
			fclose(fp);
			أرجع;
		}
	}
	oom_adj_مسیر = عدم;
}

/* Restore the saved OOM adjustment */
فراغ
oom_adjust_restore(فراغ)
{
	FILE *fp;

	debug3("%s", __func__);
	إذا (oom_adj_save == INT_MIN || oom_adj_مسیر == عدم ||
	    (fp = fopen(oom_adj_مسیر, "w")) == عدم)
		أرجع;

	إذا (fprintf(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_مسیر, strerror(errno));
	وإلا
		debug("Set %s to %d", oom_adj_مسیر, oom_adj_save);

	fclose(fp);
	أرجع;
}
#پایان_اگر /* LINUX_OOM_ADJUST */

#اگر_تعریف_شده LINUX_MEMLOCK_ONFAULT
#ضمن <sys/mman.h>

فراغ
memlock_onfault_راهاندازی(فراغ)
{
	إذا (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", strerror(errno));
	وإلا
		debug("memory locked");
}
#پایان_اگر /* LINUX_MEMLOCK_ONFAULT */

#اگر_تعریف_شده SYSTEMD_NOTIFY

ساكن فراغ ssh_systemd_notify(ثابت حرف *, ...)
    __attribute__((__format__ (چاپ_کن, 1, 2))) __attribute__((__nonnull__ (1)));

ساكن فراغ
ssh_systemd_notify(ثابت حرف *fmt, ...)
{
	حرف *s = عدم;
	ثابت حرف *مسیر;
	بنية stat sb;
	بنية sockaddr_un addr;
	صحيح fd = -1;
	va_list ap;

	إذا ((مسیر = getenv("NOTIFY_SOCKET")) == عدم || طول_رشته(مسیر) == 0)
		أرجع;

	va_start(ap, fmt);
	xvasprintf(&s, fmt, ap);
	va_end(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	إذا (مسیر[0] != '/' && مسیر[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", مسیر);
		اذهب بیرون;
	}

	إذا (مسیر[0] == '/' && stat(مسیر, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", مسیر, strerror(errno));
		اذهب بیرون;
	}

	memset(&addr, 0, حجم(addr));
	addr.sun_family = AF_UNIX;
	إذا (strlcpy(addr.sun_مسیر, مسیر,
	    حجم(addr.sun_مسیر)) >= حجم(addr.sun_مسیر)) {
		error_f("socket path \"%s\" too long", مسیر);
		اذهب بیرون;
	}
	/* Support for abstract socket */
	إذا (addr.sun_مسیر[0] == '@')
		addr.sun_مسیر[0] = 0;
	إذا ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", مسیر, strerror(errno));
		اذهب بیرون;
	}
	إذا (connect(fd, (بنية sockaddr *)&addr, حجم(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", مسیر, strerror(errno));
		اذهب بیرون;
	}
	إذا (اكتب(fd, s, طول_رشته(s)) != (ssize_t)طول_رشته(s)) {
		error_f("socket \"%s\" write: %s", مسیر, strerror(errno));
		اذهب بیرون;
	}
	debug_f("socket \"%s\" notified %s", مسیر, s);
 بیرون:
	إذا (fd != -1)
		close(fd);
	حرر(s);
}

فراغ
ssh_systemd_notify_ready(فراغ)
{
	ssh_systemd_notify("READY=1");
}

فراغ
ssh_systemd_notify_reload(فراغ)
{
	بنية timespec now;

	monotime_ts(&now);
	إذا (now.tv_sec < 0 || now.tv_nsec < 0) {
		error_f("monotime returned negative value");
		ssh_systemd_notify("RELOADING=1");
	} وإلا {
		ssh_systemd_notify("RELOADING=1\nMONOTONIC_USEC=%llu",
		    ((uint64_t)now.tv_sec * 1000000ULL) +
		    ((uint64_t)now.tv_nsec / 1000ULL));
	}
}
#پایان_اگر /* SYSTEMD_NOTIFY */

#پایان_اگر /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
