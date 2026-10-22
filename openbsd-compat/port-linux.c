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

#جيڪڏهن_وصف_ٿيل LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

ساكن صحيح oom_adj_save = INT_MIN;
ساكن حرف *oom_adj_رستو = عدم;
بنية {
	حرف *رستو;
	صحيح قدر;
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
oom_adjust_تياري(فراغ)
{
	صحيح i, قدر;
	FILE *fp;

	debug3("%s", __func__);
	 لكل (i = 0; oom_adjust[i].رستو != عدم; i++) {
		oom_adj_رستو = oom_adjust[i].رستو;
		قدر = oom_adjust[i].قدر;
		إذا ((fp = fopen(oom_adj_رستو, "r+")) != عدم) {
			إذا (fscanf(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_رستو,
				    strerror(errno));
			وإلا {
				rewind(fp);
				إذا (fprintf(fp, "%d\n", قدر) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_رستو, strerror(errno));
				وإلا
					debug("Set %s from %d to %d",
					   oom_adj_رستو, oom_adj_save, قدر);
			}
			fclose(fp);
			أرجع;
		}
	}
	oom_adj_رستو = عدم;
}

/* Restore the saved OOM adjustment */
فراغ
oom_adjust_restore(فراغ)
{
	FILE *fp;

	debug3("%s", __func__);
	إذا (oom_adj_save == INT_MIN || oom_adj_رستو == عدم ||
	    (fp = fopen(oom_adj_رستو, "w")) == عدم)
		أرجع;

	إذا (fprintf(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_رستو, strerror(errno));
	وإلا
		debug("Set %s to %d", oom_adj_رستو, oom_adj_save);

	fclose(fp);
	أرجع;
}
#جيڪڏهن_پورو /* LINUX_OOM_ADJUST */

#جيڪڏهن_وصف_ٿيل LINUX_MEMLOCK_ONFAULT
#ضمن <sys/mman.h>

فراغ
memlock_onfault_تياري(فراغ)
{
	إذا (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", strerror(errno));
	وإلا
		debug("memory locked");
}
#جيڪڏهن_پورو /* LINUX_MEMLOCK_ONFAULT */

#جيڪڏهن_وصف_ٿيل SYSTEMD_NOTIFY

ساكن فراغ ssh_systemd_notify(ثابت حرف *, ...)
    __attribute__((__format__ (لکو, 1, 2))) __attribute__((__nonnull__ (1)));

ساكن فراغ
ssh_systemd_notify(ثابت حرف *fmt, ...)
{
	حرف *s = عدم;
	ثابت حرف *رستو;
	بنية stat sb;
	بنية sockaddr_un addr;
	صحيح fd = -1;
	va_list ap;

	إذا ((رستو = getenv("NOTIFY_SOCKET")) == عدم || لڙي_ڊيگهه(رستو) == 0)
		أرجع;

	va_start(ap, fmt);
	xvasprintf(&s, fmt, ap);
	va_end(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	إذا (رستو[0] != '/' && رستو[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", رستو);
		اذهب ٻاهريون;
	}

	إذا (رستو[0] == '/' && stat(رستو, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", رستو, strerror(errno));
		اذهب ٻاهريون;
	}

	memset(&addr, 0, حجم(addr));
	addr.sun_family = AF_UNIX;
	إذا (strlcpy(addr.sun_رستو, رستو,
	    حجم(addr.sun_رستو)) >= حجم(addr.sun_رستو)) {
		error_f("socket path \"%s\" too long", رستو);
		اذهب ٻاهريون;
	}
	/* Support for abstract socket */
	إذا (addr.sun_رستو[0] == '@')
		addr.sun_رستو[0] = 0;
	إذا ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", رستو, strerror(errno));
		اذهب ٻاهريون;
	}
	إذا (connect(fd, (بنية sockaddr *)&addr, حجم(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", رستو, strerror(errno));
		اذهب ٻاهريون;
	}
	إذا (اكتب(fd, s, لڙي_ڊيگهه(s)) != (ssize_t)لڙي_ڊيگهه(s)) {
		error_f("socket \"%s\" write: %s", رستو, strerror(errno));
		اذهب ٻاهريون;
	}
	debug_f("socket \"%s\" notified %s", رستو, s);
 ٻاهريون:
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
#جيڪڏهن_پورو /* SYSTEMD_NOTIFY */

#جيڪڏهن_پورو /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
