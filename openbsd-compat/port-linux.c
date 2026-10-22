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

#اگر_تعریف_شدہ LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

ساکن صحیح oom_adj_save = INT_MIN;
ساکن حرف *oom_adj_راستہ = تہی;
ساخت {
	حرف *راستہ;
	صحیح قدر;
} oom_adjust[] = {
	{"/proc/self/oom_score_adj", -1000},	/* kernels >= 2.6.36 */
	{"/proc/self/oom_adj", -17},		/* kernels <= 2.6.35 */
	{تہی, 0},
};

/*
 * Tell the kernel's out-of-memory killer to avoid sshd.
 * Returns the previous oom_adj value or zero.
 */
خالی
oom_adjust_تیاری(خالی)
{
	صحیح i, قدر;
	FILE *fp;

	debug3("%s", __func__);
	 برائے (i = 0; oom_adjust[i].راستہ != تہی; i++) {
		oom_adj_راستہ = oom_adjust[i].راستہ;
		قدر = oom_adjust[i].قدر;
		اگر ((fp = fopen(oom_adj_راستہ, "r+")) != تہی) {
			اگر (fscanf(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_راستہ,
				    strerror(errno));
			ورنہ {
				rewind(fp);
				اگر (fprintf(fp, "%d\n", قدر) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_راستہ, strerror(errno));
				ورنہ
					debug("Set %s from %d to %d",
					   oom_adj_راستہ, oom_adj_save, قدر);
			}
			fclose(fp);
			واپس;
		}
	}
	oom_adj_راستہ = تہی;
}

/* Restore the saved OOM adjustment */
خالی
oom_adjust_restore(خالی)
{
	FILE *fp;

	debug3("%s", __func__);
	اگر (oom_adj_save == INT_MIN || oom_adj_راستہ == تہی ||
	    (fp = fopen(oom_adj_راستہ, "w")) == تہی)
		واپس;

	اگر (fprintf(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_راستہ, strerror(errno));
	ورنہ
		debug("Set %s to %d", oom_adj_راستہ, oom_adj_save);

	fclose(fp);
	واپس;
}
#اگر_ختم /* LINUX_OOM_ADJUST */

#اگر_تعریف_شدہ LINUX_MEMLOCK_ONFAULT
#شامل <sys/mman.h>

خالی
memlock_onfault_تیاری(خالی)
{
	اگر (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", strerror(errno));
	ورنہ
		debug("memory locked");
}
#اگر_ختم /* LINUX_MEMLOCK_ONFAULT */

#اگر_تعریف_شدہ SYSTEMD_NOTIFY

ساکن خالی ssh_systemd_notify(ثابت حرف *, ...)
    __attribute__((__format__ (لکھو, 1, 2))) __attribute__((__nonnull__ (1)));

ساکن خالی
ssh_systemd_notify(ثابت حرف *fmt, ...)
{
	حرف *s = تہی;
	ثابت حرف *راستہ;
	ساخت stat sb;
	ساخت sockaddr_un addr;
	صحیح fd = -1;
	va_list ap;

	اگر ((راستہ = getenv("NOTIFY_SOCKET")) == تہی || لڑی_لمبائی(راستہ) == 0)
		واپس;

	va_start(ap, fmt);
	xvasprintf(&s, fmt, ap);
	va_end(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	اگر (راستہ[0] != '/' && راستہ[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", راستہ);
		جاؤ برآمد;
	}

	اگر (راستہ[0] == '/' && stat(راستہ, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", راستہ, strerror(errno));
		جاؤ برآمد;
	}

	memset(&addr, 0, حجم(addr));
	addr.sun_family = AF_UNIX;
	اگر (strlcpy(addr.sun_راستہ, راستہ,
	    حجم(addr.sun_راستہ)) >= حجم(addr.sun_راستہ)) {
		error_f("socket path \"%s\" too long", راستہ);
		جاؤ برآمد;
	}
	/* Support for abstract socket */
	اگر (addr.sun_راستہ[0] == '@')
		addr.sun_راستہ[0] = 0;
	اگر ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", راستہ, strerror(errno));
		جاؤ برآمد;
	}
	اگر (connect(fd, (ساخت sockaddr *)&addr, حجم(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", راستہ, strerror(errno));
		جاؤ برآمد;
	}
	اگر (اكتب(fd, s, لڑی_لمبائی(s)) != (ssize_t)لڑی_لمبائی(s)) {
		error_f("socket \"%s\" write: %s", راستہ, strerror(errno));
		جاؤ برآمد;
	}
	debug_f("socket \"%s\" notified %s", راستہ, s);
 برآمد:
	اگر (fd != -1)
		close(fd);
	آزاد(s);
}

خالی
ssh_systemd_notify_ready(خالی)
{
	ssh_systemd_notify("READY=1");
}

خالی
ssh_systemd_notify_reload(خالی)
{
	ساخت timespec now;

	monotime_ts(&now);
	اگر (now.tv_sec < 0 || now.tv_nsec < 0) {
		error_f("monotime returned negative value");
		ssh_systemd_notify("RELOADING=1");
	} ورنہ {
		ssh_systemd_notify("RELOADING=1\nMONOTONIC_USEC=%llu",
		    ((uint64_t)now.tv_sec * 1000000ULL) +
		    ((uint64_t)now.tv_nsec / 1000ULL));
	}
}
#اگر_ختم /* SYSTEMD_NOTIFY */

#اگر_ختم /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
