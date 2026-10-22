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

#அந்தர்பாவ "includes.h"

#எனில் defined(LINUX_OOM_ADJUST) || defined(SYSTEMD_NOTIFY)
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/un.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <inttypes.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "port-linux.h"
#அந்தர்பாவ "misc.h"

#ifdef LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

நிலையான முழு oom_adj_save = INT_MIN;
நிலையான எழுத்து *oom_adj_path = வெற்று;
கட்டமைப்பு {
	எழுத்து *path;
	முழு மதிப்பு;
} oom_adjust[] = {
	{"/proc/self/oom_score_adj", -1000},	/* kernels >= 2.6.36 */
	{"/proc/self/oom_adj", -17},		/* kernels <= 2.6.35 */
	{வெற்று, 0},
};

/*
 * Tell the kernel's out-of-memory killer to avoid sshd.
 * Returns the previous oom_adj value or zero.
 */
வெறுமை
oom_adjust_setup(வெறுமை)
{
	முழு i, மதிப்பு;
	FILE *fp;

	debug3("%s", __func__);
	 க்கு (i = 0; oom_adjust[i].path != வெற்று; i++) {
		oom_adj_path = oom_adjust[i].path;
		மதிப்பு = oom_adjust[i].மதிப்பு;
		எனில் ((fp = fopen(oom_adj_path, "r+")) != வெற்று) {
			எனில் (fscanf(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_path,
				    strerror(errno));
			இல்லையெனில் {
				rewind(fp);
				எனில் (fprintf(fp, "%d\n", மதிப்பு) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_path, strerror(errno));
				இல்லையெனில்
					debug("Set %s from %d to %d",
					   oom_adj_path, oom_adj_save, மதிப்பு);
			}
			fclose(fp);
			திரும்பு;
		}
	}
	oom_adj_path = வெற்று;
}

/* Restore the saved OOM adjustment */
வெறுமை
oom_adjust_restore(வெறுமை)
{
	FILE *fp;

	debug3("%s", __func__);
	எனில் (oom_adj_save == INT_MIN || oom_adj_path == வெற்று ||
	    (fp = fopen(oom_adj_path, "w")) == வெற்று)
		திரும்பு;

	எனில் (fprintf(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_path, strerror(errno));
	இல்லையெனில்
		debug("Set %s to %d", oom_adj_path, oom_adj_save);

	fclose(fp);
	திரும்பு;
}
#endif /* LINUX_OOM_ADJUST */

#ifdef LINUX_MEMLOCK_ONFAULT
#அந்தர்பாவ <sys/mman.h>

வெறுமை
memlock_onfault_setup(வெறுமை)
{
	எனில் (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", strerror(errno));
	இல்லையெனில்
		debug("memory locked");
}
#endif /* LINUX_MEMLOCK_ONFAULT */

#ifdef SYSTEMD_NOTIFY

நிலையான வெறுமை ssh_systemd_notify(மாறிலி எழுத்து *, ...)
    __attribute__((__format__ (printf, 1, 2))) __attribute__((__nonnull__ (1)));

நிலையான வெறுமை
ssh_systemd_notify(மாறிலி எழுத்து *fmt, ...)
{
	எழுத்து *s = வெற்று;
	மாறிலி எழுத்து *path;
	கட்டமைப்பு stat sb;
	கட்டமைப்பு sockaddr_un addr;
	முழு fd = -1;
	va_list ap;

	எனில் ((path = getenv("NOTIFY_SOCKET")) == வெற்று || strlen(path) == 0)
		திரும்பு;

	va_start(ap, fmt);
	xvasprintf(&s, fmt, ap);
	va_end(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	எனில் (path[0] != '/' && path[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", path);
		செல் out;
	}

	எனில் (path[0] == '/' && stat(path, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", path, strerror(errno));
		செல் out;
	}

	memset(&addr, 0, அளவு(addr));
	addr.sun_family = AF_UNIX;
	எனில் (strlcpy(addr.sun_path, path,
	    அளவு(addr.sun_path)) >= அளவு(addr.sun_path)) {
		error_f("socket path \"%s\" too long", path);
		செல் out;
	}
	/* Support for abstract socket */
	எனில் (addr.sun_path[0] == '@')
		addr.sun_path[0] = 0;
	எனில் ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", path, strerror(errno));
		செல் out;
	}
	எனில் (connect(fd, (கட்டமைப்பு sockaddr *)&addr, அளவு(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", path, strerror(errno));
		செல் out;
	}
	எனில் (லிக(fd, s, strlen(s)) != (ssize_t)strlen(s)) {
		error_f("socket \"%s\" write: %s", path, strerror(errno));
		செல் out;
	}
	debug_f("socket \"%s\" notified %s", path, s);
 out:
	எனில் (fd != -1)
		close(fd);
	விடுவி(s);
}

வெறுமை
ssh_systemd_notify_ready(வெறுமை)
{
	ssh_systemd_notify("READY=1");
}

வெறுமை
ssh_systemd_notify_reload(வெறுமை)
{
	கட்டமைப்பு timespec now;

	monotime_ts(&now);
	எனில் (now.tv_sec < 0 || now.tv_nsec < 0) {
		error_f("monotime returned negative value");
		ssh_systemd_notify("RELOADING=1");
	} இல்லையெனில் {
		ssh_systemd_notify("RELOADING=1\nMONOTONIC_USEC=%llu",
		    ((uint64_t)now.tv_sec * 1000000ULL) +
		    ((uint64_t)now.tv_nsec / 1000ULL));
	}
}
#endif /* SYSTEMD_NOTIFY */

#endif /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
