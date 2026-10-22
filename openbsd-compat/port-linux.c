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

#అన్తర్భావ "includes.h"

#ఒకవేళ defined(LINUX_OOM_ADJUST) || defined(SYSTEMD_NOTIFY)
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/un.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <inttypes.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "port-linux.h"
#అన్తర్భావ "misc.h"

#నిర్వచితమైతే LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

స్థిర పూర్ణాంకం oom_adj_save = INT_MIN;
స్థిర అక్షరం *oom_adj_మార్గం = ఖాళీ;
నిర్మాణం {
	అక్షరం *మార్గం;
	పూర్ణాంకం విలువ;
} oom_adjust[] = {
	{"/proc/self/oom_score_adj", -1000},	/* kernels >= 2.6.36 */
	{"/proc/self/oom_adj", -17},		/* kernels <= 2.6.35 */
	{ఖాళీ, 0},
};

/*
 * Tell the kernel's out-of-memory killer to avoid sshd.
 * Returns the previous oom_adj value or zero.
 */
శూన్య
oom_adjust_అమరిక(శూన్య)
{
	పూర్ణాంకం i, విలువ;
	FILE *fp;

	debug3("%s", __func__);
	 కొరకు (i = 0; oom_adjust[i].మార్గం != ఖాళీ; i++) {
		oom_adj_మార్గం = oom_adjust[i].మార్గం;
		విలువ = oom_adjust[i].విలువ;
		ఒకవేళ ((fp = fopen(oom_adj_మార్గం, "r+")) != ఖాళీ) {
			ఒకవేళ (fscanf(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_మార్గం,
				    strerror(errno));
			లేకపోతే {
				rewind(fp);
				ఒకవేళ (fprintf(fp, "%d\n", విలువ) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_మార్గం, strerror(errno));
				లేకపోతే
					debug("Set %s from %d to %d",
					   oom_adj_మార్గం, oom_adj_save, విలువ);
			}
			fclose(fp);
			తిరిగి;
		}
	}
	oom_adj_మార్గం = ఖాళీ;
}

/* Restore the saved OOM adjustment */
శూన్య
oom_adjust_restore(శూన్య)
{
	FILE *fp;

	debug3("%s", __func__);
	ఒకవేళ (oom_adj_save == INT_MIN || oom_adj_మార్గం == ఖాళీ ||
	    (fp = fopen(oom_adj_మార్గం, "w")) == ఖాళీ)
		తిరిగి;

	ఒకవేళ (fprintf(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_మార్గం, strerror(errno));
	లేకపోతే
		debug("Set %s to %d", oom_adj_మార్గం, oom_adj_save);

	fclose(fp);
	తిరిగి;
}
#అయితే_ముగింపు /* LINUX_OOM_ADJUST */

#నిర్వచితమైతే LINUX_MEMLOCK_ONFAULT
#అన్తర్భావ <sys/mman.h>

శూన్య
memlock_onfault_అమరిక(శూన్య)
{
	ఒకవేళ (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", strerror(errno));
	లేకపోతే
		debug("memory locked");
}
#అయితే_ముగింపు /* LINUX_MEMLOCK_ONFAULT */

#నిర్వచితమైతే SYSTEMD_NOTIFY

స్థిర శూన్య ssh_systemd_notify(స్థిరరాశి అక్షరం *, ...)
    __attribute__((__format__ (రాయి, 1, 2))) __attribute__((__nonnull__ (1)));

స్థిర శూన్య
ssh_systemd_notify(స్థిరరాశి అక్షరం *fmt, ...)
{
	అక్షరం *s = ఖాళీ;
	స్థిరరాశి అక్షరం *మార్గం;
	నిర్మాణం stat sb;
	నిర్మాణం sockaddr_un addr;
	పూర్ణాంకం fd = -1;
	va_list ap;

	ఒకవేళ ((మార్గం = getenv("NOTIFY_SOCKET")) == ఖాళీ || అక్షరశ్రేణి_పొడవు(మార్గం) == 0)
		తిరిగి;

	va_start(ap, fmt);
	xvasprintf(&s, fmt, ap);
	va_end(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	ఒకవేళ (మార్గం[0] != '/' && మార్గం[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", మార్గం);
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (మార్గం[0] == '/' && stat(మార్గం, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", మార్గం, strerror(errno));
		వెళ్ళు బహిర్గతం;
	}

	memset(&addr, 0, పరిమాణం(addr));
	addr.sun_family = AF_UNIX;
	ఒకవేళ (strlcpy(addr.sun_మార్గం, మార్గం,
	    పరిమాణం(addr.sun_మార్గం)) >= పరిమాణం(addr.sun_మార్గం)) {
		error_f("socket path \"%s\" too long", మార్గం);
		వెళ్ళు బహిర్గతం;
	}
	/* Support for abstract socket */
	ఒకవేళ (addr.sun_మార్గం[0] == '@')
		addr.sun_మార్గం[0] = 0;
	ఒకవేళ ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", మార్గం, strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (connect(fd, (నిర్మాణం sockaddr *)&addr, పరిమాణం(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", మార్గం, strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (లిఖ(fd, s, అక్షరశ్రేణి_పొడవు(s)) != (ssize_t)అక్షరశ్రేణి_పొడవు(s)) {
		error_f("socket \"%s\" write: %s", మార్గం, strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	debug_f("socket \"%s\" notified %s", మార్గం, s);
 బహిర్గతం:
	ఒకవేళ (fd != -1)
		close(fd);
	విడుదల(s);
}

శూన్య
ssh_systemd_notify_ready(శూన్య)
{
	ssh_systemd_notify("READY=1");
}

శూన్య
ssh_systemd_notify_reload(శూన్య)
{
	నిర్మాణం timespec now;

	monotime_ts(&now);
	ఒకవేళ (now.tv_sec < 0 || now.tv_nsec < 0) {
		error_f("monotime returned negative value");
		ssh_systemd_notify("RELOADING=1");
	} లేకపోతే {
		ssh_systemd_notify("RELOADING=1\nMONOTONIC_USEC=%llu",
		    ((uint64_t)now.tv_sec * 1000000ULL) +
		    ((uint64_t)now.tv_nsec / 1000ULL));
	}
}
#అయితే_ముగింపు /* SYSTEMD_NOTIFY */

#అయితే_ముగింపు /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
