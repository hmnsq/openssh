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

#अन्तर्भाव "includes.h"

#यदि defined(LINUX_OOM_ADJUST) || defined(SYSTEMD_NOTIFY)
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/un.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <inttypes.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "port-linux.h"
#अन्तर्भाव "misc.h"

#यदि_परिभाषितम् LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

स्थिर पूर्णाङ्क oom_adj_save = INT_MIN;
स्थिर वर्ण *oom_adj_मार्गः = रिक्त;
संरचना {
	वर्ण *मार्गः;
	पूर्णाङ्क मानम्;
} oom_adjust[] = {
	{"/proc/self/oom_score_adj", -1000},	/* kernels >= 2.6.36 */
	{"/proc/self/oom_adj", -17},		/* kernels <= 2.6.35 */
	{रिक्त, 0},
};

/*
 * Tell the kernel's out-of-memory killer to avoid sshd.
 * Returns the previous oom_adj value or zero.
 */
शून्य
oom_adjust_सज्जता(शून्य)
{
	पूर्णाङ्क i, मानम्;
	FILE *fp;

	debug3("%s", __func__);
	 प्रति (i = 0; oom_adjust[i].मार्गः != रिक्त; i++) {
		oom_adj_मार्गः = oom_adjust[i].मार्गः;
		मानम् = oom_adjust[i].मानम्;
		यदि ((fp = fopen(oom_adj_मार्गः, "r+")) != रिक्त) {
			यदि (fscanf(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_मार्गः,
				    strerror(errno));
			अन्यथा {
				rewind(fp);
				यदि (fprintf(fp, "%d\n", मानम्) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_मार्गः, strerror(errno));
				अन्यथा
					debug("Set %s from %d to %d",
					   oom_adj_मार्गः, oom_adj_save, मानम्);
			}
			fclose(fp);
			प्रत्यागम;
		}
	}
	oom_adj_मार्गः = रिक्त;
}

/* Restore the saved OOM adjustment */
शून्य
oom_adjust_restore(शून्य)
{
	FILE *fp;

	debug3("%s", __func__);
	यदि (oom_adj_save == INT_MIN || oom_adj_मार्गः == रिक्त ||
	    (fp = fopen(oom_adj_मार्गः, "w")) == रिक्त)
		प्रत्यागम;

	यदि (fprintf(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_मार्गः, strerror(errno));
	अन्यथा
		debug("Set %s to %d", oom_adj_मार्गः, oom_adj_save);

	fclose(fp);
	प्रत्यागम;
}
#यदि_अन्तः /* LINUX_OOM_ADJUST */

#यदि_परिभाषितम् LINUX_MEMLOCK_ONFAULT
#अन्तर्भाव <sys/mman.h>

शून्य
memlock_onfault_सज्जता(शून्य)
{
	यदि (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", strerror(errno));
	अन्यथा
		debug("memory locked");
}
#यदि_अन्तः /* LINUX_MEMLOCK_ONFAULT */

#यदि_परिभाषितम् SYSTEMD_NOTIFY

स्थिर शून्य ssh_systemd_notify(ध्रुव वर्ण *, ...)
    __attribute__((__format__ (प्रारूप_लिख, 1, 2))) __attribute__((__nonnull__ (1)));

स्थिर शून्य
ssh_systemd_notify(ध्रुव वर्ण *fmt, ...)
{
	वर्ण *s = रिक्त;
	ध्रुव वर्ण *मार्गः;
	संरचना stat sb;
	संरचना sockaddr_un addr;
	पूर्णाङ्क fd = -1;
	va_list ap;

	यदि ((मार्गः = getenv("NOTIFY_SOCKET")) == रिक्त || वाक्यदैर्घ्यम्(मार्गः) == 0)
		प्रत्यागम;

	va_start(ap, fmt);
	xvasprintf(&s, fmt, ap);
	va_end(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	यदि (मार्गः[0] != '/' && मार्गः[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", मार्गः);
		गच्छ बहिर्गमनम्;
	}

	यदि (मार्गः[0] == '/' && stat(मार्गः, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", मार्गः, strerror(errno));
		गच्छ बहिर्गमनम्;
	}

	स्मृतिं_पूरय(&addr, 0, परिमाण(addr));
	addr.sun_family = AF_UNIX;
	यदि (strlcpy(addr.sun_मार्गः, मार्गः,
	    परिमाण(addr.sun_मार्गः)) >= परिमाण(addr.sun_मार्गः)) {
		error_f("socket path \"%s\" too long", मार्गः);
		गच्छ बहिर्गमनम्;
	}
	/* Support for abstract socket */
	यदि (addr.sun_मार्गः[0] == '@')
		addr.sun_मार्गः[0] = 0;
	यदि ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", मार्गः, strerror(errno));
		गच्छ बहिर्गमनम्;
	}
	यदि (connect(fd, (संरचना sockaddr *)&addr, परिमाण(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", मार्गः, strerror(errno));
		गच्छ बहिर्गमनम्;
	}
	यदि (लिख(fd, s, वाक्यदैर्घ्यम्(s)) != (ssize_t)वाक्यदैर्घ्यम्(s)) {
		error_f("socket \"%s\" write: %s", मार्गः, strerror(errno));
		गच्छ बहिर्गमनम्;
	}
	debug_f("socket \"%s\" notified %s", मार्गः, s);
 बहिर्गमनम्:
	यदि (fd != -1)
		close(fd);
	मुक्त(s);
}

शून्य
ssh_systemd_notify_ready(शून्य)
{
	ssh_systemd_notify("READY=1");
}

शून्य
ssh_systemd_notify_reload(शून्य)
{
	संरचना timespec now;

	monotime_ts(&now);
	यदि (now.tv_sec < 0 || now.tv_nsec < 0) {
		error_f("monotime returned negative value");
		ssh_systemd_notify("RELOADING=1");
	} अन्यथा {
		ssh_systemd_notify("RELOADING=1\nMONOTONIC_USEC=%llu",
		    ((uint64_t)now.tv_sec * 1000000ULL) +
		    ((uint64_t)now.tv_nsec / 1000ULL));
	}
}
#यदि_अन्तः /* SYSTEMD_NOTIFY */

#यदि_अन्तः /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
