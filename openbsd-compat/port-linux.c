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

#ifdef LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

स्थिर पूर्णाङ्क oom_adj_save = पूर्णांक_न्यून;
स्थिर वर्ण *oom_adj_path = रिक्त;
संरचना {
	वर्ण *path;
	पूर्णाङ्क मान;
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
oom_adjust_setup(शून्य)
{
	पूर्णाङ्क i, मान;
	खाता *fp;

	debug3("%s", __func__);
	 लागि (i = 0; oom_adjust[i].path != रिक्त; i++) {
		oom_adj_path = oom_adjust[i].path;
		मान = oom_adjust[i].मान;
		यदि ((fp = ख_खोलो(oom_adj_path, "r+")) != रिक्त) {
			यदि (ख_पूछो(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_path,
				    म_त्रुटि(त्रुटि_सं));
			अन्यथा {
				शुरुआत(fp);
				यदि (ख_लिखो(fp, "%d\n", मान) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_path, म_त्रुटि(त्रुटि_सं));
				अन्यथा
					debug("Set %s from %d to %d",
					   oom_adj_path, oom_adj_save, मान);
			}
			ख_बंद(fp);
			फर्काऊ;
		}
	}
	oom_adj_path = रिक्त;
}

/* Restore the saved OOM adjustment */
शून्य
oom_adjust_restore(शून्य)
{
	खाता *fp;

	debug3("%s", __func__);
	यदि (oom_adj_save == पूर्णांक_न्यून || oom_adj_path == रिक्त ||
	    (fp = ख_खोलो(oom_adj_path, "w")) == रिक्त)
		फर्काऊ;

	यदि (ख_लिखो(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_path, म_त्रुटि(त्रुटि_सं));
	अन्यथा
		debug("Set %s to %d", oom_adj_path, oom_adj_save);

	ख_बंद(fp);
	फर्काऊ;
}
#endif /* LINUX_OOM_ADJUST */

#ifdef LINUX_MEMLOCK_ONFAULT
#अन्तर्भाव <sys/mman.h>

शून्य
memlock_onfault_setup(शून्य)
{
	यदि (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", म_त्रुटि(त्रुटि_सं));
	अन्यथा
		debug("memory locked");
}
#endif /* LINUX_MEMLOCK_ONFAULT */

#ifdef SYSTEMD_NOTIFY

स्थिर शून्य ssh_systemd_notify(अचर वर्ण *, ...)
    __attribute__((__format__ (म_लिखो, 1, 2))) __attribute__((__nonnull__ (1)));

स्थिर शून्य
ssh_systemd_notify(अचर वर्ण *fmt, ...)
{
	वर्ण *s = रिक्त;
	अचर वर्ण *path;
	संरचना stat sb;
	संरचना sockaddr_un addr;
	पूर्णाङ्क fd = -1;
	बहु_सूची ap;

	यदि ((path = दो_पर्या("NOTIFY_SOCKET")) == रिक्त || म_माप(path) == 0)
		फर्काऊ;

	बहु_शुरू(ap, fmt);
	xvasprintf(&s, fmt, ap);
	बहु_पूर्ण(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	यदि (path[0] != '/' && path[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", path);
		गच्छ out;
	}

	यदि (path[0] == '/' && stat(path, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", path, म_त्रुटि(त्रुटि_सं));
		गच्छ out;
	}

	स_रखो(&addr, 0, परिमाण(addr));
	addr.sun_family = AF_UNIX;
	यदि (strlcpy(addr.sun_path, path,
	    परिमाण(addr.sun_path)) >= परिमाण(addr.sun_path)) {
		error_f("socket path \"%s\" too long", path);
		गच्छ out;
	}
	/* Support for abstract socket */
	यदि (addr.sun_path[0] == '@')
		addr.sun_path[0] = 0;
	यदि ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", path, म_त्रुटि(त्रुटि_सं));
		गच्छ out;
	}
	यदि (connect(fd, (संरचना sockaddr *)&addr, परिमाण(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", path, म_त्रुटि(त्रुटि_सं));
		गच्छ out;
	}
	यदि (लिख(fd, s, म_माप(s)) != (ssize_t)म_माप(s)) {
		error_f("socket \"%s\" write: %s", path, म_त्रुटि(त्रुटि_सं));
		गच्छ out;
	}
	debug_f("socket \"%s\" notified %s", path, s);
 out:
	यदि (fd != -1)
		बंद(fd);
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
#endif /* SYSTEMD_NOTIFY */

#endif /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
