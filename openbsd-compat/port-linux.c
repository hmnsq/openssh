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

#समावेश "includes.h"

#अगर defined(LINUX_OOM_ADJUST) || defined(SYSTEMD_NOTIFY)
#समावेश <sys/socket.h>
#समावेश <sys/un.h>

#समावेश <errno.h>
#समावेश <inttypes.h>
#समावेश <stdarg.h>
#समावेश <string.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <time.h>
#समावेश <unistd.h>

#समावेश "log.h"
#समावेश "xmalloc.h"
#समावेश "port-linux.h"
#समावेश "misc.h"

#अगर_घोषित LINUX_OOM_ADJUST
/*
 * The magic "don't kill me" values, old and new, as documented in eg:
 * http://lxr.linux.no/#linux+v2.6.32/Documentation/filesystems/proc.txt
 * http://lxr.linux.no/#linux+v2.6.36/Documentation/filesystems/proc.txt
 */

अटल पूर्णांक oom_adj_save = पूर्णांक_न्यून;
अटल अक्षर *oom_adj_path = शून्य;
काष्ठा {
	अक्षर *path;
	पूर्णांक मूल्य;
} oom_adjust[] = {
	{"/proc/self/oom_score_adj", -1000},	/* kernels >= 2.6.36 */
	{"/proc/self/oom_adj", -17},		/* kernels <= 2.6.35 */
	{शून्य, 0},
};

/*
 * Tell the kernel's out-of-memory killer to avoid sshd.
 * Returns the previous oom_adj value or zero.
 */
व्योम
oom_adjust_setup(व्योम)
{
	पूर्णांक i, मूल्य;
	खाता *fp;

	debug3("%s", __func__);
	 क्रम (i = 0; oom_adjust[i].path != शून्य; i++) {
		oom_adj_path = oom_adjust[i].path;
		मूल्य = oom_adjust[i].मूल्य;
		अगर ((fp = ख_खोलो(oom_adj_path, "r+")) != शून्य) {
			अगर (ख_पूछो(fp, "%d", &oom_adj_save) != 1)
				verbose("error reading %s: %s", oom_adj_path,
				    म_त्रुटि(त्रुटि_सं));
			अन्यथा {
				शुरुआत(fp);
				अगर (ख_लिखो(fp, "%d\n", मूल्य) <= 0)
					verbose("error writing %s: %s",
					   oom_adj_path, म_त्रुटि(त्रुटि_सं));
				अन्यथा
					debug("Set %s from %d to %d",
					   oom_adj_path, oom_adj_save, मूल्य);
			}
			ख_बंद(fp);
			वापस;
		}
	}
	oom_adj_path = शून्य;
}

/* Restore the saved OOM adjustment */
व्योम
oom_adjust_restore(व्योम)
{
	खाता *fp;

	debug3("%s", __func__);
	अगर (oom_adj_save == पूर्णांक_न्यून || oom_adj_path == शून्य ||
	    (fp = ख_खोलो(oom_adj_path, "w")) == शून्य)
		वापस;

	अगर (ख_लिखो(fp, "%d\n", oom_adj_save) <= 0)
		verbose("error writing %s: %s", oom_adj_path, म_त्रुटि(त्रुटि_सं));
	अन्यथा
		debug("Set %s to %d", oom_adj_path, oom_adj_save);

	ख_बंद(fp);
	वापस;
}
#पूर्ण_अगर /* LINUX_OOM_ADJUST */

#अगर_घोषित LINUX_MEMLOCK_ONFAULT
#समावेश <sys/mman.h>

व्योम
memlock_onfault_setup(व्योम)
{
	अगर (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) < 0)
		verbose("unable to lock memory: %s", म_त्रुटि(त्रुटि_सं));
	अन्यथा
		debug("memory locked");
}
#पूर्ण_अगर /* LINUX_MEMLOCK_ONFAULT */

#अगर_घोषित SYSTEMD_NOTIFY

अटल व्योम ssh_systemd_notify(स्थिर अक्षर *, ...)
    __attribute__((__format__ (म_लिखो, 1, 2))) __attribute__((__nonnull__ (1)));

अटल व्योम
ssh_systemd_notify(स्थिर अक्षर *fmt, ...)
{
	अक्षर *s = शून्य;
	स्थिर अक्षर *path;
	काष्ठा stat sb;
	काष्ठा sockaddr_un addr;
	पूर्णांक fd = -1;
	बहु_सूची ap;

	अगर ((path = दो_पर्या("NOTIFY_SOCKET")) == शून्य || म_माप(path) == 0)
		वापस;

	बहु_शुरू(ap, fmt);
	xvasprintf(&s, fmt, ap);
	बहु_पूर्ण(ap);

	/* Only AF_UNIX is supported, with path or abstract sockets */
	अगर (path[0] != '/' && path[0] != '@') {
		error_f("socket \"%s\" is not compatible with AF_UNIX", path);
		जाओ out;
	}

	अगर (path[0] == '/' && stat(path, &sb) != 0) {
		error_f("socket \"%s\" stat: %s", path, म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}

	स_रखो(&addr, 0, माप(addr));
	addr.sun_family = AF_UNIX;
	अगर (strlcpy(addr.sun_path, path,
	    माप(addr.sun_path)) >= माप(addr.sun_path)) {
		error_f("socket path \"%s\" too long", path);
		जाओ out;
	}
	/* Support for abstract socket */
	अगर (addr.sun_path[0] == '@')
		addr.sun_path[0] = 0;
	अगर ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		error_f("socket \"%s\": %s", path, म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	अगर (connect(fd, (काष्ठा sockaddr *)&addr, माप(addr)) != 0) {
		error_f("socket \"%s\" connect: %s", path, म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	अगर (ग_लिखो(fd, s, म_माप(s)) != (ssize_t)म_माप(s)) {
		error_f("socket \"%s\" write: %s", path, म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	debug_f("socket \"%s\" notified %s", path, s);
 out:
	अगर (fd != -1)
		बंद(fd);
	मुक्त(s);
}

व्योम
ssh_systemd_notify_ready(व्योम)
{
	ssh_systemd_notify("READY=1");
}

व्योम
ssh_systemd_notify_reload(व्योम)
{
	काष्ठा timespec now;

	monotime_ts(&now);
	अगर (now.tv_sec < 0 || now.tv_nsec < 0) {
		error_f("monotime returned negative value");
		ssh_systemd_notify("RELOADING=1");
	} अन्यथा {
		ssh_systemd_notify("RELOADING=1\nMONOTONIC_USEC=%llu",
		    ((uint64_t)now.tv_sec * 1000000ULL) +
		    ((uint64_t)now.tv_nsec / 1000ULL));
	}
}
#पूर्ण_अगर /* SYSTEMD_NOTIFY */

#पूर्ण_अगर /* WITH_SELINUX || LINUX_OOM_ADJUST || SYSTEMD_NOTIFY */
