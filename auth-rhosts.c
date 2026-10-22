/* $OpenBSD: auth-rhosts.c,v 1.58 2024/05/17 00:30:23 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Rhosts authentication.  This file contains code to check whether to admit
 * the login based on rhosts authentication.  This file also processes
 * /etc/hosts.equiv.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <netgroup.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "packet.h"
#अन्तर्भाव "uidswap.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"

/* import */
बाह्य ServerOptions options;

/*
 * This function processes an rhosts-style file (.rhosts, .shosts, or
 * /etc/hosts.equiv).  This returns true if authentication can be granted
 * based on the file, and returns zero otherwise.
 */

स्थिर पूर्णांक
check_rhosts_file(स्थिरांक अक्षर *filename, स्थिरांक अक्षर *hostname,
		  स्थिरांक अक्षर *ipaddr, स्थिरांक अक्षर *client_user,
		  स्थिरांक अक्षर *server_user)
{
	खाता *f;
#define RBUFLN 1024
	अक्षर buf[RBUFLN];/* Must not be larger than host, user, dummy below. */
	पूर्णांक fd;
	संरचना stat st;

	/* Open the .rhosts file, deny if unreadable */
	जर ((fd = खोलो(filename, O_RDONLY|O_NONBLOCK)) == -1)
		परत 0;
	जर (ख_स्थिति(fd, &st) == -1) {
		बंद(fd);
		परत 0;
	}
	जर (!S_ISREG(st.st_mode)) {
		logit("User %s hosts file %s is not a regular file",
		    server_user, filename);
		बंद(fd);
		परत 0;
	}
	unset_nonblock(fd);
	जर ((f = fdopen(fd, "r")) == रिक्त) {
		बंद(fd);
		परत 0;
	}
	पर्यंत (ख_माला_लो(buf, आकार(buf), f)) {
		/* All three must have length >= buf to avoid overflows. */
		अक्षर hostbuf[RBUFLN], userbuf[RBUFLN], dummy[RBUFLN];
		अक्षर *host, *user, *cp;
		पूर्णांक negated;

		साठी (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		जर (*cp == '#' || *cp == '\n' || !*cp)
			सुरूठेवा;

		/*
		 * NO_PLUS is supported at least on OSF/1.  We skip it (we
		 * don't ever support the plus syntax).
		 */
		जर (म_भेदन(cp, "NO_PLUS", 7) == 0)
			सुरूठेवा;

		/*
		 * This should be safe because each buffer is as big as the
		 * whole string, and thus cannot be overwritten.
		 */
		निवड (माला_पूछो(buf, "%1023s %1023s %1023s", hostbuf, userbuf,
		    dummy)) {
		स्थिती 0:
			auth_debug_add("Found empty line in %.100s.", filename);
			सुरूठेवा;
		स्थिती 1:
			/* Host name only. */
			strlcpy(userbuf, server_user, आकार(userbuf));
			थांबा;
		स्थिती 2:
			/* Got both host and user name. */
			थांबा;
		स्थिती 3:
			auth_debug_add("Found garbage in %.100s.", filename);
			सुरूठेवा;
		पूर्वनिर्धारित:
			/* Weird... */
			सुरूठेवा;
		}

		host = hostbuf;
		user = userbuf;
		negated = 0;

		/* Process negated host names, or positive netgroups. */
		जर (host[0] == '-') {
			negated = 1;
			host++;
		} अन्यथा जर (host[0] == '+')
			host++;

		जर (user[0] == '-') {
			negated = 1;
			user++;
		} अन्यथा जर (user[0] == '+')
			user++;

		/* Check for empty host/user names (particularly '+'). */
		जर (!host[0] || !user[0]) {
			/* We come here if either was '+' or '-'. */
			auth_debug_add("Ignoring wild host/user names "
			    "in %.100s.", filename);
			सुरूठेवा;
		}
		/* Verify that host name matches. */
		जर (host[0] == '@') {
			जर (!innetgr(host + 1, hostname, रिक्त, रिक्त) &&
			    !innetgr(host + 1, ipaddr, रिक्त, रिक्त))
				सुरूठेवा;
		} अन्यथा जर (strcasecmp(host, hostname) &&
		    म_भेद(host, ipaddr) != 0)
			सुरूठेवा;	/* Different hostname. */

		/* Verify that user name matches. */
		जर (user[0] == '@') {
			जर (!innetgr(user + 1, रिक्त, client_user, रिक्त))
				सुरूठेवा;
		} अन्यथा जर (म_भेद(user, client_user) != 0)
			सुरूठेवा;	/* Different username. */

		/* Found the user and host. */
		ख_बंद(f);

		/* If the entry was negated, deny access. */
		जर (negated) {
			auth_debug_add("Matched negative entry in %.100s.",
			    filename);
			परत 0;
		}
		/* Accept authentication. */
		परत 1;
	}

	/* Authentication using this file denied. */
	ख_बंद(f);
	परत 0;
}

/*
 * Tries to authenticate the user using the .shosts or .rhosts file. Returns
 * true if authentication succeeds.  If ignore_rhosts is true, only
 * /etc/hosts.equiv will be considered (.rhosts and .shosts are ignored).
 */
पूर्णांक
auth_rhosts2(संरचना passwd *pw, स्थिरांक अक्षर *client_user, स्थिरांक अक्षर *hostname,
    स्थिरांक अक्षर *ipaddr)
{
	अक्षर *path = रिक्त;
	संरचना stat st;
	स्थिर स्थिरांक अक्षर * स्थिरांक rhosts_files[] = {".shosts", ".rhosts", रिक्त};
	u_int rhosts_file_index;
	पूर्णांक r;

	debug2_f("clientuser %s hostname %s ipaddr %s",
	    client_user, hostname, ipaddr);

	/* Switch to the user's uid. */
	temporarily_use_uid(pw);
	/*
	 * Quick check: if the user has no .shosts or .rhosts files and
	 * no system hosts.equiv/shosts.equiv files exist then return
	 * failure immediately without doing costly lookups from name
	 * servers.
	 */
	साठी (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		r = stat(path, &st);
		मुक्त(path);
		जर (r >= 0)
			थांबा;
	}
	/* Switch back to privileged uid. */
	restore_uid();

	/*
	 * Deny if The user has no .shosts or .rhosts file and there
	 * are no system-wide files.
	 */
	जर (!rhosts_files[rhosts_file_index] &&
	    stat(_PATH_RHOSTS_EQUIV, &st) == -1 &&
	    stat(_PATH_SSH_HOSTS_EQUIV, &st) == -1) {
		debug3_f("no hosts access files exist");
		परत 0;
	}

	/*
	 * If not logging in as superuser, try /etc/hosts.equiv and
	 * shosts.equiv.
	 */
	जर (pw->pw_uid == 0)
		debug3_f("root user, ignoring system hosts files");
	अन्यथा {
		जर (check_rhosts_file(_PATH_RHOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "/etc/hosts.equiv.", hostname, ipaddr);
			परत 1;
		}
		जर (check_rhosts_file(_PATH_SSH_HOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "%.100s.", hostname, ipaddr, _PATH_SSH_HOSTS_EQUIV);
			परत 1;
		}
	}

	/*
	 * Check that the home directory is owned by root or the user, and is
	 * not group or world writable.
	 */
	जर (stat(pw->pw_dir, &st) == -1) {
		logit("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		परत 0;
	}
	जर (options.strict_modes &&
	    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	    (st.st_mode & 022) != 0)) {
		logit("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		परत 0;
	}
	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	/* Check all .rhosts files (currently .shosts and .rhosts). */
	साठी (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		जर (stat(path, &st) == -1) {
			debug3_f("stat %s: %s", path, म_त्रुटि(त्रुटि_सं));
			मुक्त(path);
			सुरूठेवा;
		}

		/*
		 * Make sure that the file is either owned by the user or by
		 * root, and make sure it is not writable by anyone but the
		 * owner.  This is to help avoid novices accidentally
		 * allowing access to their account by anyone.
		 */
		जर (options.strict_modes &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Rhosts authentication refused for %.100s: "
			    "bad modes for %.200s", pw->pw_name, path);
			auth_debug_add("Bad file modes for %.200s", path);
			मुक्त(path);
			सुरूठेवा;
		}
		/*
		 * Check if we have been configured to ignore .rhosts
		 * and .shosts files.
		 */
		जर (options.ignore_rhosts == IGNORE_RHOSTS_YES ||
		    (options.ignore_rhosts == IGNORE_RHOSTS_SHOSTS &&
		    म_भेद(rhosts_files[rhosts_file_index], ".shosts") != 0)) {
			auth_debug_add("Server has been configured to "
			    "ignore %.100s.", rhosts_files[rhosts_file_index]);
			मुक्त(path);
			सुरूठेवा;
		}
		/* Check if authentication is permitted by the file. */
		जर (check_rhosts_file(path, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted by %.100s.",
			    rhosts_files[rhosts_file_index]);
			/* Restore the privileged uid. */
			restore_uid();
			auth_debug_add("Accepted host %s ip %s client_user "
			    "%s server_user %s", hostname, ipaddr,
			    client_user, pw->pw_name);
			मुक्त(path);
			परत 1;
		}
		मुक्त(path);
	}

	/* Restore the privileged uid. */
	restore_uid();
	परत 0;
}
