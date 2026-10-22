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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <netgroup.h>
#समावेश <pwd.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <stdarg.h>
#समावेश <stdlib.h>
#समावेश <unistd.h>

#समावेश "packet.h"
#समावेश "uidswap.h"
#समावेश "pathnames.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "xmalloc.h"
#समावेश "sshbuf.h"
#समावेश "sshkey.h"
#समावेश "servconf.h"
#समावेश "canohost.h"
#समावेश "hostfile.h"
#समावेश "auth.h"

/* import */
बाह्य ServerOptions options;

/*
 * This function processes an rhosts-style file (.rhosts, .shosts, or
 * /etc/hosts.equiv).  This returns true if authentication can be granted
 * based on the file, and returns zero otherwise.
 */

अटल पूर्णांक
check_rhosts_file(स्थिर अक्षर *filename, स्थिर अक्षर *hostname,
		  स्थिर अक्षर *ipaddr, स्थिर अक्षर *client_user,
		  स्थिर अक्षर *server_user)
{
	खाता *f;
#घोषणा RBUFLN 1024
	अक्षर buf[RBUFLN];/* Must not be larger than host, user, dummy below. */
	पूर्णांक fd;
	काष्ठा stat st;

	/* Open the .rhosts file, deny if unreadable */
	अगर ((fd = खोलो(filename, O_RDONLY|O_NONBLOCK)) == -1)
		वापस 0;
	अगर (ख_स्थिति(fd, &st) == -1) {
		बंद(fd);
		वापस 0;
	}
	अगर (!S_ISREG(st.st_mode)) {
		logit("User %s hosts file %s is not a regular file",
		    server_user, filename);
		बंद(fd);
		वापस 0;
	}
	unset_nonblock(fd);
	अगर ((f = fdopen(fd, "r")) == शून्य) {
		बंद(fd);
		वापस 0;
	}
	जबतक (ख_माला_लो(buf, माप(buf), f)) {
		/* All three must have length >= buf to avoid overflows. */
		अक्षर hostbuf[RBUFLN], userbuf[RBUFLN], dummy[RBUFLN];
		अक्षर *host, *user, *cp;
		पूर्णांक negated;

		क्रम (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		अगर (*cp == '#' || *cp == '\n' || !*cp)
			जारी;

		/*
		 * NO_PLUS is supported at least on OSF/1.  We skip it (we
		 * don't ever support the plus syntax).
		 */
		अगर (म_भेदन(cp, "NO_PLUS", 7) == 0)
			जारी;

		/*
		 * This should be safe because each buffer is as big as the
		 * whole string, and thus cannot be overwritten.
		 */
		चयन (माला_पूछो(buf, "%1023s %1023s %1023s", hostbuf, userbuf,
		    dummy)) {
		हाल 0:
			auth_debug_add("Found empty line in %.100s.", filename);
			जारी;
		हाल 1:
			/* Host name only. */
			strlcpy(userbuf, server_user, माप(userbuf));
			अवरोध;
		हाल 2:
			/* Got both host and user name. */
			अवरोध;
		हाल 3:
			auth_debug_add("Found garbage in %.100s.", filename);
			जारी;
		शेष:
			/* Weird... */
			जारी;
		}

		host = hostbuf;
		user = userbuf;
		negated = 0;

		/* Process negated host names, or positive netgroups. */
		अगर (host[0] == '-') {
			negated = 1;
			host++;
		} अन्यथा अगर (host[0] == '+')
			host++;

		अगर (user[0] == '-') {
			negated = 1;
			user++;
		} अन्यथा अगर (user[0] == '+')
			user++;

		/* Check for empty host/user names (particularly '+'). */
		अगर (!host[0] || !user[0]) {
			/* We come here if either was '+' or '-'. */
			auth_debug_add("Ignoring wild host/user names "
			    "in %.100s.", filename);
			जारी;
		}
		/* Verify that host name matches. */
		अगर (host[0] == '@') {
			अगर (!innetgr(host + 1, hostname, शून्य, शून्य) &&
			    !innetgr(host + 1, ipaddr, शून्य, शून्य))
				जारी;
		} अन्यथा अगर (strcasecmp(host, hostname) &&
		    म_भेद(host, ipaddr) != 0)
			जारी;	/* Different hostname. */

		/* Verify that user name matches. */
		अगर (user[0] == '@') {
			अगर (!innetgr(user + 1, शून्य, client_user, शून्य))
				जारी;
		} अन्यथा अगर (म_भेद(user, client_user) != 0)
			जारी;	/* Different username. */

		/* Found the user and host. */
		ख_बंद(f);

		/* If the entry was negated, deny access. */
		अगर (negated) {
			auth_debug_add("Matched negative entry in %.100s.",
			    filename);
			वापस 0;
		}
		/* Accept authentication. */
		वापस 1;
	}

	/* Authentication using this file denied. */
	ख_बंद(f);
	वापस 0;
}

/*
 * Tries to authenticate the user using the .shosts or .rhosts file. Returns
 * true if authentication succeeds.  If ignore_rhosts is true, only
 * /etc/hosts.equiv will be considered (.rhosts and .shosts are ignored).
 */
पूर्णांक
auth_rhosts2(काष्ठा passwd *pw, स्थिर अक्षर *client_user, स्थिर अक्षर *hostname,
    स्थिर अक्षर *ipaddr)
{
	अक्षर *path = शून्य;
	काष्ठा stat st;
	अटल स्थिर अक्षर * स्थिर rhosts_files[] = {".shosts", ".rhosts", शून्य};
	u_int rhosts_file_सूचकांक;
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
	क्रम (rhosts_file_सूचकांक = 0; rhosts_files[rhosts_file_सूचकांक];
	    rhosts_file_सूचकांक++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_सूचकांक]);
		r = stat(path, &st);
		मुक्त(path);
		अगर (r >= 0)
			अवरोध;
	}
	/* Switch back to privileged uid. */
	restore_uid();

	/*
	 * Deny if The user has no .shosts or .rhosts file and there
	 * are no system-wide files.
	 */
	अगर (!rhosts_files[rhosts_file_सूचकांक] &&
	    stat(_PATH_RHOSTS_EQUIV, &st) == -1 &&
	    stat(_PATH_SSH_HOSTS_EQUIV, &st) == -1) {
		debug3_f("no hosts access files exist");
		वापस 0;
	}

	/*
	 * If not logging in as superuser, try /etc/hosts.equiv and
	 * shosts.equiv.
	 */
	अगर (pw->pw_uid == 0)
		debug3_f("root user, ignoring system hosts files");
	अन्यथा {
		अगर (check_rhosts_file(_PATH_RHOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "/etc/hosts.equiv.", hostname, ipaddr);
			वापस 1;
		}
		अगर (check_rhosts_file(_PATH_SSH_HOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "%.100s.", hostname, ipaddr, _PATH_SSH_HOSTS_EQUIV);
			वापस 1;
		}
	}

	/*
	 * Check that the home directory is owned by root or the user, and is
	 * not group or world writable.
	 */
	अगर (stat(pw->pw_dir, &st) == -1) {
		logit("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		वापस 0;
	}
	अगर (options.strict_modes &&
	    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	    (st.st_mode & 022) != 0)) {
		logit("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		वापस 0;
	}
	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	/* Check all .rhosts files (currently .shosts and .rhosts). */
	क्रम (rhosts_file_सूचकांक = 0; rhosts_files[rhosts_file_सूचकांक];
	    rhosts_file_सूचकांक++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_सूचकांक]);
		अगर (stat(path, &st) == -1) {
			debug3_f("stat %s: %s", path, म_त्रुटि(त्रुटि_सं));
			मुक्त(path);
			जारी;
		}

		/*
		 * Make sure that the file is either owned by the user or by
		 * root, and make sure it is not writable by anyone but the
		 * owner.  This is to help avoid novices accidentally
		 * allowing access to their account by anyone.
		 */
		अगर (options.strict_modes &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Rhosts authentication refused for %.100s: "
			    "bad modes for %.200s", pw->pw_name, path);
			auth_debug_add("Bad file modes for %.200s", path);
			मुक्त(path);
			जारी;
		}
		/*
		 * Check if we have been configured to ignore .rhosts
		 * and .shosts files.
		 */
		अगर (options.ignore_rhosts == IGNORE_RHOSTS_YES ||
		    (options.ignore_rhosts == IGNORE_RHOSTS_SHOSTS &&
		    म_भेद(rhosts_files[rhosts_file_सूचकांक], ".shosts") != 0)) {
			auth_debug_add("Server has been configured to "
			    "ignore %.100s.", rhosts_files[rhosts_file_सूचकांक]);
			मुक्त(path);
			जारी;
		}
		/* Check if authentication is permitted by the file. */
		अगर (check_rhosts_file(path, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted by %.100s.",
			    rhosts_files[rhosts_file_सूचकांक]);
			/* Restore the privileged uid. */
			restore_uid();
			auth_debug_add("Accepted host %s ip %s client_user "
			    "%s server_user %s", hostname, ipaddr,
			    client_user, pw->pw_name);
			मुक्त(path);
			वापस 1;
		}
		मुक्त(path);
	}

	/* Restore the privileged uid. */
	restore_uid();
	वापस 0;
}
