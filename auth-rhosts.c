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

स्थिर पूर्णाङ्क
check_rhosts_file(अचर वर्ण *filename, अचर वर्ण *hostname,
		  अचर वर्ण *ipaddr, अचर वर्ण *client_user,
		  अचर वर्ण *server_user)
{
	खाता *f;
#define RBUFLN 1024
	वर्ण buf[RBUFLN];/* Must not be larger than host, user, dummy below. */
	पूर्णाङ्क fd;
	संरचना stat st;

	/* Open the .rhosts file, deny if unreadable */
	यदि ((fd = खोलो(filename, O_RDONLY|O_NONBLOCK)) == -1)
		फर्काऊ 0;
	यदि (ख_स्थिति(fd, &st) == -1) {
		बंद(fd);
		फर्काऊ 0;
	}
	यदि (!S_ISREG(st.st_mode)) {
		logit("User %s hosts file %s is not a regular file",
		    server_user, filename);
		बंद(fd);
		फर्काऊ 0;
	}
	unset_nonblock(fd);
	यदि ((f = fdopen(fd, "r")) == रिक्त) {
		बंद(fd);
		फर्काऊ 0;
	}
	जबसम्म (ख_माला_लो(buf, परिमाण(buf), f)) {
		/* All three must have length >= buf to avoid overflows. */
		वर्ण hostbuf[RBUFLN], userbuf[RBUFLN], dummy[RBUFLN];
		वर्ण *host, *user, *cp;
		पूर्णाङ्क negated;

		लागि (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		यदि (*cp == '#' || *cp == '\n' || !*cp)
			जारी;

		/*
		 * NO_PLUS is supported at least on OSF/1.  We skip it (we
		 * don't ever support the plus syntax).
		 */
		यदि (म_भेदन(cp, "NO_PLUS", 7) == 0)
			जारी;

		/*
		 * This should be safe because each buffer is as big as the
		 * whole string, and thus cannot be overwritten.
		 */
		विकल्प (माला_पूछो(buf, "%1023s %1023s %1023s", hostbuf, userbuf,
		    dummy)) {
		पक्ष 0:
			auth_debug_add("Found empty line in %.100s.", filename);
			जारी;
		पक्ष 1:
			/* Host name only. */
			strlcpy(userbuf, server_user, परिमाण(userbuf));
			रोक;
		पक्ष 2:
			/* Got both host and user name. */
			रोक;
		पक्ष 3:
			auth_debug_add("Found garbage in %.100s.", filename);
			जारी;
		स्वभाव:
			/* Weird... */
			जारी;
		}

		host = hostbuf;
		user = userbuf;
		negated = 0;

		/* Process negated host names, or positive netgroups. */
		यदि (host[0] == '-') {
			negated = 1;
			host++;
		} अन्यथा यदि (host[0] == '+')
			host++;

		यदि (user[0] == '-') {
			negated = 1;
			user++;
		} अन्यथा यदि (user[0] == '+')
			user++;

		/* Check for empty host/user names (particularly '+'). */
		यदि (!host[0] || !user[0]) {
			/* We come here if either was '+' or '-'. */
			auth_debug_add("Ignoring wild host/user names "
			    "in %.100s.", filename);
			जारी;
		}
		/* Verify that host name matches. */
		यदि (host[0] == '@') {
			यदि (!innetgr(host + 1, hostname, रिक्त, रिक्त) &&
			    !innetgr(host + 1, ipaddr, रिक्त, रिक्त))
				जारी;
		} अन्यथा यदि (strcasecmp(host, hostname) &&
		    म_भेद(host, ipaddr) != 0)
			जारी;	/* Different hostname. */

		/* Verify that user name matches. */
		यदि (user[0] == '@') {
			यदि (!innetgr(user + 1, रिक्त, client_user, रिक्त))
				जारी;
		} अन्यथा यदि (म_भेद(user, client_user) != 0)
			जारी;	/* Different username. */

		/* Found the user and host. */
		ख_बंद(f);

		/* If the entry was negated, deny access. */
		यदि (negated) {
			auth_debug_add("Matched negative entry in %.100s.",
			    filename);
			फर्काऊ 0;
		}
		/* Accept authentication. */
		फर्काऊ 1;
	}

	/* Authentication using this file denied. */
	ख_बंद(f);
	फर्काऊ 0;
}

/*
 * Tries to authenticate the user using the .shosts or .rhosts file. Returns
 * true if authentication succeeds.  If ignore_rhosts is true, only
 * /etc/hosts.equiv will be considered (.rhosts and .shosts are ignored).
 */
पूर्णाङ्क
auth_rhosts2(संरचना passwd *pw, अचर वर्ण *client_user, अचर वर्ण *hostname,
    अचर वर्ण *ipaddr)
{
	वर्ण *path = रिक्त;
	संरचना stat st;
	स्थिर अचर वर्ण * अचर rhosts_files[] = {".shosts", ".rhosts", रिक्त};
	u_int rhosts_file_index;
	पूर्णाङ्क r;

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
	लागि (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		r = stat(path, &st);
		मुक्त(path);
		यदि (r >= 0)
			रोक;
	}
	/* Switch back to privileged uid. */
	restore_uid();

	/*
	 * Deny if The user has no .shosts or .rhosts file and there
	 * are no system-wide files.
	 */
	यदि (!rhosts_files[rhosts_file_index] &&
	    stat(_PATH_RHOSTS_EQUIV, &st) == -1 &&
	    stat(_PATH_SSH_HOSTS_EQUIV, &st) == -1) {
		debug3_f("no hosts access files exist");
		फर्काऊ 0;
	}

	/*
	 * If not logging in as superuser, try /etc/hosts.equiv and
	 * shosts.equiv.
	 */
	यदि (pw->pw_uid == 0)
		debug3_f("root user, ignoring system hosts files");
	अन्यथा {
		यदि (check_rhosts_file(_PATH_RHOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "/etc/hosts.equiv.", hostname, ipaddr);
			फर्काऊ 1;
		}
		यदि (check_rhosts_file(_PATH_SSH_HOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "%.100s.", hostname, ipaddr, _PATH_SSH_HOSTS_EQUIV);
			फर्काऊ 1;
		}
	}

	/*
	 * Check that the home directory is owned by root or the user, and is
	 * not group or world writable.
	 */
	यदि (stat(pw->pw_dir, &st) == -1) {
		logit("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		फर्काऊ 0;
	}
	यदि (options.strict_modes &&
	    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	    (st.st_mode & 022) != 0)) {
		logit("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		फर्काऊ 0;
	}
	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	/* Check all .rhosts files (currently .shosts and .rhosts). */
	लागि (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		यदि (stat(path, &st) == -1) {
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
		यदि (options.strict_modes &&
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
		यदि (options.ignore_rhosts == IGNORE_RHOSTS_YES ||
		    (options.ignore_rhosts == IGNORE_RHOSTS_SHOSTS &&
		    म_भेद(rhosts_files[rhosts_file_index], ".shosts") != 0)) {
			auth_debug_add("Server has been configured to "
			    "ignore %.100s.", rhosts_files[rhosts_file_index]);
			मुक्त(path);
			जारी;
		}
		/* Check if authentication is permitted by the file. */
		यदि (check_rhosts_file(path, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted by %.100s.",
			    rhosts_files[rhosts_file_index]);
			/* Restore the privileged uid. */
			restore_uid();
			auth_debug_add("Accepted host %s ip %s client_user "
			    "%s server_user %s", hostname, ipaddr,
			    client_user, pw->pw_name);
			मुक्त(path);
			फर्काऊ 1;
		}
		मुक्त(path);
	}

	/* Restore the privileged uid. */
	restore_uid();
	फर्काऊ 0;
}
