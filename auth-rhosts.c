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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <netgroup.h>
#ضمن <pwd.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <stdlib.h>
#ضمن <unistd.h>

#ضمن "packet.h"
#ضمن "uidswap.h"
#ضمن "pathnames.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "xmalloc.h"
#ضمن "sshbuf.h"
#ضمن "sshkey.h"
#ضمن "servconf.h"
#ضمن "canohost.h"
#ضمن "hostfile.h"
#ضمن "auth.h"

/* import */
خارجي ServerOptions options;

/*
 * This function processes an rhosts-style file (.rhosts, .shosts, or
 * /etc/hosts.equiv).  This returns true if authentication can be granted
 * based on the file, and returns zero otherwise.
 */

ساكن صحيح
check_rhosts_file(ثابت حرف *filename, ثابت حرف *hostname,
		  ثابت حرف *ipaddr, ثابت حرف *client_user,
		  ثابت حرف *server_user)
{
	FILE *f;
#define RBUFLN 1024
	حرف buf[RBUFLN];/* Must not be larger than host, user, dummy below. */
	صحيح fd;
	بنية stat st;

	/* Open the .rhosts file, deny if unreadable */
	ܐܢ ((fd = open(filename, O_RDONLY|O_NONBLOCK)) == -1)
		ܦܢܐ 0;
	ܐܢ (fstat(fd, &st) == -1) {
		close(fd);
		ܦܢܐ 0;
	}
	ܐܢ (!S_ISREG(st.st_mode)) {
		logit("User %s hosts file %s is not a regular file",
		    server_user, filename);
		close(fd);
		ܦܢܐ 0;
	}
	unset_nonblock(fd);
	ܐܢ ((f = fdopen(fd, "r")) == عدم) {
		close(fd);
		ܦܢܐ 0;
	}
	ܟܡܐ (fgets(buf, حجم(buf), f)) {
		/* All three must have length >= buf to avoid overflows. */
		حرف hostbuf[RBUFLN], userbuf[RBUFLN], dummy[RBUFLN];
		حرف *host, *user, *cp;
		صحيح negated;

		لكل (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		ܐܢ (*cp == '#' || *cp == '\n' || !*cp)
			استمر;

		/*
		 * NO_PLUS is supported at least on OSF/1.  We skip it (we
		 * don't ever support the plus syntax).
		 */
		ܐܢ (strncmp(cp, "NO_PLUS", 7) == 0)
			استمر;

		/*
		 * This should be safe because each buffer is as big as the
		 * whole string, and thus cannot be overwritten.
		 */
		بدل (sscanf(buf, "%1023s %1023s %1023s", hostbuf, userbuf,
		    dummy)) {
		حالة 0:
			auth_debug_add("Found empty line in %.100s.", filename);
			استمر;
		حالة 1:
			/* Host name only. */
			strlcpy(userbuf, server_user, حجم(userbuf));
			اكسر;
		حالة 2:
			/* Got both host and user name. */
			اكسر;
		حالة 3:
			auth_debug_add("Found garbage in %.100s.", filename);
			استمر;
		افتراضي:
			/* Weird... */
			استمر;
		}

		host = hostbuf;
		user = userbuf;
		negated = 0;

		/* Process negated host names, or positive netgroups. */
		ܐܢ (host[0] == '-') {
			negated = 1;
			host++;
		} ܐܚܪܢܐ ܐܢ (host[0] == '+')
			host++;

		ܐܢ (user[0] == '-') {
			negated = 1;
			user++;
		} ܐܚܪܢܐ ܐܢ (user[0] == '+')
			user++;

		/* Check for empty host/user names (particularly '+'). */
		ܐܢ (!host[0] || !user[0]) {
			/* We come here if either was '+' or '-'. */
			auth_debug_add("Ignoring wild host/user names "
			    "in %.100s.", filename);
			استمر;
		}
		/* Verify that host name matches. */
		ܐܢ (host[0] == '@') {
			ܐܢ (!innetgr(host + 1, hostname, عدم, عدم) &&
			    !innetgr(host + 1, ipaddr, عدم, عدم))
				استمر;
		} ܐܚܪܢܐ ܐܢ (strcasecmp(host, hostname) &&
		    strcmp(host, ipaddr) != 0)
			استمر;	/* Different hostname. */

		/* Verify that user name matches. */
		ܐܢ (user[0] == '@') {
			ܐܢ (!innetgr(user + 1, عدم, client_user, عدم))
				استمر;
		} ܐܚܪܢܐ ܐܢ (strcmp(user, client_user) != 0)
			استمر;	/* Different username. */

		/* Found the user and host. */
		fclose(f);

		/* If the entry was negated, deny access. */
		ܐܢ (negated) {
			auth_debug_add("Matched negative entry in %.100s.",
			    filename);
			ܦܢܐ 0;
		}
		/* Accept authentication. */
		ܦܢܐ 1;
	}

	/* Authentication using this file denied. */
	fclose(f);
	ܦܢܐ 0;
}

/*
 * Tries to authenticate the user using the .shosts or .rhosts file. Returns
 * true if authentication succeeds.  If ignore_rhosts is true, only
 * /etc/hosts.equiv will be considered (.rhosts and .shosts are ignored).
 */
صحيح
auth_rhosts2(بنية passwd *pw, ثابت حرف *client_user, ثابت حرف *hostname,
    ثابت حرف *ipaddr)
{
	حرف *path = عدم;
	بنية stat st;
	ساكن ثابت حرف * ثابت rhosts_files[] = {".shosts", ".rhosts", عدم};
	u_int rhosts_file_index;
	صحيح r;

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
	لكل (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		r = stat(path, &st);
		حرر(path);
		ܐܢ (r >= 0)
			اكسر;
	}
	/* Switch back to privileged uid. */
	restore_uid();

	/*
	 * Deny if The user has no .shosts or .rhosts file and there
	 * are no system-wide files.
	 */
	ܐܢ (!rhosts_files[rhosts_file_index] &&
	    stat(_PATH_RHOSTS_EQUIV, &st) == -1 &&
	    stat(_PATH_SSH_HOSTS_EQUIV, &st) == -1) {
		debug3_f("no hosts access files exist");
		ܦܢܐ 0;
	}

	/*
	 * If not logging in as superuser, try /etc/hosts.equiv and
	 * shosts.equiv.
	 */
	ܐܢ (pw->pw_uid == 0)
		debug3_f("root user, ignoring system hosts files");
	ܐܚܪܢܐ {
		ܐܢ (check_rhosts_file(_PATH_RHOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "/etc/hosts.equiv.", hostname, ipaddr);
			ܦܢܐ 1;
		}
		ܐܢ (check_rhosts_file(_PATH_SSH_HOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "%.100s.", hostname, ipaddr, _PATH_SSH_HOSTS_EQUIV);
			ܦܢܐ 1;
		}
	}

	/*
	 * Check that the home directory is owned by root or the user, and is
	 * not group or world writable.
	 */
	ܐܢ (stat(pw->pw_dir, &st) == -1) {
		logit("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		ܦܢܐ 0;
	}
	ܐܢ (options.strict_modes &&
	    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	    (st.st_mode & 022) != 0)) {
		logit("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		ܦܢܐ 0;
	}
	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	/* Check all .rhosts files (currently .shosts and .rhosts). */
	لكل (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		ܐܢ (stat(path, &st) == -1) {
			debug3_f("stat %s: %s", path, strerror(errno));
			حرر(path);
			استمر;
		}

		/*
		 * Make sure that the file is either owned by the user or by
		 * root, and make sure it is not writable by anyone but the
		 * owner.  This is to help avoid novices accidentally
		 * allowing access to their account by anyone.
		 */
		ܐܢ (options.strict_modes &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Rhosts authentication refused for %.100s: "
			    "bad modes for %.200s", pw->pw_name, path);
			auth_debug_add("Bad file modes for %.200s", path);
			حرر(path);
			استمر;
		}
		/*
		 * Check if we have been configured to ignore .rhosts
		 * and .shosts files.
		 */
		ܐܢ (options.ignore_rhosts == IGNORE_RHOSTS_YES ||
		    (options.ignore_rhosts == IGNORE_RHOSTS_SHOSTS &&
		    strcmp(rhosts_files[rhosts_file_index], ".shosts") != 0)) {
			auth_debug_add("Server has been configured to "
			    "ignore %.100s.", rhosts_files[rhosts_file_index]);
			حرر(path);
			استمر;
		}
		/* Check if authentication is permitted by the file. */
		ܐܢ (check_rhosts_file(path, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted by %.100s.",
			    rhosts_files[rhosts_file_index]);
			/* Restore the privileged uid. */
			restore_uid();
			auth_debug_add("Accepted host %s ip %s client_user "
			    "%s server_user %s", hostname, ipaddr,
			    client_user, pw->pw_name);
			حرر(path);
			ܦܢܐ 1;
		}
		حرر(path);
	}

	/* Restore the privileged uid. */
	restore_uid();
	ܦܢܐ 0;
}
