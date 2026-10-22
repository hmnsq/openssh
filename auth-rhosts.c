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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <netgroup.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "uidswap.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"

/* import */
বাহ্য ServerOptions options;

/*
 * This function processes an rhosts-style file (.rhosts, .shosts, or
 * /etc/hosts.equiv).  This returns true if authentication can be granted
 * based on the file, and returns zero otherwise.
 */

স্থির পূর্ণাঙ্ক
check_rhosts_file(ধ্রুব বর্ণ *filename, ধ্রুব বর্ণ *hostname,
		  ধ্রুব বর্ণ *ipaddr, ধ্রুব বর্ণ *client_user,
		  ধ্রুব বর্ণ *server_user)
{
	FILE *f;
#define RBUFLN 1024
	বর্ণ buf[RBUFLN];/* Must not be larger than host, user, dummy below. */
	পূর্ণাঙ্ক fd;
	সংরচনা stat st;

	/* Open the .rhosts file, deny if unreadable */
	যদি ((fd = open(filename, O_RDONLY|O_NONBLOCK)) == -1)
		প্রত্যাগম 0;
	যদি (fstat(fd, &st) == -1) {
		close(fd);
		প্রত্যাগম 0;
	}
	যদি (!S_ISREG(st.st_mode)) {
		logit("User %s hosts file %s is not a regular file",
		    server_user, filename);
		close(fd);
		প্রত্যাগম 0;
	}
	unset_nonblock(fd);
	যদি ((f = fdopen(fd, "r")) == রিক্ত) {
		close(fd);
		প্রত্যাগম 0;
	}
	যাবত্ (fgets(buf, পরিমাণ(buf), f)) {
		/* All three must have length >= buf to avoid overflows. */
		বর্ণ hostbuf[RBUFLN], userbuf[RBUFLN], dummy[RBUFLN];
		বর্ণ *host, *user, *cp;
		পূর্ণাঙ্ক negated;

		প্রতি (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		যদি (*cp == '#' || *cp == '\n' || !*cp)
			অনুবর্ত;

		/*
		 * NO_PLUS is supported at least on OSF/1.  We skip it (we
		 * don't ever support the plus syntax).
		 */
		যদি (strncmp(cp, "NO_PLUS", 7) == 0)
			অনুবর্ত;

		/*
		 * This should be safe because each buffer is as big as the
		 * whole string, and thus cannot be overwritten.
		 */
		বিকল্প (sscanf(buf, "%1023s %1023s %1023s", hostbuf, userbuf,
		    dummy)) {
		পক্ষ 0:
			auth_debug_add("Found empty line in %.100s.", filename);
			অনুবর্ত;
		পক্ষ 1:
			/* Host name only. */
			strlcpy(userbuf, server_user, পরিমাণ(userbuf));
			ভঙ্গ;
		পক্ষ 2:
			/* Got both host and user name. */
			ভঙ্গ;
		পক্ষ 3:
			auth_debug_add("Found garbage in %.100s.", filename);
			অনুবর্ত;
		স্বভাব:
			/* Weird... */
			অনুবর্ত;
		}

		host = hostbuf;
		user = userbuf;
		negated = 0;

		/* Process negated host names, or positive netgroups. */
		যদি (host[0] == '-') {
			negated = 1;
			host++;
		} অন্যথা যদি (host[0] == '+')
			host++;

		যদি (user[0] == '-') {
			negated = 1;
			user++;
		} অন্যথা যদি (user[0] == '+')
			user++;

		/* Check for empty host/user names (particularly '+'). */
		যদি (!host[0] || !user[0]) {
			/* We come here if either was '+' or '-'. */
			auth_debug_add("Ignoring wild host/user names "
			    "in %.100s.", filename);
			অনুবর্ত;
		}
		/* Verify that host name matches. */
		যদি (host[0] == '@') {
			যদি (!innetgr(host + 1, hostname, রিক্ত, রিক্ত) &&
			    !innetgr(host + 1, ipaddr, রিক্ত, রিক্ত))
				অনুবর্ত;
		} অন্যথা যদি (strcasecmp(host, hostname) &&
		    strcmp(host, ipaddr) != 0)
			অনুবর্ত;	/* Different hostname. */

		/* Verify that user name matches. */
		যদি (user[0] == '@') {
			যদি (!innetgr(user + 1, রিক্ত, client_user, রিক্ত))
				অনুবর্ত;
		} অন্যথা যদি (strcmp(user, client_user) != 0)
			অনুবর্ত;	/* Different username. */

		/* Found the user and host. */
		fclose(f);

		/* If the entry was negated, deny access. */
		যদি (negated) {
			auth_debug_add("Matched negative entry in %.100s.",
			    filename);
			প্রত্যাগম 0;
		}
		/* Accept authentication. */
		প্রত্যাগম 1;
	}

	/* Authentication using this file denied. */
	fclose(f);
	প্রত্যাগম 0;
}

/*
 * Tries to authenticate the user using the .shosts or .rhosts file. Returns
 * true if authentication succeeds.  If ignore_rhosts is true, only
 * /etc/hosts.equiv will be considered (.rhosts and .shosts are ignored).
 */
পূর্ণাঙ্ক
auth_rhosts2(সংরচনা passwd *pw, ধ্রুব বর্ণ *client_user, ধ্রুব বর্ণ *hostname,
    ধ্রুব বর্ণ *ipaddr)
{
	বর্ণ *path = রিক্ত;
	সংরচনা stat st;
	স্থির ধ্রুব বর্ণ * ধ্রুব rhosts_files[] = {".shosts", ".rhosts", রিক্ত};
	u_int rhosts_file_index;
	পূর্ণাঙ্ক r;

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
	প্রতি (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		r = stat(path, &st);
		মুক্ত(path);
		যদি (r >= 0)
			ভঙ্গ;
	}
	/* Switch back to privileged uid. */
	restore_uid();

	/*
	 * Deny if The user has no .shosts or .rhosts file and there
	 * are no system-wide files.
	 */
	যদি (!rhosts_files[rhosts_file_index] &&
	    stat(_PATH_RHOSTS_EQUIV, &st) == -1 &&
	    stat(_PATH_SSH_HOSTS_EQUIV, &st) == -1) {
		debug3_f("no hosts access files exist");
		প্রত্যাগম 0;
	}

	/*
	 * If not logging in as superuser, try /etc/hosts.equiv and
	 * shosts.equiv.
	 */
	যদি (pw->pw_uid == 0)
		debug3_f("root user, ignoring system hosts files");
	অন্যথা {
		যদি (check_rhosts_file(_PATH_RHOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "/etc/hosts.equiv.", hostname, ipaddr);
			প্রত্যাগম 1;
		}
		যদি (check_rhosts_file(_PATH_SSH_HOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "%.100s.", hostname, ipaddr, _PATH_SSH_HOSTS_EQUIV);
			প্রত্যাগম 1;
		}
	}

	/*
	 * Check that the home directory is owned by root or the user, and is
	 * not group or world writable.
	 */
	যদি (stat(pw->pw_dir, &st) == -1) {
		logit("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		প্রত্যাগম 0;
	}
	যদি (options.strict_modes &&
	    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	    (st.st_mode & 022) != 0)) {
		logit("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		প্রত্যাগম 0;
	}
	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	/* Check all .rhosts files (currently .shosts and .rhosts). */
	প্রতি (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		যদি (stat(path, &st) == -1) {
			debug3_f("stat %s: %s", path, strerror(errno));
			মুক্ত(path);
			অনুবর্ত;
		}

		/*
		 * Make sure that the file is either owned by the user or by
		 * root, and make sure it is not writable by anyone but the
		 * owner.  This is to help avoid novices accidentally
		 * allowing access to their account by anyone.
		 */
		যদি (options.strict_modes &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Rhosts authentication refused for %.100s: "
			    "bad modes for %.200s", pw->pw_name, path);
			auth_debug_add("Bad file modes for %.200s", path);
			মুক্ত(path);
			অনুবর্ত;
		}
		/*
		 * Check if we have been configured to ignore .rhosts
		 * and .shosts files.
		 */
		যদি (options.ignore_rhosts == IGNORE_RHOSTS_YES ||
		    (options.ignore_rhosts == IGNORE_RHOSTS_SHOSTS &&
		    strcmp(rhosts_files[rhosts_file_index], ".shosts") != 0)) {
			auth_debug_add("Server has been configured to "
			    "ignore %.100s.", rhosts_files[rhosts_file_index]);
			মুক্ত(path);
			অনুবর্ত;
		}
		/* Check if authentication is permitted by the file. */
		যদি (check_rhosts_file(path, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted by %.100s.",
			    rhosts_files[rhosts_file_index]);
			/* Restore the privileged uid. */
			restore_uid();
			auth_debug_add("Accepted host %s ip %s client_user "
			    "%s server_user %s", hostname, ipaddr,
			    client_user, pw->pw_name);
			মুক্ত(path);
			প্রত্যাগম 1;
		}
		মুক্ত(path);
	}

	/* Restore the privileged uid. */
	restore_uid();
	প্রত্যাগম 0;
}
