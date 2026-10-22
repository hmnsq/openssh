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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <netgroup.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "uidswap.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"

/* import */
ಬಾಹ್ಯ ServerOptions options;

/*
 * This function processes an rhosts-style file (.rhosts, .shosts, or
 * /etc/hosts.equiv).  This returns true if authentication can be granted
 * based on the file, and returns zero otherwise.
 */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_rhosts_file(ಧ್ರುವ ವರ್ಣ *filename, ಧ್ರುವ ವರ್ಣ *hostname,
		  ಧ್ರುವ ವರ್ಣ *ipaddr, ಧ್ರುವ ವರ್ಣ *client_user,
		  ಧ್ರುವ ವರ್ಣ *server_user)
{
	FILE *f;
#define RBUFLN 1024
	ವರ್ಣ buf[RBUFLN];/* Must not be larger than host, user, dummy below. */
	ಪೂರ್ಣಾಙ್ಕ fd;
	ಸಂರಚನಾ stat st;

	/* Open the .rhosts file, deny if unreadable */
	ಯದಿ ((fd = open(filename, O_RDONLY|O_NONBLOCK)) == -1)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (fstat(fd, &st) == -1) {
		close(fd);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (!S_ISREG(st.st_mode)) {
		logit("User %s hosts file %s is not a regular file",
		    server_user, filename);
		close(fd);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	unset_nonblock(fd);
	ಯದಿ ((f = fdopen(fd, "r")) == ರಿಕ್ತ) {
		close(fd);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯಾವತ್ (fgets(buf, ಪರಿಮಾಣ(buf), f)) {
		/* All three must have length >= buf to avoid overflows. */
		ವರ್ಣ hostbuf[RBUFLN], userbuf[RBUFLN], dummy[RBUFLN];
		ವರ್ಣ *host, *user, *cp;
		ಪೂರ್ಣಾಙ್ಕ negated;

		ಪ್ರತಿ (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		ಯದಿ (*cp == '#' || *cp == '\n' || !*cp)
			ಅನುವರ್ತ;

		/*
		 * NO_PLUS is supported at least on OSF/1.  We skip it (we
		 * don't ever support the plus syntax).
		 */
		ಯದಿ (strncmp(cp, "NO_PLUS", 7) == 0)
			ಅನುವರ್ತ;

		/*
		 * This should be safe because each buffer is as big as the
		 * whole string, and thus cannot be overwritten.
		 */
		ವಿಕಲ್ಪ (sscanf(buf, "%1023s %1023s %1023s", hostbuf, userbuf,
		    dummy)) {
		ಪಕ್ಷ 0:
			auth_debug_add("Found empty line in %.100s.", filename);
			ಅನುವರ್ತ;
		ಪಕ್ಷ 1:
			/* Host name only. */
			strlcpy(userbuf, server_user, ಪರಿಮಾಣ(userbuf));
			ಭಙ್ಗ;
		ಪಕ್ಷ 2:
			/* Got both host and user name. */
			ಭಙ್ಗ;
		ಪಕ್ಷ 3:
			auth_debug_add("Found garbage in %.100s.", filename);
			ಅನುವರ್ತ;
		ಸ್ವಭಾವ:
			/* Weird... */
			ಅನುವರ್ತ;
		}

		host = hostbuf;
		user = userbuf;
		negated = 0;

		/* Process negated host names, or positive netgroups. */
		ಯದಿ (host[0] == '-') {
			negated = 1;
			host++;
		} ಅನ್ಯಥಾ ಯದಿ (host[0] == '+')
			host++;

		ಯದಿ (user[0] == '-') {
			negated = 1;
			user++;
		} ಅನ್ಯಥಾ ಯದಿ (user[0] == '+')
			user++;

		/* Check for empty host/user names (particularly '+'). */
		ಯದಿ (!host[0] || !user[0]) {
			/* We come here if either was '+' or '-'. */
			auth_debug_add("Ignoring wild host/user names "
			    "in %.100s.", filename);
			ಅನುವರ್ತ;
		}
		/* Verify that host name matches. */
		ಯದಿ (host[0] == '@') {
			ಯದಿ (!innetgr(host + 1, hostname, ರಿಕ್ತ, ರಿಕ್ತ) &&
			    !innetgr(host + 1, ipaddr, ರಿಕ್ತ, ರಿಕ್ತ))
				ಅನುವರ್ತ;
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(host, hostname) &&
		    strcmp(host, ipaddr) != 0)
			ಅನುವರ್ತ;	/* Different hostname. */

		/* Verify that user name matches. */
		ಯದಿ (user[0] == '@') {
			ಯದಿ (!innetgr(user + 1, ರಿಕ್ತ, client_user, ರಿಕ್ತ))
				ಅನುವರ್ತ;
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(user, client_user) != 0)
			ಅನುವರ್ತ;	/* Different username. */

		/* Found the user and host. */
		fclose(f);

		/* If the entry was negated, deny access. */
		ಯದಿ (negated) {
			auth_debug_add("Matched negative entry in %.100s.",
			    filename);
			ಪ್ರತ್ಯಾಗಮ 0;
		}
		/* Accept authentication. */
		ಪ್ರತ್ಯಾಗಮ 1;
	}

	/* Authentication using this file denied. */
	fclose(f);
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Tries to authenticate the user using the .shosts or .rhosts file. Returns
 * true if authentication succeeds.  If ignore_rhosts is true, only
 * /etc/hosts.equiv will be considered (.rhosts and .shosts are ignored).
 */
ಪೂರ್ಣಾಙ್ಕ
auth_rhosts2(ಸಂರಚನಾ passwd *pw, ಧ್ರುವ ವರ್ಣ *client_user, ಧ್ರುವ ವರ್ಣ *hostname,
    ಧ್ರುವ ವರ್ಣ *ipaddr)
{
	ವರ್ಣ *path = ರಿಕ್ತ;
	ಸಂರಚನಾ stat st;
	ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ * ಧ್ರುವ rhosts_files[] = {".shosts", ".rhosts", ರಿಕ್ತ};
	u_int rhosts_file_index;
	ಪೂರ್ಣಾಙ್ಕ r;

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
	ಪ್ರತಿ (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		r = stat(path, &st);
		ಮುಕ್ತ(path);
		ಯದಿ (r >= 0)
			ಭಙ್ಗ;
	}
	/* Switch back to privileged uid. */
	restore_uid();

	/*
	 * Deny if The user has no .shosts or .rhosts file and there
	 * are no system-wide files.
	 */
	ಯದಿ (!rhosts_files[rhosts_file_index] &&
	    stat(_PATH_RHOSTS_EQUIV, &st) == -1 &&
	    stat(_PATH_SSH_HOSTS_EQUIV, &st) == -1) {
		debug3_f("no hosts access files exist");
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	/*
	 * If not logging in as superuser, try /etc/hosts.equiv and
	 * shosts.equiv.
	 */
	ಯದಿ (pw->pw_uid == 0)
		debug3_f("root user, ignoring system hosts files");
	ಅನ್ಯಥಾ {
		ಯದಿ (check_rhosts_file(_PATH_RHOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "/etc/hosts.equiv.", hostname, ipaddr);
			ಪ್ರತ್ಯಾಗಮ 1;
		}
		ಯದಿ (check_rhosts_file(_PATH_SSH_HOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "%.100s.", hostname, ipaddr, _PATH_SSH_HOSTS_EQUIV);
			ಪ್ರತ್ಯಾಗಮ 1;
		}
	}

	/*
	 * Check that the home directory is owned by root or the user, and is
	 * not group or world writable.
	 */
	ಯದಿ (stat(pw->pw_dir, &st) == -1) {
		logit("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (options.strict_modes &&
	    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	    (st.st_mode & 022) != 0)) {
		logit("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	/* Check all .rhosts files (currently .shosts and .rhosts). */
	ಪ್ರತಿ (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		ಯದಿ (stat(path, &st) == -1) {
			debug3_f("stat %s: %s", path, strerror(errno));
			ಮುಕ್ತ(path);
			ಅನುವರ್ತ;
		}

		/*
		 * Make sure that the file is either owned by the user or by
		 * root, and make sure it is not writable by anyone but the
		 * owner.  This is to help avoid novices accidentally
		 * allowing access to their account by anyone.
		 */
		ಯದಿ (options.strict_modes &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Rhosts authentication refused for %.100s: "
			    "bad modes for %.200s", pw->pw_name, path);
			auth_debug_add("Bad file modes for %.200s", path);
			ಮುಕ್ತ(path);
			ಅನುವರ್ತ;
		}
		/*
		 * Check if we have been configured to ignore .rhosts
		 * and .shosts files.
		 */
		ಯದಿ (options.ignore_rhosts == IGNORE_RHOSTS_YES ||
		    (options.ignore_rhosts == IGNORE_RHOSTS_SHOSTS &&
		    strcmp(rhosts_files[rhosts_file_index], ".shosts") != 0)) {
			auth_debug_add("Server has been configured to "
			    "ignore %.100s.", rhosts_files[rhosts_file_index]);
			ಮುಕ್ತ(path);
			ಅನುವರ್ತ;
		}
		/* Check if authentication is permitted by the file. */
		ಯದಿ (check_rhosts_file(path, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted by %.100s.",
			    rhosts_files[rhosts_file_index]);
			/* Restore the privileged uid. */
			restore_uid();
			auth_debug_add("Accepted host %s ip %s client_user "
			    "%s server_user %s", hostname, ipaddr,
			    client_user, pw->pw_name);
			ಮುಕ್ತ(path);
			ಪ್ರತ್ಯಾಗಮ 1;
		}
		ಮುಕ್ತ(path);
	}

	/* Restore the privileged uid. */
	restore_uid();
	ಪ್ರತ್ಯಾಗಮ 0;
}
