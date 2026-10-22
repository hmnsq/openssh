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

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_rhosts_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname,
		  ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ipaddr, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *client_user,
		  ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *server_user)
{
	FILE *f;
#ವ್ಯಾಖ್ಯಾನಿಸು RBUFLN 1024
	ಅಕ್ಷರ buf[RBUFLN];/* Must not be larger than host, user, dummy below. */
	ಪೂರ್ಣಾಂಕ fd;
	ರಚನೆ stat st;

	/* Open the .rhosts file, deny if unreadable */
	ಆದರೆ ((fd = open(filename, O_RDONLY|O_NONBLOCK)) == -1)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (fstat(fd, &st) == -1) {
		close(fd);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (!S_ISREG(st.st_mode)) {
		logit("User %s hosts file %s is not a regular file",
		    server_user, filename);
		close(fd);
		ಹಿಂತಿರುಗಿ 0;
	}
	unset_nonblock(fd);
	ಆದರೆ ((f = fdopen(fd, "r")) == ಖಾಲಿ) {
		close(fd);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆಗ (fgets(buf, ಗಾತ್ರ(buf), f)) {
		/* All three must have length >= buf to avoid overflows. */
		ಅಕ್ಷರ hostbuf[RBUFLN], userbuf[RBUFLN], dummy[RBUFLN];
		ಅಕ್ಷರ *host, *user, *cp;
		ಪೂರ್ಣಾಂಕ negated;

		ಗಾಗಿ (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		ಆದರೆ (*cp == '#' || *cp == '\n' || !*cp)
			ಮುಂದುವರಿ;

		/*
		 * NO_PLUS is supported at least on OSF/1.  We skip it (we
		 * don't ever support the plus syntax).
		 */
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(cp, "NO_PLUS", 7) == 0)
			ಮುಂದುವರಿ;

		/*
		 * This should be safe because each buffer is as big as the
		 * whole string, and thus cannot be overwritten.
		 */
		ಆಯ್ಕೆ (ಅಕ್ಷರಸರಣಿ_ಓದು(buf, "%1023s %1023s %1023s", hostbuf, userbuf,
		    dummy)) {
		ಸ್ಥಿತಿ 0:
			auth_debug_ಕೂಡಿಸು("Found empty line in %.100s.", filename);
			ಮುಂದುವರಿ;
		ಸ್ಥಿತಿ 1:
			/* Host name only. */
			strlcpy(userbuf, server_user, ಗಾತ್ರ(userbuf));
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 2:
			/* Got both host and user name. */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 3:
			auth_debug_ಕೂಡಿಸು("Found garbage in %.100s.", filename);
			ಮುಂದುವರಿ;
		ಪೂರ್ವನಿಯೋಜಿತ:
			/* Weird... */
			ಮುಂದುವರಿ;
		}

		host = hostbuf;
		user = userbuf;
		negated = 0;

		/* Process negated host names, or positive netgroups. */
		ಆದರೆ (host[0] == '-') {
			negated = 1;
			host++;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (host[0] == '+')
			host++;

		ಆದರೆ (user[0] == '-') {
			negated = 1;
			user++;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (user[0] == '+')
			user++;

		/* Check for empty host/user names (particularly '+'). */
		ಆದರೆ (!host[0] || !user[0]) {
			/* We come here if either was '+' or '-'. */
			auth_debug_ಕೂಡಿಸು("Ignoring wild host/user names "
			    "in %.100s.", filename);
			ಮುಂದುವರಿ;
		}
		/* Verify that host name matches. */
		ಆದರೆ (host[0] == '@') {
			ಆದರೆ (!innetgr(host + 1, hostname, ಖಾಲಿ, ಖಾಲಿ) &&
			    !innetgr(host + 1, ipaddr, ಖಾಲಿ, ಖಾಲಿ))
				ಮುಂದುವರಿ;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(host, hostname) &&
		    strcmp(host, ipaddr) != 0)
			ಮುಂದುವರಿ;	/* Different hostname. */

		/* Verify that user name matches. */
		ಆದರೆ (user[0] == '@') {
			ಆದರೆ (!innetgr(user + 1, ಖಾಲಿ, client_user, ಖಾಲಿ))
				ಮುಂದುವರಿ;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(user, client_user) != 0)
			ಮುಂದುವರಿ;	/* Different username. */

		/* Found the user and host. */
		fclose(f);

		/* If the entry was negated, deny access. */
		ಆದರೆ (negated) {
			auth_debug_ಕೂಡಿಸು("Matched negative entry in %.100s.",
			    filename);
			ಹಿಂತಿರುಗಿ 0;
		}
		/* Accept authentication. */
		ಹಿಂತಿರುಗಿ 1;
	}

	/* Authentication using this file denied. */
	fclose(f);
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Tries to authenticate the user using the .shosts or .rhosts file. Returns
 * true if authentication succeeds.  If ignore_rhosts is true, only
 * /etc/hosts.equiv will be considered (.rhosts and .shosts are ignored).
 */
ಪೂರ್ಣಾಂಕ
auth_rhosts2(ರಚನೆ passwd *pw, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *client_user, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ipaddr)
{
	ಅಕ್ಷರ *ಮಾರ್ಗ = ಖಾಲಿ;
	ರಚನೆ stat st;
	ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ rhosts_files[] = {".shosts", ".rhosts", ಖಾಲಿ};
	u_int rhosts_file_ಸೂಚ್ಯಂಕ;
	ಪೂರ್ಣಾಂಕ r;

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
	ಗಾಗಿ (rhosts_file_ಸೂಚ್ಯಂಕ = 0; rhosts_files[rhosts_file_ಸೂಚ್ಯಂಕ];
	    rhosts_file_ಸೂಚ್ಯಂಕ++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&ಮಾರ್ಗ, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_ಸೂಚ್ಯಂಕ]);
		r = stat(ಮಾರ್ಗ, &st);
		ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
		ಆದರೆ (r >= 0)
			ನಿಲ್ಲಿಸು;
	}
	/* Switch back to privileged uid. */
	restore_uid();

	/*
	 * Deny if The user has no .shosts or .rhosts file and there
	 * are no system-wide files.
	 */
	ಆದರೆ (!rhosts_files[rhosts_file_ಸೂಚ್ಯಂಕ] &&
	    stat(ಮಾರ್ಗ_RHOSTS_EQUIV, &st) == -1 &&
	    stat(ಮಾರ್ಗ_SSH_HOSTS_EQUIV, &st) == -1) {
		debug3_f("no hosts access files exist");
		ಹಿಂತಿರುಗಿ 0;
	}

	/*
	 * If not logging in as superuser, try /etc/hosts.equiv and
	 * shosts.equiv.
	 */
	ಆದರೆ (pw->pw_uid == 0)
		debug3_f("root user, ignoring system hosts files");
	ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (check_rhosts_file(ಮಾರ್ಗ_RHOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_ಕೂಡಿಸು("Accepted for %.100s [%.100s] by "
			    "/etc/hosts.equiv.", hostname, ipaddr);
			ಹಿಂತಿರುಗಿ 1;
		}
		ಆದರೆ (check_rhosts_file(ಮಾರ್ಗ_SSH_HOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_ಕೂಡಿಸು("Accepted for %.100s [%.100s] by "
			    "%.100s.", hostname, ipaddr, ಮಾರ್ಗ_SSH_HOSTS_EQUIV);
			ಹಿಂತಿರುಗಿ 1;
		}
	}

	/*
	 * Check that the home directory is owned by root or the user, and is
	 * not group or world writable.
	 */
	ಆದರೆ (stat(pw->pw_dir, &st) == -1) {
		logit("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		auth_debug_ಕೂಡಿಸು("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (options.strict_modes &&
	    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	    (st.st_mode & 022) != 0)) {
		logit("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		auth_debug_ಕೂಡಿಸು("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		ಹಿಂತಿರುಗಿ 0;
	}
	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	/* Check all .rhosts files (currently .shosts and .rhosts). */
	ಗಾಗಿ (rhosts_file_ಸೂಚ್ಯಂಕ = 0; rhosts_files[rhosts_file_ಸೂಚ್ಯಂಕ];
	    rhosts_file_ಸೂಚ್ಯಂಕ++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&ಮಾರ್ಗ, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_ಸೂಚ್ಯಂಕ]);
		ಆದರೆ (stat(ಮಾರ್ಗ, &st) == -1) {
			debug3_f("stat %s: %s", ಮಾರ್ಗ, strerror(errno));
			ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
			ಮುಂದುವರಿ;
		}

		/*
		 * Make sure that the file is either owned by the user or by
		 * root, and make sure it is not writable by anyone but the
		 * owner.  This is to help avoid novices accidentally
		 * allowing access to their account by anyone.
		 */
		ಆದರೆ (options.strict_modes &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Rhosts authentication refused for %.100s: "
			    "bad modes for %.200s", pw->pw_name, ಮಾರ್ಗ);
			auth_debug_ಕೂಡಿಸು("Bad file modes for %.200s", ಮಾರ್ಗ);
			ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
			ಮುಂದುವರಿ;
		}
		/*
		 * Check if we have been configured to ignore .rhosts
		 * and .shosts files.
		 */
		ಆದರೆ (options.ignore_rhosts == IGNORE_RHOSTS_YES ||
		    (options.ignore_rhosts == IGNORE_RHOSTS_SHOSTS &&
		    strcmp(rhosts_files[rhosts_file_ಸೂಚ್ಯಂಕ], ".shosts") != 0)) {
			auth_debug_ಕೂಡಿಸು("Server has been configured to "
			    "ignore %.100s.", rhosts_files[rhosts_file_ಸೂಚ್ಯಂಕ]);
			ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
			ಮುಂದುವರಿ;
		}
		/* Check if authentication is permitted by the file. */
		ಆದರೆ (check_rhosts_file(ಮಾರ್ಗ, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_ಕೂಡಿಸು("Accepted by %.100s.",
			    rhosts_files[rhosts_file_ಸೂಚ್ಯಂಕ]);
			/* Restore the privileged uid. */
			restore_uid();
			auth_debug_ಕೂಡಿಸು("Accepted host %s ip %s client_user "
			    "%s server_user %s", hostname, ipaddr,
			    client_user, pw->pw_name);
			ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
			ಹಿಂತಿರುಗಿ 1;
		}
		ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
	}

	/* Restore the privileged uid. */
	restore_uid();
	ಹಿಂತಿರುಗಿ 0;
}
