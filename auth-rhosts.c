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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netgroup.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "uidswap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"

/* import */
ਬਾਹਰੀ ServerOptions options;

/*
 * This function processes an rhosts-style file (.rhosts, .shosts, or
 * /etc/hosts.equiv).  This returns true if authentication can be granted
 * based on the file, and returns zero otherwise.
 */

ਸਥਿਰ ਪੂਰਨ
check_rhosts_file(ਅਚਲ ਅੱਖਰ *filename, ਅਚਲ ਅੱਖਰ *hostname,
		  ਅਚਲ ਅੱਖਰ *ipaddr, ਅਚਲ ਅੱਖਰ *client_user,
		  ਅਚਲ ਅੱਖਰ *server_user)
{
	FILE *f;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RBUFLN 1024
	ਅੱਖਰ buf[RBUFLN];/* Must not be larger than host, user, dummy below. */
	ਪੂਰਨ fd;
	ਬਣਤਰ stat st;

	/* Open the .rhosts file, deny if unreadable */
	ਜੇ ((fd = open(filename, O_RDONLY|O_NONBLOCK)) == -1)
		ਵਾਪਸ 0;
	ਜੇ (fstat(fd, &st) == -1) {
		close(fd);
		ਵਾਪਸ 0;
	}
	ਜੇ (!S_ISREG(st.st_mode)) {
		logit("User %s hosts file %s is not a regular file",
		    server_user, filename);
		close(fd);
		ਵਾਪਸ 0;
	}
	unset_nonblock(fd);
	ਜੇ ((f = fdopen(fd, "r")) == ਨਿਰਾ) {
		close(fd);
		ਵਾਪਸ 0;
	}
	ਜਦੋਂ (fgets(buf, ਆਕਾਰ(buf), f)) {
		/* All three must have length >= buf to avoid overflows. */
		ਅੱਖਰ hostbuf[RBUFLN], userbuf[RBUFLN], dummy[RBUFLN];
		ਅੱਖਰ *host, *user, *cp;
		ਪੂਰਨ negated;

		ਲਈ (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		ਜੇ (*cp == '#' || *cp == '\n' || !*cp)
			ਜਾਰੀ;

		/*
		 * NO_PLUS is supported at least on OSF/1.  We skip it (we
		 * don't ever support the plus syntax).
		 */
		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(cp, "NO_PLUS", 7) == 0)
			ਜਾਰੀ;

		/*
		 * This should be safe because each buffer is as big as the
		 * whole string, and thus cannot be overwritten.
		 */
		ਚੋਣ (ਲੜੀ_ਤੋਂ_ਪੜ੍ਹੋ(buf, "%1023s %1023s %1023s", hostbuf, userbuf,
		    dummy)) {
		ਹਾਲਤ 0:
			auth_debug_ਜੋੜੋ("Found empty line in %.100s.", filename);
			ਜਾਰੀ;
		ਹਾਲਤ 1:
			/* Host name only. */
			strlcpy(userbuf, server_user, ਆਕਾਰ(userbuf));
			ਰੋਕੋ;
		ਹਾਲਤ 2:
			/* Got both host and user name. */
			ਰੋਕੋ;
		ਹਾਲਤ 3:
			auth_debug_ਜੋੜੋ("Found garbage in %.100s.", filename);
			ਜਾਰੀ;
		ਮੂਲ:
			/* Weird... */
			ਜਾਰੀ;
		}

		host = hostbuf;
		user = userbuf;
		negated = 0;

		/* Process negated host names, or positive netgroups. */
		ਜੇ (host[0] == '-') {
			negated = 1;
			host++;
		} ਨਹੀਂਤਾਂ ਜੇ (host[0] == '+')
			host++;

		ਜੇ (user[0] == '-') {
			negated = 1;
			user++;
		} ਨਹੀਂਤਾਂ ਜੇ (user[0] == '+')
			user++;

		/* Check for empty host/user names (particularly '+'). */
		ਜੇ (!host[0] || !user[0]) {
			/* We come here if either was '+' or '-'. */
			auth_debug_ਜੋੜੋ("Ignoring wild host/user names "
			    "in %.100s.", filename);
			ਜਾਰੀ;
		}
		/* Verify that host name matches. */
		ਜੇ (host[0] == '@') {
			ਜੇ (!innetgr(host + 1, hostname, ਨਿਰਾ, ਨਿਰਾ) &&
			    !innetgr(host + 1, ipaddr, ਨਿਰਾ, ਨਿਰਾ))
				ਜਾਰੀ;
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(host, hostname) &&
		    strcmp(host, ipaddr) != 0)
			ਜਾਰੀ;	/* Different hostname. */

		/* Verify that user name matches. */
		ਜੇ (user[0] == '@') {
			ਜੇ (!innetgr(user + 1, ਨਿਰਾ, client_user, ਨਿਰਾ))
				ਜਾਰੀ;
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(user, client_user) != 0)
			ਜਾਰੀ;	/* Different username. */

		/* Found the user and host. */
		fclose(f);

		/* If the entry was negated, deny access. */
		ਜੇ (negated) {
			auth_debug_ਜੋੜੋ("Matched negative entry in %.100s.",
			    filename);
			ਵਾਪਸ 0;
		}
		/* Accept authentication. */
		ਵਾਪਸ 1;
	}

	/* Authentication using this file denied. */
	fclose(f);
	ਵਾਪਸ 0;
}

/*
 * Tries to authenticate the user using the .shosts or .rhosts file. Returns
 * true if authentication succeeds.  If ignore_rhosts is true, only
 * /etc/hosts.equiv will be considered (.rhosts and .shosts are ignored).
 */
ਪੂਰਨ
auth_rhosts2(ਬਣਤਰ passwd *pw, ਅਚਲ ਅੱਖਰ *client_user, ਅਚਲ ਅੱਖਰ *hostname,
    ਅਚਲ ਅੱਖਰ *ipaddr)
{
	ਅੱਖਰ *ਰਸਤਾ = ਨਿਰਾ;
	ਬਣਤਰ stat st;
	ਸਥਿਰ ਅਚਲ ਅੱਖਰ * ਅਚਲ rhosts_files[] = {".shosts", ".rhosts", ਨਿਰਾ};
	u_int rhosts_file_ਸੂਚਕਾਂਕ;
	ਪੂਰਨ r;

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
	ਲਈ (rhosts_file_ਸੂਚਕਾਂਕ = 0; rhosts_files[rhosts_file_ਸੂਚਕਾਂਕ];
	    rhosts_file_ਸੂਚਕਾਂਕ++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&ਰਸਤਾ, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_ਸੂਚਕਾਂਕ]);
		r = stat(ਰਸਤਾ, &st);
		ਮੁਕਤ(ਰਸਤਾ);
		ਜੇ (r >= 0)
			ਰੋਕੋ;
	}
	/* Switch back to privileged uid. */
	restore_uid();

	/*
	 * Deny if The user has no .shosts or .rhosts file and there
	 * are no system-wide files.
	 */
	ਜੇ (!rhosts_files[rhosts_file_ਸੂਚਕਾਂਕ] &&
	    stat(ਰਸਤਾ_RHOSTS_EQUIV, &st) == -1 &&
	    stat(ਰਸਤਾ_SSH_HOSTS_EQUIV, &st) == -1) {
		debug3_f("no hosts access files exist");
		ਵਾਪਸ 0;
	}

	/*
	 * If not logging in as superuser, try /etc/hosts.equiv and
	 * shosts.equiv.
	 */
	ਜੇ (pw->pw_uid == 0)
		debug3_f("root user, ignoring system hosts files");
	ਨਹੀਂਤਾਂ {
		ਜੇ (check_rhosts_file(ਰਸਤਾ_RHOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_ਜੋੜੋ("Accepted for %.100s [%.100s] by "
			    "/etc/hosts.equiv.", hostname, ipaddr);
			ਵਾਪਸ 1;
		}
		ਜੇ (check_rhosts_file(ਰਸਤਾ_SSH_HOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_ਜੋੜੋ("Accepted for %.100s [%.100s] by "
			    "%.100s.", hostname, ipaddr, ਰਸਤਾ_SSH_HOSTS_EQUIV);
			ਵਾਪਸ 1;
		}
	}

	/*
	 * Check that the home directory is owned by root or the user, and is
	 * not group or world writable.
	 */
	ਜੇ (stat(pw->pw_dir, &st) == -1) {
		logit("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		auth_debug_ਜੋੜੋ("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		ਵਾਪਸ 0;
	}
	ਜੇ (options.strict_modes &&
	    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	    (st.st_mode & 022) != 0)) {
		logit("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		auth_debug_ਜੋੜੋ("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		ਵਾਪਸ 0;
	}
	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	/* Check all .rhosts files (currently .shosts and .rhosts). */
	ਲਈ (rhosts_file_ਸੂਚਕਾਂਕ = 0; rhosts_files[rhosts_file_ਸੂਚਕਾਂਕ];
	    rhosts_file_ਸੂਚਕਾਂਕ++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&ਰਸਤਾ, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_ਸੂਚਕਾਂਕ]);
		ਜੇ (stat(ਰਸਤਾ, &st) == -1) {
			debug3_f("stat %s: %s", ਰਸਤਾ, strerror(errno));
			ਮੁਕਤ(ਰਸਤਾ);
			ਜਾਰੀ;
		}

		/*
		 * Make sure that the file is either owned by the user or by
		 * root, and make sure it is not writable by anyone but the
		 * owner.  This is to help avoid novices accidentally
		 * allowing access to their account by anyone.
		 */
		ਜੇ (options.strict_modes &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Rhosts authentication refused for %.100s: "
			    "bad modes for %.200s", pw->pw_name, ਰਸਤਾ);
			auth_debug_ਜੋੜੋ("Bad file modes for %.200s", ਰਸਤਾ);
			ਮੁਕਤ(ਰਸਤਾ);
			ਜਾਰੀ;
		}
		/*
		 * Check if we have been configured to ignore .rhosts
		 * and .shosts files.
		 */
		ਜੇ (options.ignore_rhosts == IGNORE_RHOSTS_YES ||
		    (options.ignore_rhosts == IGNORE_RHOSTS_SHOSTS &&
		    strcmp(rhosts_files[rhosts_file_ਸੂਚਕਾਂਕ], ".shosts") != 0)) {
			auth_debug_ਜੋੜੋ("Server has been configured to "
			    "ignore %.100s.", rhosts_files[rhosts_file_ਸੂਚਕਾਂਕ]);
			ਮੁਕਤ(ਰਸਤਾ);
			ਜਾਰੀ;
		}
		/* Check if authentication is permitted by the file. */
		ਜੇ (check_rhosts_file(ਰਸਤਾ, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_ਜੋੜੋ("Accepted by %.100s.",
			    rhosts_files[rhosts_file_ਸੂਚਕਾਂਕ]);
			/* Restore the privileged uid. */
			restore_uid();
			auth_debug_ਜੋੜੋ("Accepted host %s ip %s client_user "
			    "%s server_user %s", hostname, ipaddr,
			    client_user, pw->pw_name);
			ਮੁਕਤ(ਰਸਤਾ);
			ਵਾਪਸ 1;
		}
		ਮੁਕਤ(ਰਸਤਾ);
	}

	/* Restore the privileged uid. */
	restore_uid();
	ਵਾਪਸ 0;
}
