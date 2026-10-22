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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <netgroup.h>
#شامل <pwd.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <stdlib.h>
#شامل <unistd.h>

#شامل "packet.h"
#شامل "uidswap.h"
#شامل "pathnames.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "xmalloc.h"
#شامل "sshbuf.h"
#شامل "sshkey.h"
#شامل "servconf.h"
#شامل "canohost.h"
#شامل "hostfile.h"
#شامل "auth.h"

/* import */
خارجی ServerOptions options;

/*
 * This function processes an rhosts-style file (.rhosts, .shosts, or
 * /etc/hosts.equiv).  This returns true if authentication can be granted
 * based on the file, and returns zero otherwise.
 */

ساکن صحیح
check_rhosts_file(ثابت حرف *filename, ثابت حرف *hostname,
		  ثابت حرف *ipaddr, ثابت حرف *client_user,
		  ثابت حرف *server_user)
{
	FILE *f;
#تعریف_کرو RBUFLN 1024
	حرف buf[RBUFLN];/* Must not be larger than host, user, dummy below. */
	صحیح fd;
	ساخت stat st;

	/* Open the .rhosts file, deny if unreadable */
	اگر ((fd = open(filename, O_RDONLY|O_NONBLOCK)) == -1)
		واپس 0;
	اگر (fstat(fd, &st) == -1) {
		close(fd);
		واپس 0;
	}
	اگر (!S_ISREG(st.st_mode)) {
		logit("User %s hosts file %s is not a regular file",
		    server_user, filename);
		close(fd);
		واپس 0;
	}
	unset_nonblock(fd);
	اگر ((f = fdopen(fd, "r")) == تہی) {
		close(fd);
		واپس 0;
	}
	جب (fgets(buf, حجم(buf), f)) {
		/* All three must have length >= buf to avoid overflows. */
		حرف hostbuf[RBUFLN], userbuf[RBUFLN], dummy[RBUFLN];
		حرف *host, *user, *cp;
		صحیح negated;

		برائے (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		اگر (*cp == '#' || *cp == '\n' || !*cp)
			جاری;

		/*
		 * NO_PLUS is supported at least on OSF/1.  We skip it (we
		 * don't ever support the plus syntax).
		 */
		اگر (لڑی_موازنہ(cp, "NO_PLUS", 7) == 0)
			جاری;

		/*
		 * This should be safe because each buffer is as big as the
		 * whole string, and thus cannot be overwritten.
		 */
		انتخاب (لڑی_سے_پڑھو(buf, "%1023s %1023s %1023s", hostbuf, userbuf,
		    dummy)) {
		حالت 0:
			auth_debug_جوڑو("Found empty line in %.100s.", filename);
			جاری;
		حالت 1:
			/* Host name only. */
			strlcpy(userbuf, server_user, حجم(userbuf));
			توڑو;
		حالت 2:
			/* Got both host and user name. */
			توڑو;
		حالت 3:
			auth_debug_جوڑو("Found garbage in %.100s.", filename);
			جاری;
		طےشدہ:
			/* Weird... */
			جاری;
		}

		host = hostbuf;
		user = userbuf;
		negated = 0;

		/* Process negated host names, or positive netgroups. */
		اگر (host[0] == '-') {
			negated = 1;
			host++;
		} ورنہ اگر (host[0] == '+')
			host++;

		اگر (user[0] == '-') {
			negated = 1;
			user++;
		} ورنہ اگر (user[0] == '+')
			user++;

		/* Check for empty host/user names (particularly '+'). */
		اگر (!host[0] || !user[0]) {
			/* We come here if either was '+' or '-'. */
			auth_debug_جوڑو("Ignoring wild host/user names "
			    "in %.100s.", filename);
			جاری;
		}
		/* Verify that host name matches. */
		اگر (host[0] == '@') {
			اگر (!innetgr(host + 1, hostname, تہی, تہی) &&
			    !innetgr(host + 1, ipaddr, تہی, تہی))
				جاری;
		} ورنہ اگر (strcasecmp(host, hostname) &&
		    strcmp(host, ipaddr) != 0)
			جاری;	/* Different hostname. */

		/* Verify that user name matches. */
		اگر (user[0] == '@') {
			اگر (!innetgr(user + 1, تہی, client_user, تہی))
				جاری;
		} ورنہ اگر (strcmp(user, client_user) != 0)
			جاری;	/* Different username. */

		/* Found the user and host. */
		fclose(f);

		/* If the entry was negated, deny access. */
		اگر (negated) {
			auth_debug_جوڑو("Matched negative entry in %.100s.",
			    filename);
			واپس 0;
		}
		/* Accept authentication. */
		واپس 1;
	}

	/* Authentication using this file denied. */
	fclose(f);
	واپس 0;
}

/*
 * Tries to authenticate the user using the .shosts or .rhosts file. Returns
 * true if authentication succeeds.  If ignore_rhosts is true, only
 * /etc/hosts.equiv will be considered (.rhosts and .shosts are ignored).
 */
صحیح
auth_rhosts2(ساخت passwd *pw, ثابت حرف *client_user, ثابت حرف *hostname,
    ثابت حرف *ipaddr)
{
	حرف *راستہ = تہی;
	ساخت stat st;
	ساکن ثابت حرف * ثابت rhosts_files[] = {".shosts", ".rhosts", تہی};
	u_int rhosts_file_اشاریہ;
	صحیح r;

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
	برائے (rhosts_file_اشاریہ = 0; rhosts_files[rhosts_file_اشاریہ];
	    rhosts_file_اشاریہ++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&راستہ, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_اشاریہ]);
		r = stat(راستہ, &st);
		آزاد(راستہ);
		اگر (r >= 0)
			توڑو;
	}
	/* Switch back to privileged uid. */
	restore_uid();

	/*
	 * Deny if The user has no .shosts or .rhosts file and there
	 * are no system-wide files.
	 */
	اگر (!rhosts_files[rhosts_file_اشاریہ] &&
	    stat(راستہ_RHOSTS_EQUIV, &st) == -1 &&
	    stat(راستہ_SSH_HOSTS_EQUIV, &st) == -1) {
		debug3_f("no hosts access files exist");
		واپس 0;
	}

	/*
	 * If not logging in as superuser, try /etc/hosts.equiv and
	 * shosts.equiv.
	 */
	اگر (pw->pw_uid == 0)
		debug3_f("root user, ignoring system hosts files");
	ورنہ {
		اگر (check_rhosts_file(راستہ_RHOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_جوڑو("Accepted for %.100s [%.100s] by "
			    "/etc/hosts.equiv.", hostname, ipaddr);
			واپس 1;
		}
		اگر (check_rhosts_file(راستہ_SSH_HOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_جوڑو("Accepted for %.100s [%.100s] by "
			    "%.100s.", hostname, ipaddr, راستہ_SSH_HOSTS_EQUIV);
			واپس 1;
		}
	}

	/*
	 * Check that the home directory is owned by root or the user, and is
	 * not group or world writable.
	 */
	اگر (stat(pw->pw_dir, &st) == -1) {
		logit("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		auth_debug_جوڑو("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		واپس 0;
	}
	اگر (options.strict_modes &&
	    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	    (st.st_mode & 022) != 0)) {
		logit("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		auth_debug_جوڑو("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		واپس 0;
	}
	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	/* Check all .rhosts files (currently .shosts and .rhosts). */
	برائے (rhosts_file_اشاریہ = 0; rhosts_files[rhosts_file_اشاریہ];
	    rhosts_file_اشاریہ++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&راستہ, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_اشاریہ]);
		اگر (stat(راستہ, &st) == -1) {
			debug3_f("stat %s: %s", راستہ, strerror(errno));
			آزاد(راستہ);
			جاری;
		}

		/*
		 * Make sure that the file is either owned by the user or by
		 * root, and make sure it is not writable by anyone but the
		 * owner.  This is to help avoid novices accidentally
		 * allowing access to their account by anyone.
		 */
		اگر (options.strict_modes &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Rhosts authentication refused for %.100s: "
			    "bad modes for %.200s", pw->pw_name, راستہ);
			auth_debug_جوڑو("Bad file modes for %.200s", راستہ);
			آزاد(راستہ);
			جاری;
		}
		/*
		 * Check if we have been configured to ignore .rhosts
		 * and .shosts files.
		 */
		اگر (options.ignore_rhosts == IGNORE_RHOSTS_YES ||
		    (options.ignore_rhosts == IGNORE_RHOSTS_SHOSTS &&
		    strcmp(rhosts_files[rhosts_file_اشاریہ], ".shosts") != 0)) {
			auth_debug_جوڑو("Server has been configured to "
			    "ignore %.100s.", rhosts_files[rhosts_file_اشاریہ]);
			آزاد(راستہ);
			جاری;
		}
		/* Check if authentication is permitted by the file. */
		اگر (check_rhosts_file(راستہ, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_جوڑو("Accepted by %.100s.",
			    rhosts_files[rhosts_file_اشاریہ]);
			/* Restore the privileged uid. */
			restore_uid();
			auth_debug_جوڑو("Accepted host %s ip %s client_user "
			    "%s server_user %s", hostname, ipaddr,
			    client_user, pw->pw_name);
			آزاد(راستہ);
			واپس 1;
		}
		آزاد(راستہ);
	}

	/* Restore the privileged uid. */
	restore_uid();
	واپس 0;
}
