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
#تعریف_کرو RBUFLN 1024
	حرف buf[RBUFLN];/* Must not be larger than host, user, dummy below. */
	صحيح fd;
	بنية stat st;

	/* Open the .rhosts file, deny if unreadable */
	إذا ((fd = open(filename, O_RDONLY|O_NONBLOCK)) == -1)
		أرجع 0;
	إذا (fstat(fd, &st) == -1) {
		close(fd);
		أرجع 0;
	}
	إذا (!S_ISREG(st.st_mode)) {
		logit("User %s hosts file %s is not a regular file",
		    server_user, filename);
		close(fd);
		أرجع 0;
	}
	unset_nonblock(fd);
	إذا ((f = fdopen(fd, "r")) == عدم) {
		close(fd);
		أرجع 0;
	}
	طالما (fgets(buf, حجم(buf), f)) {
		/* All three must have length >= buf to avoid overflows. */
		حرف hostbuf[RBUFLN], userbuf[RBUFLN], dummy[RBUFLN];
		حرف *host, *user, *cp;
		صحيح negated;

		لكل (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		إذا (*cp == '#' || *cp == '\n' || !*cp)
			استمر;

		/*
		 * NO_PLUS is supported at least on OSF/1.  We skip it (we
		 * don't ever support the plus syntax).
		 */
		إذا (لڑی_مقابلہ(cp, "NO_PLUS", 7) == 0)
			استمر;

		/*
		 * This should be safe because each buffer is as big as the
		 * whole string, and thus cannot be overwritten.
		 */
		بدل (لڑی_توں_پڑھو(buf, "%1023s %1023s %1023s", hostbuf, userbuf,
		    dummy)) {
		حالة 0:
			auth_debug_جوڑو("Found empty line in %.100s.", filename);
			استمر;
		حالة 1:
			/* Host name only. */
			strlcpy(userbuf, server_user, حجم(userbuf));
			اكسر;
		حالة 2:
			/* Got both host and user name. */
			اكسر;
		حالة 3:
			auth_debug_جوڑو("Found garbage in %.100s.", filename);
			استمر;
		افتراضي:
			/* Weird... */
			استمر;
		}

		host = hostbuf;
		user = userbuf;
		negated = 0;

		/* Process negated host names, or positive netgroups. */
		إذا (host[0] == '-') {
			negated = 1;
			host++;
		} وإلا إذا (host[0] == '+')
			host++;

		إذا (user[0] == '-') {
			negated = 1;
			user++;
		} وإلا إذا (user[0] == '+')
			user++;

		/* Check for empty host/user names (particularly '+'). */
		إذا (!host[0] || !user[0]) {
			/* We come here if either was '+' or '-'. */
			auth_debug_جوڑو("Ignoring wild host/user names "
			    "in %.100s.", filename);
			استمر;
		}
		/* Verify that host name matches. */
		إذا (host[0] == '@') {
			إذا (!innetgr(host + 1, hostname, عدم, عدم) &&
			    !innetgr(host + 1, ipaddr, عدم, عدم))
				استمر;
		} وإلا إذا (strcasecmp(host, hostname) &&
		    strcmp(host, ipaddr) != 0)
			استمر;	/* Different hostname. */

		/* Verify that user name matches. */
		إذا (user[0] == '@') {
			إذا (!innetgr(user + 1, عدم, client_user, عدم))
				استمر;
		} وإلا إذا (strcmp(user, client_user) != 0)
			استمر;	/* Different username. */

		/* Found the user and host. */
		fclose(f);

		/* If the entry was negated, deny access. */
		إذا (negated) {
			auth_debug_جوڑو("Matched negative entry in %.100s.",
			    filename);
			أرجع 0;
		}
		/* Accept authentication. */
		أرجع 1;
	}

	/* Authentication using this file denied. */
	fclose(f);
	أرجع 0;
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
	حرف *رستہ = عدم;
	بنية stat st;
	ساكن ثابت حرف * ثابت rhosts_files[] = {".shosts", ".rhosts", عدم};
	u_int rhosts_file_اشاریہ;
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
	لكل (rhosts_file_اشاریہ = 0; rhosts_files[rhosts_file_اشاریہ];
	    rhosts_file_اشاریہ++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&رستہ, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_اشاریہ]);
		r = stat(رستہ, &st);
		حرر(رستہ);
		إذا (r >= 0)
			اكسر;
	}
	/* Switch back to privileged uid. */
	restore_uid();

	/*
	 * Deny if The user has no .shosts or .rhosts file and there
	 * are no system-wide files.
	 */
	إذا (!rhosts_files[rhosts_file_اشاریہ] &&
	    stat(رستہ_RHOSTS_EQUIV, &st) == -1 &&
	    stat(رستہ_SSH_HOSTS_EQUIV, &st) == -1) {
		debug3_f("no hosts access files exist");
		أرجع 0;
	}

	/*
	 * If not logging in as superuser, try /etc/hosts.equiv and
	 * shosts.equiv.
	 */
	إذا (pw->pw_uid == 0)
		debug3_f("root user, ignoring system hosts files");
	وإلا {
		إذا (check_rhosts_file(رستہ_RHOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_جوڑو("Accepted for %.100s [%.100s] by "
			    "/etc/hosts.equiv.", hostname, ipaddr);
			أرجع 1;
		}
		إذا (check_rhosts_file(رستہ_SSH_HOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_جوڑو("Accepted for %.100s [%.100s] by "
			    "%.100s.", hostname, ipaddr, رستہ_SSH_HOSTS_EQUIV);
			أرجع 1;
		}
	}

	/*
	 * Check that the home directory is owned by root or the user, and is
	 * not group or world writable.
	 */
	إذا (stat(pw->pw_dir, &st) == -1) {
		logit("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		auth_debug_جوڑو("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		أرجع 0;
	}
	إذا (options.strict_modes &&
	    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	    (st.st_mode & 022) != 0)) {
		logit("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		auth_debug_جوڑو("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		أرجع 0;
	}
	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	/* Check all .rhosts files (currently .shosts and .rhosts). */
	لكل (rhosts_file_اشاریہ = 0; rhosts_files[rhosts_file_اشاریہ];
	    rhosts_file_اشاریہ++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&رستہ, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_اشاریہ]);
		إذا (stat(رستہ, &st) == -1) {
			debug3_f("stat %s: %s", رستہ, strerror(errno));
			حرر(رستہ);
			استمر;
		}

		/*
		 * Make sure that the file is either owned by the user or by
		 * root, and make sure it is not writable by anyone but the
		 * owner.  This is to help avoid novices accidentally
		 * allowing access to their account by anyone.
		 */
		إذا (options.strict_modes &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Rhosts authentication refused for %.100s: "
			    "bad modes for %.200s", pw->pw_name, رستہ);
			auth_debug_جوڑو("Bad file modes for %.200s", رستہ);
			حرر(رستہ);
			استمر;
		}
		/*
		 * Check if we have been configured to ignore .rhosts
		 * and .shosts files.
		 */
		إذا (options.ignore_rhosts == IGNORE_RHOSTS_YES ||
		    (options.ignore_rhosts == IGNORE_RHOSTS_SHOSTS &&
		    strcmp(rhosts_files[rhosts_file_اشاریہ], ".shosts") != 0)) {
			auth_debug_جوڑو("Server has been configured to "
			    "ignore %.100s.", rhosts_files[rhosts_file_اشاریہ]);
			حرر(رستہ);
			استمر;
		}
		/* Check if authentication is permitted by the file. */
		إذا (check_rhosts_file(رستہ, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_جوڑو("Accepted by %.100s.",
			    rhosts_files[rhosts_file_اشاریہ]);
			/* Restore the privileged uid. */
			restore_uid();
			auth_debug_جوڑو("Accepted host %s ip %s client_user "
			    "%s server_user %s", hostname, ipaddr,
			    client_user, pw->pw_name);
			حرر(رستہ);
			أرجع 1;
		}
		حرر(رستہ);
	}

	/* Restore the privileged uid. */
	restore_uid();
	أرجع 0;
}
