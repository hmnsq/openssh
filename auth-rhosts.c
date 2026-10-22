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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <netgroup.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "packet.h"
#అన్తర్భావ "uidswap.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"

/* import */
బాహ్య ServerOptions options;

/*
 * This function processes an rhosts-style file (.rhosts, .shosts, or
 * /etc/hosts.equiv).  This returns true if authentication can be granted
 * based on the file, and returns zero otherwise.
 */

స్థిర పూర్ణాంకం
check_rhosts_file(స్థిరరాశి అక్షరం *filename, స్థిరరాశి అక్షరం *hostname,
		  స్థిరరాశి అక్షరం *ipaddr, స్థిరరాశి అక్షరం *client_user,
		  స్థిరరాశి అక్షరం *server_user)
{
	FILE *f;
#నిర్వచించు RBUFLN 1024
	అక్షరం buf[RBUFLN];/* Must not be larger than host, user, dummy below. */
	పూర్ణాంకం fd;
	నిర్మాణం stat st;

	/* Open the .rhosts file, deny if unreadable */
	ఒకవేళ ((fd = open(filename, O_RDONLY|O_NONBLOCK)) == -1)
		తిరిగి 0;
	ఒకవేళ (fstat(fd, &st) == -1) {
		close(fd);
		తిరిగి 0;
	}
	ఒకవేళ (!S_ISREG(st.st_mode)) {
		logit("User %s hosts file %s is not a regular file",
		    server_user, filename);
		close(fd);
		తిరిగి 0;
	}
	unset_nonblock(fd);
	ఒకవేళ ((f = fdopen(fd, "r")) == ఖాళీ) {
		close(fd);
		తిరిగి 0;
	}
	అయితే (fgets(buf, పరిమాణం(buf), f)) {
		/* All three must have length >= buf to avoid overflows. */
		అక్షరం hostbuf[RBUFLN], userbuf[RBUFLN], dummy[RBUFLN];
		అక్షరం *host, *user, *cp;
		పూర్ణాంకం negated;

		కొరకు (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		ఒకవేళ (*cp == '#' || *cp == '\n' || !*cp)
			కొనసాగు;

		/*
		 * NO_PLUS is supported at least on OSF/1.  We skip it (we
		 * don't ever support the plus syntax).
		 */
		ఒకవేళ (అక్షరశ్రేణి_పోలిక(cp, "NO_PLUS", 7) == 0)
			కొనసాగు;

		/*
		 * This should be safe because each buffer is as big as the
		 * whole string, and thus cannot be overwritten.
		 */
		ఎంపిక (అక్షరశ్రేణి_చదువు(buf, "%1023s %1023s %1023s", hostbuf, userbuf,
		    dummy)) {
		స్థితి 0:
			auth_debug_కూడు("Found empty line in %.100s.", filename);
			కొనసాగు;
		స్థితి 1:
			/* Host name only. */
			strlcpy(userbuf, server_user, పరిమాణం(userbuf));
			ఆపు;
		స్థితి 2:
			/* Got both host and user name. */
			ఆపు;
		స్థితి 3:
			auth_debug_కూడు("Found garbage in %.100s.", filename);
			కొనసాగు;
		అప్రమేయ:
			/* Weird... */
			కొనసాగు;
		}

		host = hostbuf;
		user = userbuf;
		negated = 0;

		/* Process negated host names, or positive netgroups. */
		ఒకవేళ (host[0] == '-') {
			negated = 1;
			host++;
		} లేకపోతే ఒకవేళ (host[0] == '+')
			host++;

		ఒకవేళ (user[0] == '-') {
			negated = 1;
			user++;
		} లేకపోతే ఒకవేళ (user[0] == '+')
			user++;

		/* Check for empty host/user names (particularly '+'). */
		ఒకవేళ (!host[0] || !user[0]) {
			/* We come here if either was '+' or '-'. */
			auth_debug_కూడు("Ignoring wild host/user names "
			    "in %.100s.", filename);
			కొనసాగు;
		}
		/* Verify that host name matches. */
		ఒకవేళ (host[0] == '@') {
			ఒకవేళ (!innetgr(host + 1, hostname, ఖాళీ, ఖాళీ) &&
			    !innetgr(host + 1, ipaddr, ఖాళీ, ఖాళీ))
				కొనసాగు;
		} లేకపోతే ఒకవేళ (strcasecmp(host, hostname) &&
		    strcmp(host, ipaddr) != 0)
			కొనసాగు;	/* Different hostname. */

		/* Verify that user name matches. */
		ఒకవేళ (user[0] == '@') {
			ఒకవేళ (!innetgr(user + 1, ఖాళీ, client_user, ఖాళీ))
				కొనసాగు;
		} లేకపోతే ఒకవేళ (strcmp(user, client_user) != 0)
			కొనసాగు;	/* Different username. */

		/* Found the user and host. */
		fclose(f);

		/* If the entry was negated, deny access. */
		ఒకవేళ (negated) {
			auth_debug_కూడు("Matched negative entry in %.100s.",
			    filename);
			తిరిగి 0;
		}
		/* Accept authentication. */
		తిరిగి 1;
	}

	/* Authentication using this file denied. */
	fclose(f);
	తిరిగి 0;
}

/*
 * Tries to authenticate the user using the .shosts or .rhosts file. Returns
 * true if authentication succeeds.  If ignore_rhosts is true, only
 * /etc/hosts.equiv will be considered (.rhosts and .shosts are ignored).
 */
పూర్ణాంకం
auth_rhosts2(నిర్మాణం passwd *pw, స్థిరరాశి అక్షరం *client_user, స్థిరరాశి అక్షరం *hostname,
    స్థిరరాశి అక్షరం *ipaddr)
{
	అక్షరం *మార్గం = ఖాళీ;
	నిర్మాణం stat st;
	స్థిర స్థిరరాశి అక్షరం * స్థిరరాశి rhosts_files[] = {".shosts", ".rhosts", ఖాళీ};
	u_int rhosts_file_సూచీ;
	పూర్ణాంకం r;

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
	కొరకు (rhosts_file_సూచీ = 0; rhosts_files[rhosts_file_సూచీ];
	    rhosts_file_సూచీ++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&మార్గం, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_సూచీ]);
		r = stat(మార్గం, &st);
		విడుదల(మార్గం);
		ఒకవేళ (r >= 0)
			ఆపు;
	}
	/* Switch back to privileged uid. */
	restore_uid();

	/*
	 * Deny if The user has no .shosts or .rhosts file and there
	 * are no system-wide files.
	 */
	ఒకవేళ (!rhosts_files[rhosts_file_సూచీ] &&
	    stat(మార్గం_RHOSTS_EQUIV, &st) == -1 &&
	    stat(మార్గం_SSH_HOSTS_EQUIV, &st) == -1) {
		debug3_f("no hosts access files exist");
		తిరిగి 0;
	}

	/*
	 * If not logging in as superuser, try /etc/hosts.equiv and
	 * shosts.equiv.
	 */
	ఒకవేళ (pw->pw_uid == 0)
		debug3_f("root user, ignoring system hosts files");
	లేకపోతే {
		ఒకవేళ (check_rhosts_file(మార్గం_RHOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_కూడు("Accepted for %.100s [%.100s] by "
			    "/etc/hosts.equiv.", hostname, ipaddr);
			తిరిగి 1;
		}
		ఒకవేళ (check_rhosts_file(మార్గం_SSH_HOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_కూడు("Accepted for %.100s [%.100s] by "
			    "%.100s.", hostname, ipaddr, మార్గం_SSH_HOSTS_EQUIV);
			తిరిగి 1;
		}
	}

	/*
	 * Check that the home directory is owned by root or the user, and is
	 * not group or world writable.
	 */
	ఒకవేళ (stat(pw->pw_dir, &st) == -1) {
		logit("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		auth_debug_కూడు("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		తిరిగి 0;
	}
	ఒకవేళ (options.strict_modes &&
	    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	    (st.st_mode & 022) != 0)) {
		logit("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		auth_debug_కూడు("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		తిరిగి 0;
	}
	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	/* Check all .rhosts files (currently .shosts and .rhosts). */
	కొరకు (rhosts_file_సూచీ = 0; rhosts_files[rhosts_file_సూచీ];
	    rhosts_file_సూచీ++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&మార్గం, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_సూచీ]);
		ఒకవేళ (stat(మార్గం, &st) == -1) {
			debug3_f("stat %s: %s", మార్గం, strerror(errno));
			విడుదల(మార్గం);
			కొనసాగు;
		}

		/*
		 * Make sure that the file is either owned by the user or by
		 * root, and make sure it is not writable by anyone but the
		 * owner.  This is to help avoid novices accidentally
		 * allowing access to their account by anyone.
		 */
		ఒకవేళ (options.strict_modes &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Rhosts authentication refused for %.100s: "
			    "bad modes for %.200s", pw->pw_name, మార్గం);
			auth_debug_కూడు("Bad file modes for %.200s", మార్గం);
			విడుదల(మార్గం);
			కొనసాగు;
		}
		/*
		 * Check if we have been configured to ignore .rhosts
		 * and .shosts files.
		 */
		ఒకవేళ (options.ignore_rhosts == IGNORE_RHOSTS_YES ||
		    (options.ignore_rhosts == IGNORE_RHOSTS_SHOSTS &&
		    strcmp(rhosts_files[rhosts_file_సూచీ], ".shosts") != 0)) {
			auth_debug_కూడు("Server has been configured to "
			    "ignore %.100s.", rhosts_files[rhosts_file_సూచీ]);
			విడుదల(మార్గం);
			కొనసాగు;
		}
		/* Check if authentication is permitted by the file. */
		ఒకవేళ (check_rhosts_file(మార్గం, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_కూడు("Accepted by %.100s.",
			    rhosts_files[rhosts_file_సూచీ]);
			/* Restore the privileged uid. */
			restore_uid();
			auth_debug_కూడు("Accepted host %s ip %s client_user "
			    "%s server_user %s", hostname, ipaddr,
			    client_user, pw->pw_name);
			విడుదల(మార్గం);
			తిరిగి 1;
		}
		విడుదల(మార్గం);
	}

	/* Restore the privileged uid. */
	restore_uid();
	తిరిగి 0;
}
