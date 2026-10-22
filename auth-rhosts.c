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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <netgroup.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "uidswap.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"

/* import */
ବାହ୍ୟ ServerOptions options;

/*
 * This function processes an rhosts-style file (.rhosts, .shosts, or
 * /etc/hosts.equiv).  This returns true if authentication can be granted
 * based on the file, and returns zero otherwise.
 */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_rhosts_file(ଅଚଳ ଅକ୍ଷର *filename, ଅଚଳ ଅକ୍ଷର *hostname,
		  ଅଚଳ ଅକ୍ଷର *ipaddr, ଅଚଳ ଅକ୍ଷର *client_user,
		  ଅଚଳ ଅକ୍ଷର *server_user)
{
	FILE *f;
#define RBUFLN 1024
	ଅକ୍ଷର buf[RBUFLN];/* Must not be larger than host, user, dummy below. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;
	ସଂରଚନା stat st;

	/* Open the .rhosts file, deny if unreadable */
	ଯଦି ((fd = open(filename, O_RDONLY|O_NONBLOCK)) == -1)
		ଫେରନ୍ତୁ 0;
	ଯଦି (fstat(fd, &st) == -1) {
		close(fd);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (!S_ISREG(st.st_mode)) {
		logit("User %s hosts file %s is not a regular file",
		    server_user, filename);
		close(fd);
		ଫେରନ୍ତୁ 0;
	}
	unset_nonblock(fd);
	ଯଦି ((f = fdopen(fd, "r")) == ଖାଲି) {
		close(fd);
		ଫେରନ୍ତୁ 0;
	}
	ଯେତେବେଳେ (fgets(buf, ଆକାର(buf), f)) {
		/* All three must have length >= buf to avoid overflows. */
		ଅକ୍ଷର hostbuf[RBUFLN], userbuf[RBUFLN], dummy[RBUFLN];
		ଅକ୍ଷର *host, *user, *cp;
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା negated;

		ପାଇଁ (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		ଯଦି (*cp == '#' || *cp == '\n' || !*cp)
			ଜାରି;

		/*
		 * NO_PLUS is supported at least on OSF/1.  We skip it (we
		 * don't ever support the plus syntax).
		 */
		ଯଦି (strncmp(cp, "NO_PLUS", 7) == 0)
			ଜାରି;

		/*
		 * This should be safe because each buffer is as big as the
		 * whole string, and thus cannot be overwritten.
		 */
		ବାଛ (sscanf(buf, "%1023s %1023s %1023s", hostbuf, userbuf,
		    dummy)) {
		ସ୍ଥିତି 0:
			auth_debug_add("Found empty line in %.100s.", filename);
			ଜାରି;
		ସ୍ଥିତି 1:
			/* Host name only. */
			strlcpy(userbuf, server_user, ଆକାର(userbuf));
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 2:
			/* Got both host and user name. */
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 3:
			auth_debug_add("Found garbage in %.100s.", filename);
			ଜାରି;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			/* Weird... */
			ଜାରି;
		}

		host = hostbuf;
		user = userbuf;
		negated = 0;

		/* Process negated host names, or positive netgroups. */
		ଯଦି (host[0] == '-') {
			negated = 1;
			host++;
		} ଅନ୍ୟଥା ଯଦି (host[0] == '+')
			host++;

		ଯଦି (user[0] == '-') {
			negated = 1;
			user++;
		} ଅନ୍ୟଥା ଯଦି (user[0] == '+')
			user++;

		/* Check for empty host/user names (particularly '+'). */
		ଯଦି (!host[0] || !user[0]) {
			/* We come here if either was '+' or '-'. */
			auth_debug_add("Ignoring wild host/user names "
			    "in %.100s.", filename);
			ଜାରି;
		}
		/* Verify that host name matches. */
		ଯଦି (host[0] == '@') {
			ଯଦି (!innetgr(host + 1, hostname, ଖାଲି, ଖାଲି) &&
			    !innetgr(host + 1, ipaddr, ଖାଲି, ଖାଲି))
				ଜାରି;
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(host, hostname) &&
		    strcmp(host, ipaddr) != 0)
			ଜାରି;	/* Different hostname. */

		/* Verify that user name matches. */
		ଯଦି (user[0] == '@') {
			ଯଦି (!innetgr(user + 1, ଖାଲି, client_user, ଖାଲି))
				ଜାରି;
		} ଅନ୍ୟଥା ଯଦି (strcmp(user, client_user) != 0)
			ଜାରି;	/* Different username. */

		/* Found the user and host. */
		fclose(f);

		/* If the entry was negated, deny access. */
		ଯଦି (negated) {
			auth_debug_add("Matched negative entry in %.100s.",
			    filename);
			ଫେରନ୍ତୁ 0;
		}
		/* Accept authentication. */
		ଫେରନ୍ତୁ 1;
	}

	/* Authentication using this file denied. */
	fclose(f);
	ଫେରନ୍ତୁ 0;
}

/*
 * Tries to authenticate the user using the .shosts or .rhosts file. Returns
 * true if authentication succeeds.  If ignore_rhosts is true, only
 * /etc/hosts.equiv will be considered (.rhosts and .shosts are ignored).
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth_rhosts2(ସଂରଚନା passwd *pw, ଅଚଳ ଅକ୍ଷର *client_user, ଅଚଳ ଅକ୍ଷର *hostname,
    ଅଚଳ ଅକ୍ଷର *ipaddr)
{
	ଅକ୍ଷର *path = ଖାଲି;
	ସଂରଚନା stat st;
	ସ୍ଥିର ଅଚଳ ଅକ୍ଷର * ଅଚଳ rhosts_files[] = {".shosts", ".rhosts", ଖାଲି};
	u_int rhosts_file_index;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

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
	ପାଇଁ (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		r = stat(path, &st);
		ମୁକ୍ତ(path);
		ଯଦି (r >= 0)
			ଭାଙ୍ଗ;
	}
	/* Switch back to privileged uid. */
	restore_uid();

	/*
	 * Deny if The user has no .shosts or .rhosts file and there
	 * are no system-wide files.
	 */
	ଯଦି (!rhosts_files[rhosts_file_index] &&
	    stat(_PATH_RHOSTS_EQUIV, &st) == -1 &&
	    stat(_PATH_SSH_HOSTS_EQUIV, &st) == -1) {
		debug3_f("no hosts access files exist");
		ଫେରନ୍ତୁ 0;
	}

	/*
	 * If not logging in as superuser, try /etc/hosts.equiv and
	 * shosts.equiv.
	 */
	ଯଦି (pw->pw_uid == 0)
		debug3_f("root user, ignoring system hosts files");
	ଅନ୍ୟଥା {
		ଯଦି (check_rhosts_file(_PATH_RHOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "/etc/hosts.equiv.", hostname, ipaddr);
			ଫେରନ୍ତୁ 1;
		}
		ଯଦି (check_rhosts_file(_PATH_SSH_HOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "%.100s.", hostname, ipaddr, _PATH_SSH_HOSTS_EQUIV);
			ଫେରନ୍ତୁ 1;
		}
	}

	/*
	 * Check that the home directory is owned by root or the user, and is
	 * not group or world writable.
	 */
	ଯଦି (stat(pw->pw_dir, &st) == -1) {
		logit("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (options.strict_modes &&
	    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	    (st.st_mode & 022) != 0)) {
		logit("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		ଫେରନ୍ତୁ 0;
	}
	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	/* Check all .rhosts files (currently .shosts and .rhosts). */
	ପାଇଁ (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		ଯଦି (stat(path, &st) == -1) {
			debug3_f("stat %s: %s", path, strerror(errno));
			ମୁକ୍ତ(path);
			ଜାରି;
		}

		/*
		 * Make sure that the file is either owned by the user or by
		 * root, and make sure it is not writable by anyone but the
		 * owner.  This is to help avoid novices accidentally
		 * allowing access to their account by anyone.
		 */
		ଯଦି (options.strict_modes &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Rhosts authentication refused for %.100s: "
			    "bad modes for %.200s", pw->pw_name, path);
			auth_debug_add("Bad file modes for %.200s", path);
			ମୁକ୍ତ(path);
			ଜାରି;
		}
		/*
		 * Check if we have been configured to ignore .rhosts
		 * and .shosts files.
		 */
		ଯଦି (options.ignore_rhosts == IGNORE_RHOSTS_YES ||
		    (options.ignore_rhosts == IGNORE_RHOSTS_SHOSTS &&
		    strcmp(rhosts_files[rhosts_file_index], ".shosts") != 0)) {
			auth_debug_add("Server has been configured to "
			    "ignore %.100s.", rhosts_files[rhosts_file_index]);
			ମୁକ୍ତ(path);
			ଜାରି;
		}
		/* Check if authentication is permitted by the file. */
		ଯଦି (check_rhosts_file(path, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted by %.100s.",
			    rhosts_files[rhosts_file_index]);
			/* Restore the privileged uid. */
			restore_uid();
			auth_debug_add("Accepted host %s ip %s client_user "
			    "%s server_user %s", hostname, ipaddr,
			    client_user, pw->pw_name);
			ମୁକ୍ତ(path);
			ଫେରନ୍ତୁ 1;
		}
		ମୁକ୍ତ(path);
	}

	/* Restore the privileged uid. */
	restore_uid();
	ଫେରନ୍ତୁ 0;
}
