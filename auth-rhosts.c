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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <netgroup.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "uidswap.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"

/* import */
બાહ્ય ServerOptions options;

/*
 * This function processes an rhosts-style file (.rhosts, .shosts, or
 * /etc/hosts.equiv).  This returns true if authentication can be granted
 * based on the file, and returns zero otherwise.
 */

સ્થિર પૂર્ણાંક
check_rhosts_file(અચલ અક્ષર *filename, અચલ અક્ષર *hostname,
		  અચલ અક્ષર *ipaddr, અચલ અક્ષર *client_user,
		  અચલ અક્ષર *server_user)
{
	FILE *f;
#define RBUFLN 1024
	અક્ષર buf[RBUFLN];/* Must not be larger than host, user, dummy below. */
	પૂર્ણાંક fd;
	સંરચના stat st;

	/* Open the .rhosts file, deny if unreadable */
	જો ((fd = open(filename, O_RDONLY|O_NONBLOCK)) == -1)
		પાછા 0;
	જો (fstat(fd, &st) == -1) {
		close(fd);
		પાછા 0;
	}
	જો (!S_ISREG(st.st_mode)) {
		logit("User %s hosts file %s is not a regular file",
		    server_user, filename);
		close(fd);
		પાછા 0;
	}
	unset_nonblock(fd);
	જો ((f = fdopen(fd, "r")) == ખાલી) {
		close(fd);
		પાછા 0;
	}
	જ્યારે (fgets(buf, કદ(buf), f)) {
		/* All three must have length >= buf to avoid overflows. */
		અક્ષર hostbuf[RBUFLN], userbuf[RBUFLN], dummy[RBUFLN];
		અક્ષર *host, *user, *cp;
		પૂર્ણાંક negated;

		માટે (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		જો (*cp == '#' || *cp == '\n' || !*cp)
			ચાલુ;

		/*
		 * NO_PLUS is supported at least on OSF/1.  We skip it (we
		 * don't ever support the plus syntax).
		 */
		જો (strncmp(cp, "NO_PLUS", 7) == 0)
			ચાલુ;

		/*
		 * This should be safe because each buffer is as big as the
		 * whole string, and thus cannot be overwritten.
		 */
		પસંદગી (sscanf(buf, "%1023s %1023s %1023s", hostbuf, userbuf,
		    dummy)) {
		સ્થિતિ 0:
			auth_debug_add("Found empty line in %.100s.", filename);
			ચાલુ;
		સ્થિતિ 1:
			/* Host name only. */
			strlcpy(userbuf, server_user, કદ(userbuf));
			તોડો;
		સ્થિતિ 2:
			/* Got both host and user name. */
			તોડો;
		સ્થિતિ 3:
			auth_debug_add("Found garbage in %.100s.", filename);
			ચાલુ;
		મૂળભૂત:
			/* Weird... */
			ચાલુ;
		}

		host = hostbuf;
		user = userbuf;
		negated = 0;

		/* Process negated host names, or positive netgroups. */
		જો (host[0] == '-') {
			negated = 1;
			host++;
		} નહીંતર જો (host[0] == '+')
			host++;

		જો (user[0] == '-') {
			negated = 1;
			user++;
		} નહીંતર જો (user[0] == '+')
			user++;

		/* Check for empty host/user names (particularly '+'). */
		જો (!host[0] || !user[0]) {
			/* We come here if either was '+' or '-'. */
			auth_debug_add("Ignoring wild host/user names "
			    "in %.100s.", filename);
			ચાલુ;
		}
		/* Verify that host name matches. */
		જો (host[0] == '@') {
			જો (!innetgr(host + 1, hostname, ખાલી, ખાલી) &&
			    !innetgr(host + 1, ipaddr, ખાલી, ખાલી))
				ચાલુ;
		} નહીંતર જો (strcasecmp(host, hostname) &&
		    strcmp(host, ipaddr) != 0)
			ચાલુ;	/* Different hostname. */

		/* Verify that user name matches. */
		જો (user[0] == '@') {
			જો (!innetgr(user + 1, ખાલી, client_user, ખાલી))
				ચાલુ;
		} નહીંતર જો (strcmp(user, client_user) != 0)
			ચાલુ;	/* Different username. */

		/* Found the user and host. */
		fclose(f);

		/* If the entry was negated, deny access. */
		જો (negated) {
			auth_debug_add("Matched negative entry in %.100s.",
			    filename);
			પાછા 0;
		}
		/* Accept authentication. */
		પાછા 1;
	}

	/* Authentication using this file denied. */
	fclose(f);
	પાછા 0;
}

/*
 * Tries to authenticate the user using the .shosts or .rhosts file. Returns
 * true if authentication succeeds.  If ignore_rhosts is true, only
 * /etc/hosts.equiv will be considered (.rhosts and .shosts are ignored).
 */
પૂર્ણાંક
auth_rhosts2(સંરચના passwd *pw, અચલ અક્ષર *client_user, અચલ અક્ષર *hostname,
    અચલ અક્ષર *ipaddr)
{
	અક્ષર *path = ખાલી;
	સંરચના stat st;
	સ્થિર અચલ અક્ષર * અચલ rhosts_files[] = {".shosts", ".rhosts", ખાલી};
	u_int rhosts_file_index;
	પૂર્ણાંક r;

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
	માટે (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		r = stat(path, &st);
		મુક્ત(path);
		જો (r >= 0)
			તોડો;
	}
	/* Switch back to privileged uid. */
	restore_uid();

	/*
	 * Deny if The user has no .shosts or .rhosts file and there
	 * are no system-wide files.
	 */
	જો (!rhosts_files[rhosts_file_index] &&
	    stat(_PATH_RHOSTS_EQUIV, &st) == -1 &&
	    stat(_PATH_SSH_HOSTS_EQUIV, &st) == -1) {
		debug3_f("no hosts access files exist");
		પાછા 0;
	}

	/*
	 * If not logging in as superuser, try /etc/hosts.equiv and
	 * shosts.equiv.
	 */
	જો (pw->pw_uid == 0)
		debug3_f("root user, ignoring system hosts files");
	નહીંતર {
		જો (check_rhosts_file(_PATH_RHOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "/etc/hosts.equiv.", hostname, ipaddr);
			પાછા 1;
		}
		જો (check_rhosts_file(_PATH_SSH_HOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "%.100s.", hostname, ipaddr, _PATH_SSH_HOSTS_EQUIV);
			પાછા 1;
		}
	}

	/*
	 * Check that the home directory is owned by root or the user, and is
	 * not group or world writable.
	 */
	જો (stat(pw->pw_dir, &st) == -1) {
		logit("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		પાછા 0;
	}
	જો (options.strict_modes &&
	    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	    (st.st_mode & 022) != 0)) {
		logit("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		પાછા 0;
	}
	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	/* Check all .rhosts files (currently .shosts and .rhosts). */
	માટે (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		જો (stat(path, &st) == -1) {
			debug3_f("stat %s: %s", path, strerror(errno));
			મુક્ત(path);
			ચાલુ;
		}

		/*
		 * Make sure that the file is either owned by the user or by
		 * root, and make sure it is not writable by anyone but the
		 * owner.  This is to help avoid novices accidentally
		 * allowing access to their account by anyone.
		 */
		જો (options.strict_modes &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Rhosts authentication refused for %.100s: "
			    "bad modes for %.200s", pw->pw_name, path);
			auth_debug_add("Bad file modes for %.200s", path);
			મુક્ત(path);
			ચાલુ;
		}
		/*
		 * Check if we have been configured to ignore .rhosts
		 * and .shosts files.
		 */
		જો (options.ignore_rhosts == IGNORE_RHOSTS_YES ||
		    (options.ignore_rhosts == IGNORE_RHOSTS_SHOSTS &&
		    strcmp(rhosts_files[rhosts_file_index], ".shosts") != 0)) {
			auth_debug_add("Server has been configured to "
			    "ignore %.100s.", rhosts_files[rhosts_file_index]);
			મુક્ત(path);
			ચાલુ;
		}
		/* Check if authentication is permitted by the file. */
		જો (check_rhosts_file(path, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted by %.100s.",
			    rhosts_files[rhosts_file_index]);
			/* Restore the privileged uid. */
			restore_uid();
			auth_debug_add("Accepted host %s ip %s client_user "
			    "%s server_user %s", hostname, ipaddr,
			    client_user, pw->pw_name);
			મુક્ત(path);
			પાછા 1;
		}
		મુક્ત(path);
	}

	/* Restore the privileged uid. */
	restore_uid();
	પાછા 0;
}
