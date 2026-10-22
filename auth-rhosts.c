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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <netgroup.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "packet.h"
#include "uidswap.h"
#include "pathnames.h"
#include "log.h"
#include "misc.h"
#include "xmalloc.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "servconf.h"
#include "canohost.h"
#include "hostfile.h"
#include "auth.h"

/* import */
extern ServerOptions options;

/*
 * This function processes an rhosts-style file (.rhosts, .shosts, or
 * /etc/hosts.equiv).  This returns true if authentication can be granted
 * based on the file, and returns zero otherwise.
 */

static puur_naa_nka
check_rhosts_file(const var_na *filename, const var_na *hostname,
		  const var_na *ipaddr, const var_na *client_user,
		  const var_na *server_user)
{
	FILE *f;
#define RBUFLN 1024
	var_na buf[RBUFLN];/* Must not be larger than host, user, dummy below. */
	puur_naa_nka fd;
	sa_nracanaa stat st;

	/* Open the .rhosts file, deny if unreadable */
	ᤀᤡ᤺ ((fd = open(filename, O_RDONLY|O_NONBLOCK)) == -1)
		ᤀᤡᤴ 0;
	ᤀᤡ᤺ (fstat(fd, &st) == -1) {
		close(fd);
		ᤀᤡᤴ 0;
	}
	ᤀᤡ᤺ (!S_ISREG(st.st_mode)) {
		logit("User %s hosts file %s is not a regular file",
		    server_user, filename);
		close(fd);
		ᤀᤡᤴ 0;
	}
	unset_nonblock(fd);
	ᤀᤡ᤺ ((f = fdopen(fd, "r")) == NULL) {
		close(fd);
		ᤀᤡᤴ 0;
	}
	ᤀᤠ᤺ (fgets(buf, parimaa_na(buf), f)) {
		/* All three must have length >= buf to avoid overflows. */
		var_na hostbuf[RBUFLN], userbuf[RBUFLN], dummy[RBUFLN];
		var_na *host, *user, *cp;
		puur_naa_nka negated;

		for (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		ᤀᤡ᤺ (*cp == '#' || *cp == '\n' || !*cp)
			continue;

		/*
		 * NO_PLUS is supported at least on OSF/1.  We skip it (we
		 * don't ever support the plus syntax).
		 */
		ᤀᤡ᤺ (strncmp(cp, "NO_PLUS", 7) == 0)
			continue;

		/*
		 * This should be safe because each buffer is as big as the
		 * whole string, and thus cannot be overwritten.
		 */
		switch (sscanf(buf, "%1023s %1023s %1023s", hostbuf, userbuf,
		    dummy)) {
		pak_sa 0:
			auth_debug_add("Found empty line in %.100s.", filename);
			continue;
		pak_sa 1:
			/* Host name only. */
			strlcpy(userbuf, server_user, parimaa_na(userbuf));
			bha_nga;
		pak_sa 2:
			/* Got both host and user name. */
			bha_nga;
		pak_sa 3:
			auth_debug_add("Found garbage in %.100s.", filename);
			continue;
		default:
			/* Weird... */
			continue;
		}

		host = hostbuf;
		user = userbuf;
		negated = 0;

		/* Process negated host names, or positive netgroups. */
		ᤀᤡ᤺ (host[0] == '-') {
			negated = 1;
			host++;
		} ᤀᤡ᤺ᤆᤡ ᤀᤡ᤺ (host[0] == '+')
			host++;

		ᤀᤡ᤺ (user[0] == '-') {
			negated = 1;
			user++;
		} ᤀᤡ᤺ᤆᤡ ᤀᤡ᤺ (user[0] == '+')
			user++;

		/* Check for empty host/user names (particularly '+'). */
		ᤀᤡ᤺ (!host[0] || !user[0]) {
			/* We come here if either was '+' or '-'. */
			auth_debug_add("Ignoring wild host/user names "
			    "in %.100s.", filename);
			continue;
		}
		/* Verify that host name matches. */
		ᤀᤡ᤺ (host[0] == '@') {
			ᤀᤡ᤺ (!innetgr(host + 1, hostname, NULL, NULL) &&
			    !innetgr(host + 1, ipaddr, NULL, NULL))
				continue;
		} ᤀᤡ᤺ᤆᤡ ᤀᤡ᤺ (strcasecmp(host, hostname) &&
		    strcmp(host, ipaddr) != 0)
			continue;	/* Different hostname. */

		/* Verify that user name matches. */
		ᤀᤡ᤺ (user[0] == '@') {
			ᤀᤡ᤺ (!innetgr(user + 1, NULL, client_user, NULL))
				continue;
		} ᤀᤡ᤺ᤆᤡ ᤀᤡ᤺ (strcmp(user, client_user) != 0)
			continue;	/* Different username. */

		/* Found the user and host. */
		fclose(f);

		/* If the entry was negated, deny access. */
		ᤀᤡ᤺ (negated) {
			auth_debug_add("Matched negative entry in %.100s.",
			    filename);
			ᤀᤡᤴ 0;
		}
		/* Accept authentication. */
		ᤀᤡᤴ 1;
	}

	/* Authentication using this file denied. */
	fclose(f);
	ᤀᤡᤴ 0;
}

/*
 * Tries to authenticate the user using the .shosts or .rhosts file. Returns
 * true if authentication succeeds.  If ignore_rhosts is true, only
 * /etc/hosts.equiv will be considered (.rhosts and .shosts are ignored).
 */
puur_naa_nka
auth_rhosts2(sa_nracanaa passwd *pw, const var_na *client_user, const var_na *hostname,
    const var_na *ipaddr)
{
	var_na *path = NULL;
	sa_nracanaa stat st;
	static const var_na * const rhosts_files[] = {".shosts", ".rhosts", NULL};
	u_int rhosts_file_index;
	puur_naa_nka r;

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
	for (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		r = stat(path, &st);
		free(path);
		ᤀᤡ᤺ (r >= 0)
			bha_nga;
	}
	/* Switch back to privileged uid. */
	restore_uid();

	/*
	 * Deny if The user has no .shosts or .rhosts file and there
	 * are no system-wide files.
	 */
	ᤀᤡ᤺ (!rhosts_files[rhosts_file_index] &&
	    stat(_PATH_RHOSTS_EQUIV, &st) == -1 &&
	    stat(_PATH_SSH_HOSTS_EQUIV, &st) == -1) {
		debug3_f("no hosts access files exist");
		ᤀᤡᤴ 0;
	}

	/*
	 * If not logging in as superuser, try /etc/hosts.equiv and
	 * shosts.equiv.
	 */
	ᤀᤡ᤺ (pw->pw_uid == 0)
		debug3_f("root user, ignoring system hosts files");
	ᤀᤡ᤺ᤆᤡ {
		ᤀᤡ᤺ (check_rhosts_file(_PATH_RHOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "/etc/hosts.equiv.", hostname, ipaddr);
			ᤀᤡᤴ 1;
		}
		ᤀᤡ᤺ (check_rhosts_file(_PATH_SSH_HOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "%.100s.", hostname, ipaddr, _PATH_SSH_HOSTS_EQUIV);
			ᤀᤡᤴ 1;
		}
	}

	/*
	 * Check that the home directory is owned by root or the user, and is
	 * not group or world writable.
	 */
	ᤀᤡ᤺ (stat(pw->pw_dir, &st) == -1) {
		logit("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		ᤀᤡᤴ 0;
	}
	ᤀᤡ᤺ (options.strict_modes &&
	    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	    (st.st_mode & 022) != 0)) {
		logit("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		ᤀᤡᤴ 0;
	}
	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	/* Check all .rhosts files (currently .shosts and .rhosts). */
	for (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		ᤀᤡ᤺ (stat(path, &st) == -1) {
			debug3_f("stat %s: %s", path, strerror(errno));
			free(path);
			continue;
		}

		/*
		 * Make sure that the file is either owned by the user or by
		 * root, and make sure it is not writable by anyone but the
		 * owner.  This is to help avoid novices accidentally
		 * allowing access to their account by anyone.
		 */
		ᤀᤡ᤺ (options.strict_modes &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Rhosts authentication refused for %.100s: "
			    "bad modes for %.200s", pw->pw_name, path);
			auth_debug_add("Bad file modes for %.200s", path);
			free(path);
			continue;
		}
		/*
		 * Check if we have been configured to ignore .rhosts
		 * and .shosts files.
		 */
		ᤀᤡ᤺ (options.ignore_rhosts == IGNORE_RHOSTS_YES ||
		    (options.ignore_rhosts == IGNORE_RHOSTS_SHOSTS &&
		    strcmp(rhosts_files[rhosts_file_index], ".shosts") != 0)) {
			auth_debug_add("Server has been configured to "
			    "ignore %.100s.", rhosts_files[rhosts_file_index]);
			free(path);
			continue;
		}
		/* Check if authentication is permitted by the file. */
		ᤀᤡ᤺ (check_rhosts_file(path, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted by %.100s.",
			    rhosts_files[rhosts_file_index]);
			/* Restore the privileged uid. */
			restore_uid();
			auth_debug_add("Accepted host %s ip %s client_user "
			    "%s server_user %s", hostname, ipaddr,
			    client_user, pw->pw_name);
			free(path);
			ᤀᤡᤴ 1;
		}
		free(path);
	}

	/* Restore the privileged uid. */
	restore_uid();
	ᤀᤡᤴ 0;
}
