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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <netgroup.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "uidswap.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"

/* import */
வெளி ServerOptions options;

/*
 * This function processes an rhosts-style file (.rhosts, .shosts, or
 * /etc/hosts.equiv).  This returns true if authentication can be granted
 * based on the file, and returns zero otherwise.
 */

நிலையான முழு
check_rhosts_file(மாறிலி எழுத்து *filename, மாறிலி எழுத்து *hostname,
		  மாறிலி எழுத்து *ipaddr, மாறிலி எழுத்து *client_user,
		  மாறிலி எழுத்து *server_user)
{
	FILE *f;
#define RBUFLN 1024
	எழுத்து buf[RBUFLN];/* Must not be larger than host, user, dummy below. */
	முழு fd;
	கட்டமைப்பு stat st;

	/* Open the .rhosts file, deny if unreadable */
	எனில் ((fd = open(filename, O_RDONLY|O_NONBLOCK)) == -1)
		திரும்பு 0;
	எனில் (fstat(fd, &st) == -1) {
		close(fd);
		திரும்பு 0;
	}
	எனில் (!S_ISREG(st.st_mode)) {
		logit("User %s hosts file %s is not a regular file",
		    server_user, filename);
		close(fd);
		திரும்பு 0;
	}
	unset_nonblock(fd);
	எனில் ((f = fdopen(fd, "r")) == வெற்று) {
		close(fd);
		திரும்பு 0;
	}
	போது (fgets(buf, அளவு(buf), f)) {
		/* All three must have length >= buf to avoid overflows. */
		எழுத்து hostbuf[RBUFLN], userbuf[RBUFLN], dummy[RBUFLN];
		எழுத்து *host, *user, *cp;
		முழு negated;

		க்கு (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		எனில் (*cp == '#' || *cp == '\n' || !*cp)
			தொடர்;

		/*
		 * NO_PLUS is supported at least on OSF/1.  We skip it (we
		 * don't ever support the plus syntax).
		 */
		எனில் (strncmp(cp, "NO_PLUS", 7) == 0)
			தொடர்;

		/*
		 * This should be safe because each buffer is as big as the
		 * whole string, and thus cannot be overwritten.
		 */
		தேர்வு (sscanf(buf, "%1023s %1023s %1023s", hostbuf, userbuf,
		    dummy)) {
		நிலை 0:
			auth_debug_add("Found empty line in %.100s.", filename);
			தொடர்;
		நிலை 1:
			/* Host name only. */
			strlcpy(userbuf, server_user, அளவு(userbuf));
			நிறுத்து;
		நிலை 2:
			/* Got both host and user name. */
			நிறுத்து;
		நிலை 3:
			auth_debug_add("Found garbage in %.100s.", filename);
			தொடர்;
		இயல்பு:
			/* Weird... */
			தொடர்;
		}

		host = hostbuf;
		user = userbuf;
		negated = 0;

		/* Process negated host names, or positive netgroups. */
		எனில் (host[0] == '-') {
			negated = 1;
			host++;
		} இல்லையெனில் எனில் (host[0] == '+')
			host++;

		எனில் (user[0] == '-') {
			negated = 1;
			user++;
		} இல்லையெனில் எனில் (user[0] == '+')
			user++;

		/* Check for empty host/user names (particularly '+'). */
		எனில் (!host[0] || !user[0]) {
			/* We come here if either was '+' or '-'. */
			auth_debug_add("Ignoring wild host/user names "
			    "in %.100s.", filename);
			தொடர்;
		}
		/* Verify that host name matches. */
		எனில் (host[0] == '@') {
			எனில் (!innetgr(host + 1, hostname, வெற்று, வெற்று) &&
			    !innetgr(host + 1, ipaddr, வெற்று, வெற்று))
				தொடர்;
		} இல்லையெனில் எனில் (strcasecmp(host, hostname) &&
		    strcmp(host, ipaddr) != 0)
			தொடர்;	/* Different hostname. */

		/* Verify that user name matches. */
		எனில் (user[0] == '@') {
			எனில் (!innetgr(user + 1, வெற்று, client_user, வெற்று))
				தொடர்;
		} இல்லையெனில் எனில் (strcmp(user, client_user) != 0)
			தொடர்;	/* Different username. */

		/* Found the user and host. */
		fclose(f);

		/* If the entry was negated, deny access. */
		எனில் (negated) {
			auth_debug_add("Matched negative entry in %.100s.",
			    filename);
			திரும்பு 0;
		}
		/* Accept authentication. */
		திரும்பு 1;
	}

	/* Authentication using this file denied. */
	fclose(f);
	திரும்பு 0;
}

/*
 * Tries to authenticate the user using the .shosts or .rhosts file. Returns
 * true if authentication succeeds.  If ignore_rhosts is true, only
 * /etc/hosts.equiv will be considered (.rhosts and .shosts are ignored).
 */
முழு
auth_rhosts2(கட்டமைப்பு passwd *pw, மாறிலி எழுத்து *client_user, மாறிலி எழுத்து *hostname,
    மாறிலி எழுத்து *ipaddr)
{
	எழுத்து *path = வெற்று;
	கட்டமைப்பு stat st;
	நிலையான மாறிலி எழுத்து * மாறிலி rhosts_files[] = {".shosts", ".rhosts", வெற்று};
	u_int rhosts_file_index;
	முழு r;

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
	க்கு (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		r = stat(path, &st);
		விடுவி(path);
		எனில் (r >= 0)
			நிறுத்து;
	}
	/* Switch back to privileged uid. */
	restore_uid();

	/*
	 * Deny if The user has no .shosts or .rhosts file and there
	 * are no system-wide files.
	 */
	எனில் (!rhosts_files[rhosts_file_index] &&
	    stat(_PATH_RHOSTS_EQUIV, &st) == -1 &&
	    stat(_PATH_SSH_HOSTS_EQUIV, &st) == -1) {
		debug3_f("no hosts access files exist");
		திரும்பு 0;
	}

	/*
	 * If not logging in as superuser, try /etc/hosts.equiv and
	 * shosts.equiv.
	 */
	எனில் (pw->pw_uid == 0)
		debug3_f("root user, ignoring system hosts files");
	இல்லையெனில் {
		எனில் (check_rhosts_file(_PATH_RHOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "/etc/hosts.equiv.", hostname, ipaddr);
			திரும்பு 1;
		}
		எனில் (check_rhosts_file(_PATH_SSH_HOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "%.100s.", hostname, ipaddr, _PATH_SSH_HOSTS_EQUIV);
			திரும்பு 1;
		}
	}

	/*
	 * Check that the home directory is owned by root or the user, and is
	 * not group or world writable.
	 */
	எனில் (stat(pw->pw_dir, &st) == -1) {
		logit("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		திரும்பு 0;
	}
	எனில் (options.strict_modes &&
	    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	    (st.st_mode & 022) != 0)) {
		logit("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		திரும்பு 0;
	}
	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	/* Check all .rhosts files (currently .shosts and .rhosts). */
	க்கு (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		எனில் (stat(path, &st) == -1) {
			debug3_f("stat %s: %s", path, strerror(errno));
			விடுவி(path);
			தொடர்;
		}

		/*
		 * Make sure that the file is either owned by the user or by
		 * root, and make sure it is not writable by anyone but the
		 * owner.  This is to help avoid novices accidentally
		 * allowing access to their account by anyone.
		 */
		எனில் (options.strict_modes &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Rhosts authentication refused for %.100s: "
			    "bad modes for %.200s", pw->pw_name, path);
			auth_debug_add("Bad file modes for %.200s", path);
			விடுவி(path);
			தொடர்;
		}
		/*
		 * Check if we have been configured to ignore .rhosts
		 * and .shosts files.
		 */
		எனில் (options.ignore_rhosts == IGNORE_RHOSTS_YES ||
		    (options.ignore_rhosts == IGNORE_RHOSTS_SHOSTS &&
		    strcmp(rhosts_files[rhosts_file_index], ".shosts") != 0)) {
			auth_debug_add("Server has been configured to "
			    "ignore %.100s.", rhosts_files[rhosts_file_index]);
			விடுவி(path);
			தொடர்;
		}
		/* Check if authentication is permitted by the file. */
		எனில் (check_rhosts_file(path, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted by %.100s.",
			    rhosts_files[rhosts_file_index]);
			/* Restore the privileged uid. */
			restore_uid();
			auth_debug_add("Accepted host %s ip %s client_user "
			    "%s server_user %s", hostname, ipaddr,
			    client_user, pw->pw_name);
			விடுவி(path);
			திரும்பு 1;
		}
		விடுவி(path);
	}

	/* Restore the privileged uid. */
	restore_uid();
	திரும்பு 0;
}
