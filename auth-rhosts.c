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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <netgroup.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "uidswap.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"

/* import */
ബാഹ്യ ServerOptions options;

/*
 * This function processes an rhosts-style file (.rhosts, .shosts, or
 * /etc/hosts.equiv).  This returns true if authentication can be granted
 * based on the file, and returns zero otherwise.
 */

സ്ഥിതം പൂർണ്ണസംഖ്യ
check_rhosts_file(സ്ഥിരം അക്ഷരം *filename, സ്ഥിരം അക്ഷരം *hostname,
		  സ്ഥിരം അക്ഷരം *ipaddr, സ്ഥിരം അക്ഷരം *client_user,
		  സ്ഥിരം അക്ഷരം *server_user)
{
	FILE *f;
#define RBUFLN 1024
	അക്ഷരം buf[RBUFLN];/* Must not be larger than host, user, dummy below. */
	പൂർണ്ണസംഖ്യ fd;
	ഘടന stat st;

	/* Open the .rhosts file, deny if unreadable */
	എങ്കിൽ ((fd = open(filename, O_RDONLY|O_NONBLOCK)) == -1)
		തിരികെ 0;
	എങ്കിൽ (fstat(fd, &st) == -1) {
		close(fd);
		തിരികെ 0;
	}
	എങ്കിൽ (!S_ISREG(st.st_mode)) {
		logit("User %s hosts file %s is not a regular file",
		    server_user, filename);
		close(fd);
		തിരികെ 0;
	}
	unset_nonblock(fd);
	എങ്കിൽ ((f = fdopen(fd, "r")) == ശൂന്യ) {
		close(fd);
		തിരികെ 0;
	}
	ആകുമ്പോൾ (fgets(buf, വലുപ്പം(buf), f)) {
		/* All three must have length >= buf to avoid overflows. */
		അക്ഷരം hostbuf[RBUFLN], userbuf[RBUFLN], dummy[RBUFLN];
		അക്ഷരം *host, *user, *cp;
		പൂർണ്ണസംഖ്യ negated;

		വേണ്ടി (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		എങ്കിൽ (*cp == '#' || *cp == '\n' || !*cp)
			തുടരുക;

		/*
		 * NO_PLUS is supported at least on OSF/1.  We skip it (we
		 * don't ever support the plus syntax).
		 */
		എങ്കിൽ (strncmp(cp, "NO_PLUS", 7) == 0)
			തുടരുക;

		/*
		 * This should be safe because each buffer is as big as the
		 * whole string, and thus cannot be overwritten.
		 */
		തിരഞ്ഞെടുപ്പ് (sscanf(buf, "%1023s %1023s %1023s", hostbuf, userbuf,
		    dummy)) {
		അവസ്ഥ 0:
			auth_debug_add("Found empty line in %.100s.", filename);
			തുടരുക;
		അവസ്ഥ 1:
			/* Host name only. */
			strlcpy(userbuf, server_user, വലുപ്പം(userbuf));
			നിർത്തുക;
		അവസ്ഥ 2:
			/* Got both host and user name. */
			നിർത്തുക;
		അവസ്ഥ 3:
			auth_debug_add("Found garbage in %.100s.", filename);
			തുടരുക;
		സ്ഥിരസ്ഥിതി:
			/* Weird... */
			തുടരുക;
		}

		host = hostbuf;
		user = userbuf;
		negated = 0;

		/* Process negated host names, or positive netgroups. */
		എങ്കിൽ (host[0] == '-') {
			negated = 1;
			host++;
		} അല്ലെങ്കിൽ എങ്കിൽ (host[0] == '+')
			host++;

		എങ്കിൽ (user[0] == '-') {
			negated = 1;
			user++;
		} അല്ലെങ്കിൽ എങ്കിൽ (user[0] == '+')
			user++;

		/* Check for empty host/user names (particularly '+'). */
		എങ്കിൽ (!host[0] || !user[0]) {
			/* We come here if either was '+' or '-'. */
			auth_debug_add("Ignoring wild host/user names "
			    "in %.100s.", filename);
			തുടരുക;
		}
		/* Verify that host name matches. */
		എങ്കിൽ (host[0] == '@') {
			എങ്കിൽ (!innetgr(host + 1, hostname, ശൂന്യ, ശൂന്യ) &&
			    !innetgr(host + 1, ipaddr, ശൂന്യ, ശൂന്യ))
				തുടരുക;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(host, hostname) &&
		    strcmp(host, ipaddr) != 0)
			തുടരുക;	/* Different hostname. */

		/* Verify that user name matches. */
		എങ്കിൽ (user[0] == '@') {
			എങ്കിൽ (!innetgr(user + 1, ശൂന്യ, client_user, ശൂന്യ))
				തുടരുക;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(user, client_user) != 0)
			തുടരുക;	/* Different username. */

		/* Found the user and host. */
		fclose(f);

		/* If the entry was negated, deny access. */
		എങ്കിൽ (negated) {
			auth_debug_add("Matched negative entry in %.100s.",
			    filename);
			തിരികെ 0;
		}
		/* Accept authentication. */
		തിരികെ 1;
	}

	/* Authentication using this file denied. */
	fclose(f);
	തിരികെ 0;
}

/*
 * Tries to authenticate the user using the .shosts or .rhosts file. Returns
 * true if authentication succeeds.  If ignore_rhosts is true, only
 * /etc/hosts.equiv will be considered (.rhosts and .shosts are ignored).
 */
പൂർണ്ണസംഖ്യ
auth_rhosts2(ഘടന passwd *pw, സ്ഥിരം അക്ഷരം *client_user, സ്ഥിരം അക്ഷരം *hostname,
    സ്ഥിരം അക്ഷരം *ipaddr)
{
	അക്ഷരം *path = ശൂന്യ;
	ഘടന stat st;
	സ്ഥിതം സ്ഥിരം അക്ഷരം * സ്ഥിരം rhosts_files[] = {".shosts", ".rhosts", ശൂന്യ};
	u_int rhosts_file_index;
	പൂർണ്ണസംഖ്യ r;

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
	വേണ്ടി (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		r = stat(path, &st);
		സ്വതന്ത്രം(path);
		എങ്കിൽ (r >= 0)
			നിർത്തുക;
	}
	/* Switch back to privileged uid. */
	restore_uid();

	/*
	 * Deny if The user has no .shosts or .rhosts file and there
	 * are no system-wide files.
	 */
	എങ്കിൽ (!rhosts_files[rhosts_file_index] &&
	    stat(_PATH_RHOSTS_EQUIV, &st) == -1 &&
	    stat(_PATH_SSH_HOSTS_EQUIV, &st) == -1) {
		debug3_f("no hosts access files exist");
		തിരികെ 0;
	}

	/*
	 * If not logging in as superuser, try /etc/hosts.equiv and
	 * shosts.equiv.
	 */
	എങ്കിൽ (pw->pw_uid == 0)
		debug3_f("root user, ignoring system hosts files");
	അല്ലെങ്കിൽ {
		എങ്കിൽ (check_rhosts_file(_PATH_RHOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "/etc/hosts.equiv.", hostname, ipaddr);
			തിരികെ 1;
		}
		എങ്കിൽ (check_rhosts_file(_PATH_SSH_HOSTS_EQUIV, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted for %.100s [%.100s] by "
			    "%.100s.", hostname, ipaddr, _PATH_SSH_HOSTS_EQUIV);
			തിരികെ 1;
		}
	}

	/*
	 * Check that the home directory is owned by root or the user, and is
	 * not group or world writable.
	 */
	എങ്കിൽ (stat(pw->pw_dir, &st) == -1) {
		logit("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "no home directory %.200s", pw->pw_name, pw->pw_dir);
		തിരികെ 0;
	}
	എങ്കിൽ (options.strict_modes &&
	    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	    (st.st_mode & 022) != 0)) {
		logit("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		auth_debug_add("Rhosts authentication refused for %.100s: "
		    "bad ownership or modes for home directory.", pw->pw_name);
		തിരികെ 0;
	}
	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	/* Check all .rhosts files (currently .shosts and .rhosts). */
	വേണ്ടി (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
	    rhosts_file_index++) {
		/* Check users .rhosts or .shosts. */
		xasprintf(&path, "%s/%s",
		    pw->pw_dir, rhosts_files[rhosts_file_index]);
		എങ്കിൽ (stat(path, &st) == -1) {
			debug3_f("stat %s: %s", path, strerror(errno));
			സ്വതന്ത്രം(path);
			തുടരുക;
		}

		/*
		 * Make sure that the file is either owned by the user or by
		 * root, and make sure it is not writable by anyone but the
		 * owner.  This is to help avoid novices accidentally
		 * allowing access to their account by anyone.
		 */
		എങ്കിൽ (options.strict_modes &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Rhosts authentication refused for %.100s: "
			    "bad modes for %.200s", pw->pw_name, path);
			auth_debug_add("Bad file modes for %.200s", path);
			സ്വതന്ത്രം(path);
			തുടരുക;
		}
		/*
		 * Check if we have been configured to ignore .rhosts
		 * and .shosts files.
		 */
		എങ്കിൽ (options.ignore_rhosts == IGNORE_RHOSTS_YES ||
		    (options.ignore_rhosts == IGNORE_RHOSTS_SHOSTS &&
		    strcmp(rhosts_files[rhosts_file_index], ".shosts") != 0)) {
			auth_debug_add("Server has been configured to "
			    "ignore %.100s.", rhosts_files[rhosts_file_index]);
			സ്വതന്ത്രം(path);
			തുടരുക;
		}
		/* Check if authentication is permitted by the file. */
		എങ്കിൽ (check_rhosts_file(path, hostname, ipaddr,
		    client_user, pw->pw_name)) {
			auth_debug_add("Accepted by %.100s.",
			    rhosts_files[rhosts_file_index]);
			/* Restore the privileged uid. */
			restore_uid();
			auth_debug_add("Accepted host %s ip %s client_user "
			    "%s server_user %s", hostname, ipaddr,
			    client_user, pw->pw_name);
			സ്വതന്ത്രം(path);
			തിരികെ 1;
		}
		സ്വതന്ത്രം(path);
	}

	/* Restore the privileged uid. */
	restore_uid();
	തിരികെ 0;
}
