/* $OpenBSD: uidswap.c,v 1.43 2026/02/11 17:05:32 dtucker Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Code for uid-swapping.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <grp.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdlib.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "uidswap.h"
#അന്തര്ഭാവ "xmalloc.h"

/*
 * Note: all these functions must work in all of the following cases:
 *    1. euid=0, ruid=0
 *    2. euid=0, ruid!=0
 *    3. euid!=0, ruid!=0
 * Additionally, they must work regardless of whether the system has
 * POSIX saved uids or not.
 */

#എങ്കിൽ defined(_POSIX_SAVED_IDS) && !defined(BROKEN_SAVED_UIDS)
/* Lets assume that posix saved ids also work with seteuid, even though that
   is not part of the posix specification. */
#define SAVED_IDS_WORK_WITH_SETEUID
/* Saved effective uid. */
സ്ഥിതം uid_t	saved_euid = 0;
സ്ഥിതം gid_t	saved_egid = 0;
#endif

/* Saved effective uid. */
സ്ഥിതം പൂർണ്ണസംഖ്യ	privileged = 0;
സ്ഥിതം പൂർണ്ണസംഖ്യ	temporarily_use_uid_effective = 0;
സ്ഥിതം uid_t	user_groups_uid;
സ്ഥിതം gid_t	*saved_egroups = ശൂന്യ, *user_groups = ശൂന്യ;
സ്ഥിതം പൂർണ്ണസംഖ്യ	saved_egroupslen = -1, user_groupslen = -1;

/*
 * Temporarily changes to the given uid.  If the effective user
 * id is not root, this does nothing.  This call cannot be nested.
 */
ശൂന്യം
temporarily_use_uid(ഘടന passwd *pw)
{
	/* Save the current euid, and egroups. */
#ifdef SAVED_IDS_WORK_WITH_SETEUID
	saved_euid = geteuid();
	saved_egid = getegid();
	debug("temporarily_use_uid: %u/%u (e=%u/%u)",
	    (u_int)pw->pw_uid, (u_int)pw->pw_gid,
	    (u_int)saved_euid, (u_int)saved_egid);
#ifndef HAVE_CYGWIN
	എങ്കിൽ (saved_euid != 0) {
		privileged = 0;
		തിരികെ;
	}
#endif
#അല്ലെങ്കിൽ
	എങ്കിൽ (geteuid() != 0) {
		privileged = 0;
		തിരികെ;
	}
#endif /* SAVED_IDS_WORK_WITH_SETEUID */

	privileged = 1;
	temporarily_use_uid_effective = 1;

	saved_egroupslen = getgroups(0, ശൂന്യ);
	എങ്കിൽ (saved_egroupslen == -1)
		fatal("getgroups: %.100s", strerror(errno));
	എങ്കിൽ (saved_egroupslen > 0) {
		saved_egroups = xreallocarray(saved_egroups,
		    saved_egroupslen, വലുപ്പം(gid_t));
		എങ്കിൽ (getgroups(saved_egroupslen, saved_egroups) == -1)
			fatal("getgroups: %.100s", strerror(errno));
	} അല്ലെങ്കിൽ { /* saved_egroupslen == 0 */
		സ്വതന്ത്രം(saved_egroups);
		saved_egroups = ശൂന്യ;
	}

	/* set and save the user's groups */
	എങ്കിൽ (user_groupslen == -1 || user_groups_uid != pw->pw_uid) {
		എങ്കിൽ (initgroups(pw->pw_name, pw->pw_gid) == -1)
			fatal("initgroups: %s: %.100s", pw->pw_name,
			    strerror(errno));

		user_groupslen = getgroups(0, ശൂന്യ);
		എങ്കിൽ (user_groupslen == -1)
			fatal("getgroups: %.100s", strerror(errno));
		എങ്കിൽ (user_groupslen > 0) {
			user_groups = xreallocarray(user_groups,
			    user_groupslen, വലുപ്പം(gid_t));
			എങ്കിൽ (getgroups(user_groupslen, user_groups) == -1)
				fatal("getgroups: %.100s", strerror(errno));
		} അല്ലെങ്കിൽ { /* user_groupslen == 0 */
			സ്വതന്ത്രം(user_groups);
			user_groups = ശൂന്യ;
		}
		user_groups_uid = pw->pw_uid;
	}
	/* Set the effective uid to the given (unprivileged) uid. */
	എങ്കിൽ (setgroups(user_groupslen, user_groups) == -1)
		fatal("setgroups: %.100s", strerror(errno));
#ifndef SAVED_IDS_WORK_WITH_SETEUID
	/* Propagate the privileged gid to all of our gids. */
	എങ്കിൽ (setgid(getegid()) == -1)
		debug("setgid %u: %.100s", (u_int) getegid(), strerror(errno));
	/* Propagate the privileged uid to all of our uids. */
	എങ്കിൽ (setuid(geteuid()) == -1)
		debug("setuid %u: %.100s", (u_int) geteuid(), strerror(errno));
#endif /* SAVED_IDS_WORK_WITH_SETEUID */
	എങ്കിൽ (setegid(pw->pw_gid) == -1)
		fatal("setegid %u: %.100s", (u_int)pw->pw_gid,
		    strerror(errno));
	എങ്കിൽ (seteuid(pw->pw_uid) == -1)
		fatal("seteuid %u: %.100s", (u_int)pw->pw_uid,
		    strerror(errno));
}

/*
 * Restores to the original (privileged) uid.
 */
ശൂന്യം
restore_uid(ശൂന്യം)
{
	/* it's a no-op unless privileged */
	എങ്കിൽ (!privileged) {
		debug("restore_uid: (unprivileged)");
		തിരികെ;
	}
	എങ്കിൽ (!temporarily_use_uid_effective)
		fatal("restore_uid: temporarily_use_uid not effective");

#ifdef SAVED_IDS_WORK_WITH_SETEUID
	debug("restore_uid: %u/%u", (u_int)saved_euid, (u_int)saved_egid);
	/* Set the effective uid back to the saved privileged uid. */
	എങ്കിൽ (seteuid(saved_euid) == -1)
		fatal("seteuid %u: %.100s", (u_int)saved_euid, strerror(errno));
	എങ്കിൽ (setegid(saved_egid) == -1)
		fatal("setegid %u: %.100s", (u_int)saved_egid, strerror(errno));
#അല്ലെങ്കിൽ /* SAVED_IDS_WORK_WITH_SETEUID */
	/*
	 * We are unable to restore the real uid to its unprivileged value.
	 * Propagate the real uid (usually more privileged) to effective uid
	 * as well.
	 */
	എങ്കിൽ (setuid(getuid()) == -1)
		fatal_f("setuid failed: %s", strerror(errno));
	എങ്കിൽ (setgid(getgid()) == -1)
		fatal_f("setgid failed: %s", strerror(errno));
#endif /* SAVED_IDS_WORK_WITH_SETEUID */

	എങ്കിൽ (setgroups(saved_egroupslen, saved_egroups) == -1)
		fatal("setgroups: %.100s", strerror(errno));
	temporarily_use_uid_effective = 0;
}

/*
 * Permanently sets all uids to the given uid.  This cannot be
 * called while temporarily_use_uid is effective.
 */
ശൂന്യം
permanently_set_uid(ഘടന passwd *pw)
{
#ifndef NO_UID_RESTORATION_TEST
	uid_t old_uid = getuid();
	gid_t old_gid = getgid();
#endif

	എങ്കിൽ (pw == ശൂന്യ)
		fatal("permanently_set_uid: no user given");
	എങ്കിൽ (temporarily_use_uid_effective)
		fatal("permanently_set_uid: temporarily_use_uid effective");
	debug("permanently_set_uid: %u/%u", (u_int)pw->pw_uid,
	    (u_int)pw->pw_gid);

	എങ്കിൽ (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
		fatal("setresgid %u: %.100s", (u_int)pw->pw_gid, strerror(errno));

#ifdef __APPLE__
	/*
	 * OS X requires initgroups after setgid to opt back into
	 * memberd support for >16 supplemental groups.
	 */
	എങ്കിൽ (initgroups(pw->pw_name, pw->pw_gid) == -1)
		fatal("initgroups %.100s %u: %.100s",
		    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
#endif

	എങ്കിൽ (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		fatal("setresuid %u: %.100s", (u_int)pw->pw_uid, strerror(errno));

#ifndef NO_UID_RESTORATION_TEST
	/* Try restoration of GID if changed (test clearing of saved gid) */
	എങ്കിൽ (old_gid != pw->pw_gid && pw->pw_uid != 0 &&
	    (setgid(old_gid) != -1 || setegid(old_gid) != -1))
		fatal_f("was able to restore old [e]gid");
#endif

	/* Verify GID drop was successful */
	എങ്കിൽ (getgid() != pw->pw_gid || getegid() != pw->pw_gid) {
		fatal("%s: egid incorrect gid:%u egid:%u (should be %u)",
		    __func__, (u_int)getgid(), (u_int)getegid(),
		    (u_int)pw->pw_gid);
	}

#ifndef NO_UID_RESTORATION_TEST
	/* Try restoration of UID if changed (test clearing of saved uid) */
	എങ്കിൽ (old_uid != pw->pw_uid &&
	    (setuid(old_uid) != -1 || seteuid(old_uid) != -1))
		fatal_f("was able to restore old [e]uid");
#endif

	/* Verify UID drop was successful */
	എങ്കിൽ (getuid() != pw->pw_uid || geteuid() != pw->pw_uid) {
		fatal("%s: euid incorrect uid:%u euid:%u (should be %u)",
		    __func__, (u_int)getuid(), (u_int)geteuid(),
		    (u_int)pw->pw_uid);
	}
}
