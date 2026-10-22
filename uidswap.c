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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <grp.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "uidswap.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

/*
 * Note: all these functions must work in all of the following cases:
 *    1. euid=0, ruid=0
 *    2. euid=0, ruid!=0
 *    3. euid!=0, ruid!=0
 * Additionally, they must work regardless of whether the system has
 * POSIX saved uids or not.
 */

#ಆದರೆ defined(_POSIX_SAVED_IDS) && !defined(BROKEN_SAVED_UIDS)
/* Lets assume that posix saved ids also work with seteuid, even though that
   is not part of the posix specification. */
#ವ್ಯಾಖ್ಯಾನಿಸು SAVED_IDS_WORK_WITH_SETEUID
/* Saved effective uid. */
ಸ್ಥಿರ uid_t	saved_euid = 0;
ಸ್ಥಿರ gid_t	saved_egid = 0;
#ಆದರೆ_ಅಂತ್ಯ

/* Saved effective uid. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	privileged = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	temporarily_use_uid_effective = 0;
ಸ್ಥಿರ uid_t	user_groups_uid;
ಸ್ಥಿರ gid_t	*saved_egroups = ಖಾಲಿ, *user_groups = ಖಾಲಿ;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	saved_egroupslen = -1, user_groupslen = -1;

/*
 * Temporarily changes to the given uid.  If the effective user
 * id is not root, this does nothing.  This call cannot be nested.
 */
ಶೂನ್ಯ
temporarily_use_uid(ರಚನೆ passwd *pw)
{
	/* Save the current euid, and egroups. */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SAVED_IDS_WORK_WITH_SETEUID
	saved_euid = geteuid();
	saved_egid = getegid();
	debug("temporarily_use_uid: %u/%u (e=%u/%u)",
	    (u_int)pw->pw_uid, (u_int)pw->pw_gid,
	    (u_int)saved_euid, (u_int)saved_egid);
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_CYGWIN
	ಆದರೆ (saved_euid != 0) {
		privileged = 0;
		ಹಿಂತಿರುಗಿ;
	}
#ಆದರೆ_ಅಂತ್ಯ
#ಇಲ್ಲದಿದ್ದರೆ
	ಆದರೆ (geteuid() != 0) {
		privileged = 0;
		ಹಿಂತಿರುಗಿ;
	}
#ಆದರೆ_ಅಂತ್ಯ /* SAVED_IDS_WORK_WITH_SETEUID */

	privileged = 1;
	temporarily_use_uid_effective = 1;

	saved_egroupslen = getgroups(0, ಖಾಲಿ);
	ಆದರೆ (saved_egroupslen == -1)
		fatal("getgroups: %.100s", strerror(errno));
	ಆದರೆ (saved_egroupslen > 0) {
		saved_egroups = xreallocarray(saved_egroups,
		    saved_egroupslen, ಗಾತ್ರ(gid_t));
		ಆದರೆ (getgroups(saved_egroupslen, saved_egroups) == -1)
			fatal("getgroups: %.100s", strerror(errno));
	} ಇಲ್ಲದಿದ್ದರೆ { /* saved_egroupslen == 0 */
		ಬಿಡುಗಡೆ(saved_egroups);
		saved_egroups = ಖಾಲಿ;
	}

	/* set and save the user's groups */
	ಆದರೆ (user_groupslen == -1 || user_groups_uid != pw->pw_uid) {
		ಆದರೆ (initgroups(pw->pw_name, pw->pw_gid) == -1)
			fatal("initgroups: %s: %.100s", pw->pw_name,
			    strerror(errno));

		user_groupslen = getgroups(0, ಖಾಲಿ);
		ಆದರೆ (user_groupslen == -1)
			fatal("getgroups: %.100s", strerror(errno));
		ಆದರೆ (user_groupslen > 0) {
			user_groups = xreallocarray(user_groups,
			    user_groupslen, ಗಾತ್ರ(gid_t));
			ಆದರೆ (getgroups(user_groupslen, user_groups) == -1)
				fatal("getgroups: %.100s", strerror(errno));
		} ಇಲ್ಲದಿದ್ದರೆ { /* user_groupslen == 0 */
			ಬಿಡುಗಡೆ(user_groups);
			user_groups = ಖಾಲಿ;
		}
		user_groups_uid = pw->pw_uid;
	}
	/* Set the effective uid to the given (unprivileged) uid. */
	ಆದರೆ (setgroups(user_groupslen, user_groups) == -1)
		fatal("setgroups: %.100s", strerror(errno));
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SAVED_IDS_WORK_WITH_SETEUID
	/* Propagate the privileged gid to all of our gids. */
	ಆದರೆ (setgid(getegid()) == -1)
		debug("setgid %u: %.100s", (u_int) getegid(), strerror(errno));
	/* Propagate the privileged uid to all of our uids. */
	ಆದರೆ (setuid(geteuid()) == -1)
		debug("setuid %u: %.100s", (u_int) geteuid(), strerror(errno));
#ಆದರೆ_ಅಂತ್ಯ /* SAVED_IDS_WORK_WITH_SETEUID */
	ಆದರೆ (setegid(pw->pw_gid) == -1)
		fatal("setegid %u: %.100s", (u_int)pw->pw_gid,
		    strerror(errno));
	ಆದರೆ (seteuid(pw->pw_uid) == -1)
		fatal("seteuid %u: %.100s", (u_int)pw->pw_uid,
		    strerror(errno));
}

/*
 * Restores to the original (privileged) uid.
 */
ಶೂನ್ಯ
restore_uid(ಶೂನ್ಯ)
{
	/* it's a no-op unless privileged */
	ಆದರೆ (!privileged) {
		debug("restore_uid: (unprivileged)");
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (!temporarily_use_uid_effective)
		fatal("restore_uid: temporarily_use_uid not effective");

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SAVED_IDS_WORK_WITH_SETEUID
	debug("restore_uid: %u/%u", (u_int)saved_euid, (u_int)saved_egid);
	/* Set the effective uid back to the saved privileged uid. */
	ಆದರೆ (seteuid(saved_euid) == -1)
		fatal("seteuid %u: %.100s", (u_int)saved_euid, strerror(errno));
	ಆದರೆ (setegid(saved_egid) == -1)
		fatal("setegid %u: %.100s", (u_int)saved_egid, strerror(errno));
#ಇಲ್ಲದಿದ್ದರೆ /* SAVED_IDS_WORK_WITH_SETEUID */
	/*
	 * We are unable to restore the real uid to its unprivileged value.
	 * Propagate the real uid (usually more privileged) to effective uid
	 * as well.
	 */
	ಆದರೆ (setuid(getuid()) == -1)
		fatal_f("setuid failed: %s", strerror(errno));
	ಆದರೆ (setgid(getgid()) == -1)
		fatal_f("setgid failed: %s", strerror(errno));
#ಆದರೆ_ಅಂತ್ಯ /* SAVED_IDS_WORK_WITH_SETEUID */

	ಆದರೆ (setgroups(saved_egroupslen, saved_egroups) == -1)
		fatal("setgroups: %.100s", strerror(errno));
	temporarily_use_uid_effective = 0;
}

/*
 * Permanently sets all uids to the given uid.  This cannot be
 * called while temporarily_use_uid is effective.
 */
ಶೂನ್ಯ
permanently_ಗಣ_uid(ರಚನೆ passwd *pw)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ NO_UID_RESTORATION_TEST
	uid_t old_uid = getuid();
	gid_t old_gid = getgid();
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (pw == ಖಾಲಿ)
		fatal("permanently_set_uid: no user given");
	ಆದರೆ (temporarily_use_uid_effective)
		fatal("permanently_set_uid: temporarily_use_uid effective");
	debug("permanently_set_uid: %u/%u", (u_int)pw->pw_uid,
	    (u_int)pw->pw_gid);

	ಆದರೆ (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
		fatal("setresgid %u: %.100s", (u_int)pw->pw_gid, strerror(errno));

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __APPLE__
	/*
	 * OS X requires initgroups after setgid to opt back into
	 * memberd support for >16 supplemental groups.
	 */
	ಆದರೆ (initgroups(pw->pw_name, pw->pw_gid) == -1)
		fatal("initgroups %.100s %u: %.100s",
		    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		fatal("setresuid %u: %.100s", (u_int)pw->pw_uid, strerror(errno));

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ NO_UID_RESTORATION_TEST
	/* Try restoration of GID if changed (test clearing of saved gid) */
	ಆದರೆ (old_gid != pw->pw_gid && pw->pw_uid != 0 &&
	    (setgid(old_gid) != -1 || setegid(old_gid) != -1))
		fatal_f("was able to restore old [e]gid");
#ಆದರೆ_ಅಂತ್ಯ

	/* Verify GID drop was successful */
	ಆದರೆ (getgid() != pw->pw_gid || getegid() != pw->pw_gid) {
		fatal("%s: egid incorrect gid:%u egid:%u (should be %u)",
		    __func__, (u_int)getgid(), (u_int)getegid(),
		    (u_int)pw->pw_gid);
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ NO_UID_RESTORATION_TEST
	/* Try restoration of UID if changed (test clearing of saved uid) */
	ಆದರೆ (old_uid != pw->pw_uid &&
	    (setuid(old_uid) != -1 || seteuid(old_uid) != -1))
		fatal_f("was able to restore old [e]uid");
#ಆದರೆ_ಅಂತ್ಯ

	/* Verify UID drop was successful */
	ಆದರೆ (getuid() != pw->pw_uid || geteuid() != pw->pw_uid) {
		fatal("%s: euid incorrect uid:%u euid:%u (should be %u)",
		    __func__, (u_int)getuid(), (u_int)geteuid(),
		    (u_int)pw->pw_uid);
	}
}
