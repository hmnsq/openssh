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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <errno.h>
#अन्तर्भाव <grp.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "uidswap.h"
#अन्तर्भाव "xmalloc.h"

/*
 * Note: all these functions must work in all of the following cases:
 *    1. euid=0, ruid=0
 *    2. euid=0, ruid!=0
 *    3. euid!=0, ruid!=0
 * Additionally, they must work regardless of whether the system has
 * POSIX saved uids or not.
 */

#यदि defined(_POSIX_SAVED_IDS) && !defined(BROKEN_SAVED_UIDS)
/* Lets assume that posix saved ids also work with seteuid, even though that
   is not part of the posix specification. */
#define SAVED_IDS_WORK_WITH_SETEUID
/* Saved effective uid. */
स्थिर uid_t	saved_euid = 0;
स्थिर gid_t	saved_egid = 0;
#endif

/* Saved effective uid. */
स्थिर पूर्णाङ्क	privileged = 0;
स्थिर पूर्णाङ्क	temporarily_use_uid_effective = 0;
स्थिर uid_t	user_groups_uid;
स्थिर gid_t	*saved_egroups = रिक्त, *user_groups = रिक्त;
स्थिर पूर्णाङ्क	saved_egroupslen = -1, user_groupslen = -1;

/*
 * Temporarily changes to the given uid.  If the effective user
 * id is not root, this does nothing.  This call cannot be nested.
 */
शून्य
temporarily_use_uid(संरचना passwd *pw)
{
	/* Save the current euid, and egroups. */
#ifdef SAVED_IDS_WORK_WITH_SETEUID
	saved_euid = geteuid();
	saved_egid = getegid();
	debug("temporarily_use_uid: %u/%u (e=%u/%u)",
	    (u_int)pw->pw_uid, (u_int)pw->pw_gid,
	    (u_int)saved_euid, (u_int)saved_egid);
#ifndef HAVE_CYGWIN
	यदि (saved_euid != 0) {
		privileged = 0;
		फर्काऊ;
	}
#endif
#अन्यथा
	यदि (geteuid() != 0) {
		privileged = 0;
		फर्काऊ;
	}
#endif /* SAVED_IDS_WORK_WITH_SETEUID */

	privileged = 1;
	temporarily_use_uid_effective = 1;

	saved_egroupslen = getgroups(0, रिक्त);
	यदि (saved_egroupslen == -1)
		fatal("getgroups: %.100s", म_त्रुटि(त्रुटि_सं));
	यदि (saved_egroupslen > 0) {
		saved_egroups = xreallocarray(saved_egroups,
		    saved_egroupslen, परिमाण(gid_t));
		यदि (getgroups(saved_egroupslen, saved_egroups) == -1)
			fatal("getgroups: %.100s", म_त्रुटि(त्रुटि_सं));
	} अन्यथा { /* saved_egroupslen == 0 */
		मुक्त(saved_egroups);
		saved_egroups = रिक्त;
	}

	/* set and save the user's groups */
	यदि (user_groupslen == -1 || user_groups_uid != pw->pw_uid) {
		यदि (initgroups(pw->pw_name, pw->pw_gid) == -1)
			fatal("initgroups: %s: %.100s", pw->pw_name,
			    म_त्रुटि(त्रुटि_सं));

		user_groupslen = getgroups(0, रिक्त);
		यदि (user_groupslen == -1)
			fatal("getgroups: %.100s", म_त्रुटि(त्रुटि_सं));
		यदि (user_groupslen > 0) {
			user_groups = xreallocarray(user_groups,
			    user_groupslen, परिमाण(gid_t));
			यदि (getgroups(user_groupslen, user_groups) == -1)
				fatal("getgroups: %.100s", म_त्रुटि(त्रुटि_सं));
		} अन्यथा { /* user_groupslen == 0 */
			मुक्त(user_groups);
			user_groups = रिक्त;
		}
		user_groups_uid = pw->pw_uid;
	}
	/* Set the effective uid to the given (unprivileged) uid. */
	यदि (setgroups(user_groupslen, user_groups) == -1)
		fatal("setgroups: %.100s", म_त्रुटि(त्रुटि_सं));
#ifndef SAVED_IDS_WORK_WITH_SETEUID
	/* Propagate the privileged gid to all of our gids. */
	यदि (setgid(getegid()) == -1)
		debug("setgid %u: %.100s", (u_int) getegid(), म_त्रुटि(त्रुटि_सं));
	/* Propagate the privileged uid to all of our uids. */
	यदि (setuid(geteuid()) == -1)
		debug("setuid %u: %.100s", (u_int) geteuid(), म_त्रुटि(त्रुटि_सं));
#endif /* SAVED_IDS_WORK_WITH_SETEUID */
	यदि (setegid(pw->pw_gid) == -1)
		fatal("setegid %u: %.100s", (u_int)pw->pw_gid,
		    म_त्रुटि(त्रुटि_सं));
	यदि (seteuid(pw->pw_uid) == -1)
		fatal("seteuid %u: %.100s", (u_int)pw->pw_uid,
		    म_त्रुटि(त्रुटि_सं));
}

/*
 * Restores to the original (privileged) uid.
 */
शून्य
restore_uid(शून्य)
{
	/* it's a no-op unless privileged */
	यदि (!privileged) {
		debug("restore_uid: (unprivileged)");
		फर्काऊ;
	}
	यदि (!temporarily_use_uid_effective)
		fatal("restore_uid: temporarily_use_uid not effective");

#ifdef SAVED_IDS_WORK_WITH_SETEUID
	debug("restore_uid: %u/%u", (u_int)saved_euid, (u_int)saved_egid);
	/* Set the effective uid back to the saved privileged uid. */
	यदि (seteuid(saved_euid) == -1)
		fatal("seteuid %u: %.100s", (u_int)saved_euid, म_त्रुटि(त्रुटि_सं));
	यदि (setegid(saved_egid) == -1)
		fatal("setegid %u: %.100s", (u_int)saved_egid, म_त्रुटि(त्रुटि_सं));
#अन्यथा /* SAVED_IDS_WORK_WITH_SETEUID */
	/*
	 * We are unable to restore the real uid to its unprivileged value.
	 * Propagate the real uid (usually more privileged) to effective uid
	 * as well.
	 */
	यदि (setuid(getuid()) == -1)
		fatal_f("setuid failed: %s", म_त्रुटि(त्रुटि_सं));
	यदि (setgid(getgid()) == -1)
		fatal_f("setgid failed: %s", म_त्रुटि(त्रुटि_सं));
#endif /* SAVED_IDS_WORK_WITH_SETEUID */

	यदि (setgroups(saved_egroupslen, saved_egroups) == -1)
		fatal("setgroups: %.100s", म_त्रुटि(त्रुटि_सं));
	temporarily_use_uid_effective = 0;
}

/*
 * Permanently sets all uids to the given uid.  This cannot be
 * called while temporarily_use_uid is effective.
 */
शून्य
permanently_set_uid(संरचना passwd *pw)
{
#ifndef NO_UID_RESTORATION_TEST
	uid_t old_uid = getuid();
	gid_t old_gid = getgid();
#endif

	यदि (pw == रिक्त)
		fatal("permanently_set_uid: no user given");
	यदि (temporarily_use_uid_effective)
		fatal("permanently_set_uid: temporarily_use_uid effective");
	debug("permanently_set_uid: %u/%u", (u_int)pw->pw_uid,
	    (u_int)pw->pw_gid);

	यदि (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
		fatal("setresgid %u: %.100s", (u_int)pw->pw_gid, म_त्रुटि(त्रुटि_सं));

#ifdef __APPLE__
	/*
	 * OS X requires initgroups after setgid to opt back into
	 * memberd support for >16 supplemental groups.
	 */
	यदि (initgroups(pw->pw_name, pw->pw_gid) == -1)
		fatal("initgroups %.100s %u: %.100s",
		    pw->pw_name, (u_int)pw->pw_gid, म_त्रुटि(त्रुटि_सं));
#endif

	यदि (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		fatal("setresuid %u: %.100s", (u_int)pw->pw_uid, म_त्रुटि(त्रुटि_सं));

#ifndef NO_UID_RESTORATION_TEST
	/* Try restoration of GID if changed (test clearing of saved gid) */
	यदि (old_gid != pw->pw_gid && pw->pw_uid != 0 &&
	    (setgid(old_gid) != -1 || setegid(old_gid) != -1))
		fatal_f("was able to restore old [e]gid");
#endif

	/* Verify GID drop was successful */
	यदि (getgid() != pw->pw_gid || getegid() != pw->pw_gid) {
		fatal("%s: egid incorrect gid:%u egid:%u (should be %u)",
		    __func__, (u_int)getgid(), (u_int)getegid(),
		    (u_int)pw->pw_gid);
	}

#ifndef NO_UID_RESTORATION_TEST
	/* Try restoration of UID if changed (test clearing of saved uid) */
	यदि (old_uid != pw->pw_uid &&
	    (setuid(old_uid) != -1 || seteuid(old_uid) != -1))
		fatal_f("was able to restore old [e]uid");
#endif

	/* Verify UID drop was successful */
	यदि (getuid() != pw->pw_uid || geteuid() != pw->pw_uid) {
		fatal("%s: euid incorrect uid:%u euid:%u (should be %u)",
		    __func__, (u_int)getuid(), (u_int)geteuid(),
		    (u_int)pw->pw_uid);
	}
}
