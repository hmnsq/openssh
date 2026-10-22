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

#समावेश "includes.h"

#समावेश <errno.h>
#समावेश <grp.h>
#समावेश <pwd.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <limits.h>
#समावेश <stdarg.h>
#समावेश <stdlib.h>

#समावेश "log.h"
#समावेश "uidswap.h"
#समावेश "xmalloc.h"

/*
 * Note: all these functions must work in all of the following cases:
 *    1. euid=0, ruid=0
 *    2. euid=0, ruid!=0
 *    3. euid!=0, ruid!=0
 * Additionally, they must work regardless of whether the system has
 * POSIX saved uids or not.
 */

#अगर defined(_POSIX_SAVED_IDS) && !defined(BROKEN_SAVED_UIDS)
/* Lets assume that posix saved ids also work with seteuid, even though that
   is not part of the posix specification. */
#घोषणा SAVED_IDS_WORK_WITH_SETEUID
/* Saved effective uid. */
अटल uid_t	saved_euid = 0;
अटल gid_t	saved_egid = 0;
#पूर्ण_अगर

/* Saved effective uid. */
अटल पूर्णांक	privileged = 0;
अटल पूर्णांक	temporarily_use_uid_effective = 0;
अटल uid_t	user_groups_uid;
अटल gid_t	*saved_egroups = शून्य, *user_groups = शून्य;
अटल पूर्णांक	saved_egroupslen = -1, user_groupslen = -1;

/*
 * Temporarily changes to the given uid.  If the effective user
 * id is not root, this does nothing.  This call cannot be nested.
 */
व्योम
temporarily_use_uid(काष्ठा passwd *pw)
{
	/* Save the current euid, and egroups. */
#अगर_घोषित SAVED_IDS_WORK_WITH_SETEUID
	saved_euid = geteuid();
	saved_egid = getegid();
	debug("temporarily_use_uid: %u/%u (e=%u/%u)",
	    (u_int)pw->pw_uid, (u_int)pw->pw_gid,
	    (u_int)saved_euid, (u_int)saved_egid);
#अगर_अघोषित HAVE_CYGWIN
	अगर (saved_euid != 0) {
		privileged = 0;
		वापस;
	}
#पूर्ण_अगर
#अन्यथा
	अगर (geteuid() != 0) {
		privileged = 0;
		वापस;
	}
#पूर्ण_अगर /* SAVED_IDS_WORK_WITH_SETEUID */

	privileged = 1;
	temporarily_use_uid_effective = 1;

	saved_egroupslen = getgroups(0, शून्य);
	अगर (saved_egroupslen == -1)
		fatal("getgroups: %.100s", म_त्रुटि(त्रुटि_सं));
	अगर (saved_egroupslen > 0) {
		saved_egroups = xreallocarray(saved_egroups,
		    saved_egroupslen, माप(gid_t));
		अगर (getgroups(saved_egroupslen, saved_egroups) == -1)
			fatal("getgroups: %.100s", म_त्रुटि(त्रुटि_सं));
	} अन्यथा { /* saved_egroupslen == 0 */
		मुक्त(saved_egroups);
		saved_egroups = शून्य;
	}

	/* set and save the user's groups */
	अगर (user_groupslen == -1 || user_groups_uid != pw->pw_uid) {
		अगर (initgroups(pw->pw_name, pw->pw_gid) == -1)
			fatal("initgroups: %s: %.100s", pw->pw_name,
			    म_त्रुटि(त्रुटि_सं));

		user_groupslen = getgroups(0, शून्य);
		अगर (user_groupslen == -1)
			fatal("getgroups: %.100s", म_त्रुटि(त्रुटि_सं));
		अगर (user_groupslen > 0) {
			user_groups = xreallocarray(user_groups,
			    user_groupslen, माप(gid_t));
			अगर (getgroups(user_groupslen, user_groups) == -1)
				fatal("getgroups: %.100s", म_त्रुटि(त्रुटि_सं));
		} अन्यथा { /* user_groupslen == 0 */
			मुक्त(user_groups);
			user_groups = शून्य;
		}
		user_groups_uid = pw->pw_uid;
	}
	/* Set the effective uid to the given (unprivileged) uid. */
	अगर (setgroups(user_groupslen, user_groups) == -1)
		fatal("setgroups: %.100s", म_त्रुटि(त्रुटि_सं));
#अगर_अघोषित SAVED_IDS_WORK_WITH_SETEUID
	/* Propagate the privileged gid to all of our gids. */
	अगर (setgid(getegid()) == -1)
		debug("setgid %u: %.100s", (u_int) getegid(), म_त्रुटि(त्रुटि_सं));
	/* Propagate the privileged uid to all of our uids. */
	अगर (setuid(geteuid()) == -1)
		debug("setuid %u: %.100s", (u_int) geteuid(), म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर /* SAVED_IDS_WORK_WITH_SETEUID */
	अगर (setegid(pw->pw_gid) == -1)
		fatal("setegid %u: %.100s", (u_int)pw->pw_gid,
		    म_त्रुटि(त्रुटि_सं));
	अगर (seteuid(pw->pw_uid) == -1)
		fatal("seteuid %u: %.100s", (u_int)pw->pw_uid,
		    म_त्रुटि(त्रुटि_सं));
}

/*
 * Restores to the original (privileged) uid.
 */
व्योम
restore_uid(व्योम)
{
	/* it's a no-op unless privileged */
	अगर (!privileged) {
		debug("restore_uid: (unprivileged)");
		वापस;
	}
	अगर (!temporarily_use_uid_effective)
		fatal("restore_uid: temporarily_use_uid not effective");

#अगर_घोषित SAVED_IDS_WORK_WITH_SETEUID
	debug("restore_uid: %u/%u", (u_int)saved_euid, (u_int)saved_egid);
	/* Set the effective uid back to the saved privileged uid. */
	अगर (seteuid(saved_euid) == -1)
		fatal("seteuid %u: %.100s", (u_int)saved_euid, म_त्रुटि(त्रुटि_सं));
	अगर (setegid(saved_egid) == -1)
		fatal("setegid %u: %.100s", (u_int)saved_egid, म_त्रुटि(त्रुटि_सं));
#अन्यथा /* SAVED_IDS_WORK_WITH_SETEUID */
	/*
	 * We are unable to restore the real uid to its unprivileged value.
	 * Propagate the real uid (usually more privileged) to effective uid
	 * as well.
	 */
	अगर (setuid(getuid()) == -1)
		fatal_f("setuid failed: %s", म_त्रुटि(त्रुटि_सं));
	अगर (setgid(getgid()) == -1)
		fatal_f("setgid failed: %s", म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर /* SAVED_IDS_WORK_WITH_SETEUID */

	अगर (setgroups(saved_egroupslen, saved_egroups) == -1)
		fatal("setgroups: %.100s", म_त्रुटि(त्रुटि_सं));
	temporarily_use_uid_effective = 0;
}

/*
 * Permanently sets all uids to the given uid.  This cannot be
 * called while temporarily_use_uid is effective.
 */
व्योम
permanently_set_uid(काष्ठा passwd *pw)
{
#अगर_अघोषित NO_UID_RESTORATION_TEST
	uid_t old_uid = getuid();
	gid_t old_gid = getgid();
#पूर्ण_अगर

	अगर (pw == शून्य)
		fatal("permanently_set_uid: no user given");
	अगर (temporarily_use_uid_effective)
		fatal("permanently_set_uid: temporarily_use_uid effective");
	debug("permanently_set_uid: %u/%u", (u_int)pw->pw_uid,
	    (u_int)pw->pw_gid);

	अगर (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
		fatal("setresgid %u: %.100s", (u_int)pw->pw_gid, म_त्रुटि(त्रुटि_सं));

#अगर_घोषित __APPLE__
	/*
	 * OS X requires initgroups after setgid to opt back into
	 * memberd support for >16 supplemental groups.
	 */
	अगर (initgroups(pw->pw_name, pw->pw_gid) == -1)
		fatal("initgroups %.100s %u: %.100s",
		    pw->pw_name, (u_int)pw->pw_gid, म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर

	अगर (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		fatal("setresuid %u: %.100s", (u_int)pw->pw_uid, म_त्रुटि(त्रुटि_सं));

#अगर_अघोषित NO_UID_RESTORATION_TEST
	/* Try restoration of GID if changed (test clearing of saved gid) */
	अगर (old_gid != pw->pw_gid && pw->pw_uid != 0 &&
	    (setgid(old_gid) != -1 || setegid(old_gid) != -1))
		fatal_f("was able to restore old [e]gid");
#पूर्ण_अगर

	/* Verify GID drop was successful */
	अगर (getgid() != pw->pw_gid || getegid() != pw->pw_gid) {
		fatal("%s: egid incorrect gid:%u egid:%u (should be %u)",
		    __func__, (u_int)getgid(), (u_int)getegid(),
		    (u_int)pw->pw_gid);
	}

#अगर_अघोषित NO_UID_RESTORATION_TEST
	/* Try restoration of UID if changed (test clearing of saved uid) */
	अगर (old_uid != pw->pw_uid &&
	    (setuid(old_uid) != -1 || seteuid(old_uid) != -1))
		fatal_f("was able to restore old [e]uid");
#पूर्ण_अगर

	/* Verify UID drop was successful */
	अगर (getuid() != pw->pw_uid || geteuid() != pw->pw_uid) {
		fatal("%s: euid incorrect uid:%u euid:%u (should be %u)",
		    __func__, (u_int)getuid(), (u_int)geteuid(),
		    (u_int)pw->pw_uid);
	}
}
