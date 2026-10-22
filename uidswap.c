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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <errno.h>
#అన్తర్భావ <grp.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdlib.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "uidswap.h"
#అన్తర్భావ "xmalloc.h"

/*
 * Note: all these functions must work in all of the following cases:
 *    1. euid=0, ruid=0
 *    2. euid=0, ruid!=0
 *    3. euid!=0, ruid!=0
 * Additionally, they must work regardless of whether the system has
 * POSIX saved uids or not.
 */

#ఒకవేళ defined(_POSIX_SAVED_IDS) && !defined(BROKEN_SAVED_UIDS)
/* Lets assume that posix saved ids also work with seteuid, even though that
   is not part of the posix specification. */
#నిర్వచించు SAVED_IDS_WORK_WITH_SETEUID
/* Saved effective uid. */
స్థిర uid_t	saved_euid = 0;
స్థిర gid_t	saved_egid = 0;
#అయితే_ముగింపు

/* Saved effective uid. */
స్థిర పూర్ణాంకం	privileged = 0;
స్థిర పూర్ణాంకం	temporarily_use_uid_effective = 0;
స్థిర uid_t	user_groups_uid;
స్థిర gid_t	*saved_egroups = ఖాళీ, *user_groups = ఖాళీ;
స్థిర పూర్ణాంకం	saved_egroupslen = -1, user_groupslen = -1;

/*
 * Temporarily changes to the given uid.  If the effective user
 * id is not root, this does nothing.  This call cannot be nested.
 */
శూన్య
temporarily_use_uid(నిర్మాణం passwd *pw)
{
	/* Save the current euid, and egroups. */
#నిర్వచితమైతే SAVED_IDS_WORK_WITH_SETEUID
	saved_euid = geteuid();
	saved_egid = getegid();
	debug("temporarily_use_uid: %u/%u (e=%u/%u)",
	    (u_int)pw->pw_uid, (u_int)pw->pw_gid,
	    (u_int)saved_euid, (u_int)saved_egid);
#నిర్వచితం_కాకపోతే HAVE_CYGWIN
	ఒకవేళ (saved_euid != 0) {
		privileged = 0;
		తిరిగి;
	}
#అయితే_ముగింపు
#లేకపోతే
	ఒకవేళ (geteuid() != 0) {
		privileged = 0;
		తిరిగి;
	}
#అయితే_ముగింపు /* SAVED_IDS_WORK_WITH_SETEUID */

	privileged = 1;
	temporarily_use_uid_effective = 1;

	saved_egroupslen = getgroups(0, ఖాళీ);
	ఒకవేళ (saved_egroupslen == -1)
		fatal("getgroups: %.100s", strerror(errno));
	ఒకవేళ (saved_egroupslen > 0) {
		saved_egroups = xreallocarray(saved_egroups,
		    saved_egroupslen, పరిమాణం(gid_t));
		ఒకవేళ (getgroups(saved_egroupslen, saved_egroups) == -1)
			fatal("getgroups: %.100s", strerror(errno));
	} లేకపోతే { /* saved_egroupslen == 0 */
		విడుదల(saved_egroups);
		saved_egroups = ఖాళీ;
	}

	/* set and save the user's groups */
	ఒకవేళ (user_groupslen == -1 || user_groups_uid != pw->pw_uid) {
		ఒకవేళ (initgroups(pw->pw_name, pw->pw_gid) == -1)
			fatal("initgroups: %s: %.100s", pw->pw_name,
			    strerror(errno));

		user_groupslen = getgroups(0, ఖాళీ);
		ఒకవేళ (user_groupslen == -1)
			fatal("getgroups: %.100s", strerror(errno));
		ఒకవేళ (user_groupslen > 0) {
			user_groups = xreallocarray(user_groups,
			    user_groupslen, పరిమాణం(gid_t));
			ఒకవేళ (getgroups(user_groupslen, user_groups) == -1)
				fatal("getgroups: %.100s", strerror(errno));
		} లేకపోతే { /* user_groupslen == 0 */
			విడుదల(user_groups);
			user_groups = ఖాళీ;
		}
		user_groups_uid = pw->pw_uid;
	}
	/* Set the effective uid to the given (unprivileged) uid. */
	ఒకవేళ (setgroups(user_groupslen, user_groups) == -1)
		fatal("setgroups: %.100s", strerror(errno));
#నిర్వచితం_కాకపోతే SAVED_IDS_WORK_WITH_SETEUID
	/* Propagate the privileged gid to all of our gids. */
	ఒకవేళ (setgid(getegid()) == -1)
		debug("setgid %u: %.100s", (u_int) getegid(), strerror(errno));
	/* Propagate the privileged uid to all of our uids. */
	ఒకవేళ (setuid(geteuid()) == -1)
		debug("setuid %u: %.100s", (u_int) geteuid(), strerror(errno));
#అయితే_ముగింపు /* SAVED_IDS_WORK_WITH_SETEUID */
	ఒకవేళ (setegid(pw->pw_gid) == -1)
		fatal("setegid %u: %.100s", (u_int)pw->pw_gid,
		    strerror(errno));
	ఒకవేళ (seteuid(pw->pw_uid) == -1)
		fatal("seteuid %u: %.100s", (u_int)pw->pw_uid,
		    strerror(errno));
}

/*
 * Restores to the original (privileged) uid.
 */
శూన్య
restore_uid(శూన్య)
{
	/* it's a no-op unless privileged */
	ఒకవేళ (!privileged) {
		debug("restore_uid: (unprivileged)");
		తిరిగి;
	}
	ఒకవేళ (!temporarily_use_uid_effective)
		fatal("restore_uid: temporarily_use_uid not effective");

#నిర్వచితమైతే SAVED_IDS_WORK_WITH_SETEUID
	debug("restore_uid: %u/%u", (u_int)saved_euid, (u_int)saved_egid);
	/* Set the effective uid back to the saved privileged uid. */
	ఒకవేళ (seteuid(saved_euid) == -1)
		fatal("seteuid %u: %.100s", (u_int)saved_euid, strerror(errno));
	ఒకవేళ (setegid(saved_egid) == -1)
		fatal("setegid %u: %.100s", (u_int)saved_egid, strerror(errno));
#లేకపోతే /* SAVED_IDS_WORK_WITH_SETEUID */
	/*
	 * We are unable to restore the real uid to its unprivileged value.
	 * Propagate the real uid (usually more privileged) to effective uid
	 * as well.
	 */
	ఒకవేళ (setuid(getuid()) == -1)
		fatal_f("setuid failed: %s", strerror(errno));
	ఒకవేళ (setgid(getgid()) == -1)
		fatal_f("setgid failed: %s", strerror(errno));
#అయితే_ముగింపు /* SAVED_IDS_WORK_WITH_SETEUID */

	ఒకవేళ (setgroups(saved_egroupslen, saved_egroups) == -1)
		fatal("setgroups: %.100s", strerror(errno));
	temporarily_use_uid_effective = 0;
}

/*
 * Permanently sets all uids to the given uid.  This cannot be
 * called while temporarily_use_uid is effective.
 */
శూన్య
permanently_సమితి_uid(నిర్మాణం passwd *pw)
{
#నిర్వచితం_కాకపోతే NO_UID_RESTORATION_TEST
	uid_t old_uid = getuid();
	gid_t old_gid = getgid();
#అయితే_ముగింపు

	ఒకవేళ (pw == ఖాళీ)
		fatal("permanently_set_uid: no user given");
	ఒకవేళ (temporarily_use_uid_effective)
		fatal("permanently_set_uid: temporarily_use_uid effective");
	debug("permanently_set_uid: %u/%u", (u_int)pw->pw_uid,
	    (u_int)pw->pw_gid);

	ఒకవేళ (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
		fatal("setresgid %u: %.100s", (u_int)pw->pw_gid, strerror(errno));

#నిర్వచితమైతే __APPLE__
	/*
	 * OS X requires initgroups after setgid to opt back into
	 * memberd support for >16 supplemental groups.
	 */
	ఒకవేళ (initgroups(pw->pw_name, pw->pw_gid) == -1)
		fatal("initgroups %.100s %u: %.100s",
		    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
#అయితే_ముగింపు

	ఒకవేళ (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		fatal("setresuid %u: %.100s", (u_int)pw->pw_uid, strerror(errno));

#నిర్వచితం_కాకపోతే NO_UID_RESTORATION_TEST
	/* Try restoration of GID if changed (test clearing of saved gid) */
	ఒకవేళ (old_gid != pw->pw_gid && pw->pw_uid != 0 &&
	    (setgid(old_gid) != -1 || setegid(old_gid) != -1))
		fatal_f("was able to restore old [e]gid");
#అయితే_ముగింపు

	/* Verify GID drop was successful */
	ఒకవేళ (getgid() != pw->pw_gid || getegid() != pw->pw_gid) {
		fatal("%s: egid incorrect gid:%u egid:%u (should be %u)",
		    __func__, (u_int)getgid(), (u_int)getegid(),
		    (u_int)pw->pw_gid);
	}

#నిర్వచితం_కాకపోతే NO_UID_RESTORATION_TEST
	/* Try restoration of UID if changed (test clearing of saved uid) */
	ఒకవేళ (old_uid != pw->pw_uid &&
	    (setuid(old_uid) != -1 || seteuid(old_uid) != -1))
		fatal_f("was able to restore old [e]uid");
#అయితే_ముగింపు

	/* Verify UID drop was successful */
	ఒకవేళ (getuid() != pw->pw_uid || geteuid() != pw->pw_uid) {
		fatal("%s: euid incorrect uid:%u euid:%u (should be %u)",
		    __func__, (u_int)getuid(), (u_int)geteuid(),
		    (u_int)pw->pw_uid);
	}
}
