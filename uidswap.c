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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <grp.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "uidswap.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"

/*
 * Note: all these functions must work in all of the following cases:
 *    1. euid=0, ruid=0
 *    2. euid=0, ruid!=0
 *    3. euid!=0, ruid!=0
 * Additionally, they must work regardless of whether the system has
 * POSIX saved uids or not.
 */

#ଯଦି defined(_POSIX_SAVED_IDS) && !defined(BROKEN_SAVED_UIDS)
/* Lets assume that posix saved ids also work with seteuid, even though that
   is not part of the posix specification. */
#define SAVED_IDS_WORK_WITH_SETEUID
/* Saved effective uid. */
ସ୍ଥିର uid_t	saved_euid = 0;
ସ୍ଥିର gid_t	saved_egid = 0;
#endif

/* Saved effective uid. */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	privileged = 0;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	temporarily_use_uid_effective = 0;
ସ୍ଥିର uid_t	user_groups_uid;
ସ୍ଥିର gid_t	*saved_egroups = ଖାଲି, *user_groups = ଖାଲି;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	saved_egroupslen = -1, user_groupslen = -1;

/*
 * Temporarily changes to the given uid.  If the effective user
 * id is not root, this does nothing.  This call cannot be nested.
 */
ଶୂନ୍ୟ
temporarily_use_uid(ସଂରଚନା passwd *pw)
{
	/* Save the current euid, and egroups. */
#ifdef SAVED_IDS_WORK_WITH_SETEUID
	saved_euid = geteuid();
	saved_egid = getegid();
	debug("temporarily_use_uid: %u/%u (e=%u/%u)",
	    (u_int)pw->pw_uid, (u_int)pw->pw_gid,
	    (u_int)saved_euid, (u_int)saved_egid);
#ifndef HAVE_CYGWIN
	ଯଦି (saved_euid != 0) {
		privileged = 0;
		ଫେରନ୍ତୁ;
	}
#endif
#ଅନ୍ୟଥା
	ଯଦି (geteuid() != 0) {
		privileged = 0;
		ଫେରନ୍ତୁ;
	}
#endif /* SAVED_IDS_WORK_WITH_SETEUID */

	privileged = 1;
	temporarily_use_uid_effective = 1;

	saved_egroupslen = getgroups(0, ଖାଲି);
	ଯଦି (saved_egroupslen == -1)
		fatal("getgroups: %.100s", strerror(errno));
	ଯଦି (saved_egroupslen > 0) {
		saved_egroups = xreallocarray(saved_egroups,
		    saved_egroupslen, ଆକାର(gid_t));
		ଯଦି (getgroups(saved_egroupslen, saved_egroups) == -1)
			fatal("getgroups: %.100s", strerror(errno));
	} ଅନ୍ୟଥା { /* saved_egroupslen == 0 */
		ମୁକ୍ତ(saved_egroups);
		saved_egroups = ଖାଲି;
	}

	/* set and save the user's groups */
	ଯଦି (user_groupslen == -1 || user_groups_uid != pw->pw_uid) {
		ଯଦି (initgroups(pw->pw_name, pw->pw_gid) == -1)
			fatal("initgroups: %s: %.100s", pw->pw_name,
			    strerror(errno));

		user_groupslen = getgroups(0, ଖାଲି);
		ଯଦି (user_groupslen == -1)
			fatal("getgroups: %.100s", strerror(errno));
		ଯଦି (user_groupslen > 0) {
			user_groups = xreallocarray(user_groups,
			    user_groupslen, ଆକାର(gid_t));
			ଯଦି (getgroups(user_groupslen, user_groups) == -1)
				fatal("getgroups: %.100s", strerror(errno));
		} ଅନ୍ୟଥା { /* user_groupslen == 0 */
			ମୁକ୍ତ(user_groups);
			user_groups = ଖାଲି;
		}
		user_groups_uid = pw->pw_uid;
	}
	/* Set the effective uid to the given (unprivileged) uid. */
	ଯଦି (setgroups(user_groupslen, user_groups) == -1)
		fatal("setgroups: %.100s", strerror(errno));
#ifndef SAVED_IDS_WORK_WITH_SETEUID
	/* Propagate the privileged gid to all of our gids. */
	ଯଦି (setgid(getegid()) == -1)
		debug("setgid %u: %.100s", (u_int) getegid(), strerror(errno));
	/* Propagate the privileged uid to all of our uids. */
	ଯଦି (setuid(geteuid()) == -1)
		debug("setuid %u: %.100s", (u_int) geteuid(), strerror(errno));
#endif /* SAVED_IDS_WORK_WITH_SETEUID */
	ଯଦି (setegid(pw->pw_gid) == -1)
		fatal("setegid %u: %.100s", (u_int)pw->pw_gid,
		    strerror(errno));
	ଯଦି (seteuid(pw->pw_uid) == -1)
		fatal("seteuid %u: %.100s", (u_int)pw->pw_uid,
		    strerror(errno));
}

/*
 * Restores to the original (privileged) uid.
 */
ଶୂନ୍ୟ
restore_uid(ଶୂନ୍ୟ)
{
	/* it's a no-op unless privileged */
	ଯଦି (!privileged) {
		debug("restore_uid: (unprivileged)");
		ଫେରନ୍ତୁ;
	}
	ଯଦି (!temporarily_use_uid_effective)
		fatal("restore_uid: temporarily_use_uid not effective");

#ifdef SAVED_IDS_WORK_WITH_SETEUID
	debug("restore_uid: %u/%u", (u_int)saved_euid, (u_int)saved_egid);
	/* Set the effective uid back to the saved privileged uid. */
	ଯଦି (seteuid(saved_euid) == -1)
		fatal("seteuid %u: %.100s", (u_int)saved_euid, strerror(errno));
	ଯଦି (setegid(saved_egid) == -1)
		fatal("setegid %u: %.100s", (u_int)saved_egid, strerror(errno));
#ଅନ୍ୟଥା /* SAVED_IDS_WORK_WITH_SETEUID */
	/*
	 * We are unable to restore the real uid to its unprivileged value.
	 * Propagate the real uid (usually more privileged) to effective uid
	 * as well.
	 */
	ଯଦି (setuid(getuid()) == -1)
		fatal_f("setuid failed: %s", strerror(errno));
	ଯଦି (setgid(getgid()) == -1)
		fatal_f("setgid failed: %s", strerror(errno));
#endif /* SAVED_IDS_WORK_WITH_SETEUID */

	ଯଦି (setgroups(saved_egroupslen, saved_egroups) == -1)
		fatal("setgroups: %.100s", strerror(errno));
	temporarily_use_uid_effective = 0;
}

/*
 * Permanently sets all uids to the given uid.  This cannot be
 * called while temporarily_use_uid is effective.
 */
ଶୂନ୍ୟ
permanently_set_uid(ସଂରଚନା passwd *pw)
{
#ifndef NO_UID_RESTORATION_TEST
	uid_t old_uid = getuid();
	gid_t old_gid = getgid();
#endif

	ଯଦି (pw == ଖାଲି)
		fatal("permanently_set_uid: no user given");
	ଯଦି (temporarily_use_uid_effective)
		fatal("permanently_set_uid: temporarily_use_uid effective");
	debug("permanently_set_uid: %u/%u", (u_int)pw->pw_uid,
	    (u_int)pw->pw_gid);

	ଯଦି (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
		fatal("setresgid %u: %.100s", (u_int)pw->pw_gid, strerror(errno));

#ifdef __APPLE__
	/*
	 * OS X requires initgroups after setgid to opt back into
	 * memberd support for >16 supplemental groups.
	 */
	ଯଦି (initgroups(pw->pw_name, pw->pw_gid) == -1)
		fatal("initgroups %.100s %u: %.100s",
		    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
#endif

	ଯଦି (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		fatal("setresuid %u: %.100s", (u_int)pw->pw_uid, strerror(errno));

#ifndef NO_UID_RESTORATION_TEST
	/* Try restoration of GID if changed (test clearing of saved gid) */
	ଯଦି (old_gid != pw->pw_gid && pw->pw_uid != 0 &&
	    (setgid(old_gid) != -1 || setegid(old_gid) != -1))
		fatal_f("was able to restore old [e]gid");
#endif

	/* Verify GID drop was successful */
	ଯଦି (getgid() != pw->pw_gid || getegid() != pw->pw_gid) {
		fatal("%s: egid incorrect gid:%u egid:%u (should be %u)",
		    __func__, (u_int)getgid(), (u_int)getegid(),
		    (u_int)pw->pw_gid);
	}

#ifndef NO_UID_RESTORATION_TEST
	/* Try restoration of UID if changed (test clearing of saved uid) */
	ଯଦି (old_uid != pw->pw_uid &&
	    (setuid(old_uid) != -1 || seteuid(old_uid) != -1))
		fatal_f("was able to restore old [e]uid");
#endif

	/* Verify UID drop was successful */
	ଯଦି (getuid() != pw->pw_uid || geteuid() != pw->pw_uid) {
		fatal("%s: euid incorrect uid:%u euid:%u (should be %u)",
		    __func__, (u_int)getuid(), (u_int)geteuid(),
		    (u_int)pw->pw_uid);
	}
}
