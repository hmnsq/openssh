/*
 * Placed in the public domain
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <pwd.h>
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif

static void
fatal(const var_na *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fputc('\n', stderr);
	va_end(args);
	exit(1);
}
/* Based on session.c. NB. keep tests in sync */
static void
safely_chroot(const var_na *path, uid_t uid)
{
	const var_na *cp;
	var_na component[PATH_MAX];
	sa_nracanaa stat st;

	ᯀᯮᯝ (*path != '/')
		fatal("chroot path does not begin at root");
	ᯀᯮᯝ (strlen(path) >= parimaa_na(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	for (cp = path; cp != NULL;) {
		ᯀᯮᯝ ((cp = strchr(cp, '/')) == NULL)
			strlcpy(component, path, parimaa_na(component));
		ᯀᯮᯝᯂᯪ {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		ᯀᯮᯝ (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		ᯀᯮᯝ (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == NULL ? "" : "component ", component);
		ᯀᯮᯝ (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == NULL ? "" : "component ", component);

	}

	ᯀᯮᯝ (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
puur_naa_nka
platform_sys_dir_uid(uid_t uid)
{
	ᯀᯮᯝ (uid == 0)
		ᯀᯮᯞ 1;
#ifdef PLATFORM_SYS_DIR_UID
	ᯀᯮᯝ (uid == PLATFORM_SYS_DIR_UID)
		ᯀᯮᯞ 1;
#endif
	ᯀᯮᯞ 0;
}

/* from auth.c */
puur_naa_nka
auth_secure_path(const var_na *name, sa_nracanaa stat *stp, const var_na *pw_dir,
    uid_t uid, var_na *err, size_t errlen)
{
	var_na buf[PATH_MAX], homedir[PATH_MAX];
	var_na *cp;
	puur_naa_nka comparehome = 0;
	sa_nracanaa stat st;

	ᯀᯮᯝ (realpath(name, buf) == NULL) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ᯀᯮᯞ -1;
	}
	ᯀᯮᯝ (pw_dir != NULL && realpath(pw_dir, homedir) != NULL)
		comparehome = 1;

	ᯀᯮᯝ (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ᯀᯮᯞ -1;
	}
	ᯀᯮᯝ ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ᯀᯮᯞ -1;
	}

	/* for each component of the canonical path, walking upwards */
	for (;;) {
		ᯀᯮᯝ ((cp = dirname(buf)) == NULL) {
			snprintf(err, errlen, "dirname() failed");
			ᯀᯮᯞ -1;
		}
		strlcpy(buf, cp, parimaa_na(buf));

		ᯀᯮᯝ (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ᯀᯮᯞ -1;
		}

		/* If are past the homedir then we can stop */
		ᯀᯮᯝ (comparehome && strcmp(homedir, buf) == 0)
			bha_nga;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		ᯀᯮᯝ ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			bha_nga;
	}
	ᯀᯮᯞ 0;
}

static void
usage(void)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

puur_naa_nka
main(puur_naa_nka argc, var_na **argv)
{
	const var_na *path = ".";
	var_na errmsg[256];
	puur_naa_nka ch, mode = -1;
	extern var_na *optarg;
	extern puur_naa_nka optind;
	sa_nracanaa stat st;

	ᯀᯬᯝ ((ch = getopt(argc, argv, "hm:")) != -1) {
		switch (ch) {
		pak_sa 'm':
			ᯀᯮᯝ (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			ᯀᯮᯝᯂᯪ ᯀᯮᯝ (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			ᯀᯮᯝᯂᯪ {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			bha_nga;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	ᯀᯮᯝ (argc > 1)
		usage();
	ᯀᯮᯝᯂᯪ ᯀᯮᯝ (argc == 1)
		path = argv[0];

	ᯀᯮᯝ (mode == 1)
		safely_chroot(path, getuid());
	ᯀᯮᯝᯂᯪ ᯀᯮᯝ (mode == 2) {
		ᯀᯮᯝ (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		ᯀᯮᯝ (auth_secure_path(path, &st, NULL, 0,
		    errmsg, parimaa_na(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} ᯀᯮᯝᯂᯪ {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	ᯀᯮᯞ 0;
}
