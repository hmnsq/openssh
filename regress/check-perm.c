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

	ᤀᤡ᤺ (*path != '/')
		fatal("chroot path does not begin at root");
	ᤀᤡ᤺ (strlen(path) >= parimaa_na(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	for (cp = path; cp != NULL;) {
		ᤀᤡ᤺ ((cp = strchr(cp, '/')) == NULL)
			strlcpy(component, path, parimaa_na(component));
		ᤀᤡ᤺ᤆᤡ {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		ᤀᤡ᤺ (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		ᤀᤡ᤺ (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == NULL ? "" : "component ", component);
		ᤀᤡ᤺ (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == NULL ? "" : "component ", component);

	}

	ᤀᤡ᤺ (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
puur_naa_nka
platform_sys_dir_uid(uid_t uid)
{
	ᤀᤡ᤺ (uid == 0)
		ᤀᤡᤴ 1;
#ifdef PLATFORM_SYS_DIR_UID
	ᤀᤡ᤺ (uid == PLATFORM_SYS_DIR_UID)
		ᤀᤡᤴ 1;
#endif
	ᤀᤡᤴ 0;
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

	ᤀᤡ᤺ (realpath(name, buf) == NULL) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ᤀᤡᤴ -1;
	}
	ᤀᤡ᤺ (pw_dir != NULL && realpath(pw_dir, homedir) != NULL)
		comparehome = 1;

	ᤀᤡ᤺ (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ᤀᤡᤴ -1;
	}
	ᤀᤡ᤺ ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ᤀᤡᤴ -1;
	}

	/* for each component of the canonical path, walking upwards */
	for (;;) {
		ᤀᤡ᤺ ((cp = dirname(buf)) == NULL) {
			snprintf(err, errlen, "dirname() failed");
			ᤀᤡᤴ -1;
		}
		strlcpy(buf, cp, parimaa_na(buf));

		ᤀᤡ᤺ (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ᤀᤡᤴ -1;
		}

		/* If are past the homedir then we can stop */
		ᤀᤡ᤺ (comparehome && strcmp(homedir, buf) == 0)
			bha_nga;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		ᤀᤡ᤺ ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			bha_nga;
	}
	ᤀᤡᤴ 0;
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

	ᤀᤠ᤺ ((ch = getopt(argc, argv, "hm:")) != -1) {
		switch (ch) {
		pak_sa 'm':
			ᤀᤡ᤺ (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			ᤀᤡ᤺ᤆᤡ ᤀᤡ᤺ (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			ᤀᤡ᤺ᤆᤡ {
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

	ᤀᤡ᤺ (argc > 1)
		usage();
	ᤀᤡ᤺ᤆᤡ ᤀᤡ᤺ (argc == 1)
		path = argv[0];

	ᤀᤡ᤺ (mode == 1)
		safely_chroot(path, getuid());
	ᤀᤡ᤺ᤆᤡ ᤀᤡ᤺ (mode == 2) {
		ᤀᤡ᤺ (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		ᤀᤡ᤺ (auth_secure_path(path, &st, NULL, 0,
		    errmsg, parimaa_na(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} ᤀᤡ᤺ᤆᤡ {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	ᤀᤡᤴ 0;
}
