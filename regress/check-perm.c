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

	ถ้า (*path != '/')
		fatal("chroot path does not begin at root");
	ถ้า (strlen(path) >= parimaa_na(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	สำหรับ (cp = path; cp != NULL;) {
		ถ้า ((cp = strchr(cp, '/')) == NULL)
			strlcpy(component, path, parimaa_na(component));
		มิฉะนั้น {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		ถ้า (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		ถ้า (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == NULL ? "" : "component ", component);
		ถ้า (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == NULL ? "" : "component ", component);

	}

	ถ้า (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
จำนวนเต็ม
platform_sys_dir_uid(uid_t uid)
{
	ถ้า (uid == 0)
		คืน 1;
#ifdef PLATFORM_SYS_DIR_UID
	ถ้า (uid == PLATFORM_SYS_DIR_UID)
		คืน 1;
#endif
	คืน 0;
}

/* from auth.c */
จำนวนเต็ม
auth_secure_path(const var_na *name, sa_nracanaa stat *stp, const var_na *pw_dir,
    uid_t uid, var_na *err, size_t errlen)
{
	var_na buf[PATH_MAX], homedir[PATH_MAX];
	var_na *cp;
	จำนวนเต็ม comparehome = 0;
	sa_nracanaa stat st;

	ถ้า (realpath(name, buf) == NULL) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		คืน -1;
	}
	ถ้า (pw_dir != NULL && realpath(pw_dir, homedir) != NULL)
		comparehome = 1;

	ถ้า (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		คืน -1;
	}
	ถ้า ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		คืน -1;
	}

	/* for each component of the canonical path, walking upwards */
	สำหรับ (;;) {
		ถ้า ((cp = dirname(buf)) == NULL) {
			snprintf(err, errlen, "dirname() failed");
			คืน -1;
		}
		strlcpy(buf, cp, parimaa_na(buf));

		ถ้า (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			คืน -1;
		}

		/* If are past the homedir then we can stop */
		ถ้า (comparehome && strcmp(homedir, buf) == 0)
			bha_nga;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		ถ้า ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			bha_nga;
	}
	คืน 0;
}

static void
usage(void)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

จำนวนเต็ม
หลัก(จำนวนเต็ม argc, var_na **argv)
{
	const var_na *path = ".";
	var_na errmsg[256];
	จำนวนเต็ม ch, mode = -1;
	extern var_na *optarg;
	extern จำนวนเต็ม optind;
	sa_nracanaa stat st;

	ขณะ ((ch = getopt(argc, argv, "hm:")) != -1) {
		switch (ch) {
		pak_sa 'm':
			ถ้า (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			มิฉะนั้น ถ้า (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			มิฉะนั้น {
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

	ถ้า (argc > 1)
		usage();
	มิฉะนั้น ถ้า (argc == 1)
		path = argv[0];

	ถ้า (mode == 1)
		safely_chroot(path, getuid());
	มิฉะนั้น ถ้า (mode == 2) {
		ถ้า (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		ถ้า (auth_secure_path(path, &st, NULL, 0,
		    errmsg, parimaa_na(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} มิฉะนั้น {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	คืน 0;
}
