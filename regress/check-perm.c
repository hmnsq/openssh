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
fatal(const char *fmt, ...)
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
safely_chroot(const char *path, uid_t uid)
{
	const char *cp;
	char component[PATH_MAX];
	struct stat st;

	如果 (*path != '/')
		fatal("chroot path does not begin at root");
	如果 (strlen(path) >= sizeof(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	为 (cp = path; cp != NULL;) {
		如果 ((cp = strchr(cp, '/')) == NULL)
			strlcpy(component, path, sizeof(component));
		否则 {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		如果 (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		如果 (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == NULL ? "" : "component ", component);
		如果 (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == NULL ? "" : "component ", component);

	}

	如果 (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
整数
platform_sys_dir_uid(uid_t uid)
{
	如果 (uid == 0)
		返回 1;
#ifdef PLATFORM_SYS_DIR_UID
	如果 (uid == PLATFORM_SYS_DIR_UID)
		返回 1;
#endif
	返回 0;
}

/* from auth.c */
整数
auth_secure_path(const char *name, struct stat *stp, const char *pw_dir,
    uid_t uid, char *err, size_t errlen)
{
	char buf[PATH_MAX], homedir[PATH_MAX];
	char *cp;
	整数 comparehome = 0;
	struct stat st;

	如果 (realpath(name, buf) == NULL) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		返回 -1;
	}
	如果 (pw_dir != NULL && realpath(pw_dir, homedir) != NULL)
		comparehome = 1;

	如果 (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		返回 -1;
	}
	如果 ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		返回 -1;
	}

	/* for each component of the canonical path, walking upwards */
	为 (;;) {
		如果 ((cp = dirname(buf)) == NULL) {
			snprintf(err, errlen, "dirname() failed");
			返回 -1;
		}
		strlcpy(buf, cp, sizeof(buf));

		如果 (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			返回 -1;
		}

		/* If are past the homedir then we can stop */
		如果 (comparehome && strcmp(homedir, buf) == 0)
			break;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		如果 ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			break;
	}
	返回 0;
}

static void
usage(void)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

整数
主要(整数 argc, char **argv)
{
	const char *path = ".";
	char errmsg[256];
	整数 ch, mode = -1;
	extern char *optarg;
	extern 整数 optind;
	struct stat st;

	当 ((ch = getopt(argc, argv, "hm:")) != -1) {
		switch (ch) {
		case 'm':
			如果 (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			否则 如果 (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			否则 {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	如果 (argc > 1)
		usage();
	否则 如果 (argc == 1)
		path = argv[0];

	如果 (mode == 1)
		safely_chroot(path, getuid());
	否则 如果 (mode == 2) {
		如果 (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		如果 (auth_secure_path(path, &st, NULL, 0,
		    errmsg, sizeof(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} 否则 {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	返回 0;
}
