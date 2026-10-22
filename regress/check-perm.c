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

	если (*path != '/')
		fatal("chroot path does not begin at root");
	если (strlen(path) >= sizeof(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	для (cp = path; cp != NULL;) {
		если ((cp = strchr(cp, '/')) == NULL)
			strlcpy(component, path, sizeof(component));
		иначе {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		если (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		если (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == NULL ? "" : "component ", component);
		если (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == NULL ? "" : "component ", component);

	}

	если (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
целое
platform_sys_dir_uid(uid_t uid)
{
	если (uid == 0)
		вернуть 1;
#ifdef PLATFORM_SYS_DIR_UID
	если (uid == PLATFORM_SYS_DIR_UID)
		вернуть 1;
#endif
	вернуть 0;
}

/* from auth.c */
целое
auth_secure_path(const char *name, struct stat *stp, const char *pw_dir,
    uid_t uid, char *err, size_t errlen)
{
	char buf[PATH_MAX], homedir[PATH_MAX];
	char *cp;
	целое comparehome = 0;
	struct stat st;

	если (realpath(name, buf) == NULL) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		вернуть -1;
	}
	если (pw_dir != NULL && realpath(pw_dir, homedir) != NULL)
		comparehome = 1;

	если (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		вернуть -1;
	}
	если ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		вернуть -1;
	}

	/* for each component of the canonical path, walking upwards */
	для (;;) {
		если ((cp = dirname(buf)) == NULL) {
			snprintf(err, errlen, "dirname() failed");
			вернуть -1;
		}
		strlcpy(buf, cp, sizeof(buf));

		если (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			вернуть -1;
		}

		/* If are past the homedir then we can stop */
		если (comparehome && strcmp(homedir, buf) == 0)
			break;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		если ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			break;
	}
	вернуть 0;
}

static void
usage(void)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

целое
основной(целое argc, char **argv)
{
	const char *path = ".";
	char errmsg[256];
	целое ch, mode = -1;
	extern char *optarg;
	extern целое optind;
	struct stat st;

	пока ((ch = getopt(argc, argv, "hm:")) != -1) {
		switch (ch) {
		case 'm':
			если (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			иначе если (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			иначе {
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

	если (argc > 1)
		usage();
	иначе если (argc == 1)
		path = argv[0];

	если (mode == 1)
		safely_chroot(path, getuid());
	иначе если (mode == 2) {
		если (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		если (auth_secure_path(path, &st, NULL, 0,
		    errmsg, sizeof(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} иначе {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	вернуть 0;
}
