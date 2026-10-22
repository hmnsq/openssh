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

	якщо (*path != '/')
		fatal("chroot path does not begin at root");
	якщо (strlen(path) >= sizeof(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	для (cp = path; cp != NULL;) {
		якщо ((cp = strchr(cp, '/')) == NULL)
			strlcpy(component, path, sizeof(component));
		інакше {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		якщо (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		якщо (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == NULL ? "" : "component ", component);
		якщо (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == NULL ? "" : "component ", component);

	}

	якщо (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
ціле
platform_sys_dir_uid(uid_t uid)
{
	якщо (uid == 0)
		повернути 1;
#ifdef PLATFORM_SYS_DIR_UID
	якщо (uid == PLATFORM_SYS_DIR_UID)
		повернути 1;
#endif
	повернути 0;
}

/* from auth.c */
ціле
auth_secure_path(const char *name, struct stat *stp, const char *pw_dir,
    uid_t uid, char *err, size_t errlen)
{
	char buf[PATH_MAX], homedir[PATH_MAX];
	char *cp;
	ціле comparehome = 0;
	struct stat st;

	якщо (realpath(name, buf) == NULL) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		повернути -1;
	}
	якщо (pw_dir != NULL && realpath(pw_dir, homedir) != NULL)
		comparehome = 1;

	якщо (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		повернути -1;
	}
	якщо ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		повернути -1;
	}

	/* for each component of the canonical path, walking upwards */
	для (;;) {
		якщо ((cp = dirname(buf)) == NULL) {
			snprintf(err, errlen, "dirname() failed");
			повернути -1;
		}
		strlcpy(buf, cp, sizeof(buf));

		якщо (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			повернути -1;
		}

		/* If are past the homedir then we can stop */
		якщо (comparehome && strcmp(homedir, buf) == 0)
			break;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		якщо ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			break;
	}
	повернути 0;
}

static void
usage(void)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

ціле
main(ціле argc, char **argv)
{
	const char *path = ".";
	char errmsg[256];
	ціле ch, mode = -1;
	extern char *optarg;
	extern ціле optind;
	struct stat st;

	поки ((ch = getopt(argc, argv, "hm:")) != -1) {
		switch (ch) {
		case 'm':
			якщо (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			інакше якщо (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			інакше {
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

	якщо (argc > 1)
		usage();
	інакше якщо (argc == 1)
		path = argv[0];

	якщо (mode == 1)
		safely_chroot(path, getuid());
	інакше якщо (mode == 2) {
		якщо (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		якщо (auth_secure_path(path, &st, NULL, 0,
		    errmsg, sizeof(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} інакше {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	повернути 0;
}
