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

	만약 (*path != '/')
		fatal("chroot path does not begin at root");
	만약 (strlen(path) >= sizeof(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	위해 (cp = path; cp != NULL;) {
		만약 ((cp = strchr(cp, '/')) == NULL)
			strlcpy(component, path, sizeof(component));
		아니면 {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		만약 (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		만약 (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == NULL ? "" : "component ", component);
		만약 (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == NULL ? "" : "component ", component);

	}

	만약 (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
정수
platform_sys_dir_uid(uid_t uid)
{
	만약 (uid == 0)
		반환 1;
#ifdef PLATFORM_SYS_DIR_UID
	만약 (uid == PLATFORM_SYS_DIR_UID)
		반환 1;
#endif
	반환 0;
}

/* from auth.c */
정수
auth_secure_path(const char *name, struct stat *stp, const char *pw_dir,
    uid_t uid, char *err, size_t errlen)
{
	char buf[PATH_MAX], homedir[PATH_MAX];
	char *cp;
	정수 comparehome = 0;
	struct stat st;

	만약 (realpath(name, buf) == NULL) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		반환 -1;
	}
	만약 (pw_dir != NULL && realpath(pw_dir, homedir) != NULL)
		comparehome = 1;

	만약 (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		반환 -1;
	}
	만약 ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		반환 -1;
	}

	/* for each component of the canonical path, walking upwards */
	위해 (;;) {
		만약 ((cp = dirname(buf)) == NULL) {
			snprintf(err, errlen, "dirname() failed");
			반환 -1;
		}
		strlcpy(buf, cp, sizeof(buf));

		만약 (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			반환 -1;
		}

		/* If are past the homedir then we can stop */
		만약 (comparehome && strcmp(homedir, buf) == 0)
			break;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		만약 ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			break;
	}
	반환 0;
}

static void
usage(void)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

정수
main(정수 argc, char **argv)
{
	const char *path = ".";
	char errmsg[256];
	정수 ch, mode = -1;
	extern char *optarg;
	extern 정수 optind;
	struct stat st;

	동안 ((ch = getopt(argc, argv, "hm:")) != -1) {
		switch (ch) {
		case 'm':
			만약 (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			아니면 만약 (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			아니면 {
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

	만약 (argc > 1)
		usage();
	아니면 만약 (argc == 1)
		path = argv[0];

	만약 (mode == 1)
		safely_chroot(path, getuid());
	아니면 만약 (mode == 2) {
		만약 (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		만약 (auth_secure_path(path, &st, NULL, 0,
		    errmsg, sizeof(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} 아니면 {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	반환 0;
}
