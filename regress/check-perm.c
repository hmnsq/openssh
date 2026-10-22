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

	ако (*path != '/')
		fatal("chroot path does not begin at root");
	ако (strlen(path) >= sizeof(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	за (cp = path; cp != NULL;) {
		ако ((cp = strchr(cp, '/')) == NULL)
			strlcpy(component, path, sizeof(component));
		инако {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		ако (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		ако (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == NULL ? "" : "component ", component);
		ако (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == NULL ? "" : "component ", component);

	}

	ако (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
цео
platform_sys_dir_uid(uid_t uid)
{
	ако (uid == 0)
		врати 1;
#ifdef PLATFORM_SYS_DIR_UID
	ако (uid == PLATFORM_SYS_DIR_UID)
		врати 1;
#endif
	врати 0;
}

/* from auth.c */
цео
auth_secure_path(const char *name, struct stat *stp, const char *pw_dir,
    uid_t uid, char *err, size_t errlen)
{
	char buf[PATH_MAX], homedir[PATH_MAX];
	char *cp;
	цео comparehome = 0;
	struct stat st;

	ако (realpath(name, buf) == NULL) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		врати -1;
	}
	ако (pw_dir != NULL && realpath(pw_dir, homedir) != NULL)
		comparehome = 1;

	ако (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		врати -1;
	}
	ако ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		врати -1;
	}

	/* for each component of the canonical path, walking upwards */
	за (;;) {
		ако ((cp = dirname(buf)) == NULL) {
			snprintf(err, errlen, "dirname() failed");
			врати -1;
		}
		strlcpy(buf, cp, sizeof(buf));

		ако (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			врати -1;
		}

		/* If are past the homedir then we can stop */
		ако (comparehome && strcmp(homedir, buf) == 0)
			break;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		ако ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			break;
	}
	врати 0;
}

static void
usage(void)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

цео
main(цео argc, char **argv)
{
	const char *path = ".";
	char errmsg[256];
	цео ch, mode = -1;
	extern char *optarg;
	extern цео optind;
	struct stat st;

	док ((ch = getopt(argc, argv, "hm:")) != -1) {
		switch (ch) {
		case 'm':
			ако (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			инако ако (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			инако {
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

	ако (argc > 1)
		usage();
	инако ако (argc == 1)
		path = argv[0];

	ако (mode == 1)
		safely_chroot(path, getuid());
	инако ако (mode == 2) {
		ако (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		ако (auth_secure_path(path, &st, NULL, 0,
		    errmsg, sizeof(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} инако {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	врати 0;
}
