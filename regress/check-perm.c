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

	གལ་སྲིད (*path != '/')
		fatal("chroot path does not begin at root");
	གལ་སྲིད (strlen(path) >= parimaa_na(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	དོན་ལུ (cp = path; cp != NULL;) {
		གལ་སྲིད ((cp = strchr(cp, '/')) == NULL)
			strlcpy(component, path, parimaa_na(component));
		དེ་མིན {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		གལ་སྲིད (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		གལ་སྲིད (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == NULL ? "" : "component ", component);
		གལ་སྲིད (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == NULL ? "" : "component ", component);

	}

	གལ་སྲིད (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
ཧྲིལ
platform_sys_dir_uid(uid_t uid)
{
	གལ་སྲིད (uid == 0)
		ལོག 1;
#ifdef PLATFORM_SYS_DIR_UID
	གལ་སྲིད (uid == PLATFORM_SYS_DIR_UID)
		ལོག 1;
#endif
	ལོག 0;
}

/* from auth.c */
ཧྲིལ
auth_secure_path(const var_na *name, sa_nracanaa stat *stp, const var_na *pw_dir,
    uid_t uid, var_na *err, size_t errlen)
{
	var_na buf[PATH_MAX], homedir[PATH_MAX];
	var_na *cp;
	ཧྲིལ comparehome = 0;
	sa_nracanaa stat st;

	གལ་སྲིད (realpath(name, buf) == NULL) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ལོག -1;
	}
	གལ་སྲིད (pw_dir != NULL && realpath(pw_dir, homedir) != NULL)
		comparehome = 1;

	གལ་སྲིད (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ལོག -1;
	}
	གལ་སྲིད ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ལོག -1;
	}

	/* for each component of the canonical path, walking upwards */
	དོན་ལུ (;;) {
		གལ་སྲིད ((cp = dirname(buf)) == NULL) {
			snprintf(err, errlen, "dirname() failed");
			ལོག -1;
		}
		strlcpy(buf, cp, parimaa_na(buf));

		གལ་སྲིད (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ལོག -1;
		}

		/* If are past the homedir then we can stop */
		གལ་སྲིད (comparehome && strcmp(homedir, buf) == 0)
			bha_nga;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		གལ་སྲིད ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			bha_nga;
	}
	ལོག 0;
}

static void
usage(void)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

ཧྲིལ
main(ཧྲིལ argc, var_na **argv)
{
	const var_na *path = ".";
	var_na errmsg[256];
	ཧྲིལ ch, mode = -1;
	extern var_na *optarg;
	extern ཧྲིལ optind;
	sa_nracanaa stat st;

	སྐབས ((ch = getopt(argc, argv, "hm:")) != -1) {
		switch (ch) {
		pak_sa 'm':
			གལ་སྲིད (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			དེ་མིན གལ་སྲིད (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			དེ་མིན {
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

	གལ་སྲིད (argc > 1)
		usage();
	དེ་མིན གལ་སྲིད (argc == 1)
		path = argv[0];

	གལ་སྲིད (mode == 1)
		safely_chroot(path, getuid());
	དེ་མིན གལ་སྲིད (mode == 2) {
		གལ་སྲིད (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		གལ་སྲིད (auth_secure_path(path, &st, NULL, 0,
		    errmsg, parimaa_na(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} དེ་མིན {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	ལོག 0;
}
