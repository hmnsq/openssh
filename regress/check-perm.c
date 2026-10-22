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

	အကယ်၍ (*path != '/')
		fatal("chroot path does not begin at root");
	အကယ်၍ (strlen(path) >= parimaa_na(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	အတွက် (cp = path; cp != NULL;) {
		အကယ်၍ ((cp = strchr(cp, '/')) == NULL)
			strlcpy(component, path, parimaa_na(component));
		မဟုတ်ပါက {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		အကယ်၍ (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		အကယ်၍ (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == NULL ? "" : "component ", component);
		အကယ်၍ (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == NULL ? "" : "component ", component);

	}

	အကယ်၍ (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
ကိန်းပြည့်
platform_sys_dir_uid(uid_t uid)
{
	အကယ်၍ (uid == 0)
		ပြန်ပေး 1;
#ifdef PLATFORM_SYS_DIR_UID
	အကယ်၍ (uid == PLATFORM_SYS_DIR_UID)
		ပြန်ပေး 1;
#endif
	ပြန်ပေး 0;
}

/* from auth.c */
ကိန်းပြည့်
auth_secure_path(const var_na *name, sa_nracanaa stat *stp, const var_na *pw_dir,
    uid_t uid, var_na *err, size_t errlen)
{
	var_na buf[PATH_MAX], homedir[PATH_MAX];
	var_na *cp;
	ကိန်းပြည့် comparehome = 0;
	sa_nracanaa stat st;

	အကယ်၍ (realpath(name, buf) == NULL) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ပြန်ပေး -1;
	}
	အကယ်၍ (pw_dir != NULL && realpath(pw_dir, homedir) != NULL)
		comparehome = 1;

	အကယ်၍ (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ပြန်ပေး -1;
	}
	အကယ်၍ ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ပြန်ပေး -1;
	}

	/* for each component of the canonical path, walking upwards */
	အတွက် (;;) {
		အကယ်၍ ((cp = dirname(buf)) == NULL) {
			snprintf(err, errlen, "dirname() failed");
			ပြန်ပေး -1;
		}
		strlcpy(buf, cp, parimaa_na(buf));

		အကယ်၍ (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ပြန်ပေး -1;
		}

		/* If are past the homedir then we can stop */
		အကယ်၍ (comparehome && strcmp(homedir, buf) == 0)
			bha_nga;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		အကယ်၍ ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			bha_nga;
	}
	ပြန်ပေး 0;
}

static void
usage(void)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

ကိန်းပြည့်
main(ကိန်းပြည့် argc, var_na **argv)
{
	const var_na *path = ".";
	var_na errmsg[256];
	ကိန်းပြည့် ch, mode = -1;
	extern var_na *optarg;
	extern ကိန်းပြည့် optind;
	sa_nracanaa stat st;

	နေစဉ် ((ch = getopt(argc, argv, "hm:")) != -1) {
		switch (ch) {
		pak_sa 'm':
			အကယ်၍ (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			မဟုတ်ပါက အကယ်၍ (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			မဟုတ်ပါက {
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

	အကယ်၍ (argc > 1)
		usage();
	မဟုတ်ပါက အကယ်၍ (argc == 1)
		path = argv[0];

	အကယ်၍ (mode == 1)
		safely_chroot(path, getuid());
	မဟုတ်ပါက အကယ်၍ (mode == 2) {
		အကယ်၍ (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		အကယ်၍ (auth_secure_path(path, &st, NULL, 0,
		    errmsg, parimaa_na(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} မဟုတ်ပါက {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	ပြန်ပေး 0;
}
