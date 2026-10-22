/*
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ifdef HAVE_LIBGEN_H
#ಅನ್ತರ್ಭಾವ <libgen.h>
#endif

ಸ್ಥಿರ ಶೂನ್ಯ
fatal(ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fputc('\n', stderr);
	va_end(args);
	exit(1);
}
/* Based on session.c. NB. keep tests in sync */
ಸ್ಥಿರ ಶೂನ್ಯ
safely_chroot(ಧ್ರುವ ವರ್ಣ *path, uid_t uid)
{
	ಧ್ರುವ ವರ್ಣ *cp;
	ವರ್ಣ component[PATH_MAX];
	ಸಂರಚನಾ stat st;

	ಯದಿ (*path != '/')
		fatal("chroot path does not begin at root");
	ಯದಿ (strlen(path) >= ಪರಿಮಾಣ(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	ಪ್ರತಿ (cp = path; cp != ರಿಕ್ತ;) {
		ಯದಿ ((cp = strchr(cp, '/')) == ರಿಕ್ತ)
			strlcpy(component, path, ಪರಿಮಾಣ(component));
		ಅನ್ಯಥಾ {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		ಯದಿ (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		ಯದಿ (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == ರಿಕ್ತ ? "" : "component ", component);
		ಯದಿ (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == ರಿಕ್ತ ? "" : "component ", component);

	}

	ಯದಿ (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
ಪೂರ್ಣಾಙ್ಕ
platform_sys_dir_uid(uid_t uid)
{
	ಯದಿ (uid == 0)
		ಪ್ರತ್ಯಾಗಮ 1;
#ifdef PLATFORM_SYS_DIR_UID
	ಯದಿ (uid == PLATFORM_SYS_DIR_UID)
		ಪ್ರತ್ಯಾಗಮ 1;
#endif
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* from auth.c */
ಪೂರ್ಣಾಙ್ಕ
auth_secure_path(ಧ್ರುವ ವರ್ಣ *name, ಸಂರಚನಾ stat *stp, ಧ್ರುವ ವರ್ಣ *pw_dir,
    uid_t uid, ವರ್ಣ *err, size_t errlen)
{
	ವರ್ಣ buf[PATH_MAX], homedir[PATH_MAX];
	ವರ್ಣ *cp;
	ಪೂರ್ಣಾಙ್ಕ comparehome = 0;
	ಸಂರಚನಾ stat st;

	ಯದಿ (realpath(name, buf) == ರಿಕ್ತ) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (pw_dir != ರಿಕ್ತ && realpath(pw_dir, homedir) != ರಿಕ್ತ)
		comparehome = 1;

	ಯದಿ (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* for each component of the canonical path, walking upwards */
	ಪ್ರತಿ (;;) {
		ಯದಿ ((cp = dirname(buf)) == ರಿಕ್ತ) {
			snprintf(err, errlen, "dirname() failed");
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		strlcpy(buf, cp, ಪರಿಮಾಣ(buf));

		ಯದಿ (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ಪ್ರತ್ಯಾಗಮ -1;
		}

		/* If are past the homedir then we can stop */
		ಯದಿ (comparehome && strcmp(homedir, buf) == 0)
			ಭಙ್ಗ;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		ಯದಿ ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			ಭಙ್ಗ;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ಧ್ರುವ ವರ್ಣ *path = ".";
	ವರ್ಣ errmsg[256];
	ಪೂರ್ಣಾಙ್ಕ ch, mode = -1;
	ಬಾಹ್ಯ ವರ್ಣ *optarg;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ optind;
	ಸಂರಚನಾ stat st;

	ಯಾವತ್ ((ch = getopt(argc, argv, "hm:")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ 'm':
			ಯದಿ (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			ಅನ್ಯಥಾ ಯದಿ (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			ಅನ್ಯಥಾ {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	ಯದಿ (argc > 1)
		usage();
	ಅನ್ಯಥಾ ಯದಿ (argc == 1)
		path = argv[0];

	ಯದಿ (mode == 1)
		safely_chroot(path, getuid());
	ಅನ್ಯಥಾ ಯದಿ (mode == 2) {
		ಯದಿ (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		ಯದಿ (auth_secure_path(path, &st, ರಿಕ್ತ, 0,
		    errmsg, ಪರಿಮಾಣ(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} ಅನ್ಯಥಾ {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}
