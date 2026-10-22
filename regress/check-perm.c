/*
 * Placed in the public domain
 */

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/stat.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <pwd.h>
#ifdef HAVE_LIBGEN_H
#অন্তর্ভাৱ <libgen.h>
#endif

স্থির শূন্য
fatal(ধ্রুৱ ৱর্ণ *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fputc('\n', stderr);
	va_end(args);
	exit(1);
}
/* Based on session.c. NB. keep tests in sync */
স্থির শূন্য
safely_chroot(ধ্রুৱ ৱর্ণ *path, uid_t uid)
{
	ধ্রুৱ ৱর্ণ *cp;
	ৱর্ণ component[PATH_MAX];
	সংরচনা stat st;

	যদি (*path != '/')
		fatal("chroot path does not begin at root");
	যদি (strlen(path) >= পরিমাণ(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	বাবে (cp = path; cp != রিক্ত;) {
		যদি ((cp = strchr(cp, '/')) == রিক্ত)
			strlcpy(component, path, পরিমাণ(component));
		অন্যথা {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		যদি (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		যদি (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == রিক্ত ? "" : "component ", component);
		যদি (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == রিক্ত ? "" : "component ", component);

	}

	যদি (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
পূর্ণাঙ্ক
platform_sys_dir_uid(uid_t uid)
{
	যদি (uid == 0)
		ঘূৰাই 1;
#ifdef PLATFORM_SYS_DIR_UID
	যদি (uid == PLATFORM_SYS_DIR_UID)
		ঘূৰাই 1;
#endif
	ঘূৰাই 0;
}

/* from auth.c */
পূর্ণাঙ্ক
auth_secure_path(ধ্রুৱ ৱর্ণ *name, সংরচনা stat *stp, ধ্রুৱ ৱর্ণ *pw_dir,
    uid_t uid, ৱর্ণ *err, size_t errlen)
{
	ৱর্ণ buf[PATH_MAX], homedir[PATH_MAX];
	ৱর্ণ *cp;
	পূর্ণাঙ্ক comparehome = 0;
	সংরচনা stat st;

	যদি (realpath(name, buf) == রিক্ত) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ঘূৰাই -1;
	}
	যদি (pw_dir != রিক্ত && realpath(pw_dir, homedir) != রিক্ত)
		comparehome = 1;

	যদি (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ঘূৰাই -1;
	}
	যদি ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ঘূৰাই -1;
	}

	/* for each component of the canonical path, walking upwards */
	বাবে (;;) {
		যদি ((cp = dirname(buf)) == রিক্ত) {
			snprintf(err, errlen, "dirname() failed");
			ঘূৰাই -1;
		}
		strlcpy(buf, cp, পরিমাণ(buf));

		যদি (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ঘূৰাই -1;
		}

		/* If are past the homedir then we can stop */
		যদি (comparehome && strcmp(homedir, buf) == 0)
			ভঙ্গ;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		যদি ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			ভঙ্গ;
	}
	ঘূৰাই 0;
}

স্থির শূন্য
usage(শূন্য)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

পূর্ণাঙ্ক
main(পূর্ণাঙ্ক argc, ৱর্ণ **argv)
{
	ধ্রুৱ ৱর্ণ *path = ".";
	ৱর্ণ errmsg[256];
	পূর্ণাঙ্ক ch, mode = -1;
	বাহ্য ৱর্ণ *optarg;
	বাহ্য পূর্ণাঙ্ক optind;
	সংরচনা stat st;

	যেতিয়ালৈ ((ch = getopt(argc, argv, "hm:")) != -1) {
		ৱিকল্প (ch) {
		পক্ষ 'm':
			যদি (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			অন্যথা যদি (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			অন্যথা {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			ভঙ্গ;
		স্ৱভাৱ:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	যদি (argc > 1)
		usage();
	অন্যথা যদি (argc == 1)
		path = argv[0];

	যদি (mode == 1)
		safely_chroot(path, getuid());
	অন্যথা যদি (mode == 2) {
		যদি (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		যদি (auth_secure_path(path, &st, রিক্ত, 0,
		    errmsg, পরিমাণ(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} অন্যথা {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	ঘূৰাই 0;
}
