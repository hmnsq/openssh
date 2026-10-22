/*
 * Placed in the public domain
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <pwd.h>
#ifdef HAVE_LIBGEN_H
#অন্তর্ভাব <libgen.h>
#endif

স্থির শূন্য
fatal(ধ্রুবক অক্ষর *fmt, ...)
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
safely_chroot(ধ্রুবক অক্ষর *path, uid_t uid)
{
	ধ্রুবক অক্ষর *cp;
	অক্ষর component[PATH_MAX];
	কাঠামো stat st;

	যদি (*path != '/')
		fatal("chroot path does not begin at root");
	যদি (strlen(path) >= আকার(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	জন্য (cp = path; cp != ফাঁকা;) {
		যদি ((cp = strchr(cp, '/')) == ফাঁকা)
			strlcpy(component, path, আকার(component));
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
			    cp == ফাঁকা ? "" : "component ", component);
		যদি (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == ফাঁকা ? "" : "component ", component);

	}

	যদি (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
পূর্ণসংখ্যা
platform_sys_dir_uid(uid_t uid)
{
	যদি (uid == 0)
		ফেরত 1;
#ifdef PLATFORM_SYS_DIR_UID
	যদি (uid == PLATFORM_SYS_DIR_UID)
		ফেরত 1;
#endif
	ফেরত 0;
}

/* from auth.c */
পূর্ণসংখ্যা
auth_secure_path(ধ্রুবক অক্ষর *name, কাঠামো stat *stp, ধ্রুবক অক্ষর *pw_dir,
    uid_t uid, অক্ষর *err, আকার_t errlen)
{
	অক্ষর buf[PATH_MAX], homedir[PATH_MAX];
	অক্ষর *cp;
	পূর্ণসংখ্যা comparehome = 0;
	কাঠামো stat st;

	যদি (realpath(name, buf) == ফাঁকা) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ফেরত -1;
	}
	যদি (pw_dir != ফাঁকা && realpath(pw_dir, homedir) != ফাঁকা)
		comparehome = 1;

	যদি (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ফেরত -1;
	}
	যদি ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ফেরত -1;
	}

	/* for each component of the canonical path, walking upwards */
	জন্য (;;) {
		যদি ((cp = dirname(buf)) == ফাঁকা) {
			snprintf(err, errlen, "dirname() failed");
			ফেরত -1;
		}
		strlcpy(buf, cp, আকার(buf));

		যদি (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ফেরত -1;
		}

		/* If are past the homedir then we can stop */
		যদি (comparehome && strcmp(homedir, buf) == 0)
			বিরতি;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		যদি ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			বিরতি;
	}
	ফেরত 0;
}

স্থির শূন্য
usage(শূন্য)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা argc, অক্ষর **argv)
{
	ধ্রুবক অক্ষর *path = ".";
	অক্ষর errmsg[256];
	পূর্ণসংখ্যা ch, mode = -1;
	বাহ্যিক অক্ষর *optarg;
	বাহ্যিক পূর্ণসংখ্যা optind;
	কাঠামো stat st;

	যখন ((ch = getopt(argc, argv, "hm:")) != -1) {
		নির্বাচন (ch) {
		ক্ষেত্র 'm':
			যদি (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			অন্যথা যদি (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			অন্যথা {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			বিরতি;
		পূর্বনির্ধারিত:
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
		যদি (auth_secure_path(path, &st, ফাঁকা, 0,
		    errmsg, আকার(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} অন্যথা {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	ফেরত 0;
}
