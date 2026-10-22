/*
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>
#شامل <unistd.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <stdlib.h>
#شامل <errno.h>
#شامل <pwd.h>
#ifdef HAVE_LIBGEN_H
#شامل <libgen.h>
#endif

ایستا تهی
fatal(ثابت نویسه *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fputc('\n', stderr);
	va_end(args);
	exit(1);
}
/* Based on session.c. NB. keep tests in sync */
ایستا تهی
safely_chroot(ثابت نویسه *path, uid_t uid)
{
	ثابت نویسه *cp;
	نویسه component[PATH_MAX];
	ساختار stat st;

	اگر (*path != '/')
		fatal("chroot path does not begin at root");
	اگر (strlen(path) >= اندازه(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	برای (cp = path; cp != پوچ;) {
		اگر ((cp = strchr(cp, '/')) == پوچ)
			strlcpy(component, path, اندازه(component));
		وگرنه {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		اگر (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		اگر (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == پوچ ? "" : "component ", component);
		اگر (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == پوچ ? "" : "component ", component);

	}

	اگر (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
صحیح
platform_sys_dir_uid(uid_t uid)
{
	اگر (uid == 0)
		بازگشت 1;
#ifdef PLATFORM_SYS_DIR_UID
	اگر (uid == PLATFORM_SYS_DIR_UID)
		بازگشت 1;
#endif
	بازگشت 0;
}

/* from auth.c */
صحیح
auth_secure_path(ثابت نویسه *name, ساختار stat *stp, ثابت نویسه *pw_dir,
    uid_t uid, نویسه *err, size_t errlen)
{
	نویسه buf[PATH_MAX], homedir[PATH_MAX];
	نویسه *cp;
	صحیح comparehome = 0;
	ساختار stat st;

	اگر (realpath(name, buf) == پوچ) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		بازگشت -1;
	}
	اگر (pw_dir != پوچ && realpath(pw_dir, homedir) != پوچ)
		comparehome = 1;

	اگر (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		بازگشت -1;
	}
	اگر ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		بازگشت -1;
	}

	/* for each component of the canonical path, walking upwards */
	برای (;;) {
		اگر ((cp = dirname(buf)) == پوچ) {
			snprintf(err, errlen, "dirname() failed");
			بازگشت -1;
		}
		strlcpy(buf, cp, اندازه(buf));

		اگر (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			بازگشت -1;
		}

		/* If are past the homedir then we can stop */
		اگر (comparehome && strcmp(homedir, buf) == 0)
			بشکن;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		اگر ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			بشکن;
	}
	بازگشت 0;
}

ایستا تهی
usage(تهی)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

صحیح
اصلی(صحیح argc, نویسه **argv)
{
	ثابت نویسه *path = ".";
	نویسه errmsg[256];
	صحیح ch, mode = -1;
	بیرونی نویسه *optarg;
	بیرونی صحیح optind;
	ساختار stat st;

	وقتی ((ch = getopt(argc, argv, "hm:")) != -1) {
		انتخاب (ch) {
		حالت 'm':
			اگر (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			وگرنه اگر (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			وگرنه {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			بشکن;
		پیشفرض:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	اگر (argc > 1)
		usage();
	وگرنه اگر (argc == 1)
		path = argv[0];

	اگر (mode == 1)
		safely_chroot(path, getuid());
	وگرنه اگر (mode == 2) {
		اگر (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		اگر (auth_secure_path(path, &st, پوچ, 0,
		    errmsg, اندازه(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} وگرنه {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	بازگشت 0;
}
