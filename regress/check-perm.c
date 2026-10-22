/*
 * Placed in the public domain
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>
#ضمن <unistd.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <stdlib.h>
#ضمن <errno.h>
#ضمن <pwd.h>
#ifdef HAVE_LIBGEN_H
#ضمن <libgen.h>
#endif

ساكن فراغ
fatal(ثابت حرف *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fputc('\n', stderr);
	va_end(args);
	exit(1);
}
/* Based on session.c. NB. keep tests in sync */
ساكن فراغ
safely_chroot(ثابت حرف *path, uid_t uid)
{
	ثابت حرف *cp;
	حرف component[PATH_MAX];
	بنية stat st;

	אם (*path != '/')
		fatal("chroot path does not begin at root");
	אם (strlen(path) >= حجم(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	עבור (cp = path; cp != عدم;) {
		אם ((cp = strchr(cp, '/')) == عدم)
			strlcpy(component, path, حجم(component));
		אחרת {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		אם (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		אם (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == عدم ? "" : "component ", component);
		אם (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == عدم ? "" : "component ", component);

	}

	אם (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
صحيح
platform_sys_dir_uid(uid_t uid)
{
	אם (uid == 0)
		החזר 1;
#ifdef PLATFORM_SYS_DIR_UID
	אם (uid == PLATFORM_SYS_DIR_UID)
		החזר 1;
#endif
	החזר 0;
}

/* from auth.c */
صحيح
auth_secure_path(ثابت حرف *name, بنية stat *stp, ثابت حرف *pw_dir,
    uid_t uid, حرف *err, size_t errlen)
{
	حرف buf[PATH_MAX], homedir[PATH_MAX];
	حرف *cp;
	صحيح comparehome = 0;
	بنية stat st;

	אם (realpath(name, buf) == عدم) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		החזר -1;
	}
	אם (pw_dir != عدم && realpath(pw_dir, homedir) != عدم)
		comparehome = 1;

	אם (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		החזר -1;
	}
	אם ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		החזר -1;
	}

	/* for each component of the canonical path, walking upwards */
	עבור (;;) {
		אם ((cp = dirname(buf)) == عدم) {
			snprintf(err, errlen, "dirname() failed");
			החזר -1;
		}
		strlcpy(buf, cp, حجم(buf));

		אם (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			החזר -1;
		}

		/* If are past the homedir then we can stop */
		אם (comparehome && strcmp(homedir, buf) == 0)
			اكسر;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		אם ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			اكسر;
	}
	החזר 0;
}

ساكن فراغ
usage(فراغ)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

صحيح
main(صحيح argc, حرف **argv)
{
	ثابت حرف *path = ".";
	حرف errmsg[256];
	صحيح ch, mode = -1;
	خارجي حرف *optarg;
	خارجي صحيح optind;
	بنية stat st;

	כלעוד ((ch = getopt(argc, argv, "hm:")) != -1) {
		بدل (ch) {
		حالة 'm':
			אם (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			אחרת אם (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			אחרת {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			اكسر;
		افتراضي:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	אם (argc > 1)
		usage();
	אחרת אם (argc == 1)
		path = argv[0];

	אם (mode == 1)
		safely_chroot(path, getuid());
	אחרת אם (mode == 2) {
		אם (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		אם (auth_secure_path(path, &st, عدم, 0,
		    errmsg, حجم(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} אחרת {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	החזר 0;
}
