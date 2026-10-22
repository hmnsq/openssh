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
#که_تعریف_شوی HAVE_LIBGEN_H
#ضمن <libgen.h>
#د_که_پای

ساكن فراغ
fatal(ثابت حرف *fmt, ...)
{
	va_list دلیلونه;

	va_start(دلیلونه, fmt);
	vfprintf(stderr, fmt, دلیلونه);
	fputc('\n', stderr);
	va_end(دلیلونه);
	وتل(1);
}
/* Based on session.c. NB. keep tests in sync */
ساكن فراغ
safely_chroot(ثابت حرف *لار, uid_t uid)
{
	ثابت حرف *cp;
	حرف component[PATH_MAX];
	بنية stat st;

	إذا (*لار != '/')
		fatal("chroot path does not begin at root");
	إذا (مزي_اوږدوالی(لار) >= حجم(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	لكل (cp = لار; cp != عدم;) {
		إذا ((cp = strchr(cp, '/')) == عدم)
			strlcpy(component, لار, حجم(component));
		وإلا {
			cp++;
			حافظه_نقل(component, لار, cp - لار);
			component[cp - لار] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		إذا (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		إذا (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == عدم ? "" : "component ", component);
		إذا (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == عدم ? "" : "component ", component);

	}

	إذا (chdir(لار) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", لار, strerror(errno));
}

/* from platform.c */
صحيح
platform_sys_dir_uid(uid_t uid)
{
	إذا (uid == 0)
		أرجع 1;
#که_تعریف_شوی PLATFORM_SYS_DIR_UID
	إذا (uid == PLATFORM_SYS_DIR_UID)
		أرجع 1;
#د_که_پای
	أرجع 0;
}

/* from auth.c */
صحيح
auth_secure_لار(ثابت حرف *name, بنية stat *stp, ثابت حرف *pw_dir,
    uid_t uid, حرف *err, اندازه_t errlen)
{
	حرف buf[PATH_MAX], homedir[PATH_MAX];
	حرف *cp;
	صحيح comparehome = 0;
	بنية stat st;

	إذا (realpath(name, buf) == عدم) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		أرجع -1;
	}
	إذا (pw_dir != عدم && realpath(pw_dir, homedir) != عدم)
		comparehome = 1;

	إذا (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		أرجع -1;
	}
	إذا ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		أرجع -1;
	}

	/* for each component of the canonical path, walking upwards */
	لكل (;;) {
		إذا ((cp = dirname(buf)) == عدم) {
			snprintf(err, errlen, "dirname() failed");
			أرجع -1;
		}
		strlcpy(buf, cp, حجم(buf));

		إذا (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			أرجع -1;
		}

		/* If are past the homedir then we can stop */
		إذا (comparehome && strcmp(homedir, buf) == 0)
			اكسر;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		إذا ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			اكسر;
	}
	أرجع 0;
}

ساكن فراغ
usage(فراغ)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	وتل(1);
}

صحيح
اصلي(صحيح argc, حرف **argv)
{
	ثابت حرف *لار = ".";
	حرف errmsg[256];
	صحيح ch, ډېرپېښ = -1;
	خارجي حرف *optarg;
	خارجي صحيح optind;
	بنية stat st;

	طالما ((ch = getopt(argc, argv, "hm:")) != -1) {
		بدل (ch) {
		حالة 'm':
			إذا (strcasecmp(optarg, "chroot") == 0)
				ډېرپېښ = 1;
			وإلا إذا (strcasecmp(optarg, "keys-command") == 0)
				ډېرپېښ = 2;
			وإلا {
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

	إذا (argc > 1)
		usage();
	وإلا إذا (argc == 1)
		لار = argv[0];

	إذا (ډېرپېښ == 1)
		safely_chroot(لار, getuid());
	وإلا إذا (ډېرپېښ == 2) {
		إذا (stat(لار, &st) < 0)
			fatal("Could not stat %s: %s", لار, strerror(errno));
		إذا (auth_secure_لار(لار, &st, عدم, 0,
		    errmsg, حجم(errmsg)) != 0)
			fatal("Unsafe %s: %s", لار, errmsg);
	} وإلا {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	أرجع 0;
}
