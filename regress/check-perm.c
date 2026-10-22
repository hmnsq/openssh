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
#جيڪڏهن_وصف_ٿيل HAVE_LIBGEN_H
#ضمن <libgen.h>
#جيڪڏهن_پورو

ساكن فراغ
fatal(ثابت حرف *fmt, ...)
{
	va_list دليلون;

	va_start(دليلون, fmt);
	vfprintf(stderr, fmt, دليلون);
	fputc('\n', stderr);
	va_end(دليلون);
	ٻاهر_نڪرو(1);
}
/* Based on session.c. NB. keep tests in sync */
ساكن فراغ
safely_chroot(ثابت حرف *رستو, uid_t uid)
{
	ثابت حرف *cp;
	حرف component[PATH_MAX];
	بنية stat st;

	إذا (*رستو != '/')
		fatal("chroot path does not begin at root");
	إذا (لڙي_ڊيگهه(رستو) >= حجم(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	لكل (cp = رستو; cp != عدم;) {
		إذا ((cp = strchr(cp, '/')) == عدم)
			strlcpy(component, رستو, حجم(component));
		وإلا {
			cp++;
			يادگيري_نقل(component, رستو, cp - رستو);
			component[cp - رستو] = '\0';
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

	إذا (chdir(رستو) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", رستو, strerror(errno));
}

/* from platform.c */
صحيح
platform_sys_dir_uid(uid_t uid)
{
	إذا (uid == 0)
		أرجع 1;
#جيڪڏهن_وصف_ٿيل PLATFORM_SYS_DIR_UID
	إذا (uid == PLATFORM_SYS_DIR_UID)
		أرجع 1;
#جيڪڏهن_پورو
	أرجع 0;
}

/* from auth.c */
صحيح
auth_secure_رستو(ثابت حرف *name, بنية stat *stp, ثابت حرف *pw_dir,
    uid_t uid, حرف *err, سائيز_t errlen)
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
	ٻاهر_نڪرو(1);
}

صحيح
مکيه(صحيح argc, حرف **argv)
{
	ثابت حرف *رستو = ".";
	حرف errmsg[256];
	صحيح ch, گهڻائي = -1;
	خارجي حرف *optarg;
	خارجي صحيح optind;
	بنية stat st;

	طالما ((ch = getopt(argc, argv, "hm:")) != -1) {
		بدل (ch) {
		حالة 'm':
			إذا (strcasecmp(optarg, "chroot") == 0)
				گهڻائي = 1;
			وإلا إذا (strcasecmp(optarg, "keys-command") == 0)
				گهڻائي = 2;
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
		رستو = argv[0];

	إذا (گهڻائي == 1)
		safely_chroot(رستو, getuid());
	وإلا إذا (گهڻائي == 2) {
		إذا (stat(رستو, &st) < 0)
			fatal("Could not stat %s: %s", رستو, strerror(errno));
		إذا (auth_secure_رستو(رستو, &st, عدم, 0,
		    errmsg, حجم(errmsg)) != 0)
			fatal("Unsafe %s: %s", رستو, errmsg);
	} وإلا {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	أرجع 0;
}
