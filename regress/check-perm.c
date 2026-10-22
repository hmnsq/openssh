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
#اگر_تعریف_شدہ HAVE_LIBGEN_H
#شامل <libgen.h>
#اگر_ختم

ساکن خالی
fatal(ثابت حرف *fmt, ...)
{
	va_list دلائل;

	va_start(دلائل, fmt);
	vfprintf(stderr, fmt, دلائل);
	fputc('\n', stderr);
	va_end(دلائل);
	باہر_نکلو(1);
}
/* Based on session.c. NB. keep tests in sync */
ساکن خالی
safely_chroot(ثابت حرف *راستہ, uid_t uid)
{
	ثابت حرف *cp;
	حرف component[PATH_MAX];
	ساخت stat st;

	اگر (*راستہ != '/')
		fatal("chroot path does not begin at root");
	اگر (لڑی_لمبائی(راستہ) >= حجم(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	برائے (cp = راستہ; cp != تہی;) {
		اگر ((cp = strchr(cp, '/')) == تہی)
			strlcpy(component, راستہ, حجم(component));
		ورنہ {
			cp++;
			حافظہ_نقل(component, راستہ, cp - راستہ);
			component[cp - راستہ] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		اگر (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		اگر (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == تہی ? "" : "component ", component);
		اگر (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == تہی ? "" : "component ", component);

	}

	اگر (chdir(راستہ) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", راستہ, strerror(errno));
}

/* from platform.c */
صحیح
platform_sys_dir_uid(uid_t uid)
{
	اگر (uid == 0)
		واپس 1;
#اگر_تعریف_شدہ PLATFORM_SYS_DIR_UID
	اگر (uid == PLATFORM_SYS_DIR_UID)
		واپس 1;
#اگر_ختم
	واپس 0;
}

/* from auth.c */
صحیح
auth_secure_راستہ(ثابت حرف *name, ساخت stat *stp, ثابت حرف *pw_dir,
    uid_t uid, حرف *err, سائز_t errlen)
{
	حرف buf[PATH_MAX], homedir[PATH_MAX];
	حرف *cp;
	صحیح comparehome = 0;
	ساخت stat st;

	اگر (realpath(name, buf) == تہی) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		واپس -1;
	}
	اگر (pw_dir != تہی && realpath(pw_dir, homedir) != تہی)
		comparehome = 1;

	اگر (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		واپس -1;
	}
	اگر ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		واپس -1;
	}

	/* for each component of the canonical path, walking upwards */
	برائے (;;) {
		اگر ((cp = dirname(buf)) == تہی) {
			snprintf(err, errlen, "dirname() failed");
			واپس -1;
		}
		strlcpy(buf, cp, حجم(buf));

		اگر (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			واپس -1;
		}

		/* If are past the homedir then we can stop */
		اگر (comparehome && strcmp(homedir, buf) == 0)
			توڑو;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		اگر ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			توڑو;
	}
	واپس 0;
}

ساکن خالی
usage(خالی)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	باہر_نکلو(1);
}

صحیح
مین(صحیح argc, حرف **argv)
{
	ثابت حرف *راستہ = ".";
	حرف errmsg[256];
	صحیح ch, منوال = -1;
	خارجی حرف *optarg;
	خارجی صحیح optind;
	ساخت stat st;

	جب ((ch = getopt(argc, argv, "hm:")) != -1) {
		انتخاب (ch) {
		حالت 'm':
			اگر (strcasecmp(optarg, "chroot") == 0)
				منوال = 1;
			ورنہ اگر (strcasecmp(optarg, "keys-command") == 0)
				منوال = 2;
			ورنہ {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			توڑو;
		طےشدہ:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	اگر (argc > 1)
		usage();
	ورنہ اگر (argc == 1)
		راستہ = argv[0];

	اگر (منوال == 1)
		safely_chroot(راستہ, getuid());
	ورنہ اگر (منوال == 2) {
		اگر (stat(راستہ, &st) < 0)
			fatal("Could not stat %s: %s", راستہ, strerror(errno));
		اگر (auth_secure_راستہ(راستہ, &st, تہی, 0,
		    errmsg, حجم(errmsg)) != 0)
			fatal("Unsafe %s: %s", راستہ, errmsg);
	} ورنہ {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	واپس 0;
}
