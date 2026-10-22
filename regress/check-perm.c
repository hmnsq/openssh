/*
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LIBGEN_H
#ਅਨ੍ਤਰ੍ਭਾਵ <libgen.h>
#ਜੇ_ਅੰਤ

ਸਥਿਰ ਖਾਲੀ
fatal(ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ਦਲੀਲਾਂ;

	va_start(ਦਲੀਲਾਂ, fmt);
	vfprintf(stderr, fmt, ਦਲੀਲਾਂ);
	fputc('\n', stderr);
	va_end(ਦਲੀਲਾਂ);
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}
/* Based on session.c. NB. keep tests in sync */
ਸਥਿਰ ਖਾਲੀ
safely_chroot(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, uid_t uid)
{
	ਅਚਲ ਅੱਖਰ *cp;
	ਅੱਖਰ component[PATH_MAX];
	ਬਣਤਰ stat st;

	ਜੇ (*ਰਸਤਾ != '/')
		fatal("chroot path does not begin at root");
	ਜੇ (ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ) >= ਆਕਾਰ(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	ਲਈ (cp = ਰਸਤਾ; cp != ਨਿਰਾ;) {
		ਜੇ ((cp = strchr(cp, '/')) == ਨਿਰਾ)
			strlcpy(component, ਰਸਤਾ, ਆਕਾਰ(component));
		ਨਹੀਂਤਾਂ {
			cp++;
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(component, ਰਸਤਾ, cp - ਰਸਤਾ);
			component[cp - ਰਸਤਾ] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		ਜੇ (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		ਜੇ (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == ਨਿਰਾ ? "" : "component ", component);
		ਜੇ (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == ਨਿਰਾ ? "" : "component ", component);

	}

	ਜੇ (chdir(ਰਸਤਾ) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", ਰਸਤਾ, strerror(errno));
}

/* from platform.c */
ਪੂਰਨ
platform_sys_dir_uid(uid_t uid)
{
	ਜੇ (uid == 0)
		ਵਾਪਸ 1;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PLATFORM_SYS_DIR_UID
	ਜੇ (uid == PLATFORM_SYS_DIR_UID)
		ਵਾਪਸ 1;
#ਜੇ_ਅੰਤ
	ਵਾਪਸ 0;
}

/* from auth.c */
ਪੂਰਨ
auth_secure_ਰਸਤਾ(ਅਚਲ ਅੱਖਰ *name, ਬਣਤਰ stat *stp, ਅਚਲ ਅੱਖਰ *pw_dir,
    uid_t uid, ਅੱਖਰ *err, ਮਾਪ_t errlen)
{
	ਅੱਖਰ buf[PATH_MAX], homedir[PATH_MAX];
	ਅੱਖਰ *cp;
	ਪੂਰਨ comparehome = 0;
	ਬਣਤਰ stat st;

	ਜੇ (realpath(name, buf) == ਨਿਰਾ) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ਵਾਪਸ -1;
	}
	ਜੇ (pw_dir != ਨਿਰਾ && realpath(pw_dir, homedir) != ਨਿਰਾ)
		comparehome = 1;

	ਜੇ (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ਵਾਪਸ -1;
	}
	ਜੇ ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ਵਾਪਸ -1;
	}

	/* for each component of the canonical path, walking upwards */
	ਲਈ (;;) {
		ਜੇ ((cp = dirname(buf)) == ਨਿਰਾ) {
			snprintf(err, errlen, "dirname() failed");
			ਵਾਪਸ -1;
		}
		strlcpy(buf, cp, ਆਕਾਰ(buf));

		ਜੇ (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ਵਾਪਸ -1;
		}

		/* If are past the homedir then we can stop */
		ਜੇ (comparehome && strcmp(homedir, buf) == 0)
			ਰੋਕੋ;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		ਜੇ ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			ਰੋਕੋ;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
usage(ਖਾਲੀ)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਅਚਲ ਅੱਖਰ *ਰਸਤਾ = ".";
	ਅੱਖਰ errmsg[256];
	ਪੂਰਨ ch, ਬਹੁਲਕ = -1;
	ਬਾਹਰੀ ਅੱਖਰ *optarg;
	ਬਾਹਰੀ ਪੂਰਨ optind;
	ਬਣਤਰ stat st;

	ਜਦੋਂ ((ch = getopt(argc, argv, "hm:")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ 'm':
			ਜੇ (strcasecmp(optarg, "chroot") == 0)
				ਬਹੁਲਕ = 1;
			ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(optarg, "keys-command") == 0)
				ਬਹੁਲਕ = 2;
			ਨਹੀਂਤਾਂ {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			ਰੋਕੋ;
		ਮੂਲ:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	ਜੇ (argc > 1)
		usage();
	ਨਹੀਂਤਾਂ ਜੇ (argc == 1)
		ਰਸਤਾ = argv[0];

	ਜੇ (ਬਹੁਲਕ == 1)
		safely_chroot(ਰਸਤਾ, getuid());
	ਨਹੀਂਤਾਂ ਜੇ (ਬਹੁਲਕ == 2) {
		ਜੇ (stat(ਰਸਤਾ, &st) < 0)
			fatal("Could not stat %s: %s", ਰਸਤਾ, strerror(errno));
		ਜੇ (auth_secure_ਰਸਤਾ(ਰਸਤਾ, &st, ਨਿਰਾ, 0,
		    errmsg, ਆਕਾਰ(errmsg)) != 0)
			fatal("Unsafe %s: %s", ਰਸਤਾ, errmsg);
	} ਨਹੀਂਤਾਂ {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	ਵਾਪਸ 0;
}
