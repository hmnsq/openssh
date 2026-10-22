/*
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <pwd.h>
#ifdef HAVE_LIBGEN_H
#அந்தர்பாவ <libgen.h>
#endif

நிலையான வெறுமை
fatal(மாறிலி எழுத்து *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fputc('\n', stderr);
	va_end(args);
	exit(1);
}
/* Based on session.c. NB. keep tests in sync */
நிலையான வெறுமை
safely_chroot(மாறிலி எழுத்து *path, uid_t uid)
{
	மாறிலி எழுத்து *cp;
	எழுத்து component[PATH_MAX];
	கட்டமைப்பு stat st;

	எனில் (*path != '/')
		fatal("chroot path does not begin at root");
	எனில் (strlen(path) >= அளவு(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	க்கு (cp = path; cp != வெற்று;) {
		எனில் ((cp = strchr(cp, '/')) == வெற்று)
			strlcpy(component, path, அளவு(component));
		இல்லையெனில் {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		எனில் (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		எனில் (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == வெற்று ? "" : "component ", component);
		எனில் (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == வெற்று ? "" : "component ", component);

	}

	எனில் (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
முழு
platform_sys_dir_uid(uid_t uid)
{
	எனில் (uid == 0)
		திரும்பு 1;
#ifdef PLATFORM_SYS_DIR_UID
	எனில் (uid == PLATFORM_SYS_DIR_UID)
		திரும்பு 1;
#endif
	திரும்பு 0;
}

/* from auth.c */
முழு
auth_secure_path(மாறிலி எழுத்து *name, கட்டமைப்பு stat *stp, மாறிலி எழுத்து *pw_dir,
    uid_t uid, எழுத்து *err, size_t errlen)
{
	எழுத்து buf[PATH_MAX], homedir[PATH_MAX];
	எழுத்து *cp;
	முழு comparehome = 0;
	கட்டமைப்பு stat st;

	எனில் (realpath(name, buf) == வெற்று) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		திரும்பு -1;
	}
	எனில் (pw_dir != வெற்று && realpath(pw_dir, homedir) != வெற்று)
		comparehome = 1;

	எனில் (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		திரும்பு -1;
	}
	எனில் ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		திரும்பு -1;
	}

	/* for each component of the canonical path, walking upwards */
	க்கு (;;) {
		எனில் ((cp = dirname(buf)) == வெற்று) {
			snprintf(err, errlen, "dirname() failed");
			திரும்பு -1;
		}
		strlcpy(buf, cp, அளவு(buf));

		எனில் (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			திரும்பு -1;
		}

		/* If are past the homedir then we can stop */
		எனில் (comparehome && strcmp(homedir, buf) == 0)
			நிறுத்து;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		எனில் ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			நிறுத்து;
	}
	திரும்பு 0;
}

நிலையான வெறுமை
usage(வெறுமை)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	மாறிலி எழுத்து *path = ".";
	எழுத்து errmsg[256];
	முழு ch, mode = -1;
	வெளி எழுத்து *optarg;
	வெளி முழு optind;
	கட்டமைப்பு stat st;

	போது ((ch = getopt(argc, argv, "hm:")) != -1) {
		தேர்வு (ch) {
		நிலை 'm':
			எனில் (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			இல்லையெனில் எனில் (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			இல்லையெனில் {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			நிறுத்து;
		இயல்பு:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	எனில் (argc > 1)
		usage();
	இல்லையெனில் எனில் (argc == 1)
		path = argv[0];

	எனில் (mode == 1)
		safely_chroot(path, getuid());
	இல்லையெனில் எனில் (mode == 2) {
		எனில் (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		எனில் (auth_secure_path(path, &st, வெற்று, 0,
		    errmsg, அளவு(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} இல்லையெனில் {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	திரும்பு 0;
}
