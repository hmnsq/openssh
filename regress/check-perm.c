/*
 * Placed in the public domain
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ifdef HAVE_LIBGEN_H
#ଅନ୍ତର୍ଭାଵ <libgen.h>
#endif

ସ୍ଥିର ଶୂନ୍ୟ
fatal(ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fputc('\n', stderr);
	va_end(args);
	exit(1);
}
/* Based on session.c. NB. keep tests in sync */
ସ୍ଥିର ଶୂନ୍ୟ
safely_chroot(ଅଚଳ ଅକ୍ଷର *path, uid_t uid)
{
	ଅଚଳ ଅକ୍ଷର *cp;
	ଅକ୍ଷର component[PATH_MAX];
	ସଂରଚନା stat st;

	ଯଦି (*path != '/')
		fatal("chroot path does not begin at root");
	ଯଦି (strlen(path) >= ଆକାର(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	ପାଇଁ (cp = path; cp != ଖାଲି;) {
		ଯଦି ((cp = strchr(cp, '/')) == ଖାଲି)
			strlcpy(component, path, ଆକାର(component));
		ଅନ୍ୟଥା {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		ଯଦି (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		ଯଦି (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == ଖାଲି ? "" : "component ", component);
		ଯଦି (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == ଖାଲି ? "" : "component ", component);

	}

	ଯଦି (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
platform_sys_dir_uid(uid_t uid)
{
	ଯଦି (uid == 0)
		ଫେରନ୍ତୁ 1;
#ifdef PLATFORM_SYS_DIR_UID
	ଯଦି (uid == PLATFORM_SYS_DIR_UID)
		ଫେରନ୍ତୁ 1;
#endif
	ଫେରନ୍ତୁ 0;
}

/* from auth.c */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth_secure_path(ଅଚଳ ଅକ୍ଷର *name, ସଂରଚନା stat *stp, ଅଚଳ ଅକ୍ଷର *pw_dir,
    uid_t uid, ଅକ୍ଷର *err, size_t errlen)
{
	ଅକ୍ଷର buf[PATH_MAX], homedir[PATH_MAX];
	ଅକ୍ଷର *cp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା comparehome = 0;
	ସଂରଚନା stat st;

	ଯଦି (realpath(name, buf) == ଖାଲି) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (pw_dir != ଖାଲି && realpath(pw_dir, homedir) != ଖାଲି)
		comparehome = 1;

	ଯଦି (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ଫେରନ୍ତୁ -1;
	}

	/* for each component of the canonical path, walking upwards */
	ପାଇଁ (;;) {
		ଯଦି ((cp = dirname(buf)) == ଖାଲି) {
			snprintf(err, errlen, "dirname() failed");
			ଫେରନ୍ତୁ -1;
		}
		strlcpy(buf, cp, ଆକାର(buf));

		ଯଦି (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ଫେରନ୍ତୁ -1;
		}

		/* If are past the homedir then we can stop */
		ଯଦି (comparehome && strcmp(homedir, buf) == 0)
			ଭାଙ୍ଗ;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		ଯଦି ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			ଭାଙ୍ଗ;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
usage(ଶୂନ୍ୟ)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ଅଚଳ ଅକ୍ଷର *path = ".";
	ଅକ୍ଷର errmsg[256];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ch, mode = -1;
	ବାହ୍ୟ ଅକ୍ଷର *optarg;
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା optind;
	ସଂରଚନା stat st;

	ଯେତେବେଳେ ((ch = getopt(argc, argv, "hm:")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି 'm':
			ଯଦି (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			ଅନ୍ୟଥା ଯଦି (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			ଅନ୍ୟଥା {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	ଯଦି (argc > 1)
		usage();
	ଅନ୍ୟଥା ଯଦି (argc == 1)
		path = argv[0];

	ଯଦି (mode == 1)
		safely_chroot(path, getuid());
	ଅନ୍ୟଥା ଯଦି (mode == 2) {
		ଯଦି (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		ଯଦି (auth_secure_path(path, &st, ଖାଲି, 0,
		    errmsg, ଆକାର(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} ଅନ୍ୟଥା {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	ଫେରନ୍ତୁ 0;
}
