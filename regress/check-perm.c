/*
 * Placed in the public domain
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <pwd.h>
#ifdef HAVE_LIBGEN_H
#અન્તર્ભાવ <libgen.h>
#endif

સ્થિર શૂન્ય
fatal(અચલ અક્ષર *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fputc('\n', stderr);
	va_end(args);
	exit(1);
}
/* Based on session.c. NB. keep tests in sync */
સ્થિર શૂન્ય
safely_chroot(અચલ અક્ષર *path, uid_t uid)
{
	અચલ અક્ષર *cp;
	અક્ષર component[PATH_MAX];
	સંરચના stat st;

	જો (*path != '/')
		fatal("chroot path does not begin at root");
	જો (strlen(path) >= કદ(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	માટે (cp = path; cp != ખાલી;) {
		જો ((cp = strchr(cp, '/')) == ખાલી)
			strlcpy(component, path, કદ(component));
		નહીંતર {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		જો (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		જો (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == ખાલી ? "" : "component ", component);
		જો (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == ખાલી ? "" : "component ", component);

	}

	જો (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
પૂર્ણાંક
platform_sys_dir_uid(uid_t uid)
{
	જો (uid == 0)
		પાછા 1;
#ifdef PLATFORM_SYS_DIR_UID
	જો (uid == PLATFORM_SYS_DIR_UID)
		પાછા 1;
#endif
	પાછા 0;
}

/* from auth.c */
પૂર્ણાંક
auth_secure_path(અચલ અક્ષર *name, સંરચના stat *stp, અચલ અક્ષર *pw_dir,
    uid_t uid, અક્ષર *err, size_t errlen)
{
	અક્ષર buf[PATH_MAX], homedir[PATH_MAX];
	અક્ષર *cp;
	પૂર્ણાંક comparehome = 0;
	સંરચના stat st;

	જો (realpath(name, buf) == ખાલી) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		પાછા -1;
	}
	જો (pw_dir != ખાલી && realpath(pw_dir, homedir) != ખાલી)
		comparehome = 1;

	જો (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		પાછા -1;
	}
	જો ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		પાછા -1;
	}

	/* for each component of the canonical path, walking upwards */
	માટે (;;) {
		જો ((cp = dirname(buf)) == ખાલી) {
			snprintf(err, errlen, "dirname() failed");
			પાછા -1;
		}
		strlcpy(buf, cp, કદ(buf));

		જો (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			પાછા -1;
		}

		/* If are past the homedir then we can stop */
		જો (comparehome && strcmp(homedir, buf) == 0)
			તોડો;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		જો ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			તોડો;
	}
	પાછા 0;
}

સ્થિર શૂન્ય
usage(શૂન્ય)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	અચલ અક્ષર *path = ".";
	અક્ષર errmsg[256];
	પૂર્ણાંક ch, mode = -1;
	બાહ્ય અક્ષર *optarg;
	બાહ્ય પૂર્ણાંક optind;
	સંરચના stat st;

	જ્યારે ((ch = getopt(argc, argv, "hm:")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ 'm':
			જો (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			નહીંતર જો (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			નહીંતર {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			તોડો;
		મૂળભૂત:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	જો (argc > 1)
		usage();
	નહીંતર જો (argc == 1)
		path = argv[0];

	જો (mode == 1)
		safely_chroot(path, getuid());
	નહીંતર જો (mode == 2) {
		જો (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		જો (auth_secure_path(path, &st, ખાલી, 0,
		    errmsg, કદ(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} નહીંતર {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	પાછા 0;
}
