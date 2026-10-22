/*
 * Placed in the public domain
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <pwd.h>
#ifdef HAVE_LIBGEN_H
#अन्तर्भाव <libgen.h>
#endif

स्थिर शून्य
fatal(ध्रुव वर्ण *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fputc('\n', stderr);
	va_end(args);
	exit(1);
}
/* Based on session.c. NB. keep tests in sync */
स्थिर शून्य
safely_chroot(ध्रुव वर्ण *path, uid_t uid)
{
	ध्रुव वर्ण *cp;
	वर्ण component[PATH_MAX];
	संरचना stat st;

	सचे (*path != '/')
		fatal("chroot path does not begin at root");
	सचे (strlen(path) >= परिमाण(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	अत्थाय (cp = path; cp != रिक्त;) {
		सचे ((cp = strchr(cp, '/')) == रिक्त)
			strlcpy(component, path, परिमाण(component));
		अञ्ञथा {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		सचे (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		सचे (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == रिक्त ? "" : "component ", component);
		सचे (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == रिक्त ? "" : "component ", component);

	}

	सचे (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
पूर्णाङ्क
platform_sys_dir_uid(uid_t uid)
{
	सचे (uid == 0)
		पटिनिवत्त 1;
#ifdef PLATFORM_SYS_DIR_UID
	सचे (uid == PLATFORM_SYS_DIR_UID)
		पटिनिवत्त 1;
#endif
	पटिनिवत्त 0;
}

/* from auth.c */
पूर्णाङ्क
auth_secure_path(ध्रुव वर्ण *name, संरचना stat *stp, ध्रुव वर्ण *pw_dir,
    uid_t uid, वर्ण *err, size_t errlen)
{
	वर्ण buf[PATH_MAX], homedir[PATH_MAX];
	वर्ण *cp;
	पूर्णाङ्क comparehome = 0;
	संरचना stat st;

	सचे (realpath(name, buf) == रिक्त) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		पटिनिवत्त -1;
	}
	सचे (pw_dir != रिक्त && realpath(pw_dir, homedir) != रिक्त)
		comparehome = 1;

	सचे (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		पटिनिवत्त -1;
	}
	सचे ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		पटिनिवत्त -1;
	}

	/* for each component of the canonical path, walking upwards */
	अत्थाय (;;) {
		सचे ((cp = dirname(buf)) == रिक्त) {
			snprintf(err, errlen, "dirname() failed");
			पटिनिवत्त -1;
		}
		strlcpy(buf, cp, परिमाण(buf));

		सचे (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			पटिनिवत्त -1;
		}

		/* If are past the homedir then we can stop */
		सचे (comparehome && strcmp(homedir, buf) == 0)
			भङ्ग;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		सचे ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			भङ्ग;
	}
	पटिनिवत्त 0;
}

स्थिर शून्य
usage(शून्य)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	ध्रुव वर्ण *path = ".";
	वर्ण errmsg[256];
	पूर्णाङ्क ch, mode = -1;
	बाह्य वर्ण *optarg;
	बाह्य पूर्णाङ्क optind;
	संरचना stat st;

	याव ((ch = getopt(argc, argv, "hm:")) != -1) {
		विकल्प (ch) {
		पक्ष 'm':
			सचे (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			अञ्ञथा सचे (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			अञ्ञथा {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			भङ्ग;
		स्वभाव:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	सचे (argc > 1)
		usage();
	अञ्ञथा सचे (argc == 1)
		path = argv[0];

	सचे (mode == 1)
		safely_chroot(path, getuid());
	अञ्ञथा सचे (mode == 2) {
		सचे (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		सचे (auth_secure_path(path, &st, रिक्त, 0,
		    errmsg, परिमाण(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} अञ्ञथा {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	पटिनिवत्त 0;
}
