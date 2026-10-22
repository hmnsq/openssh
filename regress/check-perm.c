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

	जइ (*path != '/')
		fatal("chroot path does not begin at root");
	जइ (strlen(path) >= परिमाण(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	प्रति (cp = path; cp != रिक्त;) {
		जइ ((cp = strchr(cp, '/')) == रिक्त)
			strlcpy(component, path, परिमाण(component));
		अण्णहा {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		जइ (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		जइ (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == रिक्त ? "" : "component ", component);
		जइ (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == रिक्त ? "" : "component ", component);

	}

	जइ (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
पूर्णाङ्क
platform_sys_dir_uid(uid_t uid)
{
	जइ (uid == 0)
		प्रत्यागम 1;
#ifdef PLATFORM_SYS_DIR_UID
	जइ (uid == PLATFORM_SYS_DIR_UID)
		प्रत्यागम 1;
#endif
	प्रत्यागम 0;
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

	जइ (realpath(name, buf) == रिक्त) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		प्रत्यागम -1;
	}
	जइ (pw_dir != रिक्त && realpath(pw_dir, homedir) != रिक्त)
		comparehome = 1;

	जइ (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		प्रत्यागम -1;
	}
	जइ ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		प्रत्यागम -1;
	}

	/* for each component of the canonical path, walking upwards */
	प्रति (;;) {
		जइ ((cp = dirname(buf)) == रिक्त) {
			snprintf(err, errlen, "dirname() failed");
			प्रत्यागम -1;
		}
		strlcpy(buf, cp, परिमाण(buf));

		जइ (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			प्रत्यागम -1;
		}

		/* If are past the homedir then we can stop */
		जइ (comparehome && strcmp(homedir, buf) == 0)
			भङ्ग;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		जइ ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			भङ्ग;
	}
	प्रत्यागम 0;
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

	जाव ((ch = getopt(argc, argv, "hm:")) != -1) {
		विकल्प (ch) {
		पक्ष 'm':
			जइ (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			अण्णहा जइ (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			अण्णहा {
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

	जइ (argc > 1)
		usage();
	अण्णहा जइ (argc == 1)
		path = argv[0];

	जइ (mode == 1)
		safely_chroot(path, getuid());
	अण्णहा जइ (mode == 2) {
		जइ (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		जइ (auth_secure_path(path, &st, रिक्त, 0,
		    errmsg, परिमाण(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} अण्णहा {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	प्रत्यागम 0;
}
