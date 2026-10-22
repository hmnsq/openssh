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
#यदि_परिभाषितम् HAVE_LIBGEN_H
#अन्तर्भाव <libgen.h>
#यदि_अन्तः

स्थिर शून्य
fatal(ध्रुव वर्ण *fmt, ...)
{
	va_list तर्काः;

	va_start(तर्काः, fmt);
	vfprintf(stderr, fmt, तर्काः);
	fputc('\n', stderr);
	va_end(तर्काः);
	निर्गच्छ(1);
}
/* Based on session.c. NB. keep tests in sync */
स्थिर शून्य
safely_chroot(ध्रुव वर्ण *मार्गः, uid_t uid)
{
	ध्रुव वर्ण *cp;
	वर्ण component[PATH_MAX];
	संरचना stat st;

	यदि (*मार्गः != '/')
		fatal("chroot path does not begin at root");
	यदि (वाक्यदैर्घ्यम्(मार्गः) >= परिमाण(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	प्रति (cp = मार्गः; cp != रिक्त;) {
		यदि ((cp = strchr(cp, '/')) == रिक्त)
			strlcpy(component, मार्गः, परिमाण(component));
		अन्यथा {
			cp++;
			स्मृतिं_प्रतिलिख(component, मार्गः, cp - मार्गः);
			component[cp - मार्गः] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		यदि (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		यदि (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == रिक्त ? "" : "component ", component);
		यदि (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == रिक्त ? "" : "component ", component);

	}

	यदि (chdir(मार्गः) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", मार्गः, strerror(errno));
}

/* from platform.c */
पूर्णाङ्क
platform_sys_dir_uid(uid_t uid)
{
	यदि (uid == 0)
		प्रत्यागम 1;
#यदि_परिभाषितम् PLATFORM_SYS_DIR_UID
	यदि (uid == PLATFORM_SYS_DIR_UID)
		प्रत्यागम 1;
#यदि_अन्तः
	प्रत्यागम 0;
}

/* from auth.c */
पूर्णाङ्क
auth_secure_मार्गः(ध्रुव वर्ण *name, संरचना stat *stp, ध्रुव वर्ण *pw_dir,
    uid_t uid, वर्ण *err, आकार_t errlen)
{
	वर्ण buf[PATH_MAX], homedir[PATH_MAX];
	वर्ण *cp;
	पूर्णाङ्क comparehome = 0;
	संरचना stat st;

	यदि (realpath(name, buf) == रिक्त) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		प्रत्यागम -1;
	}
	यदि (pw_dir != रिक्त && realpath(pw_dir, homedir) != रिक्त)
		comparehome = 1;

	यदि (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		प्रत्यागम -1;
	}
	यदि ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		प्रत्यागम -1;
	}

	/* for each component of the canonical path, walking upwards */
	प्रति (;;) {
		यदि ((cp = dirname(buf)) == रिक्त) {
			snprintf(err, errlen, "dirname() failed");
			प्रत्यागम -1;
		}
		strlcpy(buf, cp, परिमाण(buf));

		यदि (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			प्रत्यागम -1;
		}

		/* If are past the homedir then we can stop */
		यदि (comparehome && वाक्यं_तुलय(homedir, buf) == 0)
			भङ्ग;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		यदि ((वाक्यं_तुलय("/", buf) == 0) || (वाक्यं_तुलय(".", buf) == 0))
			भङ्ग;
	}
	प्रत्यागम 0;
}

स्थिर शून्य
usage(शून्य)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	निर्गच्छ(1);
}

पूर्णाङ्क
मुख्यम्(पूर्णाङ्क argc, वर्ण **argv)
{
	ध्रुव वर्ण *मार्गः = ".";
	वर्ण errmsg[256];
	पूर्णाङ्क ch, बहुलकम् = -1;
	बाह्य वर्ण *optarg;
	बाह्य पूर्णाङ्क optind;
	संरचना stat st;

	यावत् ((ch = getopt(argc, argv, "hm:")) != -1) {
		विकल्प (ch) {
		पक्ष 'm':
			यदि (strcasecmp(optarg, "chroot") == 0)
				बहुलकम् = 1;
			अन्यथा यदि (strcasecmp(optarg, "keys-command") == 0)
				बहुलकम् = 2;
			अन्यथा {
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

	यदि (argc > 1)
		usage();
	अन्यथा यदि (argc == 1)
		मार्गः = argv[0];

	यदि (बहुलकम् == 1)
		safely_chroot(मार्गः, getuid());
	अन्यथा यदि (बहुलकम् == 2) {
		यदि (stat(मार्गः, &st) < 0)
			fatal("Could not stat %s: %s", मार्गः, strerror(errno));
		यदि (auth_secure_मार्गः(मार्गः, &st, रिक्त, 0,
		    errmsg, परिमाण(errmsg)) != 0)
			fatal("Unsafe %s: %s", मार्गः, errmsg);
	} अन्यथा {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	प्रत्यागम 0;
}
