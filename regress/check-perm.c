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
fatal(स्थिरांक अक्षर *fmt, ...)
{
	बहु_सूची args;

	बहु_शुरू(args, fmt);
	भख_लिखो(मानक_त्रुटि, fmt, args);
	ख_अक्षर_दो('\n', मानक_त्रुटि);
	बहु_पूर्ण(args);
	निकास(1);
}
/* Based on session.c. NB. keep tests in sync */
स्थिर शून्य
safely_chroot(स्थिरांक अक्षर *path, uid_t uid)
{
	स्थिरांक अक्षर *cp;
	अक्षर component[PATH_MAX];
	संरचना stat st;

	जर (*path != '/')
		fatal("chroot path does not begin at root");
	जर (म_माप(path) >= आकार(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	साठी (cp = path; cp != रिक्त;) {
		जर ((cp = म_अक्षर(cp, '/')) == रिक्त)
			strlcpy(component, path, आकार(component));
		अन्यथा {
			cp++;
			स_नकल(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		जर (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, म_त्रुटि(त्रुटि_सं));
		जर (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == रिक्त ? "" : "component ", component);
		जर (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == रिक्त ? "" : "component ", component);

	}

	जर (स_बदलो(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, म_त्रुटि(त्रुटि_सं));
}

/* from platform.c */
पूर्णांक
platform_sys_dir_uid(uid_t uid)
{
	जर (uid == 0)
		परत 1;
#ifdef PLATFORM_SYS_DIR_UID
	जर (uid == PLATFORM_SYS_DIR_UID)
		परत 1;
#endif
	परत 0;
}

/* from auth.c */
पूर्णांक
auth_secure_path(स्थिरांक अक्षर *name, संरचना stat *stp, स्थिरांक अक्षर *pw_dir,
    uid_t uid, अक्षर *err, माप_प्रकार errlen)
{
	अक्षर buf[PATH_MAX], homedir[PATH_MAX];
	अक्षर *cp;
	पूर्णांक comparehome = 0;
	संरचना stat st;

	जर (realpath(name, buf) == रिक्त) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	जर (pw_dir != रिक्त && realpath(pw_dir, homedir) != रिक्त)
		comparehome = 1;

	जर (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		परत -1;
	}
	जर ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		परत -1;
	}

	/* for each component of the canonical path, walking upwards */
	साठी (;;) {
		जर ((cp = स_नाम(buf)) == रिक्त) {
			snprintf(err, errlen, "dirname() failed");
			परत -1;
		}
		strlcpy(buf, cp, आकार(buf));

		जर (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			परत -1;
		}

		/* If are past the homedir then we can stop */
		जर (comparehome && म_भेद(homedir, buf) == 0)
			थांबा;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		जर ((म_भेद("/", buf) == 0) || (म_भेद(".", buf) == 0))
			थांबा;
	}
	परत 0;
}

स्थिर शून्य
usage(शून्य)
{
	ख_लिखो(मानक_त्रुटि, "check-perm -m [chroot | keys-command] [path]\n");
	निकास(1);
}

पूर्णांक
main(पूर्णांक argc, अक्षर **argv)
{
	स्थिरांक अक्षर *path = ".";
	अक्षर errmsg[256];
	पूर्णांक ch, mode = -1;
	बाह्य अक्षर *optarg;
	बाह्य पूर्णांक optind;
	संरचना stat st;

	पर्यंत ((ch = getopt(argc, argv, "hm:")) != -1) {
		निवड (ch) {
		स्थिती 'm':
			जर (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			अन्यथा जर (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			अन्यथा {
				ख_लिखो(मानक_त्रुटि, "Invalid -m option\n"),
				usage();
			}
			थांबा;
		पूर्वनिर्धारित:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	जर (argc > 1)
		usage();
	अन्यथा जर (argc == 1)
		path = argv[0];

	जर (mode == 1)
		safely_chroot(path, getuid());
	अन्यथा जर (mode == 2) {
		जर (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, म_त्रुटि(त्रुटि_सं));
		जर (auth_secure_path(path, &st, रिक्त, 0,
		    errmsg, आकार(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} अन्यथा {
		ख_लिखो(मानक_त्रुटि, "Invalid mode\n");
		usage();
	}
	परत 0;
}
