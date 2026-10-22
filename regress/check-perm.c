/*
 * Placed in the public domain
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>
#समावेश <unistd.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <stdarg.h>
#समावेश <stdlib.h>
#समावेश <errno.h>
#समावेश <pwd.h>
#अगर_घोषित HAVE_LIBGEN_H
#समावेश <libgen.h>
#पूर्ण_अगर

अटल व्योम
fatal(स्थिर अक्षर *fmt, ...)
{
	बहु_सूची args;

	बहु_शुरू(args, fmt);
	भख_लिखो(मानक_त्रुटि, fmt, args);
	ख_अक्षर_दो('\n', मानक_त्रुटि);
	बहु_पूर्ण(args);
	निकास(1);
}
/* Based on session.c. NB. keep tests in sync */
अटल व्योम
safely_chroot(स्थिर अक्षर *path, uid_t uid)
{
	स्थिर अक्षर *cp;
	अक्षर component[PATH_MAX];
	काष्ठा stat st;

	अगर (*path != '/')
		fatal("chroot path does not begin at root");
	अगर (म_माप(path) >= माप(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	क्रम (cp = path; cp != शून्य;) {
		अगर ((cp = म_अक्षर(cp, '/')) == शून्य)
			strlcpy(component, path, माप(component));
		अन्यथा {
			cp++;
			स_नकल(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		अगर (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, म_त्रुटि(त्रुटि_सं));
		अगर (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == शून्य ? "" : "component ", component);
		अगर (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == शून्य ? "" : "component ", component);

	}

	अगर (स_बदलो(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, म_त्रुटि(त्रुटि_सं));
}

/* from platform.c */
पूर्णांक
platform_sys_dir_uid(uid_t uid)
{
	अगर (uid == 0)
		वापस 1;
#अगर_घोषित PLATFORM_SYS_DIR_UID
	अगर (uid == PLATFORM_SYS_DIR_UID)
		वापस 1;
#पूर्ण_अगर
	वापस 0;
}

/* from auth.c */
पूर्णांक
auth_secure_path(स्थिर अक्षर *name, काष्ठा stat *stp, स्थिर अक्षर *pw_dir,
    uid_t uid, अक्षर *err, माप_प्रकार errlen)
{
	अक्षर buf[PATH_MAX], homedir[PATH_MAX];
	अक्षर *cp;
	पूर्णांक comparehome = 0;
	काष्ठा stat st;

	अगर (realpath(name, buf) == शून्य) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	अगर (pw_dir != शून्य && realpath(pw_dir, homedir) != शून्य)
		comparehome = 1;

	अगर (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		वापस -1;
	}
	अगर ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		वापस -1;
	}

	/* for each component of the canonical path, walking upwards */
	क्रम (;;) {
		अगर ((cp = स_नाम(buf)) == शून्य) {
			snprintf(err, errlen, "dirname() failed");
			वापस -1;
		}
		strlcpy(buf, cp, माप(buf));

		अगर (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			वापस -1;
		}

		/* If are past the homedir then we can stop */
		अगर (comparehome && म_भेद(homedir, buf) == 0)
			अवरोध;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		अगर ((म_भेद("/", buf) == 0) || (म_भेद(".", buf) == 0))
			अवरोध;
	}
	वापस 0;
}

अटल व्योम
usage(व्योम)
{
	ख_लिखो(मानक_त्रुटि, "check-perm -m [chroot | keys-command] [path]\n");
	निकास(1);
}

पूर्णांक
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	स्थिर अक्षर *path = ".";
	अक्षर errmsg[256];
	पूर्णांक ch, mode = -1;
	बाह्य अक्षर *optarg;
	बाह्य पूर्णांक optind;
	काष्ठा stat st;

	जबतक ((ch = getopt(argc, argv, "hm:")) != -1) {
		चयन (ch) {
		हाल 'm':
			अगर (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			अन्यथा अगर (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			अन्यथा {
				ख_लिखो(मानक_त्रुटि, "Invalid -m option\n"),
				usage();
			}
			अवरोध;
		शेष:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	अगर (argc > 1)
		usage();
	अन्यथा अगर (argc == 1)
		path = argv[0];

	अगर (mode == 1)
		safely_chroot(path, getuid());
	अन्यथा अगर (mode == 2) {
		अगर (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, म_त्रुटि(त्रुटि_सं));
		अगर (auth_secure_path(path, &st, शून्य, 0,
		    errmsg, माप(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} अन्यथा {
		ख_लिखो(मानक_त्रुटि, "Invalid mode\n");
		usage();
	}
	वापस 0;
}
