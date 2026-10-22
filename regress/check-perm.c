/*
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LIBGEN_H
#ಅನ್ತರ್ಭಾವ <libgen.h>
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ ಶೂನ್ಯ
fatal(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list ವಾದಗಳು;

	va_start(ವಾದಗಳು, fmt);
	vfprintf(stderr, fmt, ವಾದಗಳು);
	fputc('\n', stderr);
	va_end(ವಾದಗಳು);
	ನಿರ್ಗಮಿಸು(1);
}
/* Based on session.c. NB. keep tests in sync */
ಸ್ಥಿರ ಶೂನ್ಯ
safely_chroot(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, uid_t uid)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cp;
	ಅಕ್ಷರ component[PATH_MAX];
	ರಚನೆ stat st;

	ಆದರೆ (*ಮಾರ್ಗ != '/')
		fatal("chroot path does not begin at root");
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ) >= ಗಾತ್ರ(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	ಗಾಗಿ (cp = ಮಾರ್ಗ; cp != ಖಾಲಿ;) {
		ಆದರೆ ((cp = strchr(cp, '/')) == ಖಾಲಿ)
			strlcpy(component, ಮಾರ್ಗ, ಗಾತ್ರ(component));
		ಇಲ್ಲದಿದ್ದರೆ {
			cp++;
			ಸ್ಮರಣೆ_ನಕಲು(component, ಮಾರ್ಗ, cp - ಮಾರ್ಗ);
			component[cp - ಮಾರ್ಗ] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		ಆದರೆ (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		ಆದರೆ (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == ಖಾಲಿ ? "" : "component ", component);
		ಆದರೆ (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == ಖಾಲಿ ? "" : "component ", component);

	}

	ಆದರೆ (chdir(ಮಾರ್ಗ) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", ಮಾರ್ಗ, strerror(errno));
}

/* from platform.c */
ಪೂರ್ಣಾಂಕ
platform_sys_dir_uid(uid_t uid)
{
	ಆದರೆ (uid == 0)
		ಹಿಂತಿರುಗಿ 1;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PLATFORM_SYS_DIR_UID
	ಆದರೆ (uid == PLATFORM_SYS_DIR_UID)
		ಹಿಂತಿರುಗಿ 1;
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ 0;
}

/* from auth.c */
ಪೂರ್ಣಾಂಕ
auth_secure_ಮಾರ್ಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ರಚನೆ stat *stp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pw_dir,
    uid_t uid, ಅಕ್ಷರ *err, ಗಾತ್ರ_t errlen)
{
	ಅಕ್ಷರ buf[PATH_MAX], homedir[PATH_MAX];
	ಅಕ್ಷರ *cp;
	ಪೂರ್ಣಾಂಕ comparehome = 0;
	ರಚನೆ stat st;

	ಆದರೆ (realpath(name, buf) == ಖಾಲಿ) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (pw_dir != ಖಾಲಿ && realpath(pw_dir, homedir) != ಖಾಲಿ)
		comparehome = 1;

	ಆದರೆ (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ಹಿಂತಿರುಗಿ -1;
	}

	/* for each component of the canonical path, walking upwards */
	ಗಾಗಿ (;;) {
		ಆದರೆ ((cp = dirname(buf)) == ಖಾಲಿ) {
			snprintf(err, errlen, "dirname() failed");
			ಹಿಂತಿರುಗಿ -1;
		}
		strlcpy(buf, cp, ಗಾತ್ರ(buf));

		ಆದರೆ (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ಹಿಂತಿರುಗಿ -1;
		}

		/* If are past the homedir then we can stop */
		ಆದರೆ (comparehome && strcmp(homedir, buf) == 0)
			ನಿಲ್ಲಿಸು;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		ಆದರೆ ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			ನಿಲ್ಲಿಸು;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	ನಿರ್ಗಮಿಸು(1);
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ = ".";
	ಅಕ್ಷರ errmsg[256];
	ಪೂರ್ಣಾಂಕ ch, ಬಹುಲಕ = -1;
	ಬಾಹ್ಯ ಅಕ್ಷರ *optarg;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ optind;
	ರಚನೆ stat st;

	ಆಗ ((ch = getopt(argc, argv, "hm:")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ 'm':
			ಆದರೆ (strcasecmp(optarg, "chroot") == 0)
				ಬಹುಲಕ = 1;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(optarg, "keys-command") == 0)
				ಬಹುಲಕ = 2;
			ಇಲ್ಲದಿದ್ದರೆ {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	ಆದರೆ (argc > 1)
		usage();
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (argc == 1)
		ಮಾರ್ಗ = argv[0];

	ಆದರೆ (ಬಹುಲಕ == 1)
		safely_chroot(ಮಾರ್ಗ, getuid());
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಬಹುಲಕ == 2) {
		ಆದರೆ (stat(ಮಾರ್ಗ, &st) < 0)
			fatal("Could not stat %s: %s", ಮಾರ್ಗ, strerror(errno));
		ಆದರೆ (auth_secure_ಮಾರ್ಗ(ಮಾರ್ಗ, &st, ಖಾಲಿ, 0,
		    errmsg, ಗಾತ್ರ(errmsg)) != 0)
			fatal("Unsafe %s: %s", ಮಾರ್ಗ, errmsg);
	} ಇಲ್ಲದಿದ್ದರೆ {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	ಹಿಂತಿರುಗಿ 0;
}
