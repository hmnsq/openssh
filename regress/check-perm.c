/*
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <pwd.h>
#ifdef HAVE_LIBGEN_H
#അന്തര്ഭാവ <libgen.h>
#endif

സ്ഥിതം ശൂന്യം
fatal(സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fputc('\n', stderr);
	va_end(args);
	exit(1);
}
/* Based on session.c. NB. keep tests in sync */
സ്ഥിതം ശൂന്യം
safely_chroot(സ്ഥിരം അക്ഷരം *path, uid_t uid)
{
	സ്ഥിരം അക്ഷരം *cp;
	അക്ഷരം component[PATH_MAX];
	ഘടന stat st;

	എങ്കിൽ (*path != '/')
		fatal("chroot path does not begin at root");
	എങ്കിൽ (strlen(path) >= വലുപ്പം(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	വേണ്ടി (cp = path; cp != ശൂന്യ;) {
		എങ്കിൽ ((cp = strchr(cp, '/')) == ശൂന്യ)
			strlcpy(component, path, വലുപ്പം(component));
		അല്ലെങ്കിൽ {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		എങ്കിൽ (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		എങ്കിൽ (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == ശൂന്യ ? "" : "component ", component);
		എങ്കിൽ (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == ശൂന്യ ? "" : "component ", component);

	}

	എങ്കിൽ (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
പൂർണ്ണസംഖ്യ
platform_sys_dir_uid(uid_t uid)
{
	എങ്കിൽ (uid == 0)
		തിരികെ 1;
#ifdef PLATFORM_SYS_DIR_UID
	എങ്കിൽ (uid == PLATFORM_SYS_DIR_UID)
		തിരികെ 1;
#endif
	തിരികെ 0;
}

/* from auth.c */
പൂർണ്ണസംഖ്യ
auth_secure_path(സ്ഥിരം അക്ഷരം *name, ഘടന stat *stp, സ്ഥിരം അക്ഷരം *pw_dir,
    uid_t uid, അക്ഷരം *err, size_t errlen)
{
	അക്ഷരം buf[PATH_MAX], homedir[PATH_MAX];
	അക്ഷരം *cp;
	പൂർണ്ണസംഖ്യ comparehome = 0;
	ഘടന stat st;

	എങ്കിൽ (realpath(name, buf) == ശൂന്യ) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		തിരികെ -1;
	}
	എങ്കിൽ (pw_dir != ശൂന്യ && realpath(pw_dir, homedir) != ശൂന്യ)
		comparehome = 1;

	എങ്കിൽ (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		തിരികെ -1;
	}
	എങ്കിൽ ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		തിരികെ -1;
	}

	/* for each component of the canonical path, walking upwards */
	വേണ്ടി (;;) {
		എങ്കിൽ ((cp = dirname(buf)) == ശൂന്യ) {
			snprintf(err, errlen, "dirname() failed");
			തിരികെ -1;
		}
		strlcpy(buf, cp, വലുപ്പം(buf));

		എങ്കിൽ (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			തിരികെ -1;
		}

		/* If are past the homedir then we can stop */
		എങ്കിൽ (comparehome && strcmp(homedir, buf) == 0)
			നിർത്തുക;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		എങ്കിൽ ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			നിർത്തുക;
	}
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
usage(ശൂന്യം)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	സ്ഥിരം അക്ഷരം *path = ".";
	അക്ഷരം errmsg[256];
	പൂർണ്ണസംഖ്യ ch, mode = -1;
	ബാഹ്യ അക്ഷരം *optarg;
	ബാഹ്യ പൂർണ്ണസംഖ്യ optind;
	ഘടന stat st;

	ആകുമ്പോൾ ((ch = getopt(argc, argv, "hm:")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ 'm':
			എങ്കിൽ (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			അല്ലെങ്കിൽ {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	എങ്കിൽ (argc > 1)
		usage();
	അല്ലെങ്കിൽ എങ്കിൽ (argc == 1)
		path = argv[0];

	എങ്കിൽ (mode == 1)
		safely_chroot(path, getuid());
	അല്ലെങ്കിൽ എങ്കിൽ (mode == 2) {
		എങ്കിൽ (stat(path, &st) < 0)
			fatal("Could not stat %s: %s", path, strerror(errno));
		എങ്കിൽ (auth_secure_path(path, &st, ശൂന്യ, 0,
		    errmsg, വലുപ്പം(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} അല്ലെങ്കിൽ {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	തിരികെ 0;
}
