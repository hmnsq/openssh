/*
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <pwd.h>
#నిర్వచితమైతే HAVE_LIBGEN_H
#అన్తర్భావ <libgen.h>
#అయితే_ముగింపు

స్థిర శూన్య
fatal(స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list వాదనలు;

	va_start(వాదనలు, fmt);
	vfprintf(stderr, fmt, వాదనలు);
	fputc('\n', stderr);
	va_end(వాదనలు);
	నిష్క్రమించు(1);
}
/* Based on session.c. NB. keep tests in sync */
స్థిర శూన్య
safely_chroot(స్థిరరాశి అక్షరం *మార్గం, uid_t uid)
{
	స్థిరరాశి అక్షరం *cp;
	అక్షరం component[PATH_MAX];
	నిర్మాణం stat st;

	ఒకవేళ (*మార్గం != '/')
		fatal("chroot path does not begin at root");
	ఒకవేళ (అక్షరశ్రేణి_పొడవు(మార్గం) >= పరిమాణం(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	కొరకు (cp = మార్గం; cp != ఖాళీ;) {
		ఒకవేళ ((cp = strchr(cp, '/')) == ఖాళీ)
			strlcpy(component, మార్గం, పరిమాణం(component));
		లేకపోతే {
			cp++;
			జ్ఞాపకం_నకలు(component, మార్గం, cp - మార్గం);
			component[cp - మార్గం] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		ఒకవేళ (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		ఒకవేళ (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == ఖాళీ ? "" : "component ", component);
		ఒకవేళ (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == ఖాళీ ? "" : "component ", component);

	}

	ఒకవేళ (chdir(మార్గం) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", మార్గం, strerror(errno));
}

/* from platform.c */
పూర్ణాంకం
platform_sys_dir_uid(uid_t uid)
{
	ఒకవేళ (uid == 0)
		తిరిగి 1;
#నిర్వచితమైతే PLATFORM_SYS_DIR_UID
	ఒకవేళ (uid == PLATFORM_SYS_DIR_UID)
		తిరిగి 1;
#అయితే_ముగింపు
	తిరిగి 0;
}

/* from auth.c */
పూర్ణాంకం
auth_secure_మార్గం(స్థిరరాశి అక్షరం *name, నిర్మాణం stat *stp, స్థిరరాశి అక్షరం *pw_dir,
    uid_t uid, అక్షరం *err, కొలత_t errlen)
{
	అక్షరం buf[PATH_MAX], homedir[PATH_MAX];
	అక్షరం *cp;
	పూర్ణాంకం comparehome = 0;
	నిర్మాణం stat st;

	ఒకవేళ (realpath(name, buf) == ఖాళీ) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		తిరిగి -1;
	}
	ఒకవేళ (pw_dir != ఖాళీ && realpath(pw_dir, homedir) != ఖాళీ)
		comparehome = 1;

	ఒకవేళ (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		తిరిగి -1;
	}
	ఒకవేళ ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		తిరిగి -1;
	}

	/* for each component of the canonical path, walking upwards */
	కొరకు (;;) {
		ఒకవేళ ((cp = dirname(buf)) == ఖాళీ) {
			snprintf(err, errlen, "dirname() failed");
			తిరిగి -1;
		}
		strlcpy(buf, cp, పరిమాణం(buf));

		ఒకవేళ (stat(buf, &st) < 0 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			తిరిగి -1;
		}

		/* If are past the homedir then we can stop */
		ఒకవేళ (comparehome && strcmp(homedir, buf) == 0)
			ఆపు;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		ఒకవేళ ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			ఆపు;
	}
	తిరిగి 0;
}

స్థిర శూన్య
usage(శూన్య)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	నిష్క్రమించు(1);
}

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	స్థిరరాశి అక్షరం *మార్గం = ".";
	అక్షరం errmsg[256];
	పూర్ణాంకం ch, బహుళకం = -1;
	బాహ్య అక్షరం *optarg;
	బాహ్య పూర్ణాంకం optind;
	నిర్మాణం stat st;

	అయితే ((ch = getopt(argc, argv, "hm:")) != -1) {
		ఎంపిక (ch) {
		స్థితి 'm':
			ఒకవేళ (strcasecmp(optarg, "chroot") == 0)
				బహుళకం = 1;
			లేకపోతే ఒకవేళ (strcasecmp(optarg, "keys-command") == 0)
				బహుళకం = 2;
			లేకపోతే {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			ఆపు;
		అప్రమేయ:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	ఒకవేళ (argc > 1)
		usage();
	లేకపోతే ఒకవేళ (argc == 1)
		మార్గం = argv[0];

	ఒకవేళ (బహుళకం == 1)
		safely_chroot(మార్గం, getuid());
	లేకపోతే ఒకవేళ (బహుళకం == 2) {
		ఒకవేళ (stat(మార్గం, &st) < 0)
			fatal("Could not stat %s: %s", మార్గం, strerror(errno));
		ఒకవేళ (auth_secure_మార్గం(మార్గం, &st, ఖాళీ, 0,
		    errmsg, పరిమాణం(errmsg)) != 0)
			fatal("Unsafe %s: %s", మార్గం, errmsg);
	} లేకపోతే {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	తిరిగి 0;
}
