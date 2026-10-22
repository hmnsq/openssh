/*
 * Copyright (c) 2000 Andre Lucas.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 ** logintest.c:  simple test driver for platform-independent login recording
 **               and lastlog retrieval
 **/

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>

#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <time.h>

#ಅನ್ತರ್ಭಾವ "loginrec.h"

ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

#ವ್ಯಾಖ್ಯಾನಿಸು PAUSE_BEFORE_LOGOUT 3

ಪೂರ್ಣಾಂಕ nologtest = 0;
ಪೂರ್ಣಾಂಕ compile_opts_only = 0;
ಪೂರ್ಣಾಂಕ be_verbose = 0;


/* Dump a logininfo to stdout. Assumes a tab size of 8 chars. */
ಶೂನ್ಯ
dump_logininfo(ರಚನೆ logininfo *li, ಅಕ್ಷರ *descname)
{
	/* yes I know how nasty this is */
	ಬರೆ("struct logininfo %s = {\n\t"
	    "progname\t'%s'\n\ttype\t\t%d\n\t"
	    "pid\t\t%d\n\tuid\t\t%d\n\t"
	    "line\t\t'%s'\n\tusername\t'%s'\n\t"
	    "hostname\t'%s'\n\texit\t\t%d\n\ttermination\t%d\n\t"
	    "tv_sec\t%d\n\ttv_usec\t%d\n\t"
	    "struct login_netinfo hostaddr {\n\t\t"
	    "struct sockaddr sa {\n"
	    "\t\t\tfamily\t%d\n\t\t}\n"
	    "\t}\n"
	    "}\n",
	    descname, li->progname, li->type,
	    li->pid, li->uid, li->ಸಾಲು,
	    li->username, li->hostname, li->ನಿರ್ಗಮಿಸು,
	    li->termination, li->tv_sec, li->tv_usec,
	    li->hostaddr.sa.sa_family);
}


ಪೂರ್ಣಾಂಕ
testAPI()
{
	ರಚನೆ logininfo *li1;
	ರಚನೆ passwd *pw;
	ರಚನೆ hostent *he;
	ರಚನೆ sockaddr_in sa_in4;
	ಅಕ್ಷರ cmdstring[256], stripline[8];
	ಅಕ್ಷರ username[32];
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ಸಮಯ_H
	time_t t0, t1, t2, logintime, logouttime;
	ಅಕ್ಷರ s_t0[64],s_t1[64],s_t2[64];
	ಅಕ್ಷರ s_logintime[64], s_logouttime[64]; /* ctime() strings */
#ಆದರೆ_ಅಂತ್ಯ

	ಬರೆ("**\n** Testing the API...\n**\n");

	pw = getpwuid(getuid());
	strlcpy(username, pw->pw_name, ಗಾತ್ರ(username));

	/* gethostname(hostname, sizeof(hostname)); */

	ಬರೆ("login_alloc_entry test (no host info):\n");

	/* FIXME fake tty more effectively - this could upset some platforms */
	li1 = login_alloc_ನಮೂದು((ಪೂರ್ಣಾಂಕ)getpid(), username, ಖಾಲಿ, ttyname(0));
	strlcpy(li1->progname, "OpenSSH-logintest", ಗಾತ್ರ(li1->progname));

	ಆದರೆ (be_verbose)
		dump_logininfo(li1, "li1");

	ಬರೆ("Setting host address info for 'localhost' (may call out):\n");
	ಆದರೆ (! (he = gethostbyname("localhost"))) {
		ಬರೆ("Couldn't set hostname(lookup failed)\n");
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* NOTE: this is messy, but typically a program wouldn't have to set
		 *  any of this, a sockaddr_in* would be already prepared */
		ಸ್ಮರಣೆ_ನಕಲು((ಶೂನ್ಯ *)&(sa_in4.sin_addr), (ಶೂನ್ಯ *)&(he->h_addr_list[0][0]),
		    ಗಾತ್ರ(ರಚನೆ in_addr));
		login_ಗಣ_addr(li1, (ರಚನೆ sockaddr *) &sa_in4, ಗಾತ್ರ(sa_in4));
		strlcpy(li1->hostname, "localhost", ಗಾತ್ರ(li1->hostname));
	}
	ಆದರೆ (be_verbose)
		dump_logininfo(li1, "li1");

	ಆದರೆ ((ಪೂರ್ಣಾಂಕ)geteuid() != 0) {
		ಬರೆ("NOT RUNNING LOGIN TESTS - you are not root!\n");
		ಹಿಂತಿರುಗಿ 1;
	}

	ಆದರೆ (nologtest)
		ಹಿಂತಿರುಗಿ 1;

	ಸಾಲು_stripname(stripline, li1->ಸಾಲು, ಗಾತ್ರ(stripline));

	ಬರೆ("Performing an invalid login attempt (no type field)\n--\n");
	login_write(li1);
	ಬರೆ("--\n(Should have written errors to stderr)\n");

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ಸಮಯ_H
	(ಶೂನ್ಯ)time(&t0);
	strlcpy(s_t0, ctime(&t0), ಗಾತ್ರ(s_t0));
	t1 = login_get_lastlog_ಸಮಯ(getuid());
	strlcpy(s_t1, ctime(&t1), ಗಾತ್ರ(s_t1));
	ಬರೆ("Before logging in:\n\tcurrent time is %d - %s\t"
	    "lastlog time is %d - %s\n",
	    (ಪೂರ್ಣಾಂಕ)t0, s_t0, (ಪೂರ್ಣಾಂಕ)t1, s_t1);
#ಆದರೆ_ಅಂತ್ಯ

	ಬರೆ("Performing a login on line %s ", stripline);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ಸಮಯ_H
	(ಶೂನ್ಯ)time(&logintime);
	strlcpy(s_logintime, ctime(&logintime), ಗಾತ್ರ(s_logintime));
	ಬರೆ("at %d - %s", (ಪೂರ್ಣಾಂಕ)logintime, s_logintime);
#ಆದರೆ_ಅಂತ್ಯ
	ಬರೆ("--\n");
	login_login(li1);

	snprintf(cmdstring, ಗಾತ್ರ(cmdstring), "who | grep '%s '",
		 stripline);
	system(cmdstring);

	ಬರೆ("--\nPausing for %d second(s)...\n", PAUSE_BEFORE_LOGOUT);
	sleep(PAUSE_BEFORE_LOGOUT);

	ಬರೆ("Performing a logout ");
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ಸಮಯ_H
	(ಶೂನ್ಯ)time(&logouttime);
	strlcpy(s_logouttime, ctime(&logouttime), ಗಾತ್ರ(s_logouttime));
	ಬರೆ("at %d - %s", (ಪೂರ್ಣಾಂಕ)logouttime, s_logouttime);
#ಆದರೆ_ಅಂತ್ಯ
	ಬರೆ("\nThe root login shown above should be gone.\n"
	    "If the root login hasn't gone, but another user on the same\n"
	    "pty has, this is OK - we're hacking it here, and there\n"
	    "shouldn't be two users on one pty in reality...\n"
	    "-- ('who' output follows)\n");
	login_logout(li1);

	system(cmdstring);
	ಬರೆ("-- ('who' output ends)\n");

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ಸಮಯ_H
	t2 = login_get_lastlog_ಸಮಯ(getuid());
	strlcpy(s_t2, ctime(&t2), ಗಾತ್ರ(s_t2));
	ಬರೆ("After logging in, lastlog time is %d - %s\n", (ಪೂರ್ಣಾಂಕ)t2, s_t2);
	ಆದರೆ (t1 == t2)
		ಬರೆ("The lastlog times before and after logging in are the "
		    "same.\nThis indicates that lastlog is ** NOT WORKING "
		    "CORRECTLY **\n");
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (t0 != t2)
		/* We can be off by a second or so, even when recording works fine.
		 * I'm not 100% sure why, but it's true. */
		ಬರೆ("** The login time and the lastlog time differ.\n"
		    "** This indicates that lastlog is either recording the "
		    "wrong time,\n** or retrieving the wrong entry.\n"
		    "If it's off by less than %d second(s) "
		    "run the test again.\n", PAUSE_BEFORE_LOGOUT);
	ಇಲ್ಲದಿದ್ದರೆ
		ಬರೆ("lastlog agrees with the login time. This is a good thing.\n");

#ಆದರೆ_ಅಂತ್ಯ

	ಬರೆ("--\nThe output of 'last' shown next should have "
	    "an entry for root \n  on %s for the time shown above:\n--\n",
	    stripline);
	snprintf(cmdstring, ಗಾತ್ರ(cmdstring), "last | grep '%s ' | head -3",
		 stripline);
	system(cmdstring);

	ಬರೆ("--\nEnd of login test.\n");

	login_free_ನಮೂದು(li1);

	ಹಿಂತಿರುಗಿ 1;
} /* testAPI() */


ಶೂನ್ಯ
test_ಸಾಲು_Name(ಅಕ್ಷರ *ಸಾಲು)
{
	/* have to null-terminate - these functions are designed for
	 * structures with fixed-length char arrays, and don't null-term.*/
	ಅಕ್ಷರ ತುಂಬಿದ[17], strip[9], abbrev[5];

	memset(ತುಂಬಿದ, '\0', ಗಾತ್ರ(ತುಂಬಿದ));
	memset(strip, '\0', ಗಾತ್ರ(strip));
	memset(abbrev, '\0', ಗಾತ್ರ(abbrev));

	ಸಾಲು_fullname(ತುಂಬಿದ, ಸಾಲು, ಗಾತ್ರ(ತುಂಬಿದ)-1);
	ಸಾಲು_stripname(strip, ತುಂಬಿದ, ಗಾತ್ರ(strip)-1);
	ಸಾಲು_abbrevname(abbrev, ತುಂಬಿದ, ಗಾತ್ರ(abbrev)-1);
	ಬರೆ("%s: %s, %s, %s\n", ಸಾಲು, ತುಂಬಿದ, strip, abbrev);

} /* testLineName() */


ಪೂರ್ಣಾಂಕ
testOutput()
{
	ಬರೆ("**\n** Testing linename functions\n**\n");
	test_ಸಾಲು_Name("/dev/pts/1");
	test_ಸಾಲು_Name("pts/1");
	test_ಸಾಲು_Name("pts/999");
	test_ಸಾಲು_Name("/dev/ttyp00");
	test_ಸಾಲು_Name("ttyp00");

	ಹಿಂತಿರುಗಿ 1;
} /* testOutput() */


/* show which options got compiled in */
ಶೂನ್ಯ
showOptions(ಶೂನ್ಯ)
{
	ಬರೆ("**\n** Compile-time options\n**\n");

	ಬರೆ("login recording methods selected:\n");
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LOGIN
	ಬರೆ("\tUSE_LOGIN\n");
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_UTMP
	ಬರೆ("\tUSE_UTMP (UTMP_FILE=%s)\n", UTMP_FILE);
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_UTMPX
	ಬರೆ("\tUSE_UTMPX\n");
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_WTMP
	ಬರೆ("\tUSE_WTMP (WTMP_FILE=%s)\n", WTMP_FILE);
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_WTMPX
	ಬರೆ("\tUSE_WTMPX (WTMPX_FILE=%s)\n", WTMPX_FILE);
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LASTLOG
	ಬರೆ("\tUSE_LASTLOG (LASTLOG_FILE=%s)\n", LASTLOG_FILE);
#ಆದರೆ_ಅಂತ್ಯ
	ಬರೆ("\n");

} /* showOptions() */


ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ *argv[])
{
	ಬರೆ("Platform-independent login recording test driver\n");

	__progname = ssh_get_progname(argv[0]);
	ಆದರೆ (argc == 2) {
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(argv[1], "-i", 3) == 0)
			compile_opts_only = 1;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(argv[1], "-v", 3) == 0)
			be_verbose=1;
	}

	ಆದರೆ (!compile_opts_only) {
		ಆದರೆ (be_verbose && !testOutput())
			ಹಿಂತಿರುಗಿ 1;

		ಆದರೆ (!testAPI())
			ಹಿಂತಿರುಗಿ 1;
	}

	showOptions();

	ಹಿಂತಿರುಗಿ 0;
} /* main() */

