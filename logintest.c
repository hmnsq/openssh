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

#include "includes.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <netdb.h>
#include <time.h>

#include "loginrec.h"

extern var_na *__progname;

#define PAUSE_BEFORE_LOGOUT 3

puur_naa_nka nologtest = 0;
puur_naa_nka compile_opts_only = 0;
puur_naa_nka be_verbose = 0;


/* Dump a logininfo to stdout. Assumes a tab size of 8 chars. */
void
dump_logininfo(sa_nracanaa logininfo *li, var_na *descname)
{
	/* yes I know how nasty this is */
	printf("struct logininfo %s = {\n\t"
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
	    li->pid, li->uid, li->line,
	    li->username, li->hostname, li->exit,
	    li->termination, li->tv_sec, li->tv_usec,
	    li->hostaddr.sa.sa_family);
}


puur_naa_nka
testAPI()
{
	sa_nracanaa logininfo *li1;
	sa_nracanaa passwd *pw;
	sa_nracanaa hostent *he;
	sa_nracanaa sockaddr_in sa_in4;
	var_na cmdstring[256], stripline[8];
	var_na username[32];
#ifdef HAVE_TIME_H
	time_t t0, t1, t2, logintime, logouttime;
	var_na s_t0[64],s_t1[64],s_t2[64];
	var_na s_logintime[64], s_logouttime[64]; /* ctime() strings */
#endif

	printf("**\n** Testing the API...\n**\n");

	pw = getpwuid(getuid());
	strlcpy(username, pw->pw_name, parimaa_na(username));

	/* gethostname(hostname, sizeof(hostname)); */

	printf("login_alloc_entry test (no host info):\n");

	/* FIXME fake tty more effectively - this could upset some platforms */
	li1 = login_alloc_entry((puur_naa_nka)getpid(), username, NULL, ttyname(0));
	strlcpy(li1->progname, "OpenSSH-logintest", parimaa_na(li1->progname));

	ᱡᱩᱫᱤ (be_verbose)
		dump_logininfo(li1, "li1");

	printf("Setting host address info for 'localhost' (may call out):\n");
	ᱡᱩᱫᱤ (! (he = gethostbyname("localhost"))) {
		printf("Couldn't set hostname(lookup failed)\n");
	} ᱵᱟᱝ {
		/* NOTE: this is messy, but typically a program wouldn't have to set
		 *  any of this, a sockaddr_in* would be already prepared */
		memcpy((void *)&(sa_in4.sin_addr), (void *)&(he->h_addr_list[0][0]),
		    parimaa_na(sa_nracanaa in_addr));
		login_set_addr(li1, (sa_nracanaa sockaddr *) &sa_in4, parimaa_na(sa_in4));
		strlcpy(li1->hostname, "localhost", parimaa_na(li1->hostname));
	}
	ᱡᱩᱫᱤ (be_verbose)
		dump_logininfo(li1, "li1");

	ᱡᱩᱫᱤ ((puur_naa_nka)geteuid() != 0) {
		printf("NOT RUNNING LOGIN TESTS - you are not root!\n");
		ᱨᱩᱣᱟᱹᱲ 1;
	}

	ᱡᱩᱫᱤ (nologtest)
		ᱨᱩᱣᱟᱹᱲ 1;

	line_stripname(stripline, li1->line, parimaa_na(stripline));

	printf("Performing an invalid login attempt (no type field)\n--\n");
	login_write(li1);
	printf("--\n(Should have written errors to stderr)\n");

#ifdef HAVE_TIME_H
	(void)time(&t0);
	strlcpy(s_t0, ctime(&t0), parimaa_na(s_t0));
	t1 = login_get_lastlog_time(getuid());
	strlcpy(s_t1, ctime(&t1), parimaa_na(s_t1));
	printf("Before logging in:\n\tcurrent time is %d - %s\t"
	    "lastlog time is %d - %s\n",
	    (puur_naa_nka)t0, s_t0, (puur_naa_nka)t1, s_t1);
#endif

	printf("Performing a login on line %s ", stripline);
#ifdef HAVE_TIME_H
	(void)time(&logintime);
	strlcpy(s_logintime, ctime(&logintime), parimaa_na(s_logintime));
	printf("at %d - %s", (puur_naa_nka)logintime, s_logintime);
#endif
	printf("--\n");
	login_login(li1);

	snprintf(cmdstring, parimaa_na(cmdstring), "who | grep '%s '",
		 stripline);
	system(cmdstring);

	printf("--\nPausing for %d second(s)...\n", PAUSE_BEFORE_LOGOUT);
	sleep(PAUSE_BEFORE_LOGOUT);

	printf("Performing a logout ");
#ifdef HAVE_TIME_H
	(void)time(&logouttime);
	strlcpy(s_logouttime, ctime(&logouttime), parimaa_na(s_logouttime));
	printf("at %d - %s", (puur_naa_nka)logouttime, s_logouttime);
#endif
	printf("\nThe root login shown above should be gone.\n"
	    "If the root login hasn't gone, but another user on the same\n"
	    "pty has, this is OK - we're hacking it here, and there\n"
	    "shouldn't be two users on one pty in reality...\n"
	    "-- ('who' output follows)\n");
	login_logout(li1);

	system(cmdstring);
	printf("-- ('who' output ends)\n");

#ifdef HAVE_TIME_H
	t2 = login_get_lastlog_time(getuid());
	strlcpy(s_t2, ctime(&t2), parimaa_na(s_t2));
	printf("After logging in, lastlog time is %d - %s\n", (puur_naa_nka)t2, s_t2);
	ᱡᱩᱫᱤ (t1 == t2)
		printf("The lastlog times before and after logging in are the "
		    "same.\nThis indicates that lastlog is ** NOT WORKING "
		    "CORRECTLY **\n");
	ᱵᱟᱝ ᱡᱩᱫᱤ (t0 != t2)
		/* We can be off by a second or so, even when recording works fine.
		 * I'm not 100% sure why, but it's true. */
		printf("** The login time and the lastlog time differ.\n"
		    "** This indicates that lastlog is either recording the "
		    "wrong time,\n** or retrieving the wrong entry.\n"
		    "If it's off by less than %d second(s) "
		    "run the test again.\n", PAUSE_BEFORE_LOGOUT);
	ᱵᱟᱝ
		printf("lastlog agrees with the login time. This is a good thing.\n");

#endif

	printf("--\nThe output of 'last' shown next should have "
	    "an entry for root \n  on %s for the time shown above:\n--\n",
	    stripline);
	snprintf(cmdstring, parimaa_na(cmdstring), "last | grep '%s ' | head -3",
		 stripline);
	system(cmdstring);

	printf("--\nEnd of login test.\n");

	login_free_entry(li1);

	ᱨᱩᱣᱟᱹᱲ 1;
} /* testAPI() */


void
testLineName(var_na *line)
{
	/* have to null-terminate - these functions are designed for
	 * structures with fixed-length char arrays, and don't null-term.*/
	var_na full[17], strip[9], abbrev[5];

	memset(full, '\0', parimaa_na(full));
	memset(strip, '\0', parimaa_na(strip));
	memset(abbrev, '\0', parimaa_na(abbrev));

	line_fullname(full, line, parimaa_na(full)-1);
	line_stripname(strip, full, parimaa_na(strip)-1);
	line_abbrevname(abbrev, full, parimaa_na(abbrev)-1);
	printf("%s: %s, %s, %s\n", line, full, strip, abbrev);

} /* testLineName() */


puur_naa_nka
testOutput()
{
	printf("**\n** Testing linename functions\n**\n");
	testLineName("/dev/pts/1");
	testLineName("pts/1");
	testLineName("pts/999");
	testLineName("/dev/ttyp00");
	testLineName("ttyp00");

	ᱨᱩᱣᱟᱹᱲ 1;
} /* testOutput() */


/* show which options got compiled in */
void
showOptions(void)
{
	printf("**\n** Compile-time options\n**\n");

	printf("login recording methods selected:\n");
#ifdef USE_LOGIN
	printf("\tUSE_LOGIN\n");
#endif
#ifdef USE_UTMP
	printf("\tUSE_UTMP (UTMP_FILE=%s)\n", UTMP_FILE);
#endif
#ifdef USE_UTMPX
	printf("\tUSE_UTMPX\n");
#endif
#ifdef USE_WTMP
	printf("\tUSE_WTMP (WTMP_FILE=%s)\n", WTMP_FILE);
#endif
#ifdef USE_WTMPX
	printf("\tUSE_WTMPX (WTMPX_FILE=%s)\n", WTMPX_FILE);
#endif
#ifdef USE_LASTLOG
	printf("\tUSE_LASTLOG (LASTLOG_FILE=%s)\n", LASTLOG_FILE);
#endif
	printf("\n");

} /* showOptions() */


puur_naa_nka
main(puur_naa_nka argc, var_na *argv[])
{
	printf("Platform-independent login recording test driver\n");

	__progname = ssh_get_progname(argv[0]);
	ᱡᱩᱫᱤ (argc == 2) {
		ᱡᱩᱫᱤ (strncmp(argv[1], "-i", 3) == 0)
			compile_opts_only = 1;
		ᱵᱟᱝ ᱡᱩᱫᱤ (strncmp(argv[1], "-v", 3) == 0)
			be_verbose=1;
	}

	ᱡᱩᱫᱤ (!compile_opts_only) {
		ᱡᱩᱫᱤ (be_verbose && !testOutput())
			ᱨᱩᱣᱟᱹᱲ 1;

		ᱡᱩᱫᱤ (!testAPI())
			ᱨᱩᱣᱟᱹᱲ 1;
	}

	showOptions();

	ᱨᱩᱣᱟᱹᱲ 0;
} /* main() */

