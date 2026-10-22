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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/wait.h>
#અન્તર્ભાવ <sys/socket.h>

#અન્તર્ભાવ <netinet/in.h>

#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <time.h>

#અન્તર્ભાવ "loginrec.h"

બાહ્ય અક્ષર *__progname;

#define PAUSE_BEFORE_LOGOUT 3

પૂર્ણાંક nologtest = 0;
પૂર્ણાંક compile_opts_only = 0;
પૂર્ણાંક be_verbose = 0;


/* Dump a logininfo to stdout. Assumes a tab size of 8 chars. */
શૂન્ય
dump_logininfo(સંરચના logininfo *li, અક્ષર *descname)
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
	    li->pid, li->uid, li->લીટી,
	    li->username, li->hostname, li->exit,
	    li->termination, li->tv_sec, li->tv_usec,
	    li->hostaddr.sa.sa_family);
}


પૂર્ણાંક
testAPI()
{
	સંરચના logininfo *li1;
	સંરચના passwd *pw;
	સંરચના hostent *he;
	સંરચના sockaddr_in sa_in4;
	અક્ષર cmdstring[256], stripline[8];
	અક્ષર username[32];
#ifdef HAVE_TIME_H
	time_t t0, t1, t2, logintime, logouttime;
	અક્ષર s_t0[64],s_t1[64],s_t2[64];
	અક્ષર s_logintime[64], s_logouttime[64]; /* ctime() strings */
#endif

	printf("**\n** Testing the API...\n**\n");

	pw = getpwuid(getuid());
	strlcpy(username, pw->pw_name, કદ(username));

	/* gethostname(hostname, sizeof(hostname)); */

	printf("login_alloc_entry test (no host info):\n");

	/* FIXME fake tty more effectively - this could upset some platforms */
	li1 = login_alloc_entry((પૂર્ણાંક)getpid(), username, ખાલી, ttyname(0));
	strlcpy(li1->progname, "OpenSSH-logintest", કદ(li1->progname));

	જો (be_verbose)
		dump_logininfo(li1, "li1");

	printf("Setting host address info for 'localhost' (may call out):\n");
	જો (! (he = gethostbyname("localhost"))) {
		printf("Couldn't set hostname(lookup failed)\n");
	} નહીંતર {
		/* NOTE: this is messy, but typically a program wouldn't have to set
		 *  any of this, a sockaddr_in* would be already prepared */
		memcpy((શૂન્ય *)&(sa_in4.sin_addr), (શૂન્ય *)&(he->h_addr_list[0][0]),
		    કદ(સંરચના in_addr));
		login_set_addr(li1, (સંરચના sockaddr *) &sa_in4, કદ(sa_in4));
		strlcpy(li1->hostname, "localhost", કદ(li1->hostname));
	}
	જો (be_verbose)
		dump_logininfo(li1, "li1");

	જો ((પૂર્ણાંક)geteuid() != 0) {
		printf("NOT RUNNING LOGIN TESTS - you are not root!\n");
		પાછા 1;
	}

	જો (nologtest)
		પાછા 1;

	લીટી_stripname(stripline, li1->લીટી, કદ(stripline));

	printf("Performing an invalid login attempt (no type field)\n--\n");
	login_write(li1);
	printf("--\n(Should have written errors to stderr)\n");

#ifdef HAVE_TIME_H
	(શૂન્ય)time(&t0);
	strlcpy(s_t0, ctime(&t0), કદ(s_t0));
	t1 = login_get_lastlog_time(getuid());
	strlcpy(s_t1, ctime(&t1), કદ(s_t1));
	printf("Before logging in:\n\tcurrent time is %d - %s\t"
	    "lastlog time is %d - %s\n",
	    (પૂર્ણાંક)t0, s_t0, (પૂર્ણાંક)t1, s_t1);
#endif

	printf("Performing a login on line %s ", stripline);
#ifdef HAVE_TIME_H
	(શૂન્ય)time(&logintime);
	strlcpy(s_logintime, ctime(&logintime), કદ(s_logintime));
	printf("at %d - %s", (પૂર્ણાંક)logintime, s_logintime);
#endif
	printf("--\n");
	login_login(li1);

	snprintf(cmdstring, કદ(cmdstring), "who | grep '%s '",
		 stripline);
	system(cmdstring);

	printf("--\nPausing for %d second(s)...\n", PAUSE_BEFORE_LOGOUT);
	sleep(PAUSE_BEFORE_LOGOUT);

	printf("Performing a logout ");
#ifdef HAVE_TIME_H
	(શૂન્ય)time(&logouttime);
	strlcpy(s_logouttime, ctime(&logouttime), કદ(s_logouttime));
	printf("at %d - %s", (પૂર્ણાંક)logouttime, s_logouttime);
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
	strlcpy(s_t2, ctime(&t2), કદ(s_t2));
	printf("After logging in, lastlog time is %d - %s\n", (પૂર્ણાંક)t2, s_t2);
	જો (t1 == t2)
		printf("The lastlog times before and after logging in are the "
		    "same.\nThis indicates that lastlog is ** NOT WORKING "
		    "CORRECTLY **\n");
	નહીંતર જો (t0 != t2)
		/* We can be off by a second or so, even when recording works fine.
		 * I'm not 100% sure why, but it's true. */
		printf("** The login time and the lastlog time differ.\n"
		    "** This indicates that lastlog is either recording the "
		    "wrong time,\n** or retrieving the wrong entry.\n"
		    "If it's off by less than %d second(s) "
		    "run the test again.\n", PAUSE_BEFORE_LOGOUT);
	નહીંતર
		printf("lastlog agrees with the login time. This is a good thing.\n");

#endif

	printf("--\nThe output of 'last' shown next should have "
	    "an entry for root \n  on %s for the time shown above:\n--\n",
	    stripline);
	snprintf(cmdstring, કદ(cmdstring), "last | grep '%s ' | head -3",
		 stripline);
	system(cmdstring);

	printf("--\nEnd of login test.\n");

	login_free_entry(li1);

	પાછા 1;
} /* testAPI() */


શૂન્ય
test_લીટી_Name(અક્ષર *લીટી)
{
	/* have to null-terminate - these functions are designed for
	 * structures with fixed-length char arrays, and don't null-term.*/
	અક્ષર full[17], strip[9], abbrev[5];

	memset(full, '\0', કદ(full));
	memset(strip, '\0', કદ(strip));
	memset(abbrev, '\0', કદ(abbrev));

	લીટી_fullname(full, લીટી, કદ(full)-1);
	લીટી_stripname(strip, full, કદ(strip)-1);
	લીટી_abbrevname(abbrev, full, કદ(abbrev)-1);
	printf("%s: %s, %s, %s\n", લીટી, full, strip, abbrev);

} /* testLineName() */


પૂર્ણાંક
testOutput()
{
	printf("**\n** Testing linename functions\n**\n");
	test_લીટી_Name("/dev/pts/1");
	test_લીટી_Name("pts/1");
	test_લીટી_Name("pts/999");
	test_લીટી_Name("/dev/ttyp00");
	test_લીટી_Name("ttyp00");

	પાછા 1;
} /* testOutput() */


/* show which options got compiled in */
શૂન્ય
showOptions(શૂન્ય)
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


પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર *argv[])
{
	printf("Platform-independent login recording test driver\n");

	__progname = ssh_get_progname(argv[0]);
	જો (argc == 2) {
		જો (strncmp(argv[1], "-i", 3) == 0)
			compile_opts_only = 1;
		નહીંતર જો (strncmp(argv[1], "-v", 3) == 0)
			be_verbose=1;
	}

	જો (!compile_opts_only) {
		જો (be_verbose && !testOutput())
			પાછા 1;

		જો (!testAPI())
			પાછા 1;
	}

	showOptions();

	પાછા 0;
} /* main() */

