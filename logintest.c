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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "loginrec.h"

ਬਾਹਰੀ ਅੱਖਰ *__progname;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PAUSE_BEFORE_LOGOUT 3

ਪੂਰਨ nologtest = 0;
ਪੂਰਨ compile_opts_only = 0;
ਪੂਰਨ be_verbose = 0;


/* Dump a logininfo to stdout. Assumes a tab size of 8 chars. */
ਖਾਲੀ
dump_logininfo(ਬਣਤਰ logininfo *li, ਅੱਖਰ *descname)
{
	/* yes I know how nasty this is */
	ਲਿਖੋ("struct logininfo %s = {\n\t"
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
	    li->pid, li->uid, li->ਸਤਰ,
	    li->username, li->hostname, li->ਬਾਹਰ_ਨਿਕਲੋ,
	    li->termination, li->tv_sec, li->tv_usec,
	    li->hostaddr.sa.sa_family);
}


ਪੂਰਨ
testAPI()
{
	ਬਣਤਰ logininfo *li1;
	ਬਣਤਰ passwd *pw;
	ਬਣਤਰ hostent *he;
	ਬਣਤਰ sockaddr_in sa_in4;
	ਅੱਖਰ cmdstring[256], stripline[8];
	ਅੱਖਰ username[32];
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ਸਮਾਂ_H
	time_t t0, t1, t2, logintime, logouttime;
	ਅੱਖਰ s_t0[64],s_t1[64],s_t2[64];
	ਅੱਖਰ s_logintime[64], s_logouttime[64]; /* ctime() strings */
#ਜੇ_ਅੰਤ

	ਲਿਖੋ("**\n** Testing the API...\n**\n");

	pw = getpwuid(getuid());
	strlcpy(username, pw->pw_name, ਆਕਾਰ(username));

	/* gethostname(hostname, sizeof(hostname)); */

	ਲਿਖੋ("login_alloc_entry test (no host info):\n");

	/* FIXME fake tty more effectively - this could upset some platforms */
	li1 = login_alloc_ਇੰਦਰਾਜ((ਪੂਰਨ)getpid(), username, ਨਿਰਾ, ttyname(0));
	strlcpy(li1->progname, "OpenSSH-logintest", ਆਕਾਰ(li1->progname));

	ਜੇ (be_verbose)
		dump_logininfo(li1, "li1");

	ਲਿਖੋ("Setting host address info for 'localhost' (may call out):\n");
	ਜੇ (! (he = gethostbyname("localhost"))) {
		ਲਿਖੋ("Couldn't set hostname(lookup failed)\n");
	} ਨਹੀਂਤਾਂ {
		/* NOTE: this is messy, but typically a program wouldn't have to set
		 *  any of this, a sockaddr_in* would be already prepared */
		ਸਮ੍ਰਿਤੀ_ਨਕਲ((ਖਾਲੀ *)&(sa_in4.sin_addr), (ਖਾਲੀ *)&(he->h_addr_list[0][0]),
		    ਆਕਾਰ(ਬਣਤਰ in_addr));
		login_ਸੈੱਟ_addr(li1, (ਬਣਤਰ sockaddr *) &sa_in4, ਆਕਾਰ(sa_in4));
		strlcpy(li1->hostname, "localhost", ਆਕਾਰ(li1->hostname));
	}
	ਜੇ (be_verbose)
		dump_logininfo(li1, "li1");

	ਜੇ ((ਪੂਰਨ)geteuid() != 0) {
		ਲਿਖੋ("NOT RUNNING LOGIN TESTS - you are not root!\n");
		ਵਾਪਸ 1;
	}

	ਜੇ (nologtest)
		ਵਾਪਸ 1;

	ਸਤਰ_stripname(stripline, li1->ਸਤਰ, ਆਕਾਰ(stripline));

	ਲਿਖੋ("Performing an invalid login attempt (no type field)\n--\n");
	login_write(li1);
	ਲਿਖੋ("--\n(Should have written errors to stderr)\n");

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ਸਮਾਂ_H
	(ਖਾਲੀ)time(&t0);
	strlcpy(s_t0, ctime(&t0), ਆਕਾਰ(s_t0));
	t1 = login_get_lastlog_ਸਮਾਂ(getuid());
	strlcpy(s_t1, ctime(&t1), ਆਕਾਰ(s_t1));
	ਲਿਖੋ("Before logging in:\n\tcurrent time is %d - %s\t"
	    "lastlog time is %d - %s\n",
	    (ਪੂਰਨ)t0, s_t0, (ਪੂਰਨ)t1, s_t1);
#ਜੇ_ਅੰਤ

	ਲਿਖੋ("Performing a login on line %s ", stripline);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ਸਮਾਂ_H
	(ਖਾਲੀ)time(&logintime);
	strlcpy(s_logintime, ctime(&logintime), ਆਕਾਰ(s_logintime));
	ਲਿਖੋ("at %d - %s", (ਪੂਰਨ)logintime, s_logintime);
#ਜੇ_ਅੰਤ
	ਲਿਖੋ("--\n");
	login_login(li1);

	snprintf(cmdstring, ਆਕਾਰ(cmdstring), "who | grep '%s '",
		 stripline);
	system(cmdstring);

	ਲਿਖੋ("--\nPausing for %d second(s)...\n", PAUSE_BEFORE_LOGOUT);
	sleep(PAUSE_BEFORE_LOGOUT);

	ਲਿਖੋ("Performing a logout ");
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ਸਮਾਂ_H
	(ਖਾਲੀ)time(&logouttime);
	strlcpy(s_logouttime, ctime(&logouttime), ਆਕਾਰ(s_logouttime));
	ਲਿਖੋ("at %d - %s", (ਪੂਰਨ)logouttime, s_logouttime);
#ਜੇ_ਅੰਤ
	ਲਿਖੋ("\nThe root login shown above should be gone.\n"
	    "If the root login hasn't gone, but another user on the same\n"
	    "pty has, this is OK - we're hacking it here, and there\n"
	    "shouldn't be two users on one pty in reality...\n"
	    "-- ('who' output follows)\n");
	login_logout(li1);

	system(cmdstring);
	ਲਿਖੋ("-- ('who' output ends)\n");

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ਸਮਾਂ_H
	t2 = login_get_lastlog_ਸਮਾਂ(getuid());
	strlcpy(s_t2, ctime(&t2), ਆਕਾਰ(s_t2));
	ਲਿਖੋ("After logging in, lastlog time is %d - %s\n", (ਪੂਰਨ)t2, s_t2);
	ਜੇ (t1 == t2)
		ਲਿਖੋ("The lastlog times before and after logging in are the "
		    "same.\nThis indicates that lastlog is ** NOT WORKING "
		    "CORRECTLY **\n");
	ਨਹੀਂਤਾਂ ਜੇ (t0 != t2)
		/* We can be off by a second or so, even when recording works fine.
		 * I'm not 100% sure why, but it's true. */
		ਲਿਖੋ("** The login time and the lastlog time differ.\n"
		    "** This indicates that lastlog is either recording the "
		    "wrong time,\n** or retrieving the wrong entry.\n"
		    "If it's off by less than %d second(s) "
		    "run the test again.\n", PAUSE_BEFORE_LOGOUT);
	ਨਹੀਂਤਾਂ
		ਲਿਖੋ("lastlog agrees with the login time. This is a good thing.\n");

#ਜੇ_ਅੰਤ

	ਲਿਖੋ("--\nThe output of 'last' shown next should have "
	    "an entry for root \n  on %s for the time shown above:\n--\n",
	    stripline);
	snprintf(cmdstring, ਆਕਾਰ(cmdstring), "last | grep '%s ' | head -3",
		 stripline);
	system(cmdstring);

	ਲਿਖੋ("--\nEnd of login test.\n");

	login_free_ਇੰਦਰਾਜ(li1);

	ਵਾਪਸ 1;
} /* testAPI() */


ਖਾਲੀ
test_ਸਤਰ_Name(ਅੱਖਰ *ਸਤਰ)
{
	/* have to null-terminate - these functions are designed for
	 * structures with fixed-length char arrays, and don't null-term.*/
	ਅੱਖਰ ਭਰਿਆ[17], strip[9], abbrev[5];

	memset(ਭਰਿਆ, '\0', ਆਕਾਰ(ਭਰਿਆ));
	memset(strip, '\0', ਆਕਾਰ(strip));
	memset(abbrev, '\0', ਆਕਾਰ(abbrev));

	ਸਤਰ_fullname(ਭਰਿਆ, ਸਤਰ, ਆਕਾਰ(ਭਰਿਆ)-1);
	ਸਤਰ_stripname(strip, ਭਰਿਆ, ਆਕਾਰ(strip)-1);
	ਸਤਰ_abbrevname(abbrev, ਭਰਿਆ, ਆਕਾਰ(abbrev)-1);
	ਲਿਖੋ("%s: %s, %s, %s\n", ਸਤਰ, ਭਰਿਆ, strip, abbrev);

} /* testLineName() */


ਪੂਰਨ
testOutput()
{
	ਲਿਖੋ("**\n** Testing linename functions\n**\n");
	test_ਸਤਰ_Name("/dev/pts/1");
	test_ਸਤਰ_Name("pts/1");
	test_ਸਤਰ_Name("pts/999");
	test_ਸਤਰ_Name("/dev/ttyp00");
	test_ਸਤਰ_Name("ttyp00");

	ਵਾਪਸ 1;
} /* testOutput() */


/* show which options got compiled in */
ਖਾਲੀ
showOptions(ਖਾਲੀ)
{
	ਲਿਖੋ("**\n** Compile-time options\n**\n");

	ਲਿਖੋ("login recording methods selected:\n");
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LOGIN
	ਲਿਖੋ("\tUSE_LOGIN\n");
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_UTMP
	ਲਿਖੋ("\tUSE_UTMP (UTMP_FILE=%s)\n", UTMP_FILE);
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_UTMPX
	ਲਿਖੋ("\tUSE_UTMPX\n");
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_WTMP
	ਲਿਖੋ("\tUSE_WTMP (WTMP_FILE=%s)\n", WTMP_FILE);
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_WTMPX
	ਲਿਖੋ("\tUSE_WTMPX (WTMPX_FILE=%s)\n", WTMPX_FILE);
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LASTLOG
	ਲਿਖੋ("\tUSE_LASTLOG (LASTLOG_FILE=%s)\n", LASTLOG_FILE);
#ਜੇ_ਅੰਤ
	ਲਿਖੋ("\n");

} /* showOptions() */


ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ *argv[])
{
	ਲਿਖੋ("Platform-independent login recording test driver\n");

	__progname = ssh_get_progname(argv[0]);
	ਜੇ (argc == 2) {
		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(argv[1], "-i", 3) == 0)
			compile_opts_only = 1;
		ਨਹੀਂਤਾਂ ਜੇ (ਲੜੀ_ਤੁਲਨਾ(argv[1], "-v", 3) == 0)
			be_verbose=1;
	}

	ਜੇ (!compile_opts_only) {
		ਜੇ (be_verbose && !testOutput())
			ਵਾਪਸ 1;

		ਜੇ (!testAPI())
			ਵਾਪਸ 1;
	}

	showOptions();

	ਵਾਪਸ 0;
} /* main() */

