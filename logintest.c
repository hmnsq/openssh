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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/wait.h>
#समावेश <sys/socket.h>

#समावेश <netinet/in.h>

#समावेश <unistd.h>
#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <pwd.h>
#समावेश <netdb.h>
#समावेश <time.h>

#समावेश "loginrec.h"

बाह्य अक्षर *__progname;

#घोषणा PAUSE_BEFORE_LOGOUT 3

पूर्णांक nologtest = 0;
पूर्णांक compile_opts_only = 0;
पूर्णांक be_verbose = 0;


/* Dump a logininfo to stdout. Assumes a tab size of 8 chars. */
व्योम
dump_logininfo(काष्ठा logininfo *li, अक्षर *descname)
{
	/* yes I know how nasty this is */
	म_लिखो("struct logininfo %s = {\n\t"
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
	    li->pid, li->uid, li->पंक्ति,
	    li->username, li->hostname, li->निकास,
	    li->termination, li->tv_sec, li->tv_usec,
	    li->hostaddr.sa.sa_family);
}


पूर्णांक
testAPI()
{
	काष्ठा logininfo *li1;
	काष्ठा passwd *pw;
	काष्ठा hostent *he;
	काष्ठा sockaddr_in sa_in4;
	अक्षर cmdstring[256], stripline[8];
	अक्षर username[32];
#अगर_घोषित HAVE_TIME_H
	समय_प्रकार t0, t1, t2, logintime, logouttime;
	अक्षर s_t0[64],s_t1[64],s_t2[64];
	अक्षर s_logintime[64], s_logouttime[64]; /* ctime() strings */
#पूर्ण_अगर

	म_लिखो("**\n** Testing the API...\n**\n");

	pw = getpwuid(getuid());
	strlcpy(username, pw->pw_name, माप(username));

	/* gethostname(hostname, sizeof(hostname)); */

	म_लिखो("login_alloc_entry test (no host info):\n");

	/* FIXME fake tty more effectively - this could upset some platforms */
	li1 = login_alloc_entry((पूर्णांक)getpid(), username, शून्य, ttyname(0));
	strlcpy(li1->progname, "OpenSSH-logintest", माप(li1->progname));

	अगर (be_verbose)
		dump_logininfo(li1, "li1");

	म_लिखो("Setting host address info for 'localhost' (may call out):\n");
	अगर (! (he = gethostbyname("localhost"))) {
		म_लिखो("Couldn't set hostname(lookup failed)\n");
	} अन्यथा {
		/* NOTE: this is messy, but typically a program wouldn't have to set
		 *  any of this, a sockaddr_in* would be already prepared */
		स_नकल((व्योम *)&(sa_in4.sin_addr), (व्योम *)&(he->h_addr_list[0][0]),
		    माप(काष्ठा in_addr));
		login_set_addr(li1, (काष्ठा sockaddr *) &sa_in4, माप(sa_in4));
		strlcpy(li1->hostname, "localhost", माप(li1->hostname));
	}
	अगर (be_verbose)
		dump_logininfo(li1, "li1");

	अगर ((पूर्णांक)geteuid() != 0) {
		म_लिखो("NOT RUNNING LOGIN TESTS - you are not root!\n");
		वापस 1;
	}

	अगर (nologtest)
		वापस 1;

	पंक्ति_stripname(stripline, li1->पंक्ति, माप(stripline));

	म_लिखो("Performing an invalid login attempt (no type field)\n--\n");
	login_write(li1);
	म_लिखो("--\n(Should have written errors to stderr)\n");

#अगर_घोषित HAVE_TIME_H
	(व्योम)समय(&t0);
	strlcpy(s_t0, स_समय(&t0), माप(s_t0));
	t1 = login_get_lastlog_time(getuid());
	strlcpy(s_t1, स_समय(&t1), माप(s_t1));
	म_लिखो("Before logging in:\n\tcurrent time is %d - %s\t"
	    "lastlog time is %d - %s\n",
	    (पूर्णांक)t0, s_t0, (पूर्णांक)t1, s_t1);
#पूर्ण_अगर

	म_लिखो("Performing a login on line %s ", stripline);
#अगर_घोषित HAVE_TIME_H
	(व्योम)समय(&logintime);
	strlcpy(s_logintime, स_समय(&logintime), माप(s_logintime));
	म_लिखो("at %d - %s", (पूर्णांक)logintime, s_logintime);
#पूर्ण_अगर
	म_लिखो("--\n");
	login_login(li1);

	snprintf(cmdstring, माप(cmdstring), "who | grep '%s '",
		 stripline);
	प्रणाली(cmdstring);

	म_लिखो("--\nPausing for %d second(s)...\n", PAUSE_BEFORE_LOGOUT);
	sleep(PAUSE_BEFORE_LOGOUT);

	म_लिखो("Performing a logout ");
#अगर_घोषित HAVE_TIME_H
	(व्योम)समय(&logouttime);
	strlcpy(s_logouttime, स_समय(&logouttime), माप(s_logouttime));
	म_लिखो("at %d - %s", (पूर्णांक)logouttime, s_logouttime);
#पूर्ण_अगर
	म_लिखो("\nThe root login shown above should be gone.\n"
	    "If the root login hasn't gone, but another user on the same\n"
	    "pty has, this is OK - we're hacking it here, and there\n"
	    "shouldn't be two users on one pty in reality...\n"
	    "-- ('who' output follows)\n");
	login_logout(li1);

	प्रणाली(cmdstring);
	म_लिखो("-- ('who' output ends)\n");

#अगर_घोषित HAVE_TIME_H
	t2 = login_get_lastlog_time(getuid());
	strlcpy(s_t2, स_समय(&t2), माप(s_t2));
	म_लिखो("After logging in, lastlog time is %d - %s\n", (पूर्णांक)t2, s_t2);
	अगर (t1 == t2)
		म_लिखो("The lastlog times before and after logging in are the "
		    "same.\nThis indicates that lastlog is ** NOT WORKING "
		    "CORRECTLY **\n");
	अन्यथा अगर (t0 != t2)
		/* We can be off by a second or so, even when recording works fine.
		 * I'm not 100% sure why, but it's true. */
		म_लिखो("** The login time and the lastlog time differ.\n"
		    "** This indicates that lastlog is either recording the "
		    "wrong time,\n** or retrieving the wrong entry.\n"
		    "If it's off by less than %d second(s) "
		    "run the test again.\n", PAUSE_BEFORE_LOGOUT);
	अन्यथा
		म_लिखो("lastlog agrees with the login time. This is a good thing.\n");

#पूर्ण_अगर

	म_लिखो("--\nThe output of 'last' shown next should have "
	    "an entry for root \n  on %s for the time shown above:\n--\n",
	    stripline);
	snprintf(cmdstring, माप(cmdstring), "last | grep '%s ' | head -3",
		 stripline);
	प्रणाली(cmdstring);

	म_लिखो("--\nEnd of login test.\n");

	login_free_entry(li1);

	वापस 1;
} /* testAPI() */


व्योम
test_पंक्ति_Name(अक्षर *पंक्ति)
{
	/* have to null-terminate - these functions are designed for
	 * structures with fixed-length char arrays, and don't null-term.*/
	अक्षर full[17], strip[9], abbrev[5];

	स_रखो(full, '\0', माप(full));
	स_रखो(strip, '\0', माप(strip));
	स_रखो(abbrev, '\0', माप(abbrev));

	पंक्ति_fullname(full, पंक्ति, माप(full)-1);
	पंक्ति_stripname(strip, full, माप(strip)-1);
	पंक्ति_abbrevname(abbrev, full, माप(abbrev)-1);
	म_लिखो("%s: %s, %s, %s\n", पंक्ति, full, strip, abbrev);

} /* testLineName() */


पूर्णांक
testOutput()
{
	म_लिखो("**\n** Testing linename functions\n**\n");
	test_पंक्ति_Name("/dev/pts/1");
	test_पंक्ति_Name("pts/1");
	test_पंक्ति_Name("pts/999");
	test_पंक्ति_Name("/dev/ttyp00");
	test_पंक्ति_Name("ttyp00");

	वापस 1;
} /* testOutput() */


/* show which options got compiled in */
व्योम
showOptions(व्योम)
{
	म_लिखो("**\n** Compile-time options\n**\n");

	म_लिखो("login recording methods selected:\n");
#अगर_घोषित USE_LOGIN
	म_लिखो("\tUSE_LOGIN\n");
#पूर्ण_अगर
#अगर_घोषित USE_UTMP
	म_लिखो("\tUSE_UTMP (UTMP_FILE=%s)\n", UTMP_FILE);
#पूर्ण_अगर
#अगर_घोषित USE_UTMPX
	म_लिखो("\tUSE_UTMPX\n");
#पूर्ण_अगर
#अगर_घोषित USE_WTMP
	म_लिखो("\tUSE_WTMP (WTMP_FILE=%s)\n", WTMP_FILE);
#पूर्ण_अगर
#अगर_घोषित USE_WTMPX
	म_लिखो("\tUSE_WTMPX (WTMPX_FILE=%s)\n", WTMPX_FILE);
#पूर्ण_अगर
#अगर_घोषित USE_LASTLOG
	म_लिखो("\tUSE_LASTLOG (LASTLOG_FILE=%s)\n", LASTLOG_FILE);
#पूर्ण_अगर
	म_लिखो("\n");

} /* showOptions() */


पूर्णांक
मुख्य(पूर्णांक argc, अक्षर *argv[])
{
	म_लिखो("Platform-independent login recording test driver\n");

	__progname = ssh_get_progname(argv[0]);
	अगर (argc == 2) {
		अगर (म_भेदन(argv[1], "-i", 3) == 0)
			compile_opts_only = 1;
		अन्यथा अगर (म_भेदन(argv[1], "-v", 3) == 0)
			be_verbose=1;
	}

	अगर (!compile_opts_only) {
		अगर (be_verbose && !testOutput())
			वापस 1;

		अगर (!testAPI())
			वापस 1;
	}

	showOptions();

	वापस 0;
} /* main() */

