/* $OpenBSD: log.c,v 1.67 2026/02/14 00:18:34 jsg Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <syslog.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଯଦି defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "match.h"

ସ୍ଥିର LogLevel log_level = SYSLOG_LEVEL_INFO;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା log_on_stderr = 1;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା log_stderr_fd = STDERR_FILENO;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା log_facility = LOG_AUTH;
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *argv0;
ସ୍ଥିର log_handler_fn *log_handler;
ସ୍ଥିର ଶୂନ୍ୟ *log_handler_ctx;
ସ୍ଥିର ଅକ୍ଷର **log_verbose;
ସ୍ଥିର size_t nlog_verbose;
ବାହ୍ୟ ଅକ୍ଷର *__progname;

#define LOG_SYSLOG_VIS	(VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL)
#define LOG_STDERR_VIS	(VIS_SAFE|VIS_OCTAL)

/* textual representation of log-facilities/levels */

ସ୍ଥିର ସଂରଚନା {
	ଅଚଳ ଅକ୍ଷର *name;
	SyslogFacility val;
} log_facilities[] = {
	{ "DAEMON",	SYSLOG_FACILITY_DAEMON },
	{ "USER",	SYSLOG_FACILITY_USER },
	{ "AUTH",	SYSLOG_FACILITY_AUTH },
#ifdef LOG_AUTHPRIV
	{ "AUTHPRIV",	SYSLOG_FACILITY_AUTHPRIV },
#endif
	{ "LOCAL0",	SYSLOG_FACILITY_LOCAL0 },
	{ "LOCAL1",	SYSLOG_FACILITY_LOCAL1 },
	{ "LOCAL2",	SYSLOG_FACILITY_LOCAL2 },
	{ "LOCAL3",	SYSLOG_FACILITY_LOCAL3 },
	{ "LOCAL4",	SYSLOG_FACILITY_LOCAL4 },
	{ "LOCAL5",	SYSLOG_FACILITY_LOCAL5 },
	{ "LOCAL6",	SYSLOG_FACILITY_LOCAL6 },
	{ "LOCAL7",	SYSLOG_FACILITY_LOCAL7 },
	{ ଖାଲି,		SYSLOG_FACILITY_NOT_SET }
};

ସ୍ଥିର ସଂରଚନା {
	ଅଚଳ ଅକ୍ଷର *name;
	LogLevel val;
} log_levels[] =
{
	{ "QUIET",	SYSLOG_LEVEL_QUIET },
	{ "FATAL",	SYSLOG_LEVEL_FATAL },
	{ "ERROR",	SYSLOG_LEVEL_ERROR },
	{ "INFO",	SYSLOG_LEVEL_INFO },
	{ "VERBOSE",	SYSLOG_LEVEL_VERBOSE },
	{ "DEBUG",	SYSLOG_LEVEL_DEBUG1 },
	{ "DEBUG1",	SYSLOG_LEVEL_DEBUG1 },
	{ "DEBUG2",	SYSLOG_LEVEL_DEBUG2 },
	{ "DEBUG3",	SYSLOG_LEVEL_DEBUG3 },
	{ ଖାଲି,		SYSLOG_LEVEL_NOT_SET }
};

LogLevel
log_level_get(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ log_level;
}

SyslogFacility
log_facility_ସଂଖ୍ୟା(ଅକ୍ଷର *name)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (name != ଖାଲି)
		ପାଇଁ (i = 0; log_facilities[i].name; i++)
			ଯଦି (strcasecmp(log_facilities[i].name, name) == 0)
				ଫେରନ୍ତୁ log_facilities[i].val;
	ଫେରନ୍ତୁ SYSLOG_FACILITY_NOT_SET;
}

ଅଚଳ ଅକ୍ଷର *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	ପାଇଁ (i = 0;  log_facilities[i].name; i++)
		ଯଦି (log_facilities[i].val == facility)
			ଫେରନ୍ତୁ log_facilities[i].name;
	ଫେରନ୍ତୁ ଖାଲି;
}

LogLevel
log_level_ସଂଖ୍ୟା(ଅକ୍ଷର *name)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (name != ଖାଲି)
		ପାଇଁ (i = 0; log_levels[i].name; i++)
			ଯଦି (strcasecmp(log_levels[i].name, name) == 0)
				ଫେରନ୍ତୁ log_levels[i].val;
	ଫେରନ୍ତୁ SYSLOG_LEVEL_NOT_SET;
}

ଅଚଳ ଅକ୍ଷର *
log_level_name(LogLevel level)
{
	u_int i;

	ପାଇଁ (i = 0; log_levels[i].name != ଖାଲି; i++)
		ଯଦି (log_levels[i].val == level)
			ଫେରନ୍ତୁ log_levels[i].name;
	ଫେରନ୍ତୁ ଖାଲି;
}

ଶୂନ୍ୟ
log_verbose_add(ଅଚଳ ଅକ୍ଷର *s)
{
	ଅକ୍ଷର **tmp;

	/* Ignore failures here */
	ଯଦି ((tmp = recallocarray(log_verbose, nlog_verbose, nlog_verbose + 1,
	    ଆକାର(*log_verbose))) != ଖାଲି) {
		log_verbose = tmp;
		ଯଦି ((log_verbose[nlog_verbose] = strdup(s)) != ଖାଲି)
			nlog_verbose++;
	}
}

ଶୂନ୍ୟ
log_verbose_reset(ଶୂନ୍ୟ)
{
	size_t i;

	ପାଇଁ (i = 0; i < nlog_verbose; i++)
		ମୁକ୍ତ(log_verbose[i]);
	ମୁକ୍ତ(log_verbose);
	log_verbose = ଖାଲି;
	nlog_verbose = 0;
}

/*
 * Initialize the log.
 */

ଶୂନ୍ୟ
log_init(ଅଚଳ ଅକ୍ଷର *av0, LogLevel level, SyslogFacility facility,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା on_stderr)
{
#ଯଦି defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	ସଂରଚନା syslog_data sdata = SYSLOG_DATA_INIT;
#endif

	argv0 = av0;

	ଯଦି (log_change_level(level) != 0) {
		fprintf(stderr, "Unrecognized internal syslog level code %d\n",
		    (ପୂର୍ଣ୍ଣସଂଖ୍ୟା) level);
		exit(1);
	}

	log_handler = ଖାଲି;
	log_handler_ctx = ଖାଲି;

	log_on_stderr = on_stderr;
	ଯଦି (on_stderr)
		ଫେରନ୍ତୁ;

	ବାଛ (facility) {
	ସ୍ଥିତି SYSLOG_FACILITY_DAEMON:
		log_facility = LOG_DAEMON;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SYSLOG_FACILITY_USER:
		log_facility = LOG_USER;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SYSLOG_FACILITY_AUTH:
		log_facility = LOG_AUTH;
		ଭାଙ୍ଗ;
#ifdef LOG_AUTHPRIV
	ସ୍ଥିତି SYSLOG_FACILITY_AUTHPRIV:
		log_facility = LOG_AUTHPRIV;
		ଭାଙ୍ଗ;
#endif
	ସ୍ଥିତି SYSLOG_FACILITY_LOCAL0:
		log_facility = LOG_LOCAL0;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SYSLOG_FACILITY_LOCAL1:
		log_facility = LOG_LOCAL1;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SYSLOG_FACILITY_LOCAL2:
		log_facility = LOG_LOCAL2;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SYSLOG_FACILITY_LOCAL3:
		log_facility = LOG_LOCAL3;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SYSLOG_FACILITY_LOCAL4:
		log_facility = LOG_LOCAL4;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SYSLOG_FACILITY_LOCAL5:
		log_facility = LOG_LOCAL5;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SYSLOG_FACILITY_LOCAL6:
		log_facility = LOG_LOCAL6;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SYSLOG_FACILITY_LOCAL7:
		log_facility = LOG_LOCAL7;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fprintf(stderr,
		    "Unrecognized internal syslog facility code %d\n",
		    (ପୂର୍ଣ୍ଣସଂଖ୍ୟା) facility);
		exit(1);
	}

	/*
	 * If an external library (eg libwrap) attempts to use syslog
	 * immediately after reexec, syslog may be pointing to the wrong
	 * facility, so we force an open/close of syslog here.
	 */
#ଯଦି defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	openlog_r(argv0 ? argv0 : __progname, LOG_PID, log_facility, &sdata);
	closelog_r(&sdata);
#ଅନ୍ୟଥା
	openlog(argv0 ? argv0 : __progname, LOG_PID, log_facility);
	closelog();
#endif
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
log_change_level(LogLevel new_log_level)
{
	/* no-op if log_init has not been called */
	ଯଦି (argv0 == ଖାଲି)
		ଫେରନ୍ତୁ 0;

	ବାଛ (new_log_level) {
	ସ୍ଥିତି SYSLOG_LEVEL_QUIET:
	ସ୍ଥିତି SYSLOG_LEVEL_FATAL:
	ସ୍ଥିତି SYSLOG_LEVEL_ERROR:
	ସ୍ଥିତି SYSLOG_LEVEL_INFO:
	ସ୍ଥିତି SYSLOG_LEVEL_VERBOSE:
	ସ୍ଥିତି SYSLOG_LEVEL_DEBUG1:
	ସ୍ଥିତି SYSLOG_LEVEL_DEBUG2:
	ସ୍ଥିତି SYSLOG_LEVEL_DEBUG3:
		log_level = new_log_level;
		ଫେରନ୍ତୁ 0;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ -1;
	}
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
log_is_on_stderr(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ log_on_stderr && log_stderr_fd == STDERR_FILENO;
}

/* redirect what would usually get written to stderr to specified file */
ଶୂନ୍ୟ
log_redirect_stderr_to(ଅଚଳ ଅକ୍ଷର *logfile)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;

	ଯଦି (logfile == ଖାଲି) {
		ଯଦି (log_stderr_fd != STDERR_FILENO) {
			close(log_stderr_fd);
			log_stderr_fd = STDERR_FILENO;
		}
		ଫେରନ୍ତୁ;
	}

	ଯଦି ((fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1) {
		fprintf(stderr, "Couldn't open logfile %s: %s\n", logfile,
		    strerror(errno));
		exit(1);
	}
	log_stderr_fd = fd;
}

#define MSGBUFSIZ 1024

ଶୂନ୍ୟ
set_log_handler(log_handler_fn *handler, ଶୂନ୍ୟ *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}

ସ୍ଥିର ଶୂନ୍ୟ
do_log(LogLevel level, ପୂର୍ଣ୍ଣସଂଖ୍ୟା force, ଅଚଳ ଅକ୍ଷର *suffix, ଅଚଳ ଅକ୍ଷର *fmt,
    va_list args)
{
#ଯଦି defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	ସଂରଚନା syslog_data sdata = SYSLOG_DATA_INIT;
#endif
	ଅକ୍ଷର msgbuf[MSGBUFSIZ];
	ଅକ୍ଷର fmtbuf[MSGBUFSIZ];
	ଅକ୍ଷର *txt = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା pri = LOG_INFO;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା saved_errno = errno;
	log_handler_fn *tmp_handler;
	ଅଚଳ ଅକ୍ଷର *progname = argv0 != ଖାଲି ? argv0 : __progname;

	ଯଦି (!force && level > log_level)
		ଫେରନ୍ତୁ;

	ବାଛ (level) {
	ସ୍ଥିତି SYSLOG_LEVEL_FATAL:
		ଯଦି (!log_on_stderr)
			txt = "fatal";
		pri = LOG_CRIT;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SYSLOG_LEVEL_ERROR:
		ଯଦି (!log_on_stderr)
			txt = "error";
		pri = LOG_ERR;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SYSLOG_LEVEL_INFO:
		pri = LOG_INFO;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SYSLOG_LEVEL_VERBOSE:
		pri = LOG_INFO;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		pri = LOG_DEBUG;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		pri = LOG_DEBUG;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SYSLOG_LEVEL_DEBUG3:
		txt = "debug3";
		pri = LOG_DEBUG;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		txt = "internal error";
		pri = LOG_ERR;
		ଭାଙ୍ଗ;
	}
	ଯଦି (txt != ଖାଲି && log_handler == ଖାଲି) {
		snprintf(fmtbuf, ଆକାର(fmtbuf), "%s: %s", txt, fmt);
		vsnprintf(msgbuf, ଆକାର(msgbuf), fmtbuf, args);
	} ଅନ୍ୟଥା {
		vsnprintf(msgbuf, ଆକାର(msgbuf), fmt, args);
	}
	ଯଦି (suffix != ଖାଲି) {
		snprintf(fmtbuf, ଆକାର(fmtbuf), "%s: %s", msgbuf, suffix);
		strlcpy(msgbuf, fmtbuf, ଆକାର(msgbuf));
	}
	strnvis(fmtbuf, msgbuf, ଆକାର(fmtbuf),
	    log_on_stderr ? LOG_STDERR_VIS : LOG_SYSLOG_VIS);
	ଯଦି (log_handler != ଖାଲି) {
		/* Avoid recursion */
		tmp_handler = log_handler;
		log_handler = ଖାଲି;
		/* Note: this sends the raw (i.e. no strnvis) log message */
		tmp_handler(level, force, msgbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} ଅନ୍ୟଥା ଯଦି (log_on_stderr) {
		snprintf(msgbuf, ଆକାର msgbuf, "%s%s%.*s\r\n",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)ଆକାର msgbuf - 3, fmtbuf);
		(ଶୂନ୍ୟ)ଲିଖ(log_stderr_fd, msgbuf, strlen(msgbuf));
	} ଅନ୍ୟଥା {
#ଯଦି defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
		openlog_r(progname, LOG_PID, log_facility, &sdata);
		syslog_r(pri, &sdata, "%.500s", fmtbuf);
		closelog_r(&sdata);
#ଅନ୍ୟଥା
		openlog(progname, LOG_PID, log_facility);
		syslog(pri, "%.500s", fmtbuf);
		closelog();
#endif
	}
	errno = saved_errno;
}

ଶୂନ୍ୟ
sshlog(ଅଚଳ ଅକ୍ଷର *file, ଅଚଳ ଅକ୍ଷର *func, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା showfunc,
    LogLevel level, ଅଚଳ ଅକ୍ଷର *suffix, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, ଧାଡ଼ି, showfunc, level, suffix, fmt, args);
	va_end(args);
}

ଶୂନ୍ୟ
sshlogdie(ଅଚଳ ଅକ୍ଷର *file, ଅଚଳ ଅକ୍ଷର *func, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା showfunc,
    LogLevel level, ଅଚଳ ଅକ୍ଷର *suffix, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, ଧାଡ଼ି, showfunc, SYSLOG_LEVEL_INFO,
	    suffix, fmt, args);
	va_end(args);
	cleanup_exit(255);
}

ଶୂନ୍ୟ
sshlogv(ଅଚଳ ଅକ୍ଷର *file, ଅଚଳ ଅକ୍ଷର *func, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା showfunc,
    LogLevel level, ଅଚଳ ଅକ୍ଷର *suffix, ଅଚଳ ଅକ୍ଷର *fmt, va_list args)
{
	ଅକ୍ଷର tag[128], fmt2[MSGBUFSIZ + 128];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା forced = 0;
	ଅଚଳ ଅକ୍ଷର *cp;
	size_t i;

	/* short circuit processing early if we're not going to log anything */
	ଯଦି (nlog_verbose == 0 && level > log_level)
		ଫେରନ୍ତୁ;

	snprintf(tag, ଆକାର(tag), "%.48s:%.48s():%d (bin=%s, pid=%ld)",
	    (cp = strrchr(file, '/')) == ଖାଲି ? file : cp + 1, func, ଧାଡ଼ି,
	    argv0 == ଖାଲି ? "UNKNOWN" : argv0, (long)getpid());
	ପାଇଁ (i = 0; i < nlog_verbose; i++) {
		ଯଦି (match_pattern_list(tag, log_verbose[i], 0) == 1) {
			forced = 1;
			ଭାଙ୍ଗ;
		}
	}

	ଯଦି (forced)
		snprintf(fmt2, ଆକାର(fmt2), "%s: %s", tag, fmt);
	ଅନ୍ୟଥା ଯଦି (showfunc)
		snprintf(fmt2, ଆକାର(fmt2), "%s: %s", func, fmt);
	ଅନ୍ୟଥା
		strlcpy(fmt2, fmt, ଆକାର(fmt2));

	do_log(level, forced, suffix, fmt2, args);
}

ଶୂନ୍ୟ
sshlogdirect(LogLevel level, ପୂର୍ଣ୍ଣସଂଖ୍ୟା forced, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(level, forced, ଖାଲି, fmt, args);
	va_end(args);
}


/*
 * A simple system for ratelimiting aperiodic events such as logs, without
 * needing to be hooked into a mainloop/timer. A running total of events is
 * maintained and when it exceeds a threshold further events are dropped
 * until the rate falls back below that threshold.
 *
 * To prevent flipping in and out of rate-limiting, there is a hysteresis
 * timer that delays leaving the rate-limited state.
 *
 * While in the rate-limited state, events can be periodically allowed through
 * and the number of dropped events since the last log obtained.
 *
 * XXX a moving average rate of events might be a better approach here rather
 *     than linear decay, which can suppress events for a while after large
 *     bursts.
 */

/* #define RATELIMIT_DEBUG 1 */

#ifdef RATELIMIT_DEBUG
# define RLDBG(x) କର { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} ଯେତେବେଳେ (0)
#ଅନ୍ୟଥା
# define RLDBG(x)
#endif

/* set up a ratelimit */
ଶୂନ୍ୟ
log_ratelimit_init(ସଂରଚନା log_ratelimit_ctx *rl, u_int threshold,
    u_int max_accum, u_int hysteresis, u_int log_every)
{
	memset(rl, 0, ଆକାର(*rl));
	rl->threshold = threshold;
	rl->max_accum = max_accum;
	rl->hysteresis = hysteresis;
	rl->log_every = log_every;
	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u",
	    rl, rl->threshold, rl->max_accum, rl->hysteresis, rl->log_every));
}

/*
 * check whether a log event should be dropped because of rate-limiting.
 * returns non-zero if the event should be dropped. If events_since_last
 * is supplied then, for periodic logs, it will be set to the number of
 * dropped events since the last message.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
log_ratelimit(ସଂରଚନା log_ratelimit_ctx *rl, time_t now, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *active,
    u_int *events_dropped)
{
	time_t olast_event;

	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u "
	    "accum=%u since=%ld since_last=%u", rl, rl->threshold,
	    rl->max_accum, rl->hysteresis,
	    rl->log_every, rl->accumulated_events,
	    rl->last_event == 0 ? -1 : (long)(now - rl->last_event),
	    rl->ratelimited_events));

	ଯଦି (now < 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି (events_dropped != ଖାଲି)
		*events_dropped = 0;
	ଯଦି (active != ଖାଲି)
		*active = rl->ratelimit_active;

	/* First, decay accumulated events */
	ଯଦି (rl->last_event <= 0)
		rl->last_event = now;
	ଯଦି (now > rl->last_event) {
		uint64_t n = now - rl->last_event;

		ଯଦି (n > UINT_MAX)
			n = UINT_MAX;
		ଯଦି (rl->accumulated_events < (u_int)n)
			rl->accumulated_events = 0;
		ଅନ୍ୟଥା
			rl->accumulated_events -= (u_int)n;
		RLDBG(("decay: accum=%u", rl->accumulated_events));
	}
	rl->accumulated_events++; /* add this event */
	ଯଦି (rl->accumulated_events > rl->max_accum)
		rl->accumulated_events = rl->max_accum;
	olast_event = rl->last_event;
	rl->last_event = now;
	RLDBG(("check threshold: accum=%u vs thresh=%u",
	    rl->accumulated_events, rl->threshold));

	/* Are we under threshold? */
	ଯଦି (rl->accumulated_events < rl->threshold) {
		ଯଦି (!rl->ratelimit_active)
			ଫେରନ୍ତୁ 0;
		RLDBG(("under threshold: hys=%u since_hys=%ld since_last=%ld",
		    rl->hysteresis, rl->hysteresis_start == 0 ? -1 :
		    (long)(now - rl->hysteresis_start),
		    olast_event == 0 ? -1 : (long)(now - olast_event)));
		ଯଦି (rl->hysteresis_start == 0) {
			/* active, but under threshold; hysteresis */
			ଯଦି (olast_event + rl->hysteresis < now) {
				/* hysteresis expired before this event */
				RLDBG(("hysteresis preexpired"));
				ଯାଅ inactive;
			}
			RLDBG(("start hysteresis"));
			rl->hysteresis_start = now;
		} ଅନ୍ୟଥା ଯଦି (rl->hysteresis_start + rl->hysteresis < now) {
			/* Hysteresis period expired, transition to inactive */
			RLDBG(("complete hysteresis"));
 inactive:
			ଯଦି (events_dropped != ଖାଲି)
				*events_dropped = rl->ratelimited_events;
			ଯଦି (active != ଖାଲି)
				*active = 0;
			rl->ratelimit_active = 0;
			rl->ratelimit_start = 0;
			rl->last_log = 0;
			rl->hysteresis_start = 0;
			rl->ratelimited_events = 0;
			ଫେରନ୍ତୁ 0;
		}
		/* ratelimiting active, but in hysteresis period */
	} ଅନ୍ୟଥା ଯଦି (!rl->ratelimit_active) {
		/* Transition to rate-limiting */
		RLDBG(("start ratelimit"));
		rl->ratelimit_active = 1;
		rl->ratelimit_start = now;
		rl->last_log = now;
		rl->hysteresis_start = 0;
		rl->ratelimited_events = 1;
		ଯଦି (active != ଖାଲି)
			*active = 1;
		ଫେରନ୍ତୁ 1;
	} ଅନ୍ୟଥା ଯଦି (rl->hysteresis_start != 0) {
		/* active and over threshold; reset hysteresis timer */
		RLDBG(("clear hysteresis"));
		rl->hysteresis_start = 0;
	}

	/* over threshold or in hysteresis period; log periodically */
	ଯଦି (active != ଖାଲି)
		*active = 1;
	RLDBG(("log_every=%u since_log=%ld", rl->log_every,
	    (long)(now - rl->last_log)));
	ଯଦି (rl->log_every > 0 && now >= rl->last_log + rl->log_every) {
		RLDBG(("periodic: since_last=%u", rl->ratelimited_events));
		rl->last_log = now;
		ଯଦି (events_dropped != ଖାଲି) {
			*events_dropped = rl->ratelimited_events;
			rl->ratelimited_events = 0;
		}
		ଫେରନ୍ତୁ 0;
	}

	/* drop event */
	rl->ratelimited_events++;
	RLDBG(("drop: ratelimited_events=%u", rl->ratelimited_events));
	ଫେରନ୍ତୁ 1;
}
