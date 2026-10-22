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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <syslog.h>
#അന്തര്ഭാവ <unistd.h>
#എങ്കിൽ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "match.h"

സ്ഥിതം LogLevel log_level = SYSLOG_LEVEL_INFO;
സ്ഥിതം പൂർണ്ണസംഖ്യ log_on_stderr = 1;
സ്ഥിതം പൂർണ്ണസംഖ്യ log_stderr_fd = STDERR_FILENO;
സ്ഥിതം പൂർണ്ണസംഖ്യ log_facility = LOG_AUTH;
സ്ഥിതം സ്ഥിരം അക്ഷരം *argv0;
സ്ഥിതം log_handler_fn *log_handler;
സ്ഥിതം ശൂന്യം *log_handler_ctx;
സ്ഥിതം അക്ഷരം **log_verbose;
സ്ഥിതം size_t nlog_verbose;
ബാഹ്യ അക്ഷരം *__progname;

#define LOG_SYSLOG_VIS	(VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL)
#define LOG_STDERR_VIS	(VIS_SAFE|VIS_OCTAL)

/* textual representation of log-facilities/levels */

സ്ഥിതം ഘടന {
	സ്ഥിരം അക്ഷരം *name;
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
	{ ശൂന്യ,		SYSLOG_FACILITY_NOT_SET }
};

സ്ഥിതം ഘടന {
	സ്ഥിരം അക്ഷരം *name;
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
	{ ശൂന്യ,		SYSLOG_LEVEL_NOT_SET }
};

LogLevel
log_level_get(ശൂന്യം)
{
	തിരികെ log_level;
}

SyslogFacility
log_facility_സംഖ്യ(അക്ഷരം *name)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (name != ശൂന്യ)
		വേണ്ടി (i = 0; log_facilities[i].name; i++)
			എങ്കിൽ (strcasecmp(log_facilities[i].name, name) == 0)
				തിരികെ log_facilities[i].val;
	തിരികെ SYSLOG_FACILITY_NOT_SET;
}

സ്ഥിരം അക്ഷരം *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	വേണ്ടി (i = 0;  log_facilities[i].name; i++)
		എങ്കിൽ (log_facilities[i].val == facility)
			തിരികെ log_facilities[i].name;
	തിരികെ ശൂന്യ;
}

LogLevel
log_level_സംഖ്യ(അക്ഷരം *name)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (name != ശൂന്യ)
		വേണ്ടി (i = 0; log_levels[i].name; i++)
			എങ്കിൽ (strcasecmp(log_levels[i].name, name) == 0)
				തിരികെ log_levels[i].val;
	തിരികെ SYSLOG_LEVEL_NOT_SET;
}

സ്ഥിരം അക്ഷരം *
log_level_name(LogLevel level)
{
	u_int i;

	വേണ്ടി (i = 0; log_levels[i].name != ശൂന്യ; i++)
		എങ്കിൽ (log_levels[i].val == level)
			തിരികെ log_levels[i].name;
	തിരികെ ശൂന്യ;
}

ശൂന്യം
log_verbose_add(സ്ഥിരം അക്ഷരം *s)
{
	അക്ഷരം **tmp;

	/* Ignore failures here */
	എങ്കിൽ ((tmp = recallocarray(log_verbose, nlog_verbose, nlog_verbose + 1,
	    വലുപ്പം(*log_verbose))) != ശൂന്യ) {
		log_verbose = tmp;
		എങ്കിൽ ((log_verbose[nlog_verbose] = strdup(s)) != ശൂന്യ)
			nlog_verbose++;
	}
}

ശൂന്യം
log_verbose_reset(ശൂന്യം)
{
	size_t i;

	വേണ്ടി (i = 0; i < nlog_verbose; i++)
		സ്വതന്ത്രം(log_verbose[i]);
	സ്വതന്ത്രം(log_verbose);
	log_verbose = ശൂന്യ;
	nlog_verbose = 0;
}

/*
 * Initialize the log.
 */

ശൂന്യം
log_init(സ്ഥിരം അക്ഷരം *av0, LogLevel level, SyslogFacility facility,
    പൂർണ്ണസംഖ്യ on_stderr)
{
#എങ്കിൽ defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	ഘടന syslog_data sdata = SYSLOG_DATA_INIT;
#endif

	argv0 = av0;

	എങ്കിൽ (log_change_level(level) != 0) {
		fprintf(stderr, "Unrecognized internal syslog level code %d\n",
		    (പൂർണ്ണസംഖ്യ) level);
		exit(1);
	}

	log_handler = ശൂന്യ;
	log_handler_ctx = ശൂന്യ;

	log_on_stderr = on_stderr;
	എങ്കിൽ (on_stderr)
		തിരികെ;

	തിരഞ്ഞെടുപ്പ് (facility) {
	അവസ്ഥ SYSLOG_FACILITY_DAEMON:
		log_facility = LOG_DAEMON;
		നിർത്തുക;
	അവസ്ഥ SYSLOG_FACILITY_USER:
		log_facility = LOG_USER;
		നിർത്തുക;
	അവസ്ഥ SYSLOG_FACILITY_AUTH:
		log_facility = LOG_AUTH;
		നിർത്തുക;
#ifdef LOG_AUTHPRIV
	അവസ്ഥ SYSLOG_FACILITY_AUTHPRIV:
		log_facility = LOG_AUTHPRIV;
		നിർത്തുക;
#endif
	അവസ്ഥ SYSLOG_FACILITY_LOCAL0:
		log_facility = LOG_LOCAL0;
		നിർത്തുക;
	അവസ്ഥ SYSLOG_FACILITY_LOCAL1:
		log_facility = LOG_LOCAL1;
		നിർത്തുക;
	അവസ്ഥ SYSLOG_FACILITY_LOCAL2:
		log_facility = LOG_LOCAL2;
		നിർത്തുക;
	അവസ്ഥ SYSLOG_FACILITY_LOCAL3:
		log_facility = LOG_LOCAL3;
		നിർത്തുക;
	അവസ്ഥ SYSLOG_FACILITY_LOCAL4:
		log_facility = LOG_LOCAL4;
		നിർത്തുക;
	അവസ്ഥ SYSLOG_FACILITY_LOCAL5:
		log_facility = LOG_LOCAL5;
		നിർത്തുക;
	അവസ്ഥ SYSLOG_FACILITY_LOCAL6:
		log_facility = LOG_LOCAL6;
		നിർത്തുക;
	അവസ്ഥ SYSLOG_FACILITY_LOCAL7:
		log_facility = LOG_LOCAL7;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		fprintf(stderr,
		    "Unrecognized internal syslog facility code %d\n",
		    (പൂർണ്ണസംഖ്യ) facility);
		exit(1);
	}

	/*
	 * If an external library (eg libwrap) attempts to use syslog
	 * immediately after reexec, syslog may be pointing to the wrong
	 * facility, so we force an open/close of syslog here.
	 */
#എങ്കിൽ defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	openlog_r(argv0 ? argv0 : __progname, LOG_PID, log_facility, &sdata);
	closelog_r(&sdata);
#അല്ലെങ്കിൽ
	openlog(argv0 ? argv0 : __progname, LOG_PID, log_facility);
	closelog();
#endif
}

പൂർണ്ണസംഖ്യ
log_change_level(LogLevel new_log_level)
{
	/* no-op if log_init has not been called */
	എങ്കിൽ (argv0 == ശൂന്യ)
		തിരികെ 0;

	തിരഞ്ഞെടുപ്പ് (new_log_level) {
	അവസ്ഥ SYSLOG_LEVEL_QUIET:
	അവസ്ഥ SYSLOG_LEVEL_FATAL:
	അവസ്ഥ SYSLOG_LEVEL_ERROR:
	അവസ്ഥ SYSLOG_LEVEL_INFO:
	അവസ്ഥ SYSLOG_LEVEL_VERBOSE:
	അവസ്ഥ SYSLOG_LEVEL_DEBUG1:
	അവസ്ഥ SYSLOG_LEVEL_DEBUG2:
	അവസ്ഥ SYSLOG_LEVEL_DEBUG3:
		log_level = new_log_level;
		തിരികെ 0;
	സ്ഥിരസ്ഥിതി:
		തിരികെ -1;
	}
}

പൂർണ്ണസംഖ്യ
log_is_on_stderr(ശൂന്യം)
{
	തിരികെ log_on_stderr && log_stderr_fd == STDERR_FILENO;
}

/* redirect what would usually get written to stderr to specified file */
ശൂന്യം
log_redirect_stderr_to(സ്ഥിരം അക്ഷരം *logfile)
{
	പൂർണ്ണസംഖ്യ fd;

	എങ്കിൽ (logfile == ശൂന്യ) {
		എങ്കിൽ (log_stderr_fd != STDERR_FILENO) {
			close(log_stderr_fd);
			log_stderr_fd = STDERR_FILENO;
		}
		തിരികെ;
	}

	എങ്കിൽ ((fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1) {
		fprintf(stderr, "Couldn't open logfile %s: %s\n", logfile,
		    strerror(errno));
		exit(1);
	}
	log_stderr_fd = fd;
}

#define MSGBUFSIZ 1024

ശൂന്യം
set_log_handler(log_handler_fn *handler, ശൂന്യം *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}

സ്ഥിതം ശൂന്യം
do_log(LogLevel level, പൂർണ്ണസംഖ്യ force, സ്ഥിരം അക്ഷരം *suffix, സ്ഥിരം അക്ഷരം *fmt,
    va_list args)
{
#എങ്കിൽ defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	ഘടന syslog_data sdata = SYSLOG_DATA_INIT;
#endif
	അക്ഷരം msgbuf[MSGBUFSIZ];
	അക്ഷരം fmtbuf[MSGBUFSIZ];
	അക്ഷരം *txt = ശൂന്യ;
	പൂർണ്ണസംഖ്യ pri = LOG_INFO;
	പൂർണ്ണസംഖ്യ saved_errno = errno;
	log_handler_fn *tmp_handler;
	സ്ഥിരം അക്ഷരം *progname = argv0 != ശൂന്യ ? argv0 : __progname;

	എങ്കിൽ (!force && level > log_level)
		തിരികെ;

	തിരഞ്ഞെടുപ്പ് (level) {
	അവസ്ഥ SYSLOG_LEVEL_FATAL:
		എങ്കിൽ (!log_on_stderr)
			txt = "fatal";
		pri = LOG_CRIT;
		നിർത്തുക;
	അവസ്ഥ SYSLOG_LEVEL_ERROR:
		എങ്കിൽ (!log_on_stderr)
			txt = "error";
		pri = LOG_ERR;
		നിർത്തുക;
	അവസ്ഥ SYSLOG_LEVEL_INFO:
		pri = LOG_INFO;
		നിർത്തുക;
	അവസ്ഥ SYSLOG_LEVEL_VERBOSE:
		pri = LOG_INFO;
		നിർത്തുക;
	അവസ്ഥ SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		pri = LOG_DEBUG;
		നിർത്തുക;
	അവസ്ഥ SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		pri = LOG_DEBUG;
		നിർത്തുക;
	അവസ്ഥ SYSLOG_LEVEL_DEBUG3:
		txt = "debug3";
		pri = LOG_DEBUG;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		txt = "internal error";
		pri = LOG_ERR;
		നിർത്തുക;
	}
	എങ്കിൽ (txt != ശൂന്യ && log_handler == ശൂന്യ) {
		snprintf(fmtbuf, വലുപ്പം(fmtbuf), "%s: %s", txt, fmt);
		vsnprintf(msgbuf, വലുപ്പം(msgbuf), fmtbuf, args);
	} അല്ലെങ്കിൽ {
		vsnprintf(msgbuf, വലുപ്പം(msgbuf), fmt, args);
	}
	എങ്കിൽ (suffix != ശൂന്യ) {
		snprintf(fmtbuf, വലുപ്പം(fmtbuf), "%s: %s", msgbuf, suffix);
		strlcpy(msgbuf, fmtbuf, വലുപ്പം(msgbuf));
	}
	strnvis(fmtbuf, msgbuf, വലുപ്പം(fmtbuf),
	    log_on_stderr ? LOG_STDERR_VIS : LOG_SYSLOG_VIS);
	എങ്കിൽ (log_handler != ശൂന്യ) {
		/* Avoid recursion */
		tmp_handler = log_handler;
		log_handler = ശൂന്യ;
		/* Note: this sends the raw (i.e. no strnvis) log message */
		tmp_handler(level, force, msgbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} അല്ലെങ്കിൽ എങ്കിൽ (log_on_stderr) {
		snprintf(msgbuf, വലുപ്പം msgbuf, "%s%s%.*s\r\n",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (പൂർണ്ണസംഖ്യ)വലുപ്പം msgbuf - 3, fmtbuf);
		(ശൂന്യം)ലിഖ(log_stderr_fd, msgbuf, strlen(msgbuf));
	} അല്ലെങ്കിൽ {
#എങ്കിൽ defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
		openlog_r(progname, LOG_PID, log_facility, &sdata);
		syslog_r(pri, &sdata, "%.500s", fmtbuf);
		closelog_r(&sdata);
#അല്ലെങ്കിൽ
		openlog(progname, LOG_PID, log_facility);
		syslog(pri, "%.500s", fmtbuf);
		closelog();
#endif
	}
	errno = saved_errno;
}

ശൂന്യം
sshlog(സ്ഥിരം അക്ഷരം *file, സ്ഥിരം അക്ഷരം *func, പൂർണ്ണസംഖ്യ വരി, പൂർണ്ണസംഖ്യ showfunc,
    LogLevel level, സ്ഥിരം അക്ഷരം *suffix, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, വരി, showfunc, level, suffix, fmt, args);
	va_end(args);
}

ശൂന്യം
sshlogdie(സ്ഥിരം അക്ഷരം *file, സ്ഥിരം അക്ഷരം *func, പൂർണ്ണസംഖ്യ വരി, പൂർണ്ണസംഖ്യ showfunc,
    LogLevel level, സ്ഥിരം അക്ഷരം *suffix, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, വരി, showfunc, SYSLOG_LEVEL_INFO,
	    suffix, fmt, args);
	va_end(args);
	cleanup_exit(255);
}

ശൂന്യം
sshlogv(സ്ഥിരം അക്ഷരം *file, സ്ഥിരം അക്ഷരം *func, പൂർണ്ണസംഖ്യ വരി, പൂർണ്ണസംഖ്യ showfunc,
    LogLevel level, സ്ഥിരം അക്ഷരം *suffix, സ്ഥിരം അക്ഷരം *fmt, va_list args)
{
	അക്ഷരം tag[128], fmt2[MSGBUFSIZ + 128];
	പൂർണ്ണസംഖ്യ forced = 0;
	സ്ഥിരം അക്ഷരം *cp;
	size_t i;

	/* short circuit processing early if we're not going to log anything */
	എങ്കിൽ (nlog_verbose == 0 && level > log_level)
		തിരികെ;

	snprintf(tag, വലുപ്പം(tag), "%.48s:%.48s():%d (bin=%s, pid=%ld)",
	    (cp = strrchr(file, '/')) == ശൂന്യ ? file : cp + 1, func, വരി,
	    argv0 == ശൂന്യ ? "UNKNOWN" : argv0, (long)getpid());
	വേണ്ടി (i = 0; i < nlog_verbose; i++) {
		എങ്കിൽ (match_pattern_list(tag, log_verbose[i], 0) == 1) {
			forced = 1;
			നിർത്തുക;
		}
	}

	എങ്കിൽ (forced)
		snprintf(fmt2, വലുപ്പം(fmt2), "%s: %s", tag, fmt);
	അല്ലെങ്കിൽ എങ്കിൽ (showfunc)
		snprintf(fmt2, വലുപ്പം(fmt2), "%s: %s", func, fmt);
	അല്ലെങ്കിൽ
		strlcpy(fmt2, fmt, വലുപ്പം(fmt2));

	do_log(level, forced, suffix, fmt2, args);
}

ശൂന്യം
sshlogdirect(LogLevel level, പൂർണ്ണസംഖ്യ forced, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(level, forced, ശൂന്യ, fmt, args);
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
# define RLDBG(x) ചെയ്യുക { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} ആകുമ്പോൾ (0)
#അല്ലെങ്കിൽ
# define RLDBG(x)
#endif

/* set up a ratelimit */
ശൂന്യം
log_ratelimit_init(ഘടന log_ratelimit_ctx *rl, u_int threshold,
    u_int max_accum, u_int hysteresis, u_int log_every)
{
	memset(rl, 0, വലുപ്പം(*rl));
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
പൂർണ്ണസംഖ്യ
log_ratelimit(ഘടന log_ratelimit_ctx *rl, time_t now, പൂർണ്ണസംഖ്യ *active,
    u_int *events_dropped)
{
	time_t olast_event;

	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u "
	    "accum=%u since=%ld since_last=%u", rl, rl->threshold,
	    rl->max_accum, rl->hysteresis,
	    rl->log_every, rl->accumulated_events,
	    rl->last_event == 0 ? -1 : (long)(now - rl->last_event),
	    rl->ratelimited_events));

	എങ്കിൽ (now < 0)
		തിരികെ 0;
	എങ്കിൽ (events_dropped != ശൂന്യ)
		*events_dropped = 0;
	എങ്കിൽ (active != ശൂന്യ)
		*active = rl->ratelimit_active;

	/* First, decay accumulated events */
	എങ്കിൽ (rl->last_event <= 0)
		rl->last_event = now;
	എങ്കിൽ (now > rl->last_event) {
		uint64_t n = now - rl->last_event;

		എങ്കിൽ (n > UINT_MAX)
			n = UINT_MAX;
		എങ്കിൽ (rl->accumulated_events < (u_int)n)
			rl->accumulated_events = 0;
		അല്ലെങ്കിൽ
			rl->accumulated_events -= (u_int)n;
		RLDBG(("decay: accum=%u", rl->accumulated_events));
	}
	rl->accumulated_events++; /* add this event */
	എങ്കിൽ (rl->accumulated_events > rl->max_accum)
		rl->accumulated_events = rl->max_accum;
	olast_event = rl->last_event;
	rl->last_event = now;
	RLDBG(("check threshold: accum=%u vs thresh=%u",
	    rl->accumulated_events, rl->threshold));

	/* Are we under threshold? */
	എങ്കിൽ (rl->accumulated_events < rl->threshold) {
		എങ്കിൽ (!rl->ratelimit_active)
			തിരികെ 0;
		RLDBG(("under threshold: hys=%u since_hys=%ld since_last=%ld",
		    rl->hysteresis, rl->hysteresis_start == 0 ? -1 :
		    (long)(now - rl->hysteresis_start),
		    olast_event == 0 ? -1 : (long)(now - olast_event)));
		എങ്കിൽ (rl->hysteresis_start == 0) {
			/* active, but under threshold; hysteresis */
			എങ്കിൽ (olast_event + rl->hysteresis < now) {
				/* hysteresis expired before this event */
				RLDBG(("hysteresis preexpired"));
				പോകുക inactive;
			}
			RLDBG(("start hysteresis"));
			rl->hysteresis_start = now;
		} അല്ലെങ്കിൽ എങ്കിൽ (rl->hysteresis_start + rl->hysteresis < now) {
			/* Hysteresis period expired, transition to inactive */
			RLDBG(("complete hysteresis"));
 inactive:
			എങ്കിൽ (events_dropped != ശൂന്യ)
				*events_dropped = rl->ratelimited_events;
			എങ്കിൽ (active != ശൂന്യ)
				*active = 0;
			rl->ratelimit_active = 0;
			rl->ratelimit_start = 0;
			rl->last_log = 0;
			rl->hysteresis_start = 0;
			rl->ratelimited_events = 0;
			തിരികെ 0;
		}
		/* ratelimiting active, but in hysteresis period */
	} അല്ലെങ്കിൽ എങ്കിൽ (!rl->ratelimit_active) {
		/* Transition to rate-limiting */
		RLDBG(("start ratelimit"));
		rl->ratelimit_active = 1;
		rl->ratelimit_start = now;
		rl->last_log = now;
		rl->hysteresis_start = 0;
		rl->ratelimited_events = 1;
		എങ്കിൽ (active != ശൂന്യ)
			*active = 1;
		തിരികെ 1;
	} അല്ലെങ്കിൽ എങ്കിൽ (rl->hysteresis_start != 0) {
		/* active and over threshold; reset hysteresis timer */
		RLDBG(("clear hysteresis"));
		rl->hysteresis_start = 0;
	}

	/* over threshold or in hysteresis period; log periodically */
	എങ്കിൽ (active != ശൂന്യ)
		*active = 1;
	RLDBG(("log_every=%u since_log=%ld", rl->log_every,
	    (long)(now - rl->last_log)));
	എങ്കിൽ (rl->log_every > 0 && now >= rl->last_log + rl->log_every) {
		RLDBG(("periodic: since_last=%u", rl->ratelimited_events));
		rl->last_log = now;
		എങ്കിൽ (events_dropped != ശൂന്യ) {
			*events_dropped = rl->ratelimited_events;
			rl->ratelimited_events = 0;
		}
		തിരികെ 0;
	}

	/* drop event */
	rl->ratelimited_events++;
	RLDBG(("drop: ratelimited_events=%u", rl->ratelimited_events));
	തിരികെ 1;
}
