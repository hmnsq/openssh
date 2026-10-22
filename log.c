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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <fcntl.h>
#অন্তর্ভাৱ <limits.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <syslog.h>
#অন্তর্ভাৱ <unistd.h>
#যদি defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "match.h"

স্থির LogLevel log_level = SYSLOG_LEVEL_INFO;
স্থির পূর্ণাঙ্ক log_on_stderr = 1;
স্থির পূর্ণাঙ্ক log_stderr_fd = STDERR_FILENO;
স্থির পূর্ণাঙ্ক log_facility = LOG_AUTH;
স্থির ধ্রুৱ ৱর্ণ *argv0;
স্থির log_handler_fn *log_handler;
স্থির শূন্য *log_handler_ctx;
স্থির ৱর্ণ **log_verbose;
স্থির size_t nlog_verbose;
বাহ্য ৱর্ণ *__progname;

#define LOG_SYSLOG_VIS	(VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL)
#define LOG_STDERR_VIS	(VIS_SAFE|VIS_OCTAL)

/* textual representation of log-facilities/levels */

স্থির সংরচনা {
	ধ্রুৱ ৱর্ণ *name;
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
	{ রিক্ত,		SYSLOG_FACILITY_NOT_SET }
};

স্থির সংরচনা {
	ধ্রুৱ ৱর্ণ *name;
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
	{ রিক্ত,		SYSLOG_LEVEL_NOT_SET }
};

LogLevel
log_level_get(শূন্য)
{
	ঘূৰাই log_level;
}

SyslogFacility
log_facility_সংখ্যা(ৱর্ণ *name)
{
	পূর্ণাঙ্ক i;

	যদি (name != রিক্ত)
		বাবে (i = 0; log_facilities[i].name; i++)
			যদি (strcasecmp(log_facilities[i].name, name) == 0)
				ঘূৰাই log_facilities[i].val;
	ঘূৰাই SYSLOG_FACILITY_NOT_SET;
}

ধ্রুৱ ৱর্ণ *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	বাবে (i = 0;  log_facilities[i].name; i++)
		যদি (log_facilities[i].val == facility)
			ঘূৰাই log_facilities[i].name;
	ঘূৰাই রিক্ত;
}

LogLevel
log_level_সংখ্যা(ৱর্ণ *name)
{
	পূর্ণাঙ্ক i;

	যদি (name != রিক্ত)
		বাবে (i = 0; log_levels[i].name; i++)
			যদি (strcasecmp(log_levels[i].name, name) == 0)
				ঘূৰাই log_levels[i].val;
	ঘূৰাই SYSLOG_LEVEL_NOT_SET;
}

ধ্রুৱ ৱর্ণ *
log_level_name(LogLevel level)
{
	u_int i;

	বাবে (i = 0; log_levels[i].name != রিক্ত; i++)
		যদি (log_levels[i].val == level)
			ঘূৰাই log_levels[i].name;
	ঘূৰাই রিক্ত;
}

শূন্য
log_verbose_add(ধ্রুৱ ৱর্ণ *s)
{
	ৱর্ণ **tmp;

	/* Ignore failures here */
	যদি ((tmp = recallocarray(log_verbose, nlog_verbose, nlog_verbose + 1,
	    পরিমাণ(*log_verbose))) != রিক্ত) {
		log_verbose = tmp;
		যদি ((log_verbose[nlog_verbose] = strdup(s)) != রিক্ত)
			nlog_verbose++;
	}
}

শূন্য
log_verbose_reset(শূন্য)
{
	size_t i;

	বাবে (i = 0; i < nlog_verbose; i++)
		মুক্ত(log_verbose[i]);
	মুক্ত(log_verbose);
	log_verbose = রিক্ত;
	nlog_verbose = 0;
}

/*
 * Initialize the log.
 */

শূন্য
log_init(ধ্রুৱ ৱর্ণ *av0, LogLevel level, SyslogFacility facility,
    পূর্ণাঙ্ক on_stderr)
{
#যদি defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	সংরচনা syslog_data sdata = SYSLOG_DATA_INIT;
#endif

	argv0 = av0;

	যদি (log_change_level(level) != 0) {
		fprintf(stderr, "Unrecognized internal syslog level code %d\n",
		    (পূর্ণাঙ্ক) level);
		exit(1);
	}

	log_handler = রিক্ত;
	log_handler_ctx = রিক্ত;

	log_on_stderr = on_stderr;
	যদি (on_stderr)
		ঘূৰাই;

	ৱিকল্প (facility) {
	পক্ষ SYSLOG_FACILITY_DAEMON:
		log_facility = LOG_DAEMON;
		ভঙ্গ;
	পক্ষ SYSLOG_FACILITY_USER:
		log_facility = LOG_USER;
		ভঙ্গ;
	পক্ষ SYSLOG_FACILITY_AUTH:
		log_facility = LOG_AUTH;
		ভঙ্গ;
#ifdef LOG_AUTHPRIV
	পক্ষ SYSLOG_FACILITY_AUTHPRIV:
		log_facility = LOG_AUTHPRIV;
		ভঙ্গ;
#endif
	পক্ষ SYSLOG_FACILITY_LOCAL0:
		log_facility = LOG_LOCAL0;
		ভঙ্গ;
	পক্ষ SYSLOG_FACILITY_LOCAL1:
		log_facility = LOG_LOCAL1;
		ভঙ্গ;
	পক্ষ SYSLOG_FACILITY_LOCAL2:
		log_facility = LOG_LOCAL2;
		ভঙ্গ;
	পক্ষ SYSLOG_FACILITY_LOCAL3:
		log_facility = LOG_LOCAL3;
		ভঙ্গ;
	পক্ষ SYSLOG_FACILITY_LOCAL4:
		log_facility = LOG_LOCAL4;
		ভঙ্গ;
	পক্ষ SYSLOG_FACILITY_LOCAL5:
		log_facility = LOG_LOCAL5;
		ভঙ্গ;
	পক্ষ SYSLOG_FACILITY_LOCAL6:
		log_facility = LOG_LOCAL6;
		ভঙ্গ;
	পক্ষ SYSLOG_FACILITY_LOCAL7:
		log_facility = LOG_LOCAL7;
		ভঙ্গ;
	স্ৱভাৱ:
		fprintf(stderr,
		    "Unrecognized internal syslog facility code %d\n",
		    (পূর্ণাঙ্ক) facility);
		exit(1);
	}

	/*
	 * If an external library (eg libwrap) attempts to use syslog
	 * immediately after reexec, syslog may be pointing to the wrong
	 * facility, so we force an open/close of syslog here.
	 */
#যদি defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	openlog_r(argv0 ? argv0 : __progname, LOG_PID, log_facility, &sdata);
	closelog_r(&sdata);
#অন্যথা
	openlog(argv0 ? argv0 : __progname, LOG_PID, log_facility);
	closelog();
#endif
}

পূর্ণাঙ্ক
log_change_level(LogLevel new_log_level)
{
	/* no-op if log_init has not been called */
	যদি (argv0 == রিক্ত)
		ঘূৰাই 0;

	ৱিকল্প (new_log_level) {
	পক্ষ SYSLOG_LEVEL_QUIET:
	পক্ষ SYSLOG_LEVEL_FATAL:
	পক্ষ SYSLOG_LEVEL_ERROR:
	পক্ষ SYSLOG_LEVEL_INFO:
	পক্ষ SYSLOG_LEVEL_VERBOSE:
	পক্ষ SYSLOG_LEVEL_DEBUG1:
	পক্ষ SYSLOG_LEVEL_DEBUG2:
	পক্ষ SYSLOG_LEVEL_DEBUG3:
		log_level = new_log_level;
		ঘূৰাই 0;
	স্ৱভাৱ:
		ঘূৰাই -1;
	}
}

পূর্ণাঙ্ক
log_is_on_stderr(শূন্য)
{
	ঘূৰাই log_on_stderr && log_stderr_fd == STDERR_FILENO;
}

/* redirect what would usually get written to stderr to specified file */
শূন্য
log_redirect_stderr_to(ধ্রুৱ ৱর্ণ *logfile)
{
	পূর্ণাঙ্ক fd;

	যদি (logfile == রিক্ত) {
		যদি (log_stderr_fd != STDERR_FILENO) {
			close(log_stderr_fd);
			log_stderr_fd = STDERR_FILENO;
		}
		ঘূৰাই;
	}

	যদি ((fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1) {
		fprintf(stderr, "Couldn't open logfile %s: %s\n", logfile,
		    strerror(errno));
		exit(1);
	}
	log_stderr_fd = fd;
}

#define MSGBUFSIZ 1024

শূন্য
set_log_handler(log_handler_fn *handler, শূন্য *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}

স্থির শূন্য
do_log(LogLevel level, পূর্ণাঙ্ক force, ধ্রুৱ ৱর্ণ *suffix, ধ্রুৱ ৱর্ণ *fmt,
    va_list args)
{
#যদি defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	সংরচনা syslog_data sdata = SYSLOG_DATA_INIT;
#endif
	ৱর্ণ msgbuf[MSGBUFSIZ];
	ৱর্ণ fmtbuf[MSGBUFSIZ];
	ৱর্ণ *txt = রিক্ত;
	পূর্ণাঙ্ক pri = LOG_INFO;
	পূর্ণাঙ্ক saved_errno = errno;
	log_handler_fn *tmp_handler;
	ধ্রুৱ ৱর্ণ *progname = argv0 != রিক্ত ? argv0 : __progname;

	যদি (!force && level > log_level)
		ঘূৰাই;

	ৱিকল্প (level) {
	পক্ষ SYSLOG_LEVEL_FATAL:
		যদি (!log_on_stderr)
			txt = "fatal";
		pri = LOG_CRIT;
		ভঙ্গ;
	পক্ষ SYSLOG_LEVEL_ERROR:
		যদি (!log_on_stderr)
			txt = "error";
		pri = LOG_ERR;
		ভঙ্গ;
	পক্ষ SYSLOG_LEVEL_INFO:
		pri = LOG_INFO;
		ভঙ্গ;
	পক্ষ SYSLOG_LEVEL_VERBOSE:
		pri = LOG_INFO;
		ভঙ্গ;
	পক্ষ SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		pri = LOG_DEBUG;
		ভঙ্গ;
	পক্ষ SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		pri = LOG_DEBUG;
		ভঙ্গ;
	পক্ষ SYSLOG_LEVEL_DEBUG3:
		txt = "debug3";
		pri = LOG_DEBUG;
		ভঙ্গ;
	স্ৱভাৱ:
		txt = "internal error";
		pri = LOG_ERR;
		ভঙ্গ;
	}
	যদি (txt != রিক্ত && log_handler == রিক্ত) {
		snprintf(fmtbuf, পরিমাণ(fmtbuf), "%s: %s", txt, fmt);
		vsnprintf(msgbuf, পরিমাণ(msgbuf), fmtbuf, args);
	} অন্যথা {
		vsnprintf(msgbuf, পরিমাণ(msgbuf), fmt, args);
	}
	যদি (suffix != রিক্ত) {
		snprintf(fmtbuf, পরিমাণ(fmtbuf), "%s: %s", msgbuf, suffix);
		strlcpy(msgbuf, fmtbuf, পরিমাণ(msgbuf));
	}
	strnvis(fmtbuf, msgbuf, পরিমাণ(fmtbuf),
	    log_on_stderr ? LOG_STDERR_VIS : LOG_SYSLOG_VIS);
	যদি (log_handler != রিক্ত) {
		/* Avoid recursion */
		tmp_handler = log_handler;
		log_handler = রিক্ত;
		/* Note: this sends the raw (i.e. no strnvis) log message */
		tmp_handler(level, force, msgbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} অন্যথা যদি (log_on_stderr) {
		snprintf(msgbuf, পরিমাণ msgbuf, "%s%s%.*s\r\n",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (পূর্ণাঙ্ক)পরিমাণ msgbuf - 3, fmtbuf);
		(শূন্য)লিখ(log_stderr_fd, msgbuf, strlen(msgbuf));
	} অন্যথা {
#যদি defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
		openlog_r(progname, LOG_PID, log_facility, &sdata);
		syslog_r(pri, &sdata, "%.500s", fmtbuf);
		closelog_r(&sdata);
#অন্যথা
		openlog(progname, LOG_PID, log_facility);
		syslog(pri, "%.500s", fmtbuf);
		closelog();
#endif
	}
	errno = saved_errno;
}

শূন্য
sshlog(ধ্রুৱ ৱর্ণ *file, ধ্রুৱ ৱর্ণ *func, পূর্ণাঙ্ক সাৰি, পূর্ণাঙ্ক showfunc,
    LogLevel level, ধ্রুৱ ৱর্ণ *suffix, ধ্রুৱ ৱর্ণ *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, সাৰি, showfunc, level, suffix, fmt, args);
	va_end(args);
}

শূন্য
sshlogdie(ধ্রুৱ ৱর্ণ *file, ধ্রুৱ ৱর্ণ *func, পূর্ণাঙ্ক সাৰি, পূর্ণাঙ্ক showfunc,
    LogLevel level, ধ্রুৱ ৱর্ণ *suffix, ধ্রুৱ ৱর্ণ *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, সাৰি, showfunc, SYSLOG_LEVEL_INFO,
	    suffix, fmt, args);
	va_end(args);
	cleanup_exit(255);
}

শূন্য
sshlogv(ধ্রুৱ ৱর্ণ *file, ধ্রুৱ ৱর্ণ *func, পূর্ণাঙ্ক সাৰি, পূর্ণাঙ্ক showfunc,
    LogLevel level, ধ্রুৱ ৱর্ণ *suffix, ধ্রুৱ ৱর্ণ *fmt, va_list args)
{
	ৱর্ণ tag[128], fmt2[MSGBUFSIZ + 128];
	পূর্ণাঙ্ক forced = 0;
	ধ্রুৱ ৱর্ণ *cp;
	size_t i;

	/* short circuit processing early if we're not going to log anything */
	যদি (nlog_verbose == 0 && level > log_level)
		ঘূৰাই;

	snprintf(tag, পরিমাণ(tag), "%.48s:%.48s():%d (bin=%s, pid=%ld)",
	    (cp = strrchr(file, '/')) == রিক্ত ? file : cp + 1, func, সাৰি,
	    argv0 == রিক্ত ? "UNKNOWN" : argv0, (long)getpid());
	বাবে (i = 0; i < nlog_verbose; i++) {
		যদি (match_pattern_list(tag, log_verbose[i], 0) == 1) {
			forced = 1;
			ভঙ্গ;
		}
	}

	যদি (forced)
		snprintf(fmt2, পরিমাণ(fmt2), "%s: %s", tag, fmt);
	অন্যথা যদি (showfunc)
		snprintf(fmt2, পরিমাণ(fmt2), "%s: %s", func, fmt);
	অন্যথা
		strlcpy(fmt2, fmt, পরিমাণ(fmt2));

	do_log(level, forced, suffix, fmt2, args);
}

শূন্য
sshlogdirect(LogLevel level, পূর্ণাঙ্ক forced, ধ্রুৱ ৱর্ণ *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(level, forced, রিক্ত, fmt, args);
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
# define RLDBG(x) কৰা { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} যেতিয়ালৈ (0)
#অন্যথা
# define RLDBG(x)
#endif

/* set up a ratelimit */
শূন্য
log_ratelimit_init(সংরচনা log_ratelimit_ctx *rl, u_int threshold,
    u_int max_accum, u_int hysteresis, u_int log_every)
{
	memset(rl, 0, পরিমাণ(*rl));
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
পূর্ণাঙ্ক
log_ratelimit(সংরচনা log_ratelimit_ctx *rl, time_t now, পূর্ণাঙ্ক *active,
    u_int *events_dropped)
{
	time_t olast_event;

	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u "
	    "accum=%u since=%ld since_last=%u", rl, rl->threshold,
	    rl->max_accum, rl->hysteresis,
	    rl->log_every, rl->accumulated_events,
	    rl->last_event == 0 ? -1 : (long)(now - rl->last_event),
	    rl->ratelimited_events));

	যদি (now < 0)
		ঘূৰাই 0;
	যদি (events_dropped != রিক্ত)
		*events_dropped = 0;
	যদি (active != রিক্ত)
		*active = rl->ratelimit_active;

	/* First, decay accumulated events */
	যদি (rl->last_event <= 0)
		rl->last_event = now;
	যদি (now > rl->last_event) {
		uint64_t n = now - rl->last_event;

		যদি (n > UINT_MAX)
			n = UINT_MAX;
		যদি (rl->accumulated_events < (u_int)n)
			rl->accumulated_events = 0;
		অন্যথা
			rl->accumulated_events -= (u_int)n;
		RLDBG(("decay: accum=%u", rl->accumulated_events));
	}
	rl->accumulated_events++; /* add this event */
	যদি (rl->accumulated_events > rl->max_accum)
		rl->accumulated_events = rl->max_accum;
	olast_event = rl->last_event;
	rl->last_event = now;
	RLDBG(("check threshold: accum=%u vs thresh=%u",
	    rl->accumulated_events, rl->threshold));

	/* Are we under threshold? */
	যদি (rl->accumulated_events < rl->threshold) {
		যদি (!rl->ratelimit_active)
			ঘূৰাই 0;
		RLDBG(("under threshold: hys=%u since_hys=%ld since_last=%ld",
		    rl->hysteresis, rl->hysteresis_start == 0 ? -1 :
		    (long)(now - rl->hysteresis_start),
		    olast_event == 0 ? -1 : (long)(now - olast_event)));
		যদি (rl->hysteresis_start == 0) {
			/* active, but under threshold; hysteresis */
			যদি (olast_event + rl->hysteresis < now) {
				/* hysteresis expired before this event */
				RLDBG(("hysteresis preexpired"));
				গচ্ছ inactive;
			}
			RLDBG(("start hysteresis"));
			rl->hysteresis_start = now;
		} অন্যথা যদি (rl->hysteresis_start + rl->hysteresis < now) {
			/* Hysteresis period expired, transition to inactive */
			RLDBG(("complete hysteresis"));
 inactive:
			যদি (events_dropped != রিক্ত)
				*events_dropped = rl->ratelimited_events;
			যদি (active != রিক্ত)
				*active = 0;
			rl->ratelimit_active = 0;
			rl->ratelimit_start = 0;
			rl->last_log = 0;
			rl->hysteresis_start = 0;
			rl->ratelimited_events = 0;
			ঘূৰাই 0;
		}
		/* ratelimiting active, but in hysteresis period */
	} অন্যথা যদি (!rl->ratelimit_active) {
		/* Transition to rate-limiting */
		RLDBG(("start ratelimit"));
		rl->ratelimit_active = 1;
		rl->ratelimit_start = now;
		rl->last_log = now;
		rl->hysteresis_start = 0;
		rl->ratelimited_events = 1;
		যদি (active != রিক্ত)
			*active = 1;
		ঘূৰাই 1;
	} অন্যথা যদি (rl->hysteresis_start != 0) {
		/* active and over threshold; reset hysteresis timer */
		RLDBG(("clear hysteresis"));
		rl->hysteresis_start = 0;
	}

	/* over threshold or in hysteresis period; log periodically */
	যদি (active != রিক্ত)
		*active = 1;
	RLDBG(("log_every=%u since_log=%ld", rl->log_every,
	    (long)(now - rl->last_log)));
	যদি (rl->log_every > 0 && now >= rl->last_log + rl->log_every) {
		RLDBG(("periodic: since_last=%u", rl->ratelimited_events));
		rl->last_log = now;
		যদি (events_dropped != রিক্ত) {
			*events_dropped = rl->ratelimited_events;
			rl->ratelimited_events = 0;
		}
		ঘূৰাই 0;
	}

	/* drop event */
	rl->ratelimited_events++;
	RLDBG(("drop: ratelimited_events=%u", rl->ratelimited_events));
	ঘূৰাই 1;
}
