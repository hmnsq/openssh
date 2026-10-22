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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <syslog.h>
#அந்தர்பாவ <unistd.h>
#எனில் defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "match.h"

நிலையான LogLevel log_level = SYSLOG_LEVEL_INFO;
நிலையான முழு log_on_stderr = 1;
நிலையான முழு log_stderr_fd = STDERR_FILENO;
நிலையான முழு log_facility = LOG_AUTH;
நிலையான மாறிலி எழுத்து *argv0;
நிலையான log_handler_fn *log_handler;
நிலையான வெறுமை *log_handler_ctx;
நிலையான எழுத்து **log_verbose;
நிலையான size_t nlog_verbose;
வெளி எழுத்து *__progname;

#define LOG_SYSLOG_VIS	(VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL)
#define LOG_STDERR_VIS	(VIS_SAFE|VIS_OCTAL)

/* textual representation of log-facilities/levels */

நிலையான கட்டமைப்பு {
	மாறிலி எழுத்து *name;
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
	{ வெற்று,		SYSLOG_FACILITY_NOT_SET }
};

நிலையான கட்டமைப்பு {
	மாறிலி எழுத்து *name;
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
	{ வெற்று,		SYSLOG_LEVEL_NOT_SET }
};

LogLevel
log_level_get(வெறுமை)
{
	திரும்பு log_level;
}

SyslogFacility
log_facility_எண்(எழுத்து *name)
{
	முழு i;

	எனில் (name != வெற்று)
		க்கு (i = 0; log_facilities[i].name; i++)
			எனில் (strcasecmp(log_facilities[i].name, name) == 0)
				திரும்பு log_facilities[i].val;
	திரும்பு SYSLOG_FACILITY_NOT_SET;
}

மாறிலி எழுத்து *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	க்கு (i = 0;  log_facilities[i].name; i++)
		எனில் (log_facilities[i].val == facility)
			திரும்பு log_facilities[i].name;
	திரும்பு வெற்று;
}

LogLevel
log_level_எண்(எழுத்து *name)
{
	முழு i;

	எனில் (name != வெற்று)
		க்கு (i = 0; log_levels[i].name; i++)
			எனில் (strcasecmp(log_levels[i].name, name) == 0)
				திரும்பு log_levels[i].val;
	திரும்பு SYSLOG_LEVEL_NOT_SET;
}

மாறிலி எழுத்து *
log_level_name(LogLevel level)
{
	u_int i;

	க்கு (i = 0; log_levels[i].name != வெற்று; i++)
		எனில் (log_levels[i].val == level)
			திரும்பு log_levels[i].name;
	திரும்பு வெற்று;
}

வெறுமை
log_verbose_add(மாறிலி எழுத்து *s)
{
	எழுத்து **tmp;

	/* Ignore failures here */
	எனில் ((tmp = recallocarray(log_verbose, nlog_verbose, nlog_verbose + 1,
	    அளவு(*log_verbose))) != வெற்று) {
		log_verbose = tmp;
		எனில் ((log_verbose[nlog_verbose] = strdup(s)) != வெற்று)
			nlog_verbose++;
	}
}

வெறுமை
log_verbose_reset(வெறுமை)
{
	size_t i;

	க்கு (i = 0; i < nlog_verbose; i++)
		விடுவி(log_verbose[i]);
	விடுவி(log_verbose);
	log_verbose = வெற்று;
	nlog_verbose = 0;
}

/*
 * Initialize the log.
 */

வெறுமை
log_init(மாறிலி எழுத்து *av0, LogLevel level, SyslogFacility facility,
    முழு on_stderr)
{
#எனில் defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	கட்டமைப்பு syslog_data sdata = SYSLOG_DATA_INIT;
#endif

	argv0 = av0;

	எனில் (log_change_level(level) != 0) {
		fprintf(stderr, "Unrecognized internal syslog level code %d\n",
		    (முழு) level);
		exit(1);
	}

	log_handler = வெற்று;
	log_handler_ctx = வெற்று;

	log_on_stderr = on_stderr;
	எனில் (on_stderr)
		திரும்பு;

	தேர்வு (facility) {
	நிலை SYSLOG_FACILITY_DAEMON:
		log_facility = LOG_DAEMON;
		நிறுத்து;
	நிலை SYSLOG_FACILITY_USER:
		log_facility = LOG_USER;
		நிறுத்து;
	நிலை SYSLOG_FACILITY_AUTH:
		log_facility = LOG_AUTH;
		நிறுத்து;
#ifdef LOG_AUTHPRIV
	நிலை SYSLOG_FACILITY_AUTHPRIV:
		log_facility = LOG_AUTHPRIV;
		நிறுத்து;
#endif
	நிலை SYSLOG_FACILITY_LOCAL0:
		log_facility = LOG_LOCAL0;
		நிறுத்து;
	நிலை SYSLOG_FACILITY_LOCAL1:
		log_facility = LOG_LOCAL1;
		நிறுத்து;
	நிலை SYSLOG_FACILITY_LOCAL2:
		log_facility = LOG_LOCAL2;
		நிறுத்து;
	நிலை SYSLOG_FACILITY_LOCAL3:
		log_facility = LOG_LOCAL3;
		நிறுத்து;
	நிலை SYSLOG_FACILITY_LOCAL4:
		log_facility = LOG_LOCAL4;
		நிறுத்து;
	நிலை SYSLOG_FACILITY_LOCAL5:
		log_facility = LOG_LOCAL5;
		நிறுத்து;
	நிலை SYSLOG_FACILITY_LOCAL6:
		log_facility = LOG_LOCAL6;
		நிறுத்து;
	நிலை SYSLOG_FACILITY_LOCAL7:
		log_facility = LOG_LOCAL7;
		நிறுத்து;
	இயல்பு:
		fprintf(stderr,
		    "Unrecognized internal syslog facility code %d\n",
		    (முழு) facility);
		exit(1);
	}

	/*
	 * If an external library (eg libwrap) attempts to use syslog
	 * immediately after reexec, syslog may be pointing to the wrong
	 * facility, so we force an open/close of syslog here.
	 */
#எனில் defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	openlog_r(argv0 ? argv0 : __progname, LOG_PID, log_facility, &sdata);
	closelog_r(&sdata);
#இல்லையெனில்
	openlog(argv0 ? argv0 : __progname, LOG_PID, log_facility);
	closelog();
#endif
}

முழு
log_change_level(LogLevel new_log_level)
{
	/* no-op if log_init has not been called */
	எனில் (argv0 == வெற்று)
		திரும்பு 0;

	தேர்வு (new_log_level) {
	நிலை SYSLOG_LEVEL_QUIET:
	நிலை SYSLOG_LEVEL_FATAL:
	நிலை SYSLOG_LEVEL_ERROR:
	நிலை SYSLOG_LEVEL_INFO:
	நிலை SYSLOG_LEVEL_VERBOSE:
	நிலை SYSLOG_LEVEL_DEBUG1:
	நிலை SYSLOG_LEVEL_DEBUG2:
	நிலை SYSLOG_LEVEL_DEBUG3:
		log_level = new_log_level;
		திரும்பு 0;
	இயல்பு:
		திரும்பு -1;
	}
}

முழு
log_is_on_stderr(வெறுமை)
{
	திரும்பு log_on_stderr && log_stderr_fd == STDERR_FILENO;
}

/* redirect what would usually get written to stderr to specified file */
வெறுமை
log_redirect_stderr_to(மாறிலி எழுத்து *logfile)
{
	முழு fd;

	எனில் (logfile == வெற்று) {
		எனில் (log_stderr_fd != STDERR_FILENO) {
			close(log_stderr_fd);
			log_stderr_fd = STDERR_FILENO;
		}
		திரும்பு;
	}

	எனில் ((fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1) {
		fprintf(stderr, "Couldn't open logfile %s: %s\n", logfile,
		    strerror(errno));
		exit(1);
	}
	log_stderr_fd = fd;
}

#define MSGBUFSIZ 1024

வெறுமை
set_log_handler(log_handler_fn *handler, வெறுமை *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}

நிலையான வெறுமை
do_log(LogLevel level, முழு force, மாறிலி எழுத்து *suffix, மாறிலி எழுத்து *fmt,
    va_list args)
{
#எனில் defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	கட்டமைப்பு syslog_data sdata = SYSLOG_DATA_INIT;
#endif
	எழுத்து msgbuf[MSGBUFSIZ];
	எழுத்து fmtbuf[MSGBUFSIZ];
	எழுத்து *txt = வெற்று;
	முழு pri = LOG_INFO;
	முழு saved_errno = errno;
	log_handler_fn *tmp_handler;
	மாறிலி எழுத்து *progname = argv0 != வெற்று ? argv0 : __progname;

	எனில் (!force && level > log_level)
		திரும்பு;

	தேர்வு (level) {
	நிலை SYSLOG_LEVEL_FATAL:
		எனில் (!log_on_stderr)
			txt = "fatal";
		pri = LOG_CRIT;
		நிறுத்து;
	நிலை SYSLOG_LEVEL_ERROR:
		எனில் (!log_on_stderr)
			txt = "error";
		pri = LOG_ERR;
		நிறுத்து;
	நிலை SYSLOG_LEVEL_INFO:
		pri = LOG_INFO;
		நிறுத்து;
	நிலை SYSLOG_LEVEL_VERBOSE:
		pri = LOG_INFO;
		நிறுத்து;
	நிலை SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		pri = LOG_DEBUG;
		நிறுத்து;
	நிலை SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		pri = LOG_DEBUG;
		நிறுத்து;
	நிலை SYSLOG_LEVEL_DEBUG3:
		txt = "debug3";
		pri = LOG_DEBUG;
		நிறுத்து;
	இயல்பு:
		txt = "internal error";
		pri = LOG_ERR;
		நிறுத்து;
	}
	எனில் (txt != வெற்று && log_handler == வெற்று) {
		snprintf(fmtbuf, அளவு(fmtbuf), "%s: %s", txt, fmt);
		vsnprintf(msgbuf, அளவு(msgbuf), fmtbuf, args);
	} இல்லையெனில் {
		vsnprintf(msgbuf, அளவு(msgbuf), fmt, args);
	}
	எனில் (suffix != வெற்று) {
		snprintf(fmtbuf, அளவு(fmtbuf), "%s: %s", msgbuf, suffix);
		strlcpy(msgbuf, fmtbuf, அளவு(msgbuf));
	}
	strnvis(fmtbuf, msgbuf, அளவு(fmtbuf),
	    log_on_stderr ? LOG_STDERR_VIS : LOG_SYSLOG_VIS);
	எனில் (log_handler != வெற்று) {
		/* Avoid recursion */
		tmp_handler = log_handler;
		log_handler = வெற்று;
		/* Note: this sends the raw (i.e. no strnvis) log message */
		tmp_handler(level, force, msgbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} இல்லையெனில் எனில் (log_on_stderr) {
		snprintf(msgbuf, அளவு msgbuf, "%s%s%.*s\r\n",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (முழு)அளவு msgbuf - 3, fmtbuf);
		(வெறுமை)லிக(log_stderr_fd, msgbuf, strlen(msgbuf));
	} இல்லையெனில் {
#எனில் defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
		openlog_r(progname, LOG_PID, log_facility, &sdata);
		syslog_r(pri, &sdata, "%.500s", fmtbuf);
		closelog_r(&sdata);
#இல்லையெனில்
		openlog(progname, LOG_PID, log_facility);
		syslog(pri, "%.500s", fmtbuf);
		closelog();
#endif
	}
	errno = saved_errno;
}

வெறுமை
sshlog(மாறிலி எழுத்து *file, மாறிலி எழுத்து *func, முழு வரி, முழு showfunc,
    LogLevel level, மாறிலி எழுத்து *suffix, மாறிலி எழுத்து *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, வரி, showfunc, level, suffix, fmt, args);
	va_end(args);
}

வெறுமை
sshlogdie(மாறிலி எழுத்து *file, மாறிலி எழுத்து *func, முழு வரி, முழு showfunc,
    LogLevel level, மாறிலி எழுத்து *suffix, மாறிலி எழுத்து *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, வரி, showfunc, SYSLOG_LEVEL_INFO,
	    suffix, fmt, args);
	va_end(args);
	cleanup_exit(255);
}

வெறுமை
sshlogv(மாறிலி எழுத்து *file, மாறிலி எழுத்து *func, முழு வரி, முழு showfunc,
    LogLevel level, மாறிலி எழுத்து *suffix, மாறிலி எழுத்து *fmt, va_list args)
{
	எழுத்து tag[128], fmt2[MSGBUFSIZ + 128];
	முழு forced = 0;
	மாறிலி எழுத்து *cp;
	size_t i;

	/* short circuit processing early if we're not going to log anything */
	எனில் (nlog_verbose == 0 && level > log_level)
		திரும்பு;

	snprintf(tag, அளவு(tag), "%.48s:%.48s():%d (bin=%s, pid=%ld)",
	    (cp = strrchr(file, '/')) == வெற்று ? file : cp + 1, func, வரி,
	    argv0 == வெற்று ? "UNKNOWN" : argv0, (long)getpid());
	க்கு (i = 0; i < nlog_verbose; i++) {
		எனில் (match_pattern_list(tag, log_verbose[i], 0) == 1) {
			forced = 1;
			நிறுத்து;
		}
	}

	எனில் (forced)
		snprintf(fmt2, அளவு(fmt2), "%s: %s", tag, fmt);
	இல்லையெனில் எனில் (showfunc)
		snprintf(fmt2, அளவு(fmt2), "%s: %s", func, fmt);
	இல்லையெனில்
		strlcpy(fmt2, fmt, அளவு(fmt2));

	do_log(level, forced, suffix, fmt2, args);
}

வெறுமை
sshlogdirect(LogLevel level, முழு forced, மாறிலி எழுத்து *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(level, forced, வெற்று, fmt, args);
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
# define RLDBG(x) செய் { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} போது (0)
#இல்லையெனில்
# define RLDBG(x)
#endif

/* set up a ratelimit */
வெறுமை
log_ratelimit_init(கட்டமைப்பு log_ratelimit_ctx *rl, u_int threshold,
    u_int max_accum, u_int hysteresis, u_int log_every)
{
	memset(rl, 0, அளவு(*rl));
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
முழு
log_ratelimit(கட்டமைப்பு log_ratelimit_ctx *rl, time_t now, முழு *active,
    u_int *events_dropped)
{
	time_t olast_event;

	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u "
	    "accum=%u since=%ld since_last=%u", rl, rl->threshold,
	    rl->max_accum, rl->hysteresis,
	    rl->log_every, rl->accumulated_events,
	    rl->last_event == 0 ? -1 : (long)(now - rl->last_event),
	    rl->ratelimited_events));

	எனில் (now < 0)
		திரும்பு 0;
	எனில் (events_dropped != வெற்று)
		*events_dropped = 0;
	எனில் (active != வெற்று)
		*active = rl->ratelimit_active;

	/* First, decay accumulated events */
	எனில் (rl->last_event <= 0)
		rl->last_event = now;
	எனில் (now > rl->last_event) {
		uint64_t n = now - rl->last_event;

		எனில் (n > UINT_MAX)
			n = UINT_MAX;
		எனில் (rl->accumulated_events < (u_int)n)
			rl->accumulated_events = 0;
		இல்லையெனில்
			rl->accumulated_events -= (u_int)n;
		RLDBG(("decay: accum=%u", rl->accumulated_events));
	}
	rl->accumulated_events++; /* add this event */
	எனில் (rl->accumulated_events > rl->max_accum)
		rl->accumulated_events = rl->max_accum;
	olast_event = rl->last_event;
	rl->last_event = now;
	RLDBG(("check threshold: accum=%u vs thresh=%u",
	    rl->accumulated_events, rl->threshold));

	/* Are we under threshold? */
	எனில் (rl->accumulated_events < rl->threshold) {
		எனில் (!rl->ratelimit_active)
			திரும்பு 0;
		RLDBG(("under threshold: hys=%u since_hys=%ld since_last=%ld",
		    rl->hysteresis, rl->hysteresis_start == 0 ? -1 :
		    (long)(now - rl->hysteresis_start),
		    olast_event == 0 ? -1 : (long)(now - olast_event)));
		எனில் (rl->hysteresis_start == 0) {
			/* active, but under threshold; hysteresis */
			எனில் (olast_event + rl->hysteresis < now) {
				/* hysteresis expired before this event */
				RLDBG(("hysteresis preexpired"));
				செல் inactive;
			}
			RLDBG(("start hysteresis"));
			rl->hysteresis_start = now;
		} இல்லையெனில் எனில் (rl->hysteresis_start + rl->hysteresis < now) {
			/* Hysteresis period expired, transition to inactive */
			RLDBG(("complete hysteresis"));
 inactive:
			எனில் (events_dropped != வெற்று)
				*events_dropped = rl->ratelimited_events;
			எனில் (active != வெற்று)
				*active = 0;
			rl->ratelimit_active = 0;
			rl->ratelimit_start = 0;
			rl->last_log = 0;
			rl->hysteresis_start = 0;
			rl->ratelimited_events = 0;
			திரும்பு 0;
		}
		/* ratelimiting active, but in hysteresis period */
	} இல்லையெனில் எனில் (!rl->ratelimit_active) {
		/* Transition to rate-limiting */
		RLDBG(("start ratelimit"));
		rl->ratelimit_active = 1;
		rl->ratelimit_start = now;
		rl->last_log = now;
		rl->hysteresis_start = 0;
		rl->ratelimited_events = 1;
		எனில் (active != வெற்று)
			*active = 1;
		திரும்பு 1;
	} இல்லையெனில் எனில் (rl->hysteresis_start != 0) {
		/* active and over threshold; reset hysteresis timer */
		RLDBG(("clear hysteresis"));
		rl->hysteresis_start = 0;
	}

	/* over threshold or in hysteresis period; log periodically */
	எனில் (active != வெற்று)
		*active = 1;
	RLDBG(("log_every=%u since_log=%ld", rl->log_every,
	    (long)(now - rl->last_log)));
	எனில் (rl->log_every > 0 && now >= rl->last_log + rl->log_every) {
		RLDBG(("periodic: since_last=%u", rl->ratelimited_events));
		rl->last_log = now;
		எனில் (events_dropped != வெற்று) {
			*events_dropped = rl->ratelimited_events;
			rl->ratelimited_events = 0;
		}
		திரும்பு 0;
	}

	/* drop event */
	rl->ratelimited_events++;
	RLDBG(("drop: ratelimited_events=%u", rl->ratelimited_events));
	திரும்பு 1;
}
