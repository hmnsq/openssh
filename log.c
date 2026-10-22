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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <syslog.h>
#अन्तर्भाव <unistd.h>
#जइ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#अन्तर्भाव "log.h"
#अन्तर्भाव "match.h"

स्थिर LogLevel log_level = SYSLOG_LEVEL_INFO;
स्थिर पूर्णाङ्क log_on_stderr = 1;
स्थिर पूर्णाङ्क log_stderr_fd = STDERR_FILENO;
स्थिर पूर्णाङ्क log_facility = LOG_AUTH;
स्थिर ध्रुव वर्ण *argv0;
स्थिर log_handler_fn *log_handler;
स्थिर शून्य *log_handler_ctx;
स्थिर वर्ण **log_verbose;
स्थिर size_t nlog_verbose;
बाह्य वर्ण *__progname;

#define LOG_SYSLOG_VIS	(VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL)
#define LOG_STDERR_VIS	(VIS_SAFE|VIS_OCTAL)

/* textual representation of log-facilities/levels */

स्थिर संरचना {
	ध्रुव वर्ण *name;
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
	{ रिक्त,		SYSLOG_FACILITY_NOT_SET }
};

स्थिर संरचना {
	ध्रुव वर्ण *name;
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
	{ रिक्त,		SYSLOG_LEVEL_NOT_SET }
};

LogLevel
log_level_get(शून्य)
{
	प्रत्यागम log_level;
}

SyslogFacility
log_facility_सङ्ख्या(वर्ण *name)
{
	पूर्णाङ्क i;

	जइ (name != रिक्त)
		प्रति (i = 0; log_facilities[i].name; i++)
			जइ (strcasecmp(log_facilities[i].name, name) == 0)
				प्रत्यागम log_facilities[i].val;
	प्रत्यागम SYSLOG_FACILITY_NOT_SET;
}

ध्रुव वर्ण *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	प्रति (i = 0;  log_facilities[i].name; i++)
		जइ (log_facilities[i].val == facility)
			प्रत्यागम log_facilities[i].name;
	प्रत्यागम रिक्त;
}

LogLevel
log_level_सङ्ख्या(वर्ण *name)
{
	पूर्णाङ्क i;

	जइ (name != रिक्त)
		प्रति (i = 0; log_levels[i].name; i++)
			जइ (strcasecmp(log_levels[i].name, name) == 0)
				प्रत्यागम log_levels[i].val;
	प्रत्यागम SYSLOG_LEVEL_NOT_SET;
}

ध्रुव वर्ण *
log_level_name(LogLevel level)
{
	u_int i;

	प्रति (i = 0; log_levels[i].name != रिक्त; i++)
		जइ (log_levels[i].val == level)
			प्रत्यागम log_levels[i].name;
	प्रत्यागम रिक्त;
}

शून्य
log_verbose_add(ध्रुव वर्ण *s)
{
	वर्ण **tmp;

	/* Ignore failures here */
	जइ ((tmp = recallocarray(log_verbose, nlog_verbose, nlog_verbose + 1,
	    परिमाण(*log_verbose))) != रिक्त) {
		log_verbose = tmp;
		जइ ((log_verbose[nlog_verbose] = strdup(s)) != रिक्त)
			nlog_verbose++;
	}
}

शून्य
log_verbose_reset(शून्य)
{
	size_t i;

	प्रति (i = 0; i < nlog_verbose; i++)
		मुक्त(log_verbose[i]);
	मुक्त(log_verbose);
	log_verbose = रिक्त;
	nlog_verbose = 0;
}

/*
 * Initialize the log.
 */

शून्य
log_init(ध्रुव वर्ण *av0, LogLevel level, SyslogFacility facility,
    पूर्णाङ्क on_stderr)
{
#जइ defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	संरचना syslog_data sdata = SYSLOG_DATA_INIT;
#endif

	argv0 = av0;

	जइ (log_change_level(level) != 0) {
		fprintf(stderr, "Unrecognized internal syslog level code %d\n",
		    (पूर्णाङ्क) level);
		exit(1);
	}

	log_handler = रिक्त;
	log_handler_ctx = रिक्त;

	log_on_stderr = on_stderr;
	जइ (on_stderr)
		प्रत्यागम;

	विकल्प (facility) {
	पक्ष SYSLOG_FACILITY_DAEMON:
		log_facility = LOG_DAEMON;
		भङ्ग;
	पक्ष SYSLOG_FACILITY_USER:
		log_facility = LOG_USER;
		भङ्ग;
	पक्ष SYSLOG_FACILITY_AUTH:
		log_facility = LOG_AUTH;
		भङ्ग;
#ifdef LOG_AUTHPRIV
	पक्ष SYSLOG_FACILITY_AUTHPRIV:
		log_facility = LOG_AUTHPRIV;
		भङ्ग;
#endif
	पक्ष SYSLOG_FACILITY_LOCAL0:
		log_facility = LOG_LOCAL0;
		भङ्ग;
	पक्ष SYSLOG_FACILITY_LOCAL1:
		log_facility = LOG_LOCAL1;
		भङ्ग;
	पक्ष SYSLOG_FACILITY_LOCAL2:
		log_facility = LOG_LOCAL2;
		भङ्ग;
	पक्ष SYSLOG_FACILITY_LOCAL3:
		log_facility = LOG_LOCAL3;
		भङ्ग;
	पक्ष SYSLOG_FACILITY_LOCAL4:
		log_facility = LOG_LOCAL4;
		भङ्ग;
	पक्ष SYSLOG_FACILITY_LOCAL5:
		log_facility = LOG_LOCAL5;
		भङ्ग;
	पक्ष SYSLOG_FACILITY_LOCAL6:
		log_facility = LOG_LOCAL6;
		भङ्ग;
	पक्ष SYSLOG_FACILITY_LOCAL7:
		log_facility = LOG_LOCAL7;
		भङ्ग;
	स्वभाव:
		fprintf(stderr,
		    "Unrecognized internal syslog facility code %d\n",
		    (पूर्णाङ्क) facility);
		exit(1);
	}

	/*
	 * If an external library (eg libwrap) attempts to use syslog
	 * immediately after reexec, syslog may be pointing to the wrong
	 * facility, so we force an open/close of syslog here.
	 */
#जइ defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	openlog_r(argv0 ? argv0 : __progname, LOG_PID, log_facility, &sdata);
	closelog_r(&sdata);
#अण्णहा
	openlog(argv0 ? argv0 : __progname, LOG_PID, log_facility);
	closelog();
#endif
}

पूर्णाङ्क
log_change_level(LogLevel new_log_level)
{
	/* no-op if log_init has not been called */
	जइ (argv0 == रिक्त)
		प्रत्यागम 0;

	विकल्प (new_log_level) {
	पक्ष SYSLOG_LEVEL_QUIET:
	पक्ष SYSLOG_LEVEL_FATAL:
	पक्ष SYSLOG_LEVEL_ERROR:
	पक्ष SYSLOG_LEVEL_INFO:
	पक्ष SYSLOG_LEVEL_VERBOSE:
	पक्ष SYSLOG_LEVEL_DEBUG1:
	पक्ष SYSLOG_LEVEL_DEBUG2:
	पक्ष SYSLOG_LEVEL_DEBUG3:
		log_level = new_log_level;
		प्रत्यागम 0;
	स्वभाव:
		प्रत्यागम -1;
	}
}

पूर्णाङ्क
log_is_on_stderr(शून्य)
{
	प्रत्यागम log_on_stderr && log_stderr_fd == STDERR_FILENO;
}

/* redirect what would usually get written to stderr to specified file */
शून्य
log_redirect_stderr_to(ध्रुव वर्ण *logfile)
{
	पूर्णाङ्क fd;

	जइ (logfile == रिक्त) {
		जइ (log_stderr_fd != STDERR_FILENO) {
			close(log_stderr_fd);
			log_stderr_fd = STDERR_FILENO;
		}
		प्रत्यागम;
	}

	जइ ((fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1) {
		fprintf(stderr, "Couldn't open logfile %s: %s\n", logfile,
		    strerror(errno));
		exit(1);
	}
	log_stderr_fd = fd;
}

#define MSGBUFSIZ 1024

शून्य
set_log_handler(log_handler_fn *handler, शून्य *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}

स्थिर शून्य
do_log(LogLevel level, पूर्णाङ्क force, ध्रुव वर्ण *suffix, ध्रुव वर्ण *fmt,
    va_list args)
{
#जइ defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	संरचना syslog_data sdata = SYSLOG_DATA_INIT;
#endif
	वर्ण msgbuf[MSGBUFSIZ];
	वर्ण fmtbuf[MSGBUFSIZ];
	वर्ण *txt = रिक्त;
	पूर्णाङ्क pri = LOG_INFO;
	पूर्णाङ्क saved_errno = errno;
	log_handler_fn *tmp_handler;
	ध्रुव वर्ण *progname = argv0 != रिक्त ? argv0 : __progname;

	जइ (!force && level > log_level)
		प्रत्यागम;

	विकल्प (level) {
	पक्ष SYSLOG_LEVEL_FATAL:
		जइ (!log_on_stderr)
			txt = "fatal";
		pri = LOG_CRIT;
		भङ्ग;
	पक्ष SYSLOG_LEVEL_ERROR:
		जइ (!log_on_stderr)
			txt = "error";
		pri = LOG_ERR;
		भङ्ग;
	पक्ष SYSLOG_LEVEL_INFO:
		pri = LOG_INFO;
		भङ्ग;
	पक्ष SYSLOG_LEVEL_VERBOSE:
		pri = LOG_INFO;
		भङ्ग;
	पक्ष SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		pri = LOG_DEBUG;
		भङ्ग;
	पक्ष SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		pri = LOG_DEBUG;
		भङ्ग;
	पक्ष SYSLOG_LEVEL_DEBUG3:
		txt = "debug3";
		pri = LOG_DEBUG;
		भङ्ग;
	स्वभाव:
		txt = "internal error";
		pri = LOG_ERR;
		भङ्ग;
	}
	जइ (txt != रिक्त && log_handler == रिक्त) {
		snprintf(fmtbuf, परिमाण(fmtbuf), "%s: %s", txt, fmt);
		vsnprintf(msgbuf, परिमाण(msgbuf), fmtbuf, args);
	} अण्णहा {
		vsnprintf(msgbuf, परिमाण(msgbuf), fmt, args);
	}
	जइ (suffix != रिक्त) {
		snprintf(fmtbuf, परिमाण(fmtbuf), "%s: %s", msgbuf, suffix);
		strlcpy(msgbuf, fmtbuf, परिमाण(msgbuf));
	}
	strnvis(fmtbuf, msgbuf, परिमाण(fmtbuf),
	    log_on_stderr ? LOG_STDERR_VIS : LOG_SYSLOG_VIS);
	जइ (log_handler != रिक्त) {
		/* Avoid recursion */
		tmp_handler = log_handler;
		log_handler = रिक्त;
		/* Note: this sends the raw (i.e. no strnvis) log message */
		tmp_handler(level, force, msgbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} अण्णहा जइ (log_on_stderr) {
		snprintf(msgbuf, परिमाण msgbuf, "%s%s%.*s\r\n",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (पूर्णाङ्क)परिमाण msgbuf - 3, fmtbuf);
		(शून्य)लिख(log_stderr_fd, msgbuf, strlen(msgbuf));
	} अण्णहा {
#जइ defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
		openlog_r(progname, LOG_PID, log_facility, &sdata);
		syslog_r(pri, &sdata, "%.500s", fmtbuf);
		closelog_r(&sdata);
#अण्णहा
		openlog(progname, LOG_PID, log_facility);
		syslog(pri, "%.500s", fmtbuf);
		closelog();
#endif
	}
	errno = saved_errno;
}

शून्य
sshlog(ध्रुव वर्ण *file, ध्रुव वर्ण *func, पूर्णाङ्क पङ्क्तिः, पूर्णाङ्क showfunc,
    LogLevel level, ध्रुव वर्ण *suffix, ध्रुव वर्ण *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, पङ्क्तिः, showfunc, level, suffix, fmt, args);
	va_end(args);
}

शून्य
sshlogdie(ध्रुव वर्ण *file, ध्रुव वर्ण *func, पूर्णाङ्क पङ्क्तिः, पूर्णाङ्क showfunc,
    LogLevel level, ध्रुव वर्ण *suffix, ध्रुव वर्ण *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, पङ्क्तिः, showfunc, SYSLOG_LEVEL_INFO,
	    suffix, fmt, args);
	va_end(args);
	cleanup_exit(255);
}

शून्य
sshlogv(ध्रुव वर्ण *file, ध्रुव वर्ण *func, पूर्णाङ्क पङ्क्तिः, पूर्णाङ्क showfunc,
    LogLevel level, ध्रुव वर्ण *suffix, ध्रुव वर्ण *fmt, va_list args)
{
	वर्ण tag[128], fmt2[MSGBUFSIZ + 128];
	पूर्णाङ्क forced = 0;
	ध्रुव वर्ण *cp;
	size_t i;

	/* short circuit processing early if we're not going to log anything */
	जइ (nlog_verbose == 0 && level > log_level)
		प्रत्यागम;

	snprintf(tag, परिमाण(tag), "%.48s:%.48s():%d (bin=%s, pid=%ld)",
	    (cp = strrchr(file, '/')) == रिक्त ? file : cp + 1, func, पङ्क्तिः,
	    argv0 == रिक्त ? "UNKNOWN" : argv0, (long)getpid());
	प्रति (i = 0; i < nlog_verbose; i++) {
		जइ (match_pattern_list(tag, log_verbose[i], 0) == 1) {
			forced = 1;
			भङ्ग;
		}
	}

	जइ (forced)
		snprintf(fmt2, परिमाण(fmt2), "%s: %s", tag, fmt);
	अण्णहा जइ (showfunc)
		snprintf(fmt2, परिमाण(fmt2), "%s: %s", func, fmt);
	अण्णहा
		strlcpy(fmt2, fmt, परिमाण(fmt2));

	do_log(level, forced, suffix, fmt2, args);
}

शून्य
sshlogdirect(LogLevel level, पूर्णाङ्क forced, ध्रुव वर्ण *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(level, forced, रिक्त, fmt, args);
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
# define RLDBG(x) करेहि { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} जाव (0)
#अण्णहा
# define RLDBG(x)
#endif

/* set up a ratelimit */
शून्य
log_ratelimit_init(संरचना log_ratelimit_ctx *rl, u_int threshold,
    u_int max_accum, u_int hysteresis, u_int log_every)
{
	memset(rl, 0, परिमाण(*rl));
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
पूर्णाङ्क
log_ratelimit(संरचना log_ratelimit_ctx *rl, time_t now, पूर्णाङ्क *active,
    u_int *events_dropped)
{
	time_t olast_event;

	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u "
	    "accum=%u since=%ld since_last=%u", rl, rl->threshold,
	    rl->max_accum, rl->hysteresis,
	    rl->log_every, rl->accumulated_events,
	    rl->last_event == 0 ? -1 : (long)(now - rl->last_event),
	    rl->ratelimited_events));

	जइ (now < 0)
		प्रत्यागम 0;
	जइ (events_dropped != रिक्त)
		*events_dropped = 0;
	जइ (active != रिक्त)
		*active = rl->ratelimit_active;

	/* First, decay accumulated events */
	जइ (rl->last_event <= 0)
		rl->last_event = now;
	जइ (now > rl->last_event) {
		uint64_t n = now - rl->last_event;

		जइ (n > UINT_MAX)
			n = UINT_MAX;
		जइ (rl->accumulated_events < (u_int)n)
			rl->accumulated_events = 0;
		अण्णहा
			rl->accumulated_events -= (u_int)n;
		RLDBG(("decay: accum=%u", rl->accumulated_events));
	}
	rl->accumulated_events++; /* add this event */
	जइ (rl->accumulated_events > rl->max_accum)
		rl->accumulated_events = rl->max_accum;
	olast_event = rl->last_event;
	rl->last_event = now;
	RLDBG(("check threshold: accum=%u vs thresh=%u",
	    rl->accumulated_events, rl->threshold));

	/* Are we under threshold? */
	जइ (rl->accumulated_events < rl->threshold) {
		जइ (!rl->ratelimit_active)
			प्रत्यागम 0;
		RLDBG(("under threshold: hys=%u since_hys=%ld since_last=%ld",
		    rl->hysteresis, rl->hysteresis_start == 0 ? -1 :
		    (long)(now - rl->hysteresis_start),
		    olast_event == 0 ? -1 : (long)(now - olast_event)));
		जइ (rl->hysteresis_start == 0) {
			/* active, but under threshold; hysteresis */
			जइ (olast_event + rl->hysteresis < now) {
				/* hysteresis expired before this event */
				RLDBG(("hysteresis preexpired"));
				गच्छ inactive;
			}
			RLDBG(("start hysteresis"));
			rl->hysteresis_start = now;
		} अण्णहा जइ (rl->hysteresis_start + rl->hysteresis < now) {
			/* Hysteresis period expired, transition to inactive */
			RLDBG(("complete hysteresis"));
 inactive:
			जइ (events_dropped != रिक्त)
				*events_dropped = rl->ratelimited_events;
			जइ (active != रिक्त)
				*active = 0;
			rl->ratelimit_active = 0;
			rl->ratelimit_start = 0;
			rl->last_log = 0;
			rl->hysteresis_start = 0;
			rl->ratelimited_events = 0;
			प्रत्यागम 0;
		}
		/* ratelimiting active, but in hysteresis period */
	} अण्णहा जइ (!rl->ratelimit_active) {
		/* Transition to rate-limiting */
		RLDBG(("start ratelimit"));
		rl->ratelimit_active = 1;
		rl->ratelimit_start = now;
		rl->last_log = now;
		rl->hysteresis_start = 0;
		rl->ratelimited_events = 1;
		जइ (active != रिक्त)
			*active = 1;
		प्रत्यागम 1;
	} अण्णहा जइ (rl->hysteresis_start != 0) {
		/* active and over threshold; reset hysteresis timer */
		RLDBG(("clear hysteresis"));
		rl->hysteresis_start = 0;
	}

	/* over threshold or in hysteresis period; log periodically */
	जइ (active != रिक्त)
		*active = 1;
	RLDBG(("log_every=%u since_log=%ld", rl->log_every,
	    (long)(now - rl->last_log)));
	जइ (rl->log_every > 0 && now >= rl->last_log + rl->log_every) {
		RLDBG(("periodic: since_last=%u", rl->ratelimited_events));
		rl->last_log = now;
		जइ (events_dropped != रिक्त) {
			*events_dropped = rl->ratelimited_events;
			rl->ratelimited_events = 0;
		}
		प्रत्यागम 0;
	}

	/* drop event */
	rl->ratelimited_events++;
	RLDBG(("drop: ratelimited_events=%u", rl->ratelimited_events));
	प्रत्यागम 1;
}
