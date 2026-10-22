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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <syslog.h>
#અન્તર્ભાવ <unistd.h>
#જો defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "match.h"

સ્થિર LogLevel log_level = SYSLOG_LEVEL_INFO;
સ્થિર પૂર્ણાંક log_on_stderr = 1;
સ્થિર પૂર્ણાંક log_stderr_fd = STDERR_FILENO;
સ્થિર પૂર્ણાંક log_facility = LOG_AUTH;
સ્થિર અચલ અક્ષર *argv0;
સ્થિર log_handler_fn *log_handler;
સ્થિર શૂન્ય *log_handler_ctx;
સ્થિર અક્ષર **log_verbose;
સ્થિર size_t nlog_verbose;
બાહ્ય અક્ષર *__progname;

#define LOG_SYSLOG_VIS	(VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL)
#define LOG_STDERR_VIS	(VIS_SAFE|VIS_OCTAL)

/* textual representation of log-facilities/levels */

સ્થિર સંરચના {
	અચલ અક્ષર *name;
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
	{ ખાલી,		SYSLOG_FACILITY_NOT_SET }
};

સ્થિર સંરચના {
	અચલ અક્ષર *name;
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
	{ ખાલી,		SYSLOG_LEVEL_NOT_SET }
};

LogLevel
log_level_get(શૂન્ય)
{
	પાછા log_level;
}

SyslogFacility
log_facility_સંખ્યા(અક્ષર *name)
{
	પૂર્ણાંક i;

	જો (name != ખાલી)
		માટે (i = 0; log_facilities[i].name; i++)
			જો (strcasecmp(log_facilities[i].name, name) == 0)
				પાછા log_facilities[i].val;
	પાછા SYSLOG_FACILITY_NOT_SET;
}

અચલ અક્ષર *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	માટે (i = 0;  log_facilities[i].name; i++)
		જો (log_facilities[i].val == facility)
			પાછા log_facilities[i].name;
	પાછા ખાલી;
}

LogLevel
log_level_સંખ્યા(અક્ષર *name)
{
	પૂર્ણાંક i;

	જો (name != ખાલી)
		માટે (i = 0; log_levels[i].name; i++)
			જો (strcasecmp(log_levels[i].name, name) == 0)
				પાછા log_levels[i].val;
	પાછા SYSLOG_LEVEL_NOT_SET;
}

અચલ અક્ષર *
log_level_name(LogLevel level)
{
	u_int i;

	માટે (i = 0; log_levels[i].name != ખાલી; i++)
		જો (log_levels[i].val == level)
			પાછા log_levels[i].name;
	પાછા ખાલી;
}

શૂન્ય
log_verbose_add(અચલ અક્ષર *s)
{
	અક્ષર **tmp;

	/* Ignore failures here */
	જો ((tmp = recallocarray(log_verbose, nlog_verbose, nlog_verbose + 1,
	    કદ(*log_verbose))) != ખાલી) {
		log_verbose = tmp;
		જો ((log_verbose[nlog_verbose] = strdup(s)) != ખાલી)
			nlog_verbose++;
	}
}

શૂન્ય
log_verbose_reset(શૂન્ય)
{
	size_t i;

	માટે (i = 0; i < nlog_verbose; i++)
		મુક્ત(log_verbose[i]);
	મુક્ત(log_verbose);
	log_verbose = ખાલી;
	nlog_verbose = 0;
}

/*
 * Initialize the log.
 */

શૂન્ય
log_init(અચલ અક્ષર *av0, LogLevel level, SyslogFacility facility,
    પૂર્ણાંક on_stderr)
{
#જો defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	સંરચના syslog_data sdata = SYSLOG_DATA_INIT;
#endif

	argv0 = av0;

	જો (log_change_level(level) != 0) {
		fprintf(stderr, "Unrecognized internal syslog level code %d\n",
		    (પૂર્ણાંક) level);
		exit(1);
	}

	log_handler = ખાલી;
	log_handler_ctx = ખાલી;

	log_on_stderr = on_stderr;
	જો (on_stderr)
		પાછા;

	પસંદગી (facility) {
	સ્થિતિ SYSLOG_FACILITY_DAEMON:
		log_facility = LOG_DAEMON;
		તોડો;
	સ્થિતિ SYSLOG_FACILITY_USER:
		log_facility = LOG_USER;
		તોડો;
	સ્થિતિ SYSLOG_FACILITY_AUTH:
		log_facility = LOG_AUTH;
		તોડો;
#ifdef LOG_AUTHPRIV
	સ્થિતિ SYSLOG_FACILITY_AUTHPRIV:
		log_facility = LOG_AUTHPRIV;
		તોડો;
#endif
	સ્થિતિ SYSLOG_FACILITY_LOCAL0:
		log_facility = LOG_LOCAL0;
		તોડો;
	સ્થિતિ SYSLOG_FACILITY_LOCAL1:
		log_facility = LOG_LOCAL1;
		તોડો;
	સ્થિતિ SYSLOG_FACILITY_LOCAL2:
		log_facility = LOG_LOCAL2;
		તોડો;
	સ્થિતિ SYSLOG_FACILITY_LOCAL3:
		log_facility = LOG_LOCAL3;
		તોડો;
	સ્થિતિ SYSLOG_FACILITY_LOCAL4:
		log_facility = LOG_LOCAL4;
		તોડો;
	સ્થિતિ SYSLOG_FACILITY_LOCAL5:
		log_facility = LOG_LOCAL5;
		તોડો;
	સ્થિતિ SYSLOG_FACILITY_LOCAL6:
		log_facility = LOG_LOCAL6;
		તોડો;
	સ્થિતિ SYSLOG_FACILITY_LOCAL7:
		log_facility = LOG_LOCAL7;
		તોડો;
	મૂળભૂત:
		fprintf(stderr,
		    "Unrecognized internal syslog facility code %d\n",
		    (પૂર્ણાંક) facility);
		exit(1);
	}

	/*
	 * If an external library (eg libwrap) attempts to use syslog
	 * immediately after reexec, syslog may be pointing to the wrong
	 * facility, so we force an open/close of syslog here.
	 */
#જો defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	openlog_r(argv0 ? argv0 : __progname, LOG_PID, log_facility, &sdata);
	closelog_r(&sdata);
#નહીંતર
	openlog(argv0 ? argv0 : __progname, LOG_PID, log_facility);
	closelog();
#endif
}

પૂર્ણાંક
log_change_level(LogLevel new_log_level)
{
	/* no-op if log_init has not been called */
	જો (argv0 == ખાલી)
		પાછા 0;

	પસંદગી (new_log_level) {
	સ્થિતિ SYSLOG_LEVEL_QUIET:
	સ્થિતિ SYSLOG_LEVEL_FATAL:
	સ્થિતિ SYSLOG_LEVEL_ERROR:
	સ્થિતિ SYSLOG_LEVEL_INFO:
	સ્થિતિ SYSLOG_LEVEL_VERBOSE:
	સ્થિતિ SYSLOG_LEVEL_DEBUG1:
	સ્થિતિ SYSLOG_LEVEL_DEBUG2:
	સ્થિતિ SYSLOG_LEVEL_DEBUG3:
		log_level = new_log_level;
		પાછા 0;
	મૂળભૂત:
		પાછા -1;
	}
}

પૂર્ણાંક
log_is_on_stderr(શૂન્ય)
{
	પાછા log_on_stderr && log_stderr_fd == STDERR_FILENO;
}

/* redirect what would usually get written to stderr to specified file */
શૂન્ય
log_redirect_stderr_to(અચલ અક્ષર *logfile)
{
	પૂર્ણાંક fd;

	જો (logfile == ખાલી) {
		જો (log_stderr_fd != STDERR_FILENO) {
			close(log_stderr_fd);
			log_stderr_fd = STDERR_FILENO;
		}
		પાછા;
	}

	જો ((fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1) {
		fprintf(stderr, "Couldn't open logfile %s: %s\n", logfile,
		    strerror(errno));
		exit(1);
	}
	log_stderr_fd = fd;
}

#define MSGBUFSIZ 1024

શૂન્ય
set_log_handler(log_handler_fn *handler, શૂન્ય *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}

સ્થિર શૂન્ય
do_log(LogLevel level, પૂર્ણાંક force, અચલ અક્ષર *suffix, અચલ અક્ષર *fmt,
    va_list args)
{
#જો defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	સંરચના syslog_data sdata = SYSLOG_DATA_INIT;
#endif
	અક્ષર msgbuf[MSGBUFSIZ];
	અક્ષર fmtbuf[MSGBUFSIZ];
	અક્ષર *txt = ખાલી;
	પૂર્ણાંક pri = LOG_INFO;
	પૂર્ણાંક saved_errno = errno;
	log_handler_fn *tmp_handler;
	અચલ અક્ષર *progname = argv0 != ખાલી ? argv0 : __progname;

	જો (!force && level > log_level)
		પાછા;

	પસંદગી (level) {
	સ્થિતિ SYSLOG_LEVEL_FATAL:
		જો (!log_on_stderr)
			txt = "fatal";
		pri = LOG_CRIT;
		તોડો;
	સ્થિતિ SYSLOG_LEVEL_ERROR:
		જો (!log_on_stderr)
			txt = "error";
		pri = LOG_ERR;
		તોડો;
	સ્થિતિ SYSLOG_LEVEL_INFO:
		pri = LOG_INFO;
		તોડો;
	સ્થિતિ SYSLOG_LEVEL_VERBOSE:
		pri = LOG_INFO;
		તોડો;
	સ્થિતિ SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		pri = LOG_DEBUG;
		તોડો;
	સ્થિતિ SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		pri = LOG_DEBUG;
		તોડો;
	સ્થિતિ SYSLOG_LEVEL_DEBUG3:
		txt = "debug3";
		pri = LOG_DEBUG;
		તોડો;
	મૂળભૂત:
		txt = "internal error";
		pri = LOG_ERR;
		તોડો;
	}
	જો (txt != ખાલી && log_handler == ખાલી) {
		snprintf(fmtbuf, કદ(fmtbuf), "%s: %s", txt, fmt);
		vsnprintf(msgbuf, કદ(msgbuf), fmtbuf, args);
	} નહીંતર {
		vsnprintf(msgbuf, કદ(msgbuf), fmt, args);
	}
	જો (suffix != ખાલી) {
		snprintf(fmtbuf, કદ(fmtbuf), "%s: %s", msgbuf, suffix);
		strlcpy(msgbuf, fmtbuf, કદ(msgbuf));
	}
	strnvis(fmtbuf, msgbuf, કદ(fmtbuf),
	    log_on_stderr ? LOG_STDERR_VIS : LOG_SYSLOG_VIS);
	જો (log_handler != ખાલી) {
		/* Avoid recursion */
		tmp_handler = log_handler;
		log_handler = ખાલી;
		/* Note: this sends the raw (i.e. no strnvis) log message */
		tmp_handler(level, force, msgbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} નહીંતર જો (log_on_stderr) {
		snprintf(msgbuf, કદ msgbuf, "%s%s%.*s\r\n",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (પૂર્ણાંક)કદ msgbuf - 3, fmtbuf);
		(શૂન્ય)લિખ(log_stderr_fd, msgbuf, strlen(msgbuf));
	} નહીંતર {
#જો defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
		openlog_r(progname, LOG_PID, log_facility, &sdata);
		syslog_r(pri, &sdata, "%.500s", fmtbuf);
		closelog_r(&sdata);
#નહીંતર
		openlog(progname, LOG_PID, log_facility);
		syslog(pri, "%.500s", fmtbuf);
		closelog();
#endif
	}
	errno = saved_errno;
}

શૂન્ય
sshlog(અચલ અક્ષર *file, અચલ અક્ષર *func, પૂર્ણાંક લીટી, પૂર્ણાંક showfunc,
    LogLevel level, અચલ અક્ષર *suffix, અચલ અક્ષર *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, લીટી, showfunc, level, suffix, fmt, args);
	va_end(args);
}

શૂન્ય
sshlogdie(અચલ અક્ષર *file, અચલ અક્ષર *func, પૂર્ણાંક લીટી, પૂર્ણાંક showfunc,
    LogLevel level, અચલ અક્ષર *suffix, અચલ અક્ષર *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, લીટી, showfunc, SYSLOG_LEVEL_INFO,
	    suffix, fmt, args);
	va_end(args);
	cleanup_exit(255);
}

શૂન્ય
sshlogv(અચલ અક્ષર *file, અચલ અક્ષર *func, પૂર્ણાંક લીટી, પૂર્ણાંક showfunc,
    LogLevel level, અચલ અક્ષર *suffix, અચલ અક્ષર *fmt, va_list args)
{
	અક્ષર tag[128], fmt2[MSGBUFSIZ + 128];
	પૂર્ણાંક forced = 0;
	અચલ અક્ષર *cp;
	size_t i;

	/* short circuit processing early if we're not going to log anything */
	જો (nlog_verbose == 0 && level > log_level)
		પાછા;

	snprintf(tag, કદ(tag), "%.48s:%.48s():%d (bin=%s, pid=%ld)",
	    (cp = strrchr(file, '/')) == ખાલી ? file : cp + 1, func, લીટી,
	    argv0 == ખાલી ? "UNKNOWN" : argv0, (long)getpid());
	માટે (i = 0; i < nlog_verbose; i++) {
		જો (match_pattern_list(tag, log_verbose[i], 0) == 1) {
			forced = 1;
			તોડો;
		}
	}

	જો (forced)
		snprintf(fmt2, કદ(fmt2), "%s: %s", tag, fmt);
	નહીંતર જો (showfunc)
		snprintf(fmt2, કદ(fmt2), "%s: %s", func, fmt);
	નહીંતર
		strlcpy(fmt2, fmt, કદ(fmt2));

	do_log(level, forced, suffix, fmt2, args);
}

શૂન્ય
sshlogdirect(LogLevel level, પૂર્ણાંક forced, અચલ અક્ષર *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(level, forced, ખાલી, fmt, args);
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
# define RLDBG(x) કરો { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} જ્યારે (0)
#નહીંતર
# define RLDBG(x)
#endif

/* set up a ratelimit */
શૂન્ય
log_ratelimit_init(સંરચના log_ratelimit_ctx *rl, u_int threshold,
    u_int max_accum, u_int hysteresis, u_int log_every)
{
	memset(rl, 0, કદ(*rl));
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
પૂર્ણાંક
log_ratelimit(સંરચના log_ratelimit_ctx *rl, time_t now, પૂર્ણાંક *active,
    u_int *events_dropped)
{
	time_t olast_event;

	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u "
	    "accum=%u since=%ld since_last=%u", rl, rl->threshold,
	    rl->max_accum, rl->hysteresis,
	    rl->log_every, rl->accumulated_events,
	    rl->last_event == 0 ? -1 : (long)(now - rl->last_event),
	    rl->ratelimited_events));

	જો (now < 0)
		પાછા 0;
	જો (events_dropped != ખાલી)
		*events_dropped = 0;
	જો (active != ખાલી)
		*active = rl->ratelimit_active;

	/* First, decay accumulated events */
	જો (rl->last_event <= 0)
		rl->last_event = now;
	જો (now > rl->last_event) {
		uint64_t n = now - rl->last_event;

		જો (n > UINT_MAX)
			n = UINT_MAX;
		જો (rl->accumulated_events < (u_int)n)
			rl->accumulated_events = 0;
		નહીંતર
			rl->accumulated_events -= (u_int)n;
		RLDBG(("decay: accum=%u", rl->accumulated_events));
	}
	rl->accumulated_events++; /* add this event */
	જો (rl->accumulated_events > rl->max_accum)
		rl->accumulated_events = rl->max_accum;
	olast_event = rl->last_event;
	rl->last_event = now;
	RLDBG(("check threshold: accum=%u vs thresh=%u",
	    rl->accumulated_events, rl->threshold));

	/* Are we under threshold? */
	જો (rl->accumulated_events < rl->threshold) {
		જો (!rl->ratelimit_active)
			પાછા 0;
		RLDBG(("under threshold: hys=%u since_hys=%ld since_last=%ld",
		    rl->hysteresis, rl->hysteresis_start == 0 ? -1 :
		    (long)(now - rl->hysteresis_start),
		    olast_event == 0 ? -1 : (long)(now - olast_event)));
		જો (rl->hysteresis_start == 0) {
			/* active, but under threshold; hysteresis */
			જો (olast_event + rl->hysteresis < now) {
				/* hysteresis expired before this event */
				RLDBG(("hysteresis preexpired"));
				જાઓ inactive;
			}
			RLDBG(("start hysteresis"));
			rl->hysteresis_start = now;
		} નહીંતર જો (rl->hysteresis_start + rl->hysteresis < now) {
			/* Hysteresis period expired, transition to inactive */
			RLDBG(("complete hysteresis"));
 inactive:
			જો (events_dropped != ખાલી)
				*events_dropped = rl->ratelimited_events;
			જો (active != ખાલી)
				*active = 0;
			rl->ratelimit_active = 0;
			rl->ratelimit_start = 0;
			rl->last_log = 0;
			rl->hysteresis_start = 0;
			rl->ratelimited_events = 0;
			પાછા 0;
		}
		/* ratelimiting active, but in hysteresis period */
	} નહીંતર જો (!rl->ratelimit_active) {
		/* Transition to rate-limiting */
		RLDBG(("start ratelimit"));
		rl->ratelimit_active = 1;
		rl->ratelimit_start = now;
		rl->last_log = now;
		rl->hysteresis_start = 0;
		rl->ratelimited_events = 1;
		જો (active != ખાલી)
			*active = 1;
		પાછા 1;
	} નહીંતર જો (rl->hysteresis_start != 0) {
		/* active and over threshold; reset hysteresis timer */
		RLDBG(("clear hysteresis"));
		rl->hysteresis_start = 0;
	}

	/* over threshold or in hysteresis period; log periodically */
	જો (active != ખાલી)
		*active = 1;
	RLDBG(("log_every=%u since_log=%ld", rl->log_every,
	    (long)(now - rl->last_log)));
	જો (rl->log_every > 0 && now >= rl->last_log + rl->log_every) {
		RLDBG(("periodic: since_last=%u", rl->ratelimited_events));
		rl->last_log = now;
		જો (events_dropped != ખાલી) {
			*events_dropped = rl->ratelimited_events;
			rl->ratelimited_events = 0;
		}
		પાછા 0;
	}

	/* drop event */
	rl->ratelimited_events++;
	RLDBG(("drop: ratelimited_events=%u", rl->ratelimited_events));
	પાછા 1;
}
