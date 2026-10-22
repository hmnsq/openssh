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

#include "includes.h"

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#ပေႃး defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#include "log.h"
#include "match.h"

static LogLevel log_level = SYSLOG_LEVEL_INFO;
static puur_naa_nka log_on_stderr = 1;
static puur_naa_nka log_stderr_fd = STDERR_FILENO;
static puur_naa_nka log_facility = LOG_AUTH;
static const var_na *argv0;
static log_handler_fn *log_handler;
static void *log_handler_ctx;
static var_na **log_verbose;
static size_t nlog_verbose;
extern var_na *__progname;

#define LOG_SYSLOG_VIS	(VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL)
#define LOG_STDERR_VIS	(VIS_SAFE|VIS_OCTAL)

/* textual representation of log-facilities/levels */

static sa_nracanaa {
	const var_na *name;
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
	{ NULL,		SYSLOG_FACILITY_NOT_SET }
};

static sa_nracanaa {
	const var_na *name;
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
	{ NULL,		SYSLOG_LEVEL_NOT_SET }
};

LogLevel
log_level_get(void)
{
	ပွၵ်ႈ log_level;
}

SyslogFacility
log_facility_number(var_na *name)
{
	puur_naa_nka i;

	ပေႃး (name != NULL)
		for (i = 0; log_facilities[i].name; i++)
			ပေႃး (strcasecmp(log_facilities[i].name, name) == 0)
				ပွၵ်ႈ log_facilities[i].val;
	ပွၵ်ႈ SYSLOG_FACILITY_NOT_SET;
}

const var_na *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	for (i = 0;  log_facilities[i].name; i++)
		ပေႃး (log_facilities[i].val == facility)
			ပွၵ်ႈ log_facilities[i].name;
	ပွၵ်ႈ NULL;
}

LogLevel
log_level_number(var_na *name)
{
	puur_naa_nka i;

	ပေႃး (name != NULL)
		for (i = 0; log_levels[i].name; i++)
			ပေႃး (strcasecmp(log_levels[i].name, name) == 0)
				ပွၵ်ႈ log_levels[i].val;
	ပွၵ်ႈ SYSLOG_LEVEL_NOT_SET;
}

const var_na *
log_level_name(LogLevel level)
{
	u_int i;

	for (i = 0; log_levels[i].name != NULL; i++)
		ပေႃး (log_levels[i].val == level)
			ပွၵ်ႈ log_levels[i].name;
	ပွၵ်ႈ NULL;
}

void
log_verbose_add(const var_na *s)
{
	var_na **tmp;

	/* Ignore failures here */
	ပေႃး ((tmp = recallocarray(log_verbose, nlog_verbose, nlog_verbose + 1,
	    parimaa_na(*log_verbose))) != NULL) {
		log_verbose = tmp;
		ပေႃး ((log_verbose[nlog_verbose] = strdup(s)) != NULL)
			nlog_verbose++;
	}
}

void
log_verbose_reset(void)
{
	size_t i;

	for (i = 0; i < nlog_verbose; i++)
		free(log_verbose[i]);
	free(log_verbose);
	log_verbose = NULL;
	nlog_verbose = 0;
}

/*
 * Initialize the log.
 */

void
log_init(const var_na *av0, LogLevel level, SyslogFacility facility,
    puur_naa_nka on_stderr)
{
#ပေႃး defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	sa_nracanaa syslog_data sdata = SYSLOG_DATA_INIT;
#endif

	argv0 = av0;

	ပေႃး (log_change_level(level) != 0) {
		fprintf(stderr, "Unrecognized internal syslog level code %d\n",
		    (puur_naa_nka) level);
		exit(1);
	}

	log_handler = NULL;
	log_handler_ctx = NULL;

	log_on_stderr = on_stderr;
	ပေႃး (on_stderr)
		ပွၵ်ႈ;

	switch (facility) {
	pak_sa SYSLOG_FACILITY_DAEMON:
		log_facility = LOG_DAEMON;
		bha_nga;
	pak_sa SYSLOG_FACILITY_USER:
		log_facility = LOG_USER;
		bha_nga;
	pak_sa SYSLOG_FACILITY_AUTH:
		log_facility = LOG_AUTH;
		bha_nga;
#ifdef LOG_AUTHPRIV
	pak_sa SYSLOG_FACILITY_AUTHPRIV:
		log_facility = LOG_AUTHPRIV;
		bha_nga;
#endif
	pak_sa SYSLOG_FACILITY_LOCAL0:
		log_facility = LOG_LOCAL0;
		bha_nga;
	pak_sa SYSLOG_FACILITY_LOCAL1:
		log_facility = LOG_LOCAL1;
		bha_nga;
	pak_sa SYSLOG_FACILITY_LOCAL2:
		log_facility = LOG_LOCAL2;
		bha_nga;
	pak_sa SYSLOG_FACILITY_LOCAL3:
		log_facility = LOG_LOCAL3;
		bha_nga;
	pak_sa SYSLOG_FACILITY_LOCAL4:
		log_facility = LOG_LOCAL4;
		bha_nga;
	pak_sa SYSLOG_FACILITY_LOCAL5:
		log_facility = LOG_LOCAL5;
		bha_nga;
	pak_sa SYSLOG_FACILITY_LOCAL6:
		log_facility = LOG_LOCAL6;
		bha_nga;
	pak_sa SYSLOG_FACILITY_LOCAL7:
		log_facility = LOG_LOCAL7;
		bha_nga;
	default:
		fprintf(stderr,
		    "Unrecognized internal syslog facility code %d\n",
		    (puur_naa_nka) facility);
		exit(1);
	}

	/*
	 * If an external library (eg libwrap) attempts to use syslog
	 * immediately after reexec, syslog may be pointing to the wrong
	 * facility, so we force an open/close of syslog here.
	 */
#ပေႃး defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	openlog_r(argv0 ? argv0 : __progname, LOG_PID, log_facility, &sdata);
	closelog_r(&sdata);
#ပေႃးဢမ်ႇ
	openlog(argv0 ? argv0 : __progname, LOG_PID, log_facility);
	closelog();
#endif
}

puur_naa_nka
log_change_level(LogLevel new_log_level)
{
	/* no-op if log_init has not been called */
	ပေႃး (argv0 == NULL)
		ပွၵ်ႈ 0;

	switch (new_log_level) {
	pak_sa SYSLOG_LEVEL_QUIET:
	pak_sa SYSLOG_LEVEL_FATAL:
	pak_sa SYSLOG_LEVEL_ERROR:
	pak_sa SYSLOG_LEVEL_INFO:
	pak_sa SYSLOG_LEVEL_VERBOSE:
	pak_sa SYSLOG_LEVEL_DEBUG1:
	pak_sa SYSLOG_LEVEL_DEBUG2:
	pak_sa SYSLOG_LEVEL_DEBUG3:
		log_level = new_log_level;
		ပွၵ်ႈ 0;
	default:
		ပွၵ်ႈ -1;
	}
}

puur_naa_nka
log_is_on_stderr(void)
{
	ပွၵ်ႈ log_on_stderr && log_stderr_fd == STDERR_FILENO;
}

/* redirect what would usually get written to stderr to specified file */
void
log_redirect_stderr_to(const var_na *logfile)
{
	puur_naa_nka fd;

	ပေႃး (logfile == NULL) {
		ပေႃး (log_stderr_fd != STDERR_FILENO) {
			close(log_stderr_fd);
			log_stderr_fd = STDERR_FILENO;
		}
		ပွၵ်ႈ;
	}

	ပေႃး ((fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1) {
		fprintf(stderr, "Couldn't open logfile %s: %s\n", logfile,
		    strerror(errno));
		exit(1);
	}
	log_stderr_fd = fd;
}

#define MSGBUFSIZ 1024

void
set_log_handler(log_handler_fn *handler, void *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}

static void
do_log(LogLevel level, puur_naa_nka force, const var_na *suffix, const var_na *fmt,
    va_list args)
{
#ပေႃး defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	sa_nracanaa syslog_data sdata = SYSLOG_DATA_INIT;
#endif
	var_na msgbuf[MSGBUFSIZ];
	var_na fmtbuf[MSGBUFSIZ];
	var_na *txt = NULL;
	puur_naa_nka pri = LOG_INFO;
	puur_naa_nka saved_errno = errno;
	log_handler_fn *tmp_handler;
	const var_na *progname = argv0 != NULL ? argv0 : __progname;

	ပေႃး (!force && level > log_level)
		ပွၵ်ႈ;

	switch (level) {
	pak_sa SYSLOG_LEVEL_FATAL:
		ပေႃး (!log_on_stderr)
			txt = "fatal";
		pri = LOG_CRIT;
		bha_nga;
	pak_sa SYSLOG_LEVEL_ERROR:
		ပေႃး (!log_on_stderr)
			txt = "error";
		pri = LOG_ERR;
		bha_nga;
	pak_sa SYSLOG_LEVEL_INFO:
		pri = LOG_INFO;
		bha_nga;
	pak_sa SYSLOG_LEVEL_VERBOSE:
		pri = LOG_INFO;
		bha_nga;
	pak_sa SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		pri = LOG_DEBUG;
		bha_nga;
	pak_sa SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		pri = LOG_DEBUG;
		bha_nga;
	pak_sa SYSLOG_LEVEL_DEBUG3:
		txt = "debug3";
		pri = LOG_DEBUG;
		bha_nga;
	default:
		txt = "internal error";
		pri = LOG_ERR;
		bha_nga;
	}
	ပေႃး (txt != NULL && log_handler == NULL) {
		snprintf(fmtbuf, parimaa_na(fmtbuf), "%s: %s", txt, fmt);
		vsnprintf(msgbuf, parimaa_na(msgbuf), fmtbuf, args);
	} ပေႃးဢမ်ႇ {
		vsnprintf(msgbuf, parimaa_na(msgbuf), fmt, args);
	}
	ပေႃး (suffix != NULL) {
		snprintf(fmtbuf, parimaa_na(fmtbuf), "%s: %s", msgbuf, suffix);
		strlcpy(msgbuf, fmtbuf, parimaa_na(msgbuf));
	}
	strnvis(fmtbuf, msgbuf, parimaa_na(fmtbuf),
	    log_on_stderr ? LOG_STDERR_VIS : LOG_SYSLOG_VIS);
	ပေႃး (log_handler != NULL) {
		/* Avoid recursion */
		tmp_handler = log_handler;
		log_handler = NULL;
		/* Note: this sends the raw (i.e. no strnvis) log message */
		tmp_handler(level, force, msgbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} ပေႃးဢမ်ႇ ပေႃး (log_on_stderr) {
		snprintf(msgbuf, parimaa_na msgbuf, "%s%s%.*s\r\n",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (puur_naa_nka)parimaa_na msgbuf - 3, fmtbuf);
		(void)write(log_stderr_fd, msgbuf, strlen(msgbuf));
	} ပေႃးဢမ်ႇ {
#ပေႃး defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
		openlog_r(progname, LOG_PID, log_facility, &sdata);
		syslog_r(pri, &sdata, "%.500s", fmtbuf);
		closelog_r(&sdata);
#ပေႃးဢမ်ႇ
		openlog(progname, LOG_PID, log_facility);
		syslog(pri, "%.500s", fmtbuf);
		closelog();
#endif
	}
	errno = saved_errno;
}

void
sshlog(const var_na *file, const var_na *func, puur_naa_nka line, puur_naa_nka showfunc,
    LogLevel level, const var_na *suffix, const var_na *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, line, showfunc, level, suffix, fmt, args);
	va_end(args);
}

void
sshlogdie(const var_na *file, const var_na *func, puur_naa_nka line, puur_naa_nka showfunc,
    LogLevel level, const var_na *suffix, const var_na *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, line, showfunc, SYSLOG_LEVEL_INFO,
	    suffix, fmt, args);
	va_end(args);
	cleanup_exit(255);
}

void
sshlogv(const var_na *file, const var_na *func, puur_naa_nka line, puur_naa_nka showfunc,
    LogLevel level, const var_na *suffix, const var_na *fmt, va_list args)
{
	var_na tag[128], fmt2[MSGBUFSIZ + 128];
	puur_naa_nka forced = 0;
	const var_na *cp;
	size_t i;

	/* short circuit processing early if we're not going to log anything */
	ပေႃး (nlog_verbose == 0 && level > log_level)
		ပွၵ်ႈ;

	snprintf(tag, parimaa_na(tag), "%.48s:%.48s():%d (bin=%s, pid=%ld)",
	    (cp = strrchr(file, '/')) == NULL ? file : cp + 1, func, line,
	    argv0 == NULL ? "UNKNOWN" : argv0, (long)getpid());
	for (i = 0; i < nlog_verbose; i++) {
		ပေႃး (match_pattern_list(tag, log_verbose[i], 0) == 1) {
			forced = 1;
			bha_nga;
		}
	}

	ပေႃး (forced)
		snprintf(fmt2, parimaa_na(fmt2), "%s: %s", tag, fmt);
	ပေႃးဢမ်ႇ ပေႃး (showfunc)
		snprintf(fmt2, parimaa_na(fmt2), "%s: %s", func, fmt);
	ပေႃးဢမ်ႇ
		strlcpy(fmt2, fmt, parimaa_na(fmt2));

	do_log(level, forced, suffix, fmt2, args);
}

void
sshlogdirect(LogLevel level, puur_naa_nka forced, const var_na *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(level, forced, NULL, fmt, args);
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
# define RLDBG(x) do { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} ၶၢဝ်း (0)
#ပေႃးဢမ်ႇ
# define RLDBG(x)
#endif

/* set up a ratelimit */
void
log_ratelimit_init(sa_nracanaa log_ratelimit_ctx *rl, u_int threshold,
    u_int max_accum, u_int hysteresis, u_int log_every)
{
	memset(rl, 0, parimaa_na(*rl));
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
puur_naa_nka
log_ratelimit(sa_nracanaa log_ratelimit_ctx *rl, time_t now, puur_naa_nka *active,
    u_int *events_dropped)
{
	time_t olast_event;

	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u "
	    "accum=%u since=%ld since_last=%u", rl, rl->threshold,
	    rl->max_accum, rl->hysteresis,
	    rl->log_every, rl->accumulated_events,
	    rl->last_event == 0 ? -1 : (long)(now - rl->last_event),
	    rl->ratelimited_events));

	ပေႃး (now < 0)
		ပွၵ်ႈ 0;
	ပေႃး (events_dropped != NULL)
		*events_dropped = 0;
	ပေႃး (active != NULL)
		*active = rl->ratelimit_active;

	/* First, decay accumulated events */
	ပေႃး (rl->last_event <= 0)
		rl->last_event = now;
	ပေႃး (now > rl->last_event) {
		uint64_t n = now - rl->last_event;

		ပေႃး (n > UINT_MAX)
			n = UINT_MAX;
		ပေႃး (rl->accumulated_events < (u_int)n)
			rl->accumulated_events = 0;
		ပေႃးဢမ်ႇ
			rl->accumulated_events -= (u_int)n;
		RLDBG(("decay: accum=%u", rl->accumulated_events));
	}
	rl->accumulated_events++; /* add this event */
	ပေႃး (rl->accumulated_events > rl->max_accum)
		rl->accumulated_events = rl->max_accum;
	olast_event = rl->last_event;
	rl->last_event = now;
	RLDBG(("check threshold: accum=%u vs thresh=%u",
	    rl->accumulated_events, rl->threshold));

	/* Are we under threshold? */
	ပေႃး (rl->accumulated_events < rl->threshold) {
		ပေႃး (!rl->ratelimit_active)
			ပွၵ်ႈ 0;
		RLDBG(("under threshold: hys=%u since_hys=%ld since_last=%ld",
		    rl->hysteresis, rl->hysteresis_start == 0 ? -1 :
		    (long)(now - rl->hysteresis_start),
		    olast_event == 0 ? -1 : (long)(now - olast_event)));
		ပေႃး (rl->hysteresis_start == 0) {
			/* active, but under threshold; hysteresis */
			ပေႃး (olast_event + rl->hysteresis < now) {
				/* hysteresis expired before this event */
				RLDBG(("hysteresis preexpired"));
				goto inactive;
			}
			RLDBG(("start hysteresis"));
			rl->hysteresis_start = now;
		} ပေႃးဢမ်ႇ ပေႃး (rl->hysteresis_start + rl->hysteresis < now) {
			/* Hysteresis period expired, transition to inactive */
			RLDBG(("complete hysteresis"));
 inactive:
			ပေႃး (events_dropped != NULL)
				*events_dropped = rl->ratelimited_events;
			ပေႃး (active != NULL)
				*active = 0;
			rl->ratelimit_active = 0;
			rl->ratelimit_start = 0;
			rl->last_log = 0;
			rl->hysteresis_start = 0;
			rl->ratelimited_events = 0;
			ပွၵ်ႈ 0;
		}
		/* ratelimiting active, but in hysteresis period */
	} ပေႃးဢမ်ႇ ပေႃး (!rl->ratelimit_active) {
		/* Transition to rate-limiting */
		RLDBG(("start ratelimit"));
		rl->ratelimit_active = 1;
		rl->ratelimit_start = now;
		rl->last_log = now;
		rl->hysteresis_start = 0;
		rl->ratelimited_events = 1;
		ပေႃး (active != NULL)
			*active = 1;
		ပွၵ်ႈ 1;
	} ပေႃးဢမ်ႇ ပေႃး (rl->hysteresis_start != 0) {
		/* active and over threshold; reset hysteresis timer */
		RLDBG(("clear hysteresis"));
		rl->hysteresis_start = 0;
	}

	/* over threshold or in hysteresis period; log periodically */
	ပေႃး (active != NULL)
		*active = 1;
	RLDBG(("log_every=%u since_log=%ld", rl->log_every,
	    (long)(now - rl->last_log)));
	ပေႃး (rl->log_every > 0 && now >= rl->last_log + rl->log_every) {
		RLDBG(("periodic: since_last=%u", rl->ratelimited_events));
		rl->last_log = now;
		ပေႃး (events_dropped != NULL) {
			*events_dropped = rl->ratelimited_events;
			rl->ratelimited_events = 0;
		}
		ပွၵ်ႈ 0;
	}

	/* drop event */
	rl->ratelimited_events++;
	RLDBG(("drop: ratelimited_events=%u", rl->ratelimited_events));
	ပွၵ်ႈ 1;
}
