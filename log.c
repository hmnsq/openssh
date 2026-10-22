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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <limits.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <syslog.h>
#شامل <unistd.h>
#اگر defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#شامل "log.h"
#شامل "match.h"

ایستا LogLevel log_level = SYSLOG_LEVEL_INFO;
ایستا صحیح log_on_stderr = 1;
ایستا صحیح log_stderr_fd = STDERR_FILENO;
ایستا صحیح log_facility = LOG_AUTH;
ایستا ثابت نویسه *argv0;
ایستا log_handler_fn *log_handler;
ایستا تهی *log_handler_ctx;
ایستا نویسه **log_verbose;
ایستا size_t nlog_verbose;
بیرونی نویسه *__progname;

#define LOG_SYSLOG_VIS	(VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL)
#define LOG_STDERR_VIS	(VIS_SAFE|VIS_OCTAL)

/* textual representation of log-facilities/levels */

ایستا ساختار {
	ثابت نویسه *name;
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
	{ پوچ,		SYSLOG_FACILITY_NOT_SET }
};

ایستا ساختار {
	ثابت نویسه *name;
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
	{ پوچ,		SYSLOG_LEVEL_NOT_SET }
};

LogLevel
log_level_get(تهی)
{
	بازگشت log_level;
}

SyslogFacility
log_facility_عدد(نویسه *name)
{
	صحیح i;

	اگر (name != پوچ)
		برای (i = 0; log_facilities[i].name; i++)
			اگر (strcasecmp(log_facilities[i].name, name) == 0)
				بازگشت log_facilities[i].val;
	بازگشت SYSLOG_FACILITY_NOT_SET;
}

ثابت نویسه *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	برای (i = 0;  log_facilities[i].name; i++)
		اگر (log_facilities[i].val == facility)
			بازگشت log_facilities[i].name;
	بازگشت پوچ;
}

LogLevel
log_level_عدد(نویسه *name)
{
	صحیح i;

	اگر (name != پوچ)
		برای (i = 0; log_levels[i].name; i++)
			اگر (strcasecmp(log_levels[i].name, name) == 0)
				بازگشت log_levels[i].val;
	بازگشت SYSLOG_LEVEL_NOT_SET;
}

ثابت نویسه *
log_level_name(LogLevel level)
{
	u_int i;

	برای (i = 0; log_levels[i].name != پوچ; i++)
		اگر (log_levels[i].val == level)
			بازگشت log_levels[i].name;
	بازگشت پوچ;
}

تهی
log_verbose_add(ثابت نویسه *s)
{
	نویسه **tmp;

	/* Ignore failures here */
	اگر ((tmp = recallocarray(log_verbose, nlog_verbose, nlog_verbose + 1,
	    اندازه(*log_verbose))) != پوچ) {
		log_verbose = tmp;
		اگر ((log_verbose[nlog_verbose] = strdup(s)) != پوچ)
			nlog_verbose++;
	}
}

تهی
log_verbose_reset(تهی)
{
	size_t i;

	برای (i = 0; i < nlog_verbose; i++)
		آزاد(log_verbose[i]);
	آزاد(log_verbose);
	log_verbose = پوچ;
	nlog_verbose = 0;
}

/*
 * Initialize the log.
 */

تهی
log_init(ثابت نویسه *av0, LogLevel level, SyslogFacility facility,
    صحیح on_stderr)
{
#اگر defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	ساختار syslog_data sdata = SYSLOG_DATA_INIT;
#endif

	argv0 = av0;

	اگر (log_change_level(level) != 0) {
		fprintf(stderr, "Unrecognized internal syslog level code %d\n",
		    (صحیح) level);
		exit(1);
	}

	log_handler = پوچ;
	log_handler_ctx = پوچ;

	log_on_stderr = on_stderr;
	اگر (on_stderr)
		بازگشت;

	انتخاب (facility) {
	حالت SYSLOG_FACILITY_DAEMON:
		log_facility = LOG_DAEMON;
		بشکن;
	حالت SYSLOG_FACILITY_USER:
		log_facility = LOG_USER;
		بشکن;
	حالت SYSLOG_FACILITY_AUTH:
		log_facility = LOG_AUTH;
		بشکن;
#ifdef LOG_AUTHPRIV
	حالت SYSLOG_FACILITY_AUTHPRIV:
		log_facility = LOG_AUTHPRIV;
		بشکن;
#endif
	حالت SYSLOG_FACILITY_LOCAL0:
		log_facility = LOG_LOCAL0;
		بشکن;
	حالت SYSLOG_FACILITY_LOCAL1:
		log_facility = LOG_LOCAL1;
		بشکن;
	حالت SYSLOG_FACILITY_LOCAL2:
		log_facility = LOG_LOCAL2;
		بشکن;
	حالت SYSLOG_FACILITY_LOCAL3:
		log_facility = LOG_LOCAL3;
		بشکن;
	حالت SYSLOG_FACILITY_LOCAL4:
		log_facility = LOG_LOCAL4;
		بشکن;
	حالت SYSLOG_FACILITY_LOCAL5:
		log_facility = LOG_LOCAL5;
		بشکن;
	حالت SYSLOG_FACILITY_LOCAL6:
		log_facility = LOG_LOCAL6;
		بشکن;
	حالت SYSLOG_FACILITY_LOCAL7:
		log_facility = LOG_LOCAL7;
		بشکن;
	پیشفرض:
		fprintf(stderr,
		    "Unrecognized internal syslog facility code %d\n",
		    (صحیح) facility);
		exit(1);
	}

	/*
	 * If an external library (eg libwrap) attempts to use syslog
	 * immediately after reexec, syslog may be pointing to the wrong
	 * facility, so we force an open/close of syslog here.
	 */
#اگر defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	openlog_r(argv0 ? argv0 : __progname, LOG_PID, log_facility, &sdata);
	closelog_r(&sdata);
#وگرنه
	openlog(argv0 ? argv0 : __progname, LOG_PID, log_facility);
	closelog();
#endif
}

صحیح
log_change_level(LogLevel new_log_level)
{
	/* no-op if log_init has not been called */
	اگر (argv0 == پوچ)
		بازگشت 0;

	انتخاب (new_log_level) {
	حالت SYSLOG_LEVEL_QUIET:
	حالت SYSLOG_LEVEL_FATAL:
	حالت SYSLOG_LEVEL_ERROR:
	حالت SYSLOG_LEVEL_INFO:
	حالت SYSLOG_LEVEL_VERBOSE:
	حالت SYSLOG_LEVEL_DEBUG1:
	حالت SYSLOG_LEVEL_DEBUG2:
	حالت SYSLOG_LEVEL_DEBUG3:
		log_level = new_log_level;
		بازگشت 0;
	پیشفرض:
		بازگشت -1;
	}
}

صحیح
log_is_on_stderr(تهی)
{
	بازگشت log_on_stderr && log_stderr_fd == STDERR_FILENO;
}

/* redirect what would usually get written to stderr to specified file */
تهی
log_redirect_stderr_to(ثابت نویسه *logfile)
{
	صحیح fd;

	اگر (logfile == پوچ) {
		اگر (log_stderr_fd != STDERR_FILENO) {
			close(log_stderr_fd);
			log_stderr_fd = STDERR_FILENO;
		}
		بازگشت;
	}

	اگر ((fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1) {
		fprintf(stderr, "Couldn't open logfile %s: %s\n", logfile,
		    strerror(errno));
		exit(1);
	}
	log_stderr_fd = fd;
}

#define MSGBUFSIZ 1024

تهی
set_log_handler(log_handler_fn *handler, تهی *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}

ایستا تهی
do_log(LogLevel level, صحیح force, ثابت نویسه *suffix, ثابت نویسه *fmt,
    va_list args)
{
#اگر defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	ساختار syslog_data sdata = SYSLOG_DATA_INIT;
#endif
	نویسه msgbuf[MSGBUFSIZ];
	نویسه fmtbuf[MSGBUFSIZ];
	نویسه *txt = پوچ;
	صحیح pri = LOG_INFO;
	صحیح saved_errno = errno;
	log_handler_fn *tmp_handler;
	ثابت نویسه *progname = argv0 != پوچ ? argv0 : __progname;

	اگر (!force && level > log_level)
		بازگشت;

	انتخاب (level) {
	حالت SYSLOG_LEVEL_FATAL:
		اگر (!log_on_stderr)
			txt = "fatal";
		pri = LOG_CRIT;
		بشکن;
	حالت SYSLOG_LEVEL_ERROR:
		اگر (!log_on_stderr)
			txt = "error";
		pri = LOG_ERR;
		بشکن;
	حالت SYSLOG_LEVEL_INFO:
		pri = LOG_INFO;
		بشکن;
	حالت SYSLOG_LEVEL_VERBOSE:
		pri = LOG_INFO;
		بشکن;
	حالت SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		pri = LOG_DEBUG;
		بشکن;
	حالت SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		pri = LOG_DEBUG;
		بشکن;
	حالت SYSLOG_LEVEL_DEBUG3:
		txt = "debug3";
		pri = LOG_DEBUG;
		بشکن;
	پیشفرض:
		txt = "internal error";
		pri = LOG_ERR;
		بشکن;
	}
	اگر (txt != پوچ && log_handler == پوچ) {
		snprintf(fmtbuf, اندازه(fmtbuf), "%s: %s", txt, fmt);
		vsnprintf(msgbuf, اندازه(msgbuf), fmtbuf, args);
	} وگرنه {
		vsnprintf(msgbuf, اندازه(msgbuf), fmt, args);
	}
	اگر (suffix != پوچ) {
		snprintf(fmtbuf, اندازه(fmtbuf), "%s: %s", msgbuf, suffix);
		strlcpy(msgbuf, fmtbuf, اندازه(msgbuf));
	}
	strnvis(fmtbuf, msgbuf, اندازه(fmtbuf),
	    log_on_stderr ? LOG_STDERR_VIS : LOG_SYSLOG_VIS);
	اگر (log_handler != پوچ) {
		/* Avoid recursion */
		tmp_handler = log_handler;
		log_handler = پوچ;
		/* Note: this sends the raw (i.e. no strnvis) log message */
		tmp_handler(level, force, msgbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} وگرنه اگر (log_on_stderr) {
		snprintf(msgbuf, اندازه msgbuf, "%s%s%.*s\r\n",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (صحیح)اندازه msgbuf - 3, fmtbuf);
		(تهی)اكتب(log_stderr_fd, msgbuf, strlen(msgbuf));
	} وگرنه {
#اگر defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
		openlog_r(progname, LOG_PID, log_facility, &sdata);
		syslog_r(pri, &sdata, "%.500s", fmtbuf);
		closelog_r(&sdata);
#وگرنه
		openlog(progname, LOG_PID, log_facility);
		syslog(pri, "%.500s", fmtbuf);
		closelog();
#endif
	}
	errno = saved_errno;
}

تهی
sshlog(ثابت نویسه *file, ثابت نویسه *func, صحیح سطر, صحیح showfunc,
    LogLevel level, ثابت نویسه *suffix, ثابت نویسه *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, سطر, showfunc, level, suffix, fmt, args);
	va_end(args);
}

تهی
sshlogdie(ثابت نویسه *file, ثابت نویسه *func, صحیح سطر, صحیح showfunc,
    LogLevel level, ثابت نویسه *suffix, ثابت نویسه *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, سطر, showfunc, SYSLOG_LEVEL_INFO,
	    suffix, fmt, args);
	va_end(args);
	cleanup_exit(255);
}

تهی
sshlogv(ثابت نویسه *file, ثابت نویسه *func, صحیح سطر, صحیح showfunc,
    LogLevel level, ثابت نویسه *suffix, ثابت نویسه *fmt, va_list args)
{
	نویسه tag[128], fmt2[MSGBUFSIZ + 128];
	صحیح forced = 0;
	ثابت نویسه *cp;
	size_t i;

	/* short circuit processing early if we're not going to log anything */
	اگر (nlog_verbose == 0 && level > log_level)
		بازگشت;

	snprintf(tag, اندازه(tag), "%.48s:%.48s():%d (bin=%s, pid=%ld)",
	    (cp = strrchr(file, '/')) == پوچ ? file : cp + 1, func, سطر,
	    argv0 == پوچ ? "UNKNOWN" : argv0, (long)getpid());
	برای (i = 0; i < nlog_verbose; i++) {
		اگر (match_pattern_list(tag, log_verbose[i], 0) == 1) {
			forced = 1;
			بشکن;
		}
	}

	اگر (forced)
		snprintf(fmt2, اندازه(fmt2), "%s: %s", tag, fmt);
	وگرنه اگر (showfunc)
		snprintf(fmt2, اندازه(fmt2), "%s: %s", func, fmt);
	وگرنه
		strlcpy(fmt2, fmt, اندازه(fmt2));

	do_log(level, forced, suffix, fmt2, args);
}

تهی
sshlogdirect(LogLevel level, صحیح forced, ثابت نویسه *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(level, forced, پوچ, fmt, args);
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
# define RLDBG(x) انجامبده { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} وقتی (0)
#وگرنه
# define RLDBG(x)
#endif

/* set up a ratelimit */
تهی
log_ratelimit_init(ساختار log_ratelimit_ctx *rl, u_int threshold,
    u_int max_accum, u_int hysteresis, u_int log_every)
{
	memset(rl, 0, اندازه(*rl));
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
صحیح
log_ratelimit(ساختار log_ratelimit_ctx *rl, time_t now, صحیح *active,
    u_int *events_dropped)
{
	time_t olast_event;

	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u "
	    "accum=%u since=%ld since_last=%u", rl, rl->threshold,
	    rl->max_accum, rl->hysteresis,
	    rl->log_every, rl->accumulated_events,
	    rl->last_event == 0 ? -1 : (long)(now - rl->last_event),
	    rl->ratelimited_events));

	اگر (now < 0)
		بازگشت 0;
	اگر (events_dropped != پوچ)
		*events_dropped = 0;
	اگر (active != پوچ)
		*active = rl->ratelimit_active;

	/* First, decay accumulated events */
	اگر (rl->last_event <= 0)
		rl->last_event = now;
	اگر (now > rl->last_event) {
		uint64_t n = now - rl->last_event;

		اگر (n > UINT_MAX)
			n = UINT_MAX;
		اگر (rl->accumulated_events < (u_int)n)
			rl->accumulated_events = 0;
		وگرنه
			rl->accumulated_events -= (u_int)n;
		RLDBG(("decay: accum=%u", rl->accumulated_events));
	}
	rl->accumulated_events++; /* add this event */
	اگر (rl->accumulated_events > rl->max_accum)
		rl->accumulated_events = rl->max_accum;
	olast_event = rl->last_event;
	rl->last_event = now;
	RLDBG(("check threshold: accum=%u vs thresh=%u",
	    rl->accumulated_events, rl->threshold));

	/* Are we under threshold? */
	اگر (rl->accumulated_events < rl->threshold) {
		اگر (!rl->ratelimit_active)
			بازگشت 0;
		RLDBG(("under threshold: hys=%u since_hys=%ld since_last=%ld",
		    rl->hysteresis, rl->hysteresis_start == 0 ? -1 :
		    (long)(now - rl->hysteresis_start),
		    olast_event == 0 ? -1 : (long)(now - olast_event)));
		اگر (rl->hysteresis_start == 0) {
			/* active, but under threshold; hysteresis */
			اگر (olast_event + rl->hysteresis < now) {
				/* hysteresis expired before this event */
				RLDBG(("hysteresis preexpired"));
				برو inactive;
			}
			RLDBG(("start hysteresis"));
			rl->hysteresis_start = now;
		} وگرنه اگر (rl->hysteresis_start + rl->hysteresis < now) {
			/* Hysteresis period expired, transition to inactive */
			RLDBG(("complete hysteresis"));
 inactive:
			اگر (events_dropped != پوچ)
				*events_dropped = rl->ratelimited_events;
			اگر (active != پوچ)
				*active = 0;
			rl->ratelimit_active = 0;
			rl->ratelimit_start = 0;
			rl->last_log = 0;
			rl->hysteresis_start = 0;
			rl->ratelimited_events = 0;
			بازگشت 0;
		}
		/* ratelimiting active, but in hysteresis period */
	} وگرنه اگر (!rl->ratelimit_active) {
		/* Transition to rate-limiting */
		RLDBG(("start ratelimit"));
		rl->ratelimit_active = 1;
		rl->ratelimit_start = now;
		rl->last_log = now;
		rl->hysteresis_start = 0;
		rl->ratelimited_events = 1;
		اگر (active != پوچ)
			*active = 1;
		بازگشت 1;
	} وگرنه اگر (rl->hysteresis_start != 0) {
		/* active and over threshold; reset hysteresis timer */
		RLDBG(("clear hysteresis"));
		rl->hysteresis_start = 0;
	}

	/* over threshold or in hysteresis period; log periodically */
	اگر (active != پوچ)
		*active = 1;
	RLDBG(("log_every=%u since_log=%ld", rl->log_every,
	    (long)(now - rl->last_log)));
	اگر (rl->log_every > 0 && now >= rl->last_log + rl->log_every) {
		RLDBG(("periodic: since_last=%u", rl->ratelimited_events));
		rl->last_log = now;
		اگر (events_dropped != پوچ) {
			*events_dropped = rl->ratelimited_events;
			rl->ratelimited_events = 0;
		}
		بازگشت 0;
	}

	/* drop event */
	rl->ratelimited_events++;
	RLDBG(("drop: ratelimited_events=%u", rl->ratelimited_events));
	بازگشت 1;
}
