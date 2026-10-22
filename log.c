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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <limits.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <syslog.h>
#ضمن <unistd.h>
#إذا defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#د_که_پای

#ضمن "log.h"
#ضمن "match.h"

ساكن LogLevel log_level = SYSLOG_LEVEL_INFO;
ساكن صحيح log_on_stderr = 1;
ساكن صحيح log_stderr_fd = STDERR_FILENO;
ساكن صحيح log_facility = LOG_AUTH;
ساكن ثابت حرف *argv0;
ساكن log_handler_fn *log_handler;
ساكن فراغ *log_handler_ctx;
ساكن حرف **log_verbose;
ساكن اندازه_t nlog_verbose;
خارجي حرف *__progname;

#تعریف_کړه LOG_SYSLOG_VIS	(VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL)
#تعریف_کړه LOG_STDERR_VIS	(VIS_خوندي|VIS_OCTAL)

/* textual representation of log-facilities/levels */

ساكن بنية {
	ثابت حرف *name;
	SyslogFacility val;
} log_facilities[] = {
	{ "DAEMON",	SYSLOG_FACILITY_DAEMON },
	{ "USER",	SYSLOG_FACILITY_USER },
	{ "AUTH",	SYSLOG_FACILITY_AUTH },
#که_تعریف_شوی LOG_AUTHPRIV
	{ "AUTHPRIV",	SYSLOG_FACILITY_AUTHPRIV },
#د_که_پای
	{ "LOCAL0",	SYSLOG_FACILITY_LOCAL0 },
	{ "LOCAL1",	SYSLOG_FACILITY_LOCAL1 },
	{ "LOCAL2",	SYSLOG_FACILITY_LOCAL2 },
	{ "LOCAL3",	SYSLOG_FACILITY_LOCAL3 },
	{ "LOCAL4",	SYSLOG_FACILITY_LOCAL4 },
	{ "LOCAL5",	SYSLOG_FACILITY_LOCAL5 },
	{ "LOCAL6",	SYSLOG_FACILITY_LOCAL6 },
	{ "LOCAL7",	SYSLOG_FACILITY_LOCAL7 },
	{ عدم,		SYSLOG_FACILITY_NOT_سېټ }
};

ساكن بنية {
	ثابت حرف *name;
	LogLevel val;
} log_پوړونه[] =
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
	{ عدم,		SYSLOG_LEVEL_NOT_سېټ }
};

LogLevel
log_level_get(فراغ)
{
	أرجع log_level;
}

SyslogFacility
log_facility_شمېره(حرف *name)
{
	صحيح i;

	إذا (name != عدم)
		لكل (i = 0; log_facilities[i].name; i++)
			إذا (strcasecmp(log_facilities[i].name, name) == 0)
				أرجع log_facilities[i].val;
	أرجع SYSLOG_FACILITY_NOT_سېټ;
}

ثابت حرف *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	لكل (i = 0;  log_facilities[i].name; i++)
		إذا (log_facilities[i].val == facility)
			أرجع log_facilities[i].name;
	أرجع عدم;
}

LogLevel
log_level_شمېره(حرف *name)
{
	صحيح i;

	إذا (name != عدم)
		لكل (i = 0; log_پوړونه[i].name; i++)
			إذا (strcasecmp(log_پوړونه[i].name, name) == 0)
				أرجع log_پوړونه[i].val;
	أرجع SYSLOG_LEVEL_NOT_سېټ;
}

ثابت حرف *
log_level_name(LogLevel level)
{
	u_int i;

	لكل (i = 0; log_پوړونه[i].name != عدم; i++)
		إذا (log_پوړونه[i].val == level)
			أرجع log_پوړونه[i].name;
	أرجع عدم;
}

فراغ
log_verbose_جمع_کړه(ثابت حرف *s)
{
	حرف **tmp;

	/* Ignore failures here */
	إذا ((tmp = recallocarray(log_verbose, nlog_verbose, nlog_verbose + 1,
	    حجم(*log_verbose))) != عدم) {
		log_verbose = tmp;
		إذا ((log_verbose[nlog_verbose] = strdup(s)) != عدم)
			nlog_verbose++;
	}
}

فراغ
log_verbose_reset(فراغ)
{
	اندازه_t i;

	لكل (i = 0; i < nlog_verbose; i++)
		حرر(log_verbose[i]);
	حرر(log_verbose);
	log_verbose = عدم;
	nlog_verbose = 0;
}

/*
 * Initialize the log.
 */

فراغ
log_init(ثابت حرف *av0, LogLevel level, SyslogFacility facility,
    صحيح on_stderr)
{
#إذا defined(HAVE_OPENLOG_R) && defined(SYSLOG_معلومات_INIT)
	بنية syslog_معلومات sdata = SYSLOG_معلومات_INIT;
#د_که_پای

	argv0 = av0;

	إذا (log_change_level(level) != 0) {
		fprintf(stderr, "Unrecognized internal syslog level code %d\n",
		    (صحيح) level);
		وتل(1);
	}

	log_handler = عدم;
	log_handler_ctx = عدم;

	log_on_stderr = on_stderr;
	إذا (on_stderr)
		أرجع;

	بدل (facility) {
	حالة SYSLOG_FACILITY_DAEMON:
		log_facility = LOG_DAEMON;
		اكسر;
	حالة SYSLOG_FACILITY_USER:
		log_facility = LOG_USER;
		اكسر;
	حالة SYSLOG_FACILITY_AUTH:
		log_facility = LOG_AUTH;
		اكسر;
#که_تعریف_شوی LOG_AUTHPRIV
	حالة SYSLOG_FACILITY_AUTHPRIV:
		log_facility = LOG_AUTHPRIV;
		اكسر;
#د_که_پای
	حالة SYSLOG_FACILITY_LOCAL0:
		log_facility = LOG_LOCAL0;
		اكسر;
	حالة SYSLOG_FACILITY_LOCAL1:
		log_facility = LOG_LOCAL1;
		اكسر;
	حالة SYSLOG_FACILITY_LOCAL2:
		log_facility = LOG_LOCAL2;
		اكسر;
	حالة SYSLOG_FACILITY_LOCAL3:
		log_facility = LOG_LOCAL3;
		اكسر;
	حالة SYSLOG_FACILITY_LOCAL4:
		log_facility = LOG_LOCAL4;
		اكسر;
	حالة SYSLOG_FACILITY_LOCAL5:
		log_facility = LOG_LOCAL5;
		اكسر;
	حالة SYSLOG_FACILITY_LOCAL6:
		log_facility = LOG_LOCAL6;
		اكسر;
	حالة SYSLOG_FACILITY_LOCAL7:
		log_facility = LOG_LOCAL7;
		اكسر;
	افتراضي:
		fprintf(stderr,
		    "Unrecognized internal syslog facility code %d\n",
		    (صحيح) facility);
		وتل(1);
	}

	/*
	 * If an external library (eg libwrap) attempts to use syslog
	 * immediately after reexec, syslog may be pointing to the wrong
	 * facility, so we force an open/close of syslog here.
	 */
#إذا defined(HAVE_OPENLOG_R) && defined(SYSLOG_معلومات_INIT)
	openlog_r(argv0 ? argv0 : __progname, LOG_PID, log_facility, &sdata);
	closelog_r(&sdata);
#وإلا
	openlog(argv0 ? argv0 : __progname, LOG_PID, log_facility);
	closelog();
#د_که_پای
}

صحيح
log_change_level(LogLevel new_log_level)
{
	/* no-op if log_init has not been called */
	إذا (argv0 == عدم)
		أرجع 0;

	بدل (new_log_level) {
	حالة SYSLOG_LEVEL_QUIET:
	حالة SYSLOG_LEVEL_FATAL:
	حالة SYSLOG_LEVEL_ERROR:
	حالة SYSLOG_LEVEL_INFO:
	حالة SYSLOG_LEVEL_VERBOSE:
	حالة SYSLOG_LEVEL_DEBUG1:
	حالة SYSLOG_LEVEL_DEBUG2:
	حالة SYSLOG_LEVEL_DEBUG3:
		log_level = new_log_level;
		أرجع 0;
	افتراضي:
		أرجع -1;
	}
}

صحيح
log_is_on_stderr(فراغ)
{
	أرجع log_on_stderr && log_stderr_fd == STDERR_FILENO;
}

/* redirect what would usually get written to stderr to specified file */
فراغ
log_redirect_stderr_منزل(ثابت حرف *logfile)
{
	صحيح fd;

	إذا (logfile == عدم) {
		إذا (log_stderr_fd != STDERR_FILENO) {
			close(log_stderr_fd);
			log_stderr_fd = STDERR_FILENO;
		}
		أرجع;
	}

	إذا ((fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1) {
		fprintf(stderr, "Couldn't open logfile %s: %s\n", logfile,
		    strerror(errno));
		وتل(1);
	}
	log_stderr_fd = fd;
}

#تعریف_کړه MSGBUFSIZ 1024

فراغ
سېټ_log_handler(log_handler_fn *handler, فراغ *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}

ساكن فراغ
do_log(LogLevel level, صحيح force, ثابت حرف *suffix, ثابت حرف *fmt,
    va_list دلیلونه)
{
#إذا defined(HAVE_OPENLOG_R) && defined(SYSLOG_معلومات_INIT)
	بنية syslog_معلومات sdata = SYSLOG_معلومات_INIT;
#د_که_پای
	حرف msgbuf[MSGBUFSIZ];
	حرف fmtbuf[MSGBUFSIZ];
	حرف *txt = عدم;
	صحيح pri = LOG_INFO;
	صحيح saved_errno = errno;
	log_handler_fn *tmp_handler;
	ثابت حرف *progname = argv0 != عدم ? argv0 : __progname;

	إذا (!force && level > log_level)
		أرجع;

	بدل (level) {
	حالة SYSLOG_LEVEL_FATAL:
		إذا (!log_on_stderr)
			txt = "fatal";
		pri = LOG_CRIT;
		اكسر;
	حالة SYSLOG_LEVEL_ERROR:
		إذا (!log_on_stderr)
			txt = "error";
		pri = LOG_ERR;
		اكسر;
	حالة SYSLOG_LEVEL_INFO:
		pri = LOG_INFO;
		اكسر;
	حالة SYSLOG_LEVEL_VERBOSE:
		pri = LOG_INFO;
		اكسر;
	حالة SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		pri = LOG_DEBUG;
		اكسر;
	حالة SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		pri = LOG_DEBUG;
		اكسر;
	حالة SYSLOG_LEVEL_DEBUG3:
		txt = "debug3";
		pri = LOG_DEBUG;
		اكسر;
	افتراضي:
		txt = "internal error";
		pri = LOG_ERR;
		اكسر;
	}
	إذا (txt != عدم && log_handler == عدم) {
		snprintf(fmtbuf, حجم(fmtbuf), "%s: %s", txt, fmt);
		vsnprintf(msgbuf, حجم(msgbuf), fmtbuf, دلیلونه);
	} وإلا {
		vsnprintf(msgbuf, حجم(msgbuf), fmt, دلیلونه);
	}
	إذا (suffix != عدم) {
		snprintf(fmtbuf, حجم(fmtbuf), "%s: %s", msgbuf, suffix);
		strlcpy(msgbuf, fmtbuf, حجم(msgbuf));
	}
	strnvis(fmtbuf, msgbuf, حجم(fmtbuf),
	    log_on_stderr ? LOG_STDERR_VIS : LOG_SYSLOG_VIS);
	إذا (log_handler != عدم) {
		/* Avoid recursion */
		tmp_handler = log_handler;
		log_handler = عدم;
		/* Note: this sends the raw (i.e. no strnvis) log message */
		tmp_handler(level, force, msgbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} وإلا إذا (log_on_stderr) {
		snprintf(msgbuf, حجم msgbuf, "%s%s%.*s\r\n",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (صحيح)حجم msgbuf - 3, fmtbuf);
		(فراغ)اكتب(log_stderr_fd, msgbuf, مزي_اوږدوالی(msgbuf));
	} وإلا {
#إذا defined(HAVE_OPENLOG_R) && defined(SYSLOG_معلومات_INIT)
		openlog_r(progname, LOG_PID, log_facility, &sdata);
		syslog_r(pri, &sdata, "%.500s", fmtbuf);
		closelog_r(&sdata);
#وإلا
		openlog(progname, LOG_PID, log_facility);
		syslog(pri, "%.500s", fmtbuf);
		closelog();
#د_که_پای
	}
	errno = saved_errno;
}

فراغ
sshlog(ثابت حرف *file, ثابت حرف *func, صحيح کرښه, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list دلیلونه;

	va_start(دلیلونه, fmt);
	sshlogv(file, func, کرښه, showfunc, level, suffix, fmt, دلیلونه);
	va_end(دلیلونه);
}

فراغ
sshlogdie(ثابت حرف *file, ثابت حرف *func, صحيح کرښه, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list دلیلونه;

	va_start(دلیلونه, fmt);
	sshlogv(file, func, کرښه, showfunc, SYSLOG_LEVEL_INFO,
	    suffix, fmt, دلیلونه);
	va_end(دلیلونه);
	cleanup_exit(255);
}

فراغ
sshlogv(ثابت حرف *file, ثابت حرف *func, صحيح کرښه, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, va_list دلیلونه)
{
	حرف نښان[128], fmt2[MSGBUFSIZ + 128];
	صحيح forced = 0;
	ثابت حرف *cp;
	اندازه_t i;

	/* short circuit processing early if we're not going to log anything */
	إذا (nlog_verbose == 0 && level > log_level)
		أرجع;

	snprintf(نښان, حجم(نښان), "%.48s:%.48s():%d (bin=%s, pid=%ld)",
	    (cp = strrchr(file, '/')) == عدم ? file : cp + 1, func, کرښه,
	    argv0 == عدم ? "UNKNOWN" : argv0, (اوږد)getpid());
	لكل (i = 0; i < nlog_verbose; i++) {
		إذا (سمون_نمونه_list(نښان, log_verbose[i], 0) == 1) {
			forced = 1;
			اكسر;
		}
	}

	إذا (forced)
		snprintf(fmt2, حجم(fmt2), "%s: %s", نښان, fmt);
	وإلا إذا (showfunc)
		snprintf(fmt2, حجم(fmt2), "%s: %s", func, fmt);
	وإلا
		strlcpy(fmt2, fmt, حجم(fmt2));

	do_log(level, forced, suffix, fmt2, دلیلونه);
}

فراغ
sshlogdirect(LogLevel level, صحيح forced, ثابت حرف *fmt, ...)
{
	va_list دلیلونه;

	va_start(دلیلونه, fmt);
	do_log(level, forced, عدم, fmt, دلیلونه);
	va_end(دلیلونه);
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

#که_تعریف_شوی RATELIMIT_DEBUG
# define RLDBG(x) افعل { \
		چاپ_کړه("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		چاپ_کړه x; \
		چاپ_کړه("\n"); \
		fflush(stdout); \
	} طالما (0)
#وإلا
# define RLDBG(x)
#د_که_پای

/* set up a ratelimit */
فراغ
log_ratelimit_init(بنية log_ratelimit_ctx *rl, u_int پوله,
    u_int max_accum, u_int hysteresis, u_int log_every)
{
	memset(rl, 0, حجم(*rl));
	rl->پوله = پوله;
	rl->max_accum = max_accum;
	rl->hysteresis = hysteresis;
	rl->log_every = log_every;
	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u",
	    rl, rl->پوله, rl->max_accum, rl->hysteresis, rl->log_every));
}

/*
 * check whether a log event should be dropped because of rate-limiting.
 * returns non-zero if the event should be dropped. If events_since_last
 * is supplied then, for periodic logs, it will be set to the number of
 * dropped events since the last message.
 */
صحيح
log_ratelimit(بنية log_ratelimit_ctx *rl, time_t now, صحيح *فعال,
    u_int *events_dropped)
{
	time_t olast_event;

	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u "
	    "accum=%u since=%ld since_last=%u", rl, rl->پوله,
	    rl->max_accum, rl->hysteresis,
	    rl->log_every, rl->accumulated_events,
	    rl->وروستی_event == 0 ? -1 : (اوږد)(now - rl->وروستی_event),
	    rl->ratelimited_events));

	إذا (now < 0)
		أرجع 0;
	إذا (events_dropped != عدم)
		*events_dropped = 0;
	إذا (فعال != عدم)
		*فعال = rl->ratelimit_فعال;

	/* First, decay accumulated events */
	إذا (rl->وروستی_event <= 0)
		rl->وروستی_event = now;
	إذا (now > rl->وروستی_event) {
		uint64_t n = now - rl->وروستی_event;

		إذا (n > UINT_MAX)
			n = UINT_MAX;
		إذا (rl->accumulated_events < (u_int)n)
			rl->accumulated_events = 0;
		وإلا
			rl->accumulated_events -= (u_int)n;
		RLDBG(("decay: accum=%u", rl->accumulated_events));
	}
	rl->accumulated_events++; /* add this event */
	إذا (rl->accumulated_events > rl->max_accum)
		rl->accumulated_events = rl->max_accum;
	olast_event = rl->وروستی_event;
	rl->وروستی_event = now;
	RLDBG(("check threshold: accum=%u vs thresh=%u",
	    rl->accumulated_events, rl->پوله));

	/* Are we under threshold? */
	إذا (rl->accumulated_events < rl->پوله) {
		إذا (!rl->ratelimit_فعال)
			أرجع 0;
		RLDBG(("under threshold: hys=%u since_hys=%ld since_last=%ld",
		    rl->hysteresis, rl->hysteresis_پیل == 0 ? -1 :
		    (اوږد)(now - rl->hysteresis_پیل),
		    olast_event == 0 ? -1 : (اوږد)(now - olast_event)));
		إذا (rl->hysteresis_پیل == 0) {
			/* active, but under threshold; hysteresis */
			إذا (olast_event + rl->hysteresis < now) {
				/* hysteresis expired before this event */
				RLDBG(("hysteresis preexpired"));
				اذهب inactive;
			}
			RLDBG(("start hysteresis"));
			rl->hysteresis_پیل = now;
		} وإلا إذا (rl->hysteresis_پیل + rl->hysteresis < now) {
			/* Hysteresis period expired, transition to inactive */
			RLDBG(("complete hysteresis"));
 inactive:
			إذا (events_dropped != عدم)
				*events_dropped = rl->ratelimited_events;
			إذا (فعال != عدم)
				*فعال = 0;
			rl->ratelimit_فعال = 0;
			rl->ratelimit_پیل = 0;
			rl->وروستی_log = 0;
			rl->hysteresis_پیل = 0;
			rl->ratelimited_events = 0;
			أرجع 0;
		}
		/* ratelimiting active, but in hysteresis period */
	} وإلا إذا (!rl->ratelimit_فعال) {
		/* Transition to rate-limiting */
		RLDBG(("start ratelimit"));
		rl->ratelimit_فعال = 1;
		rl->ratelimit_پیل = now;
		rl->وروستی_log = now;
		rl->hysteresis_پیل = 0;
		rl->ratelimited_events = 1;
		إذا (فعال != عدم)
			*فعال = 1;
		أرجع 1;
	} وإلا إذا (rl->hysteresis_پیل != 0) {
		/* active and over threshold; reset hysteresis timer */
		RLDBG(("clear hysteresis"));
		rl->hysteresis_پیل = 0;
	}

	/* over threshold or in hysteresis period; log periodically */
	إذا (فعال != عدم)
		*فعال = 1;
	RLDBG(("log_every=%u since_log=%ld", rl->log_every,
	    (اوږد)(now - rl->وروستی_log)));
	إذا (rl->log_every > 0 && now >= rl->وروستی_log + rl->log_every) {
		RLDBG(("periodic: since_last=%u", rl->ratelimited_events));
		rl->وروستی_log = now;
		إذا (events_dropped != عدم) {
			*events_dropped = rl->ratelimited_events;
			rl->ratelimited_events = 0;
		}
		أرجع 0;
	}

	/* drop event */
	rl->ratelimited_events++;
	RLDBG(("drop: ratelimited_events=%u", rl->ratelimited_events));
	أرجع 1;
}
