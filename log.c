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
#اگر_ختم

#شامل "log.h"
#شامل "match.h"

ساکن LogLevel log_level = SYSLOG_LEVEL_INFO;
ساکن صحیح log_on_stderr = 1;
ساکن صحیح log_stderr_fd = STDERR_FILENO;
ساکن صحیح log_facility = LOG_AUTH;
ساکن ثابت حرف *argv0;
ساکن log_handler_fn *log_handler;
ساکن خالی *log_handler_ctx;
ساکن حرف **log_verbose;
ساکن سائز_t nlog_verbose;
خارجی حرف *__progname;

#تعریف_کرو LOG_SYSLOG_VIS	(VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL)
#تعریف_کرو LOG_STDERR_VIS	(VIS_محفوظ|VIS_OCTAL)

/* textual representation of log-facilities/levels */

ساکن ساخت {
	ثابت حرف *name;
	SyslogFacility val;
} log_facilities[] = {
	{ "DAEMON",	SYSLOG_FACILITY_DAEMON },
	{ "USER",	SYSLOG_FACILITY_USER },
	{ "AUTH",	SYSLOG_FACILITY_AUTH },
#اگر_تعریف_شدہ LOG_AUTHPRIV
	{ "AUTHPRIV",	SYSLOG_FACILITY_AUTHPRIV },
#اگر_ختم
	{ "LOCAL0",	SYSLOG_FACILITY_LOCAL0 },
	{ "LOCAL1",	SYSLOG_FACILITY_LOCAL1 },
	{ "LOCAL2",	SYSLOG_FACILITY_LOCAL2 },
	{ "LOCAL3",	SYSLOG_FACILITY_LOCAL3 },
	{ "LOCAL4",	SYSLOG_FACILITY_LOCAL4 },
	{ "LOCAL5",	SYSLOG_FACILITY_LOCAL5 },
	{ "LOCAL6",	SYSLOG_FACILITY_LOCAL6 },
	{ "LOCAL7",	SYSLOG_FACILITY_LOCAL7 },
	{ تہی,		SYSLOG_FACILITY_NOT_سیٹ }
};

ساکن ساخت {
	ثابت حرف *name;
	LogLevel val;
} log_سطحیں[] =
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
	{ تہی,		SYSLOG_LEVEL_NOT_سیٹ }
};

LogLevel
log_level_get(خالی)
{
	واپس log_level;
}

SyslogFacility
log_facility_نمبر(حرف *name)
{
	صحیح i;

	اگر (name != تہی)
		برائے (i = 0; log_facilities[i].name; i++)
			اگر (strcasecmp(log_facilities[i].name, name) == 0)
				واپس log_facilities[i].val;
	واپس SYSLOG_FACILITY_NOT_سیٹ;
}

ثابت حرف *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	برائے (i = 0;  log_facilities[i].name; i++)
		اگر (log_facilities[i].val == facility)
			واپس log_facilities[i].name;
	واپس تہی;
}

LogLevel
log_level_نمبر(حرف *name)
{
	صحیح i;

	اگر (name != تہی)
		برائے (i = 0; log_سطحیں[i].name; i++)
			اگر (strcasecmp(log_سطحیں[i].name, name) == 0)
				واپس log_سطحیں[i].val;
	واپس SYSLOG_LEVEL_NOT_سیٹ;
}

ثابت حرف *
log_level_name(LogLevel level)
{
	u_int i;

	برائے (i = 0; log_سطحیں[i].name != تہی; i++)
		اگر (log_سطحیں[i].val == level)
			واپس log_سطحیں[i].name;
	واپس تہی;
}

خالی
log_verbose_جوڑو(ثابت حرف *s)
{
	حرف **tmp;

	/* Ignore failures here */
	اگر ((tmp = recallocarray(log_verbose, nlog_verbose, nlog_verbose + 1,
	    حجم(*log_verbose))) != تہی) {
		log_verbose = tmp;
		اگر ((log_verbose[nlog_verbose] = strdup(s)) != تہی)
			nlog_verbose++;
	}
}

خالی
log_verbose_reset(خالی)
{
	سائز_t i;

	برائے (i = 0; i < nlog_verbose; i++)
		آزاد(log_verbose[i]);
	آزاد(log_verbose);
	log_verbose = تہی;
	nlog_verbose = 0;
}

/*
 * Initialize the log.
 */

خالی
log_init(ثابت حرف *av0, LogLevel level, SyslogFacility facility,
    صحیح on_stderr)
{
#اگر defined(HAVE_OPENLOG_R) && defined(SYSLOG_ڈیٹا_INIT)
	ساخت syslog_ڈیٹا sdata = SYSLOG_ڈیٹا_INIT;
#اگر_ختم

	argv0 = av0;

	اگر (log_change_level(level) != 0) {
		fprintf(stderr, "Unrecognized internal syslog level code %d\n",
		    (صحیح) level);
		باہر_نکلو(1);
	}

	log_handler = تہی;
	log_handler_ctx = تہی;

	log_on_stderr = on_stderr;
	اگر (on_stderr)
		واپس;

	انتخاب (facility) {
	حالت SYSLOG_FACILITY_DAEMON:
		log_facility = LOG_DAEMON;
		توڑو;
	حالت SYSLOG_FACILITY_USER:
		log_facility = LOG_USER;
		توڑو;
	حالت SYSLOG_FACILITY_AUTH:
		log_facility = LOG_AUTH;
		توڑو;
#اگر_تعریف_شدہ LOG_AUTHPRIV
	حالت SYSLOG_FACILITY_AUTHPRIV:
		log_facility = LOG_AUTHPRIV;
		توڑو;
#اگر_ختم
	حالت SYSLOG_FACILITY_LOCAL0:
		log_facility = LOG_LOCAL0;
		توڑو;
	حالت SYSLOG_FACILITY_LOCAL1:
		log_facility = LOG_LOCAL1;
		توڑو;
	حالت SYSLOG_FACILITY_LOCAL2:
		log_facility = LOG_LOCAL2;
		توڑو;
	حالت SYSLOG_FACILITY_LOCAL3:
		log_facility = LOG_LOCAL3;
		توڑو;
	حالت SYSLOG_FACILITY_LOCAL4:
		log_facility = LOG_LOCAL4;
		توڑو;
	حالت SYSLOG_FACILITY_LOCAL5:
		log_facility = LOG_LOCAL5;
		توڑو;
	حالت SYSLOG_FACILITY_LOCAL6:
		log_facility = LOG_LOCAL6;
		توڑو;
	حالت SYSLOG_FACILITY_LOCAL7:
		log_facility = LOG_LOCAL7;
		توڑو;
	طےشدہ:
		fprintf(stderr,
		    "Unrecognized internal syslog facility code %d\n",
		    (صحیح) facility);
		باہر_نکلو(1);
	}

	/*
	 * If an external library (eg libwrap) attempts to use syslog
	 * immediately after reexec, syslog may be pointing to the wrong
	 * facility, so we force an open/close of syslog here.
	 */
#اگر defined(HAVE_OPENLOG_R) && defined(SYSLOG_ڈیٹا_INIT)
	openlog_r(argv0 ? argv0 : __progname, LOG_PID, log_facility, &sdata);
	closelog_r(&sdata);
#ورنہ
	openlog(argv0 ? argv0 : __progname, LOG_PID, log_facility);
	closelog();
#اگر_ختم
}

صحیح
log_change_level(LogLevel new_log_level)
{
	/* no-op if log_init has not been called */
	اگر (argv0 == تہی)
		واپس 0;

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
		واپس 0;
	طےشدہ:
		واپس -1;
	}
}

صحیح
log_is_on_stderr(خالی)
{
	واپس log_on_stderr && log_stderr_fd == STDERR_FILENO;
}

/* redirect what would usually get written to stderr to specified file */
خالی
log_redirect_stderr_مقصد(ثابت حرف *logfile)
{
	صحیح fd;

	اگر (logfile == تہی) {
		اگر (log_stderr_fd != STDERR_FILENO) {
			close(log_stderr_fd);
			log_stderr_fd = STDERR_FILENO;
		}
		واپس;
	}

	اگر ((fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1) {
		fprintf(stderr, "Couldn't open logfile %s: %s\n", logfile,
		    strerror(errno));
		باہر_نکلو(1);
	}
	log_stderr_fd = fd;
}

#تعریف_کرو MSGBUFSIZ 1024

خالی
سیٹ_log_handler(log_handler_fn *handler, خالی *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}

ساکن خالی
do_log(LogLevel level, صحیح force, ثابت حرف *suffix, ثابت حرف *fmt,
    va_list دلائل)
{
#اگر defined(HAVE_OPENLOG_R) && defined(SYSLOG_ڈیٹا_INIT)
	ساخت syslog_ڈیٹا sdata = SYSLOG_ڈیٹا_INIT;
#اگر_ختم
	حرف msgbuf[MSGBUFSIZ];
	حرف fmtbuf[MSGBUFSIZ];
	حرف *txt = تہی;
	صحیح pri = LOG_INFO;
	صحیح saved_errno = errno;
	log_handler_fn *tmp_handler;
	ثابت حرف *progname = argv0 != تہی ? argv0 : __progname;

	اگر (!force && level > log_level)
		واپس;

	انتخاب (level) {
	حالت SYSLOG_LEVEL_FATAL:
		اگر (!log_on_stderr)
			txt = "fatal";
		pri = LOG_CRIT;
		توڑو;
	حالت SYSLOG_LEVEL_ERROR:
		اگر (!log_on_stderr)
			txt = "error";
		pri = LOG_ERR;
		توڑو;
	حالت SYSLOG_LEVEL_INFO:
		pri = LOG_INFO;
		توڑو;
	حالت SYSLOG_LEVEL_VERBOSE:
		pri = LOG_INFO;
		توڑو;
	حالت SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		pri = LOG_DEBUG;
		توڑو;
	حالت SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		pri = LOG_DEBUG;
		توڑو;
	حالت SYSLOG_LEVEL_DEBUG3:
		txt = "debug3";
		pri = LOG_DEBUG;
		توڑو;
	طےشدہ:
		txt = "internal error";
		pri = LOG_ERR;
		توڑو;
	}
	اگر (txt != تہی && log_handler == تہی) {
		snprintf(fmtbuf, حجم(fmtbuf), "%s: %s", txt, fmt);
		vsnprintf(msgbuf, حجم(msgbuf), fmtbuf, دلائل);
	} ورنہ {
		vsnprintf(msgbuf, حجم(msgbuf), fmt, دلائل);
	}
	اگر (suffix != تہی) {
		snprintf(fmtbuf, حجم(fmtbuf), "%s: %s", msgbuf, suffix);
		strlcpy(msgbuf, fmtbuf, حجم(msgbuf));
	}
	strnvis(fmtbuf, msgbuf, حجم(fmtbuf),
	    log_on_stderr ? LOG_STDERR_VIS : LOG_SYSLOG_VIS);
	اگر (log_handler != تہی) {
		/* Avoid recursion */
		tmp_handler = log_handler;
		log_handler = تہی;
		/* Note: this sends the raw (i.e. no strnvis) log message */
		tmp_handler(level, force, msgbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} ورنہ اگر (log_on_stderr) {
		snprintf(msgbuf, حجم msgbuf, "%s%s%.*s\r\n",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (صحیح)حجم msgbuf - 3, fmtbuf);
		(خالی)اكتب(log_stderr_fd, msgbuf, لڑی_لمبائی(msgbuf));
	} ورنہ {
#اگر defined(HAVE_OPENLOG_R) && defined(SYSLOG_ڈیٹا_INIT)
		openlog_r(progname, LOG_PID, log_facility, &sdata);
		syslog_r(pri, &sdata, "%.500s", fmtbuf);
		closelog_r(&sdata);
#ورنہ
		openlog(progname, LOG_PID, log_facility);
		syslog(pri, "%.500s", fmtbuf);
		closelog();
#اگر_ختم
	}
	errno = saved_errno;
}

خالی
sshlog(ثابت حرف *file, ثابت حرف *func, صحیح سطر, صحیح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list دلائل;

	va_start(دلائل, fmt);
	sshlogv(file, func, سطر, showfunc, level, suffix, fmt, دلائل);
	va_end(دلائل);
}

خالی
sshlogdie(ثابت حرف *file, ثابت حرف *func, صحیح سطر, صحیح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list دلائل;

	va_start(دلائل, fmt);
	sshlogv(file, func, سطر, showfunc, SYSLOG_LEVEL_INFO,
	    suffix, fmt, دلائل);
	va_end(دلائل);
	cleanup_exit(255);
}

خالی
sshlogv(ثابت حرف *file, ثابت حرف *func, صحیح سطر, صحیح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, va_list دلائل)
{
	حرف لیبل[128], fmt2[MSGBUFSIZ + 128];
	صحیح forced = 0;
	ثابت حرف *cp;
	سائز_t i;

	/* short circuit processing early if we're not going to log anything */
	اگر (nlog_verbose == 0 && level > log_level)
		واپس;

	snprintf(لیبل, حجم(لیبل), "%.48s:%.48s():%d (bin=%s, pid=%ld)",
	    (cp = strrchr(file, '/')) == تہی ? file : cp + 1, func, سطر,
	    argv0 == تہی ? "UNKNOWN" : argv0, (طویل)getpid());
	برائے (i = 0; i < nlog_verbose; i++) {
		اگر (مطابقت_نمونہ_list(لیبل, log_verbose[i], 0) == 1) {
			forced = 1;
			توڑو;
		}
	}

	اگر (forced)
		snprintf(fmt2, حجم(fmt2), "%s: %s", لیبل, fmt);
	ورنہ اگر (showfunc)
		snprintf(fmt2, حجم(fmt2), "%s: %s", func, fmt);
	ورنہ
		strlcpy(fmt2, fmt, حجم(fmt2));

	do_log(level, forced, suffix, fmt2, دلائل);
}

خالی
sshlogdirect(LogLevel level, صحیح forced, ثابت حرف *fmt, ...)
{
	va_list دلائل;

	va_start(دلائل, fmt);
	do_log(level, forced, تہی, fmt, دلائل);
	va_end(دلائل);
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

#اگر_تعریف_شدہ RATELIMIT_DEBUG
# define RLDBG(x) کرو { \
		لکھو("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		لکھو x; \
		لکھو("\n"); \
		fflush(stdout); \
	} جب (0)
#ورنہ
# define RLDBG(x)
#اگر_ختم

/* set up a ratelimit */
خالی
log_ratelimit_init(ساخت log_ratelimit_ctx *rl, u_int حد,
    u_int max_accum, u_int hysteresis, u_int log_every)
{
	memset(rl, 0, حجم(*rl));
	rl->حد = حد;
	rl->max_accum = max_accum;
	rl->hysteresis = hysteresis;
	rl->log_every = log_every;
	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u",
	    rl, rl->حد, rl->max_accum, rl->hysteresis, rl->log_every));
}

/*
 * check whether a log event should be dropped because of rate-limiting.
 * returns non-zero if the event should be dropped. If events_since_last
 * is supplied then, for periodic logs, it will be set to the number of
 * dropped events since the last message.
 */
صحیح
log_ratelimit(ساخت log_ratelimit_ctx *rl, time_t now, صحیح *فعال,
    u_int *events_dropped)
{
	time_t olast_event;

	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u "
	    "accum=%u since=%ld since_last=%u", rl, rl->حد,
	    rl->max_accum, rl->hysteresis,
	    rl->log_every, rl->accumulated_events,
	    rl->آخری_event == 0 ? -1 : (طویل)(now - rl->آخری_event),
	    rl->ratelimited_events));

	اگر (now < 0)
		واپس 0;
	اگر (events_dropped != تہی)
		*events_dropped = 0;
	اگر (فعال != تہی)
		*فعال = rl->ratelimit_فعال;

	/* First, decay accumulated events */
	اگر (rl->آخری_event <= 0)
		rl->آخری_event = now;
	اگر (now > rl->آخری_event) {
		uint64_t n = now - rl->آخری_event;

		اگر (n > UINT_MAX)
			n = UINT_MAX;
		اگر (rl->accumulated_events < (u_int)n)
			rl->accumulated_events = 0;
		ورنہ
			rl->accumulated_events -= (u_int)n;
		RLDBG(("decay: accum=%u", rl->accumulated_events));
	}
	rl->accumulated_events++; /* add this event */
	اگر (rl->accumulated_events > rl->max_accum)
		rl->accumulated_events = rl->max_accum;
	olast_event = rl->آخری_event;
	rl->آخری_event = now;
	RLDBG(("check threshold: accum=%u vs thresh=%u",
	    rl->accumulated_events, rl->حد));

	/* Are we under threshold? */
	اگر (rl->accumulated_events < rl->حد) {
		اگر (!rl->ratelimit_فعال)
			واپس 0;
		RLDBG(("under threshold: hys=%u since_hys=%ld since_last=%ld",
		    rl->hysteresis, rl->hysteresis_آغاز == 0 ? -1 :
		    (طویل)(now - rl->hysteresis_آغاز),
		    olast_event == 0 ? -1 : (طویل)(now - olast_event)));
		اگر (rl->hysteresis_آغاز == 0) {
			/* active, but under threshold; hysteresis */
			اگر (olast_event + rl->hysteresis < now) {
				/* hysteresis expired before this event */
				RLDBG(("hysteresis preexpired"));
				جاؤ inactive;
			}
			RLDBG(("start hysteresis"));
			rl->hysteresis_آغاز = now;
		} ورنہ اگر (rl->hysteresis_آغاز + rl->hysteresis < now) {
			/* Hysteresis period expired, transition to inactive */
			RLDBG(("complete hysteresis"));
 inactive:
			اگر (events_dropped != تہی)
				*events_dropped = rl->ratelimited_events;
			اگر (فعال != تہی)
				*فعال = 0;
			rl->ratelimit_فعال = 0;
			rl->ratelimit_آغاز = 0;
			rl->آخری_log = 0;
			rl->hysteresis_آغاز = 0;
			rl->ratelimited_events = 0;
			واپس 0;
		}
		/* ratelimiting active, but in hysteresis period */
	} ورنہ اگر (!rl->ratelimit_فعال) {
		/* Transition to rate-limiting */
		RLDBG(("start ratelimit"));
		rl->ratelimit_فعال = 1;
		rl->ratelimit_آغاز = now;
		rl->آخری_log = now;
		rl->hysteresis_آغاز = 0;
		rl->ratelimited_events = 1;
		اگر (فعال != تہی)
			*فعال = 1;
		واپس 1;
	} ورنہ اگر (rl->hysteresis_آغاز != 0) {
		/* active and over threshold; reset hysteresis timer */
		RLDBG(("clear hysteresis"));
		rl->hysteresis_آغاز = 0;
	}

	/* over threshold or in hysteresis period; log periodically */
	اگر (فعال != تہی)
		*فعال = 1;
	RLDBG(("log_every=%u since_log=%ld", rl->log_every,
	    (طویل)(now - rl->آخری_log)));
	اگر (rl->log_every > 0 && now >= rl->آخری_log + rl->log_every) {
		RLDBG(("periodic: since_last=%u", rl->ratelimited_events));
		rl->آخری_log = now;
		اگر (events_dropped != تہی) {
			*events_dropped = rl->ratelimited_events;
			rl->ratelimited_events = 0;
		}
		واپس 0;
	}

	/* drop event */
	rl->ratelimited_events++;
	RLDBG(("drop: ratelimited_events=%u", rl->ratelimited_events));
	واپس 1;
}
