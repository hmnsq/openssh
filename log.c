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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <syslog.h>
#అన్తర్భావ <unistd.h>
#ఒకవేళ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#అయితే_ముగింపు

#అన్తర్భావ "log.h"
#అన్తర్భావ "match.h"

స్థిర LogLevel log_level = SYSLOG_LEVEL_INFO;
స్థిర పూర్ణాంకం log_on_stderr = 1;
స్థిర పూర్ణాంకం log_stderr_fd = STDERR_FILENO;
స్థిర పూర్ణాంకం log_facility = LOG_AUTH;
స్థిర స్థిరరాశి అక్షరం *argv0;
స్థిర log_handler_fn *log_handler;
స్థిర శూన్య *log_handler_ctx;
స్థిర అక్షరం **log_verbose;
స్థిర కొలత_t nlog_verbose;
బాహ్య అక్షరం *__progname;

#నిర్వచించు LOG_SYSLOG_VIS	(VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL)
#నిర్వచించు LOG_STDERR_VIS	(VIS_సురక్షిత|VIS_OCTAL)

/* textual representation of log-facilities/levels */

స్థిర నిర్మాణం {
	స్థిరరాశి అక్షరం *name;
	SyslogFacility val;
} log_facilities[] = {
	{ "DAEMON",	SYSLOG_FACILITY_DAEMON },
	{ "USER",	SYSLOG_FACILITY_USER },
	{ "AUTH",	SYSLOG_FACILITY_AUTH },
#నిర్వచితమైతే LOG_AUTHPRIV
	{ "AUTHPRIV",	SYSLOG_FACILITY_AUTHPRIV },
#అయితే_ముగింపు
	{ "LOCAL0",	SYSLOG_FACILITY_LOCAL0 },
	{ "LOCAL1",	SYSLOG_FACILITY_LOCAL1 },
	{ "LOCAL2",	SYSLOG_FACILITY_LOCAL2 },
	{ "LOCAL3",	SYSLOG_FACILITY_LOCAL3 },
	{ "LOCAL4",	SYSLOG_FACILITY_LOCAL4 },
	{ "LOCAL5",	SYSLOG_FACILITY_LOCAL5 },
	{ "LOCAL6",	SYSLOG_FACILITY_LOCAL6 },
	{ "LOCAL7",	SYSLOG_FACILITY_LOCAL7 },
	{ ఖాళీ,		SYSLOG_FACILITY_NOT_సమితి }
};

స్థిర నిర్మాణం {
	స్థిరరాశి అక్షరం *name;
	LogLevel val;
} log_స్థాయిలు[] =
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
	{ ఖాళీ,		SYSLOG_LEVEL_NOT_సమితి }
};

LogLevel
log_level_get(శూన్య)
{
	తిరిగి log_level;
}

SyslogFacility
log_facility_సంఖ్య(అక్షరం *name)
{
	పూర్ణాంకం i;

	ఒకవేళ (name != ఖాళీ)
		కొరకు (i = 0; log_facilities[i].name; i++)
			ఒకవేళ (strcasecmp(log_facilities[i].name, name) == 0)
				తిరిగి log_facilities[i].val;
	తిరిగి SYSLOG_FACILITY_NOT_సమితి;
}

స్థిరరాశి అక్షరం *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	కొరకు (i = 0;  log_facilities[i].name; i++)
		ఒకవేళ (log_facilities[i].val == facility)
			తిరిగి log_facilities[i].name;
	తిరిగి ఖాళీ;
}

LogLevel
log_level_సంఖ్య(అక్షరం *name)
{
	పూర్ణాంకం i;

	ఒకవేళ (name != ఖాళీ)
		కొరకు (i = 0; log_స్థాయిలు[i].name; i++)
			ఒకవేళ (strcasecmp(log_స్థాయిలు[i].name, name) == 0)
				తిరిగి log_స్థాయిలు[i].val;
	తిరిగి SYSLOG_LEVEL_NOT_సమితి;
}

స్థిరరాశి అక్షరం *
log_level_name(LogLevel level)
{
	u_int i;

	కొరకు (i = 0; log_స్థాయిలు[i].name != ఖాళీ; i++)
		ఒకవేళ (log_స్థాయిలు[i].val == level)
			తిరిగి log_స్థాయిలు[i].name;
	తిరిగి ఖాళీ;
}

శూన్య
log_verbose_కూడు(స్థిరరాశి అక్షరం *s)
{
	అక్షరం **tmp;

	/* Ignore failures here */
	ఒకవేళ ((tmp = recallocarray(log_verbose, nlog_verbose, nlog_verbose + 1,
	    పరిమాణం(*log_verbose))) != ఖాళీ) {
		log_verbose = tmp;
		ఒకవేళ ((log_verbose[nlog_verbose] = strdup(s)) != ఖాళీ)
			nlog_verbose++;
	}
}

శూన్య
log_verbose_reset(శూన్య)
{
	కొలత_t i;

	కొరకు (i = 0; i < nlog_verbose; i++)
		విడుదల(log_verbose[i]);
	విడుదల(log_verbose);
	log_verbose = ఖాళీ;
	nlog_verbose = 0;
}

/*
 * Initialize the log.
 */

శూన్య
log_init(స్థిరరాశి అక్షరం *av0, LogLevel level, SyslogFacility facility,
    పూర్ణాంకం on_stderr)
{
#ఒకవేళ defined(HAVE_OPENLOG_R) && defined(SYSLOG_దత్తాంశం_INIT)
	నిర్మాణం syslog_దత్తాంశం sdata = SYSLOG_దత్తాంశం_INIT;
#అయితే_ముగింపు

	argv0 = av0;

	ఒకవేళ (log_change_level(level) != 0) {
		fprintf(stderr, "Unrecognized internal syslog level code %d\n",
		    (పూర్ణాంకం) level);
		నిష్క్రమించు(1);
	}

	log_handler = ఖాళీ;
	log_handler_ctx = ఖాళీ;

	log_on_stderr = on_stderr;
	ఒకవేళ (on_stderr)
		తిరిగి;

	ఎంపిక (facility) {
	స్థితి SYSLOG_FACILITY_DAEMON:
		log_facility = LOG_DAEMON;
		ఆపు;
	స్థితి SYSLOG_FACILITY_USER:
		log_facility = LOG_USER;
		ఆపు;
	స్థితి SYSLOG_FACILITY_AUTH:
		log_facility = LOG_AUTH;
		ఆపు;
#నిర్వచితమైతే LOG_AUTHPRIV
	స్థితి SYSLOG_FACILITY_AUTHPRIV:
		log_facility = LOG_AUTHPRIV;
		ఆపు;
#అయితే_ముగింపు
	స్థితి SYSLOG_FACILITY_LOCAL0:
		log_facility = LOG_LOCAL0;
		ఆపు;
	స్థితి SYSLOG_FACILITY_LOCAL1:
		log_facility = LOG_LOCAL1;
		ఆపు;
	స్థితి SYSLOG_FACILITY_LOCAL2:
		log_facility = LOG_LOCAL2;
		ఆపు;
	స్థితి SYSLOG_FACILITY_LOCAL3:
		log_facility = LOG_LOCAL3;
		ఆపు;
	స్థితి SYSLOG_FACILITY_LOCAL4:
		log_facility = LOG_LOCAL4;
		ఆపు;
	స్థితి SYSLOG_FACILITY_LOCAL5:
		log_facility = LOG_LOCAL5;
		ఆపు;
	స్థితి SYSLOG_FACILITY_LOCAL6:
		log_facility = LOG_LOCAL6;
		ఆపు;
	స్థితి SYSLOG_FACILITY_LOCAL7:
		log_facility = LOG_LOCAL7;
		ఆపు;
	అప్రమేయ:
		fprintf(stderr,
		    "Unrecognized internal syslog facility code %d\n",
		    (పూర్ణాంకం) facility);
		నిష్క్రమించు(1);
	}

	/*
	 * If an external library (eg libwrap) attempts to use syslog
	 * immediately after reexec, syslog may be pointing to the wrong
	 * facility, so we force an open/close of syslog here.
	 */
#ఒకవేళ defined(HAVE_OPENLOG_R) && defined(SYSLOG_దత్తాంశం_INIT)
	openlog_r(argv0 ? argv0 : __progname, LOG_PID, log_facility, &sdata);
	closelog_r(&sdata);
#లేకపోతే
	openlog(argv0 ? argv0 : __progname, LOG_PID, log_facility);
	closelog();
#అయితే_ముగింపు
}

పూర్ణాంకం
log_change_level(LogLevel new_log_level)
{
	/* no-op if log_init has not been called */
	ఒకవేళ (argv0 == ఖాళీ)
		తిరిగి 0;

	ఎంపిక (new_log_level) {
	స్థితి SYSLOG_LEVEL_QUIET:
	స్థితి SYSLOG_LEVEL_FATAL:
	స్థితి SYSLOG_LEVEL_ERROR:
	స్థితి SYSLOG_LEVEL_INFO:
	స్థితి SYSLOG_LEVEL_VERBOSE:
	స్థితి SYSLOG_LEVEL_DEBUG1:
	స్థితి SYSLOG_LEVEL_DEBUG2:
	స్థితి SYSLOG_LEVEL_DEBUG3:
		log_level = new_log_level;
		తిరిగి 0;
	అప్రమేయ:
		తిరిగి -1;
	}
}

పూర్ణాంకం
log_is_on_stderr(శూన్య)
{
	తిరిగి log_on_stderr && log_stderr_fd == STDERR_FILENO;
}

/* redirect what would usually get written to stderr to specified file */
శూన్య
log_redirect_stderr_గమ్యం(స్థిరరాశి అక్షరం *logfile)
{
	పూర్ణాంకం fd;

	ఒకవేళ (logfile == ఖాళీ) {
		ఒకవేళ (log_stderr_fd != STDERR_FILENO) {
			close(log_stderr_fd);
			log_stderr_fd = STDERR_FILENO;
		}
		తిరిగి;
	}

	ఒకవేళ ((fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1) {
		fprintf(stderr, "Couldn't open logfile %s: %s\n", logfile,
		    strerror(errno));
		నిష్క్రమించు(1);
	}
	log_stderr_fd = fd;
}

#నిర్వచించు MSGBUFSIZ 1024

శూన్య
సమితి_log_handler(log_handler_fn *handler, శూన్య *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}

స్థిర శూన్య
do_log(LogLevel level, పూర్ణాంకం force, స్థిరరాశి అక్షరం *suffix, స్థిరరాశి అక్షరం *fmt,
    va_list వాదనలు)
{
#ఒకవేళ defined(HAVE_OPENLOG_R) && defined(SYSLOG_దత్తాంశం_INIT)
	నిర్మాణం syslog_దత్తాంశం sdata = SYSLOG_దత్తాంశం_INIT;
#అయితే_ముగింపు
	అక్షరం msgbuf[MSGBUFSIZ];
	అక్షరం fmtbuf[MSGBUFSIZ];
	అక్షరం *txt = ఖాళీ;
	పూర్ణాంకం pri = LOG_INFO;
	పూర్ణాంకం saved_errno = errno;
	log_handler_fn *tmp_handler;
	స్థిరరాశి అక్షరం *progname = argv0 != ఖాళీ ? argv0 : __progname;

	ఒకవేళ (!force && level > log_level)
		తిరిగి;

	ఎంపిక (level) {
	స్థితి SYSLOG_LEVEL_FATAL:
		ఒకవేళ (!log_on_stderr)
			txt = "fatal";
		pri = LOG_CRIT;
		ఆపు;
	స్థితి SYSLOG_LEVEL_ERROR:
		ఒకవేళ (!log_on_stderr)
			txt = "error";
		pri = LOG_ERR;
		ఆపు;
	స్థితి SYSLOG_LEVEL_INFO:
		pri = LOG_INFO;
		ఆపు;
	స్థితి SYSLOG_LEVEL_VERBOSE:
		pri = LOG_INFO;
		ఆపు;
	స్థితి SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		pri = LOG_DEBUG;
		ఆపు;
	స్థితి SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		pri = LOG_DEBUG;
		ఆపు;
	స్థితి SYSLOG_LEVEL_DEBUG3:
		txt = "debug3";
		pri = LOG_DEBUG;
		ఆపు;
	అప్రమేయ:
		txt = "internal error";
		pri = LOG_ERR;
		ఆపు;
	}
	ఒకవేళ (txt != ఖాళీ && log_handler == ఖాళీ) {
		snprintf(fmtbuf, పరిమాణం(fmtbuf), "%s: %s", txt, fmt);
		vsnprintf(msgbuf, పరిమాణం(msgbuf), fmtbuf, వాదనలు);
	} లేకపోతే {
		vsnprintf(msgbuf, పరిమాణం(msgbuf), fmt, వాదనలు);
	}
	ఒకవేళ (suffix != ఖాళీ) {
		snprintf(fmtbuf, పరిమాణం(fmtbuf), "%s: %s", msgbuf, suffix);
		strlcpy(msgbuf, fmtbuf, పరిమాణం(msgbuf));
	}
	strnvis(fmtbuf, msgbuf, పరిమాణం(fmtbuf),
	    log_on_stderr ? LOG_STDERR_VIS : LOG_SYSLOG_VIS);
	ఒకవేళ (log_handler != ఖాళీ) {
		/* Avoid recursion */
		tmp_handler = log_handler;
		log_handler = ఖాళీ;
		/* Note: this sends the raw (i.e. no strnvis) log message */
		tmp_handler(level, force, msgbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} లేకపోతే ఒకవేళ (log_on_stderr) {
		snprintf(msgbuf, పరిమాణం msgbuf, "%s%s%.*s\r\n",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (పూర్ణాంకం)పరిమాణం msgbuf - 3, fmtbuf);
		(శూన్య)లిఖ(log_stderr_fd, msgbuf, అక్షరశ్రేణి_పొడవు(msgbuf));
	} లేకపోతే {
#ఒకవేళ defined(HAVE_OPENLOG_R) && defined(SYSLOG_దత్తాంశం_INIT)
		openlog_r(progname, LOG_PID, log_facility, &sdata);
		syslog_r(pri, &sdata, "%.500s", fmtbuf);
		closelog_r(&sdata);
#లేకపోతే
		openlog(progname, LOG_PID, log_facility);
		syslog(pri, "%.500s", fmtbuf);
		closelog();
#అయితే_ముగింపు
	}
	errno = saved_errno;
}

శూన్య
sshlog(స్థిరరాశి అక్షరం *file, స్థిరరాశి అక్షరం *func, పూర్ణాంకం పంక్తి, పూర్ణాంకం showfunc,
    LogLevel level, స్థిరరాశి అక్షరం *suffix, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list వాదనలు;

	va_start(వాదనలు, fmt);
	sshlogv(file, func, పంక్తి, showfunc, level, suffix, fmt, వాదనలు);
	va_end(వాదనలు);
}

శూన్య
sshlogdie(స్థిరరాశి అక్షరం *file, స్థిరరాశి అక్షరం *func, పూర్ణాంకం పంక్తి, పూర్ణాంకం showfunc,
    LogLevel level, స్థిరరాశి అక్షరం *suffix, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list వాదనలు;

	va_start(వాదనలు, fmt);
	sshlogv(file, func, పంక్తి, showfunc, SYSLOG_LEVEL_INFO,
	    suffix, fmt, వాదనలు);
	va_end(వాదనలు);
	cleanup_exit(255);
}

శూన్య
sshlogv(స్థిరరాశి అక్షరం *file, స్థిరరాశి అక్షరం *func, పూర్ణాంకం పంక్తి, పూర్ణాంకం showfunc,
    LogLevel level, స్థిరరాశి అక్షరం *suffix, స్థిరరాశి అక్షరం *fmt, va_list వాదనలు)
{
	అక్షరం ట్యాగ్[128], fmt2[MSGBUFSIZ + 128];
	పూర్ణాంకం forced = 0;
	స్థిరరాశి అక్షరం *cp;
	కొలత_t i;

	/* short circuit processing early if we're not going to log anything */
	ఒకవేళ (nlog_verbose == 0 && level > log_level)
		తిరిగి;

	snprintf(ట్యాగ్, పరిమాణం(ట్యాగ్), "%.48s:%.48s():%d (bin=%s, pid=%ld)",
	    (cp = strrchr(file, '/')) == ఖాళీ ? file : cp + 1, func, పంక్తి,
	    argv0 == ఖాళీ ? "UNKNOWN" : argv0, (దీర్ఘ)getpid());
	కొరకు (i = 0; i < nlog_verbose; i++) {
		ఒకవేళ (సరిపోలిక_నమూనా_list(ట్యాగ్, log_verbose[i], 0) == 1) {
			forced = 1;
			ఆపు;
		}
	}

	ఒకవేళ (forced)
		snprintf(fmt2, పరిమాణం(fmt2), "%s: %s", ట్యాగ్, fmt);
	లేకపోతే ఒకవేళ (showfunc)
		snprintf(fmt2, పరిమాణం(fmt2), "%s: %s", func, fmt);
	లేకపోతే
		strlcpy(fmt2, fmt, పరిమాణం(fmt2));

	do_log(level, forced, suffix, fmt2, వాదనలు);
}

శూన్య
sshlogdirect(LogLevel level, పూర్ణాంకం forced, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list వాదనలు;

	va_start(వాదనలు, fmt);
	do_log(level, forced, ఖాళీ, fmt, వాదనలు);
	va_end(వాదనలు);
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

#నిర్వచితమైతే RATELIMIT_DEBUG
# define RLDBG(x) చేయి { \
		రాయి("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		రాయి x; \
		రాయి("\n"); \
		fflush(stdout); \
	} అయితే (0)
#లేకపోతే
# define RLDBG(x)
#అయితే_ముగింపు

/* set up a ratelimit */
శూన్య
log_ratelimit_init(నిర్మాణం log_ratelimit_ctx *rl, u_int పరిమితి,
    u_int max_accum, u_int hysteresis, u_int log_every)
{
	memset(rl, 0, పరిమాణం(*rl));
	rl->పరిమితి = పరిమితి;
	rl->max_accum = max_accum;
	rl->hysteresis = hysteresis;
	rl->log_every = log_every;
	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u",
	    rl, rl->పరిమితి, rl->max_accum, rl->hysteresis, rl->log_every));
}

/*
 * check whether a log event should be dropped because of rate-limiting.
 * returns non-zero if the event should be dropped. If events_since_last
 * is supplied then, for periodic logs, it will be set to the number of
 * dropped events since the last message.
 */
పూర్ణాంకం
log_ratelimit(నిర్మాణం log_ratelimit_ctx *rl, time_t now, పూర్ణాంకం *చురుకైన,
    u_int *events_dropped)
{
	time_t olast_event;

	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u "
	    "accum=%u since=%ld since_last=%u", rl, rl->పరిమితి,
	    rl->max_accum, rl->hysteresis,
	    rl->log_every, rl->accumulated_events,
	    rl->చివరి_event == 0 ? -1 : (దీర్ఘ)(now - rl->చివరి_event),
	    rl->ratelimited_events));

	ఒకవేళ (now < 0)
		తిరిగి 0;
	ఒకవేళ (events_dropped != ఖాళీ)
		*events_dropped = 0;
	ఒకవేళ (చురుకైన != ఖాళీ)
		*చురుకైన = rl->ratelimit_చురుకైన;

	/* First, decay accumulated events */
	ఒకవేళ (rl->చివరి_event <= 0)
		rl->చివరి_event = now;
	ఒకవేళ (now > rl->చివరి_event) {
		uint64_t n = now - rl->చివరి_event;

		ఒకవేళ (n > UINT_MAX)
			n = UINT_MAX;
		ఒకవేళ (rl->accumulated_events < (u_int)n)
			rl->accumulated_events = 0;
		లేకపోతే
			rl->accumulated_events -= (u_int)n;
		RLDBG(("decay: accum=%u", rl->accumulated_events));
	}
	rl->accumulated_events++; /* add this event */
	ఒకవేళ (rl->accumulated_events > rl->max_accum)
		rl->accumulated_events = rl->max_accum;
	olast_event = rl->చివరి_event;
	rl->చివరి_event = now;
	RLDBG(("check threshold: accum=%u vs thresh=%u",
	    rl->accumulated_events, rl->పరిమితి));

	/* Are we under threshold? */
	ఒకవేళ (rl->accumulated_events < rl->పరిమితి) {
		ఒకవేళ (!rl->ratelimit_చురుకైన)
			తిరిగి 0;
		RLDBG(("under threshold: hys=%u since_hys=%ld since_last=%ld",
		    rl->hysteresis, rl->hysteresis_ప్రారంభం == 0 ? -1 :
		    (దీర్ఘ)(now - rl->hysteresis_ప్రారంభం),
		    olast_event == 0 ? -1 : (దీర్ఘ)(now - olast_event)));
		ఒకవేళ (rl->hysteresis_ప్రారంభం == 0) {
			/* active, but under threshold; hysteresis */
			ఒకవేళ (olast_event + rl->hysteresis < now) {
				/* hysteresis expired before this event */
				RLDBG(("hysteresis preexpired"));
				వెళ్ళు inactive;
			}
			RLDBG(("start hysteresis"));
			rl->hysteresis_ప్రారంభం = now;
		} లేకపోతే ఒకవేళ (rl->hysteresis_ప్రారంభం + rl->hysteresis < now) {
			/* Hysteresis period expired, transition to inactive */
			RLDBG(("complete hysteresis"));
 inactive:
			ఒకవేళ (events_dropped != ఖాళీ)
				*events_dropped = rl->ratelimited_events;
			ఒకవేళ (చురుకైన != ఖాళీ)
				*చురుకైన = 0;
			rl->ratelimit_చురుకైన = 0;
			rl->ratelimit_ప్రారంభం = 0;
			rl->చివరి_log = 0;
			rl->hysteresis_ప్రారంభం = 0;
			rl->ratelimited_events = 0;
			తిరిగి 0;
		}
		/* ratelimiting active, but in hysteresis period */
	} లేకపోతే ఒకవేళ (!rl->ratelimit_చురుకైన) {
		/* Transition to rate-limiting */
		RLDBG(("start ratelimit"));
		rl->ratelimit_చురుకైన = 1;
		rl->ratelimit_ప్రారంభం = now;
		rl->చివరి_log = now;
		rl->hysteresis_ప్రారంభం = 0;
		rl->ratelimited_events = 1;
		ఒకవేళ (చురుకైన != ఖాళీ)
			*చురుకైన = 1;
		తిరిగి 1;
	} లేకపోతే ఒకవేళ (rl->hysteresis_ప్రారంభం != 0) {
		/* active and over threshold; reset hysteresis timer */
		RLDBG(("clear hysteresis"));
		rl->hysteresis_ప్రారంభం = 0;
	}

	/* over threshold or in hysteresis period; log periodically */
	ఒకవేళ (చురుకైన != ఖాళీ)
		*చురుకైన = 1;
	RLDBG(("log_every=%u since_log=%ld", rl->log_every,
	    (దీర్ఘ)(now - rl->చివరి_log)));
	ఒకవేళ (rl->log_every > 0 && now >= rl->చివరి_log + rl->log_every) {
		RLDBG(("periodic: since_last=%u", rl->ratelimited_events));
		rl->చివరి_log = now;
		ఒకవేళ (events_dropped != ఖాళీ) {
			*events_dropped = rl->ratelimited_events;
			rl->ratelimited_events = 0;
		}
		తిరిగి 0;
	}

	/* drop event */
	rl->ratelimited_events++;
	RLDBG(("drop: ratelimited_events=%u", rl->ratelimited_events));
	తిరిగి 1;
}
