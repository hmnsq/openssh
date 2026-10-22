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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <syslog.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਜੇ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"

ਸਥਿਰ LogLevel log_level = SYSLOG_LEVEL_INFO;
ਸਥਿਰ ਪੂਰਨ log_on_stderr = 1;
ਸਥਿਰ ਪੂਰਨ log_stderr_fd = STDERR_FILENO;
ਸਥਿਰ ਪੂਰਨ log_facility = LOG_AUTH;
ਸਥਿਰ ਅਚਲ ਅੱਖਰ *argv0;
ਸਥਿਰ log_handler_fn *log_handler;
ਸਥਿਰ ਖਾਲੀ *log_handler_ctx;
ਸਥਿਰ ਅੱਖਰ **log_verbose;
ਸਥਿਰ ਮਾਪ_t nlog_verbose;
ਬਾਹਰੀ ਅੱਖਰ *__progname;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LOG_SYSLOG_VIS	(VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LOG_STDERR_VIS	(VIS_ਸੁਰੱਖਿਅਤ|VIS_OCTAL)

/* textual representation of log-facilities/levels */

ਸਥਿਰ ਬਣਤਰ {
	ਅਚਲ ਅੱਖਰ *name;
	SyslogFacility val;
} log_facilities[] = {
	{ "DAEMON",	SYSLOG_FACILITY_DAEMON },
	{ "USER",	SYSLOG_FACILITY_USER },
	{ "AUTH",	SYSLOG_FACILITY_AUTH },
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LOG_AUTHPRIV
	{ "AUTHPRIV",	SYSLOG_FACILITY_AUTHPRIV },
#ਜੇ_ਅੰਤ
	{ "LOCAL0",	SYSLOG_FACILITY_LOCAL0 },
	{ "LOCAL1",	SYSLOG_FACILITY_LOCAL1 },
	{ "LOCAL2",	SYSLOG_FACILITY_LOCAL2 },
	{ "LOCAL3",	SYSLOG_FACILITY_LOCAL3 },
	{ "LOCAL4",	SYSLOG_FACILITY_LOCAL4 },
	{ "LOCAL5",	SYSLOG_FACILITY_LOCAL5 },
	{ "LOCAL6",	SYSLOG_FACILITY_LOCAL6 },
	{ "LOCAL7",	SYSLOG_FACILITY_LOCAL7 },
	{ ਨਿਰਾ,		SYSLOG_FACILITY_NOT_ਸੈੱਟ }
};

ਸਥਿਰ ਬਣਤਰ {
	ਅਚਲ ਅੱਖਰ *name;
	LogLevel val;
} log_ਪੱਧਰ[] =
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
	{ ਨਿਰਾ,		SYSLOG_LEVEL_NOT_ਸੈੱਟ }
};

LogLevel
log_level_get(ਖਾਲੀ)
{
	ਵਾਪਸ log_level;
}

SyslogFacility
log_facility_ਸੰਖਿਆ(ਅੱਖਰ *name)
{
	ਪੂਰਨ i;

	ਜੇ (name != ਨਿਰਾ)
		ਲਈ (i = 0; log_facilities[i].name; i++)
			ਜੇ (strcasecmp(log_facilities[i].name, name) == 0)
				ਵਾਪਸ log_facilities[i].val;
	ਵਾਪਸ SYSLOG_FACILITY_NOT_ਸੈੱਟ;
}

ਅਚਲ ਅੱਖਰ *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	ਲਈ (i = 0;  log_facilities[i].name; i++)
		ਜੇ (log_facilities[i].val == facility)
			ਵਾਪਸ log_facilities[i].name;
	ਵਾਪਸ ਨਿਰਾ;
}

LogLevel
log_level_ਸੰਖਿਆ(ਅੱਖਰ *name)
{
	ਪੂਰਨ i;

	ਜੇ (name != ਨਿਰਾ)
		ਲਈ (i = 0; log_ਪੱਧਰ[i].name; i++)
			ਜੇ (strcasecmp(log_ਪੱਧਰ[i].name, name) == 0)
				ਵਾਪਸ log_ਪੱਧਰ[i].val;
	ਵਾਪਸ SYSLOG_LEVEL_NOT_ਸੈੱਟ;
}

ਅਚਲ ਅੱਖਰ *
log_level_name(LogLevel level)
{
	u_int i;

	ਲਈ (i = 0; log_ਪੱਧਰ[i].name != ਨਿਰਾ; i++)
		ਜੇ (log_ਪੱਧਰ[i].val == level)
			ਵਾਪਸ log_ਪੱਧਰ[i].name;
	ਵਾਪਸ ਨਿਰਾ;
}

ਖਾਲੀ
log_verbose_ਜੋੜੋ(ਅਚਲ ਅੱਖਰ *s)
{
	ਅੱਖਰ **tmp;

	/* Ignore failures here */
	ਜੇ ((tmp = recallocarray(log_verbose, nlog_verbose, nlog_verbose + 1,
	    ਆਕਾਰ(*log_verbose))) != ਨਿਰਾ) {
		log_verbose = tmp;
		ਜੇ ((log_verbose[nlog_verbose] = strdup(s)) != ਨਿਰਾ)
			nlog_verbose++;
	}
}

ਖਾਲੀ
log_verbose_reset(ਖਾਲੀ)
{
	ਮਾਪ_t i;

	ਲਈ (i = 0; i < nlog_verbose; i++)
		ਮੁਕਤ(log_verbose[i]);
	ਮੁਕਤ(log_verbose);
	log_verbose = ਨਿਰਾ;
	nlog_verbose = 0;
}

/*
 * Initialize the log.
 */

ਖਾਲੀ
log_init(ਅਚਲ ਅੱਖਰ *av0, LogLevel level, SyslogFacility facility,
    ਪੂਰਨ on_stderr)
{
#ਜੇ defined(HAVE_OPENLOG_R) && defined(SYSLOG_ਅੰਕੜੇ_INIT)
	ਬਣਤਰ syslog_ਅੰਕੜੇ sdata = SYSLOG_ਅੰਕੜੇ_INIT;
#ਜੇ_ਅੰਤ

	argv0 = av0;

	ਜੇ (log_change_level(level) != 0) {
		fprintf(stderr, "Unrecognized internal syslog level code %d\n",
		    (ਪੂਰਨ) level);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}

	log_handler = ਨਿਰਾ;
	log_handler_ctx = ਨਿਰਾ;

	log_on_stderr = on_stderr;
	ਜੇ (on_stderr)
		ਵਾਪਸ;

	ਚੋਣ (facility) {
	ਹਾਲਤ SYSLOG_FACILITY_DAEMON:
		log_facility = LOG_DAEMON;
		ਰੋਕੋ;
	ਹਾਲਤ SYSLOG_FACILITY_USER:
		log_facility = LOG_USER;
		ਰੋਕੋ;
	ਹਾਲਤ SYSLOG_FACILITY_AUTH:
		log_facility = LOG_AUTH;
		ਰੋਕੋ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LOG_AUTHPRIV
	ਹਾਲਤ SYSLOG_FACILITY_AUTHPRIV:
		log_facility = LOG_AUTHPRIV;
		ਰੋਕੋ;
#ਜੇ_ਅੰਤ
	ਹਾਲਤ SYSLOG_FACILITY_LOCAL0:
		log_facility = LOG_LOCAL0;
		ਰੋਕੋ;
	ਹਾਲਤ SYSLOG_FACILITY_LOCAL1:
		log_facility = LOG_LOCAL1;
		ਰੋਕੋ;
	ਹਾਲਤ SYSLOG_FACILITY_LOCAL2:
		log_facility = LOG_LOCAL2;
		ਰੋਕੋ;
	ਹਾਲਤ SYSLOG_FACILITY_LOCAL3:
		log_facility = LOG_LOCAL3;
		ਰੋਕੋ;
	ਹਾਲਤ SYSLOG_FACILITY_LOCAL4:
		log_facility = LOG_LOCAL4;
		ਰੋਕੋ;
	ਹਾਲਤ SYSLOG_FACILITY_LOCAL5:
		log_facility = LOG_LOCAL5;
		ਰੋਕੋ;
	ਹਾਲਤ SYSLOG_FACILITY_LOCAL6:
		log_facility = LOG_LOCAL6;
		ਰੋਕੋ;
	ਹਾਲਤ SYSLOG_FACILITY_LOCAL7:
		log_facility = LOG_LOCAL7;
		ਰੋਕੋ;
	ਮੂਲ:
		fprintf(stderr,
		    "Unrecognized internal syslog facility code %d\n",
		    (ਪੂਰਨ) facility);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}

	/*
	 * If an external library (eg libwrap) attempts to use syslog
	 * immediately after reexec, syslog may be pointing to the wrong
	 * facility, so we force an open/close of syslog here.
	 */
#ਜੇ defined(HAVE_OPENLOG_R) && defined(SYSLOG_ਅੰਕੜੇ_INIT)
	openlog_r(argv0 ? argv0 : __progname, LOG_PID, log_facility, &sdata);
	closelog_r(&sdata);
#ਨਹੀਂਤਾਂ
	openlog(argv0 ? argv0 : __progname, LOG_PID, log_facility);
	closelog();
#ਜੇ_ਅੰਤ
}

ਪੂਰਨ
log_change_level(LogLevel new_log_level)
{
	/* no-op if log_init has not been called */
	ਜੇ (argv0 == ਨਿਰਾ)
		ਵਾਪਸ 0;

	ਚੋਣ (new_log_level) {
	ਹਾਲਤ SYSLOG_LEVEL_QUIET:
	ਹਾਲਤ SYSLOG_LEVEL_FATAL:
	ਹਾਲਤ SYSLOG_LEVEL_ERROR:
	ਹਾਲਤ SYSLOG_LEVEL_INFO:
	ਹਾਲਤ SYSLOG_LEVEL_VERBOSE:
	ਹਾਲਤ SYSLOG_LEVEL_DEBUG1:
	ਹਾਲਤ SYSLOG_LEVEL_DEBUG2:
	ਹਾਲਤ SYSLOG_LEVEL_DEBUG3:
		log_level = new_log_level;
		ਵਾਪਸ 0;
	ਮੂਲ:
		ਵਾਪਸ -1;
	}
}

ਪੂਰਨ
log_is_on_stderr(ਖਾਲੀ)
{
	ਵਾਪਸ log_on_stderr && log_stderr_fd == STDERR_FILENO;
}

/* redirect what would usually get written to stderr to specified file */
ਖਾਲੀ
log_redirect_stderr_ਮੰਜ਼ਿਲ(ਅਚਲ ਅੱਖਰ *logfile)
{
	ਪੂਰਨ fd;

	ਜੇ (logfile == ਨਿਰਾ) {
		ਜੇ (log_stderr_fd != STDERR_FILENO) {
			close(log_stderr_fd);
			log_stderr_fd = STDERR_FILENO;
		}
		ਵਾਪਸ;
	}

	ਜੇ ((fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1) {
		fprintf(stderr, "Couldn't open logfile %s: %s\n", logfile,
		    strerror(errno));
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	log_stderr_fd = fd;
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MSGBUFSIZ 1024

ਖਾਲੀ
ਸੈੱਟ_log_handler(log_handler_fn *handler, ਖਾਲੀ *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}

ਸਥਿਰ ਖਾਲੀ
do_log(LogLevel level, ਪੂਰਨ force, ਅਚਲ ਅੱਖਰ *suffix, ਅਚਲ ਅੱਖਰ *fmt,
    va_list ਦਲੀਲਾਂ)
{
#ਜੇ defined(HAVE_OPENLOG_R) && defined(SYSLOG_ਅੰਕੜੇ_INIT)
	ਬਣਤਰ syslog_ਅੰਕੜੇ sdata = SYSLOG_ਅੰਕੜੇ_INIT;
#ਜੇ_ਅੰਤ
	ਅੱਖਰ msgbuf[MSGBUFSIZ];
	ਅੱਖਰ fmtbuf[MSGBUFSIZ];
	ਅੱਖਰ *txt = ਨਿਰਾ;
	ਪੂਰਨ pri = LOG_INFO;
	ਪੂਰਨ saved_errno = errno;
	log_handler_fn *tmp_handler;
	ਅਚਲ ਅੱਖਰ *progname = argv0 != ਨਿਰਾ ? argv0 : __progname;

	ਜੇ (!force && level > log_level)
		ਵਾਪਸ;

	ਚੋਣ (level) {
	ਹਾਲਤ SYSLOG_LEVEL_FATAL:
		ਜੇ (!log_on_stderr)
			txt = "fatal";
		pri = LOG_CRIT;
		ਰੋਕੋ;
	ਹਾਲਤ SYSLOG_LEVEL_ERROR:
		ਜੇ (!log_on_stderr)
			txt = "error";
		pri = LOG_ERR;
		ਰੋਕੋ;
	ਹਾਲਤ SYSLOG_LEVEL_INFO:
		pri = LOG_INFO;
		ਰੋਕੋ;
	ਹਾਲਤ SYSLOG_LEVEL_VERBOSE:
		pri = LOG_INFO;
		ਰੋਕੋ;
	ਹਾਲਤ SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		pri = LOG_DEBUG;
		ਰੋਕੋ;
	ਹਾਲਤ SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		pri = LOG_DEBUG;
		ਰੋਕੋ;
	ਹਾਲਤ SYSLOG_LEVEL_DEBUG3:
		txt = "debug3";
		pri = LOG_DEBUG;
		ਰੋਕੋ;
	ਮੂਲ:
		txt = "internal error";
		pri = LOG_ERR;
		ਰੋਕੋ;
	}
	ਜੇ (txt != ਨਿਰਾ && log_handler == ਨਿਰਾ) {
		snprintf(fmtbuf, ਆਕਾਰ(fmtbuf), "%s: %s", txt, fmt);
		vsnprintf(msgbuf, ਆਕਾਰ(msgbuf), fmtbuf, ਦਲੀਲਾਂ);
	} ਨਹੀਂਤਾਂ {
		vsnprintf(msgbuf, ਆਕਾਰ(msgbuf), fmt, ਦਲੀਲਾਂ);
	}
	ਜੇ (suffix != ਨਿਰਾ) {
		snprintf(fmtbuf, ਆਕਾਰ(fmtbuf), "%s: %s", msgbuf, suffix);
		strlcpy(msgbuf, fmtbuf, ਆਕਾਰ(msgbuf));
	}
	strnvis(fmtbuf, msgbuf, ਆਕਾਰ(fmtbuf),
	    log_on_stderr ? LOG_STDERR_VIS : LOG_SYSLOG_VIS);
	ਜੇ (log_handler != ਨਿਰਾ) {
		/* Avoid recursion */
		tmp_handler = log_handler;
		log_handler = ਨਿਰਾ;
		/* Note: this sends the raw (i.e. no strnvis) log message */
		tmp_handler(level, force, msgbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} ਨਹੀਂਤਾਂ ਜੇ (log_on_stderr) {
		snprintf(msgbuf, ਆਕਾਰ msgbuf, "%s%s%.*s\r\n",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (ਪੂਰਨ)ਆਕਾਰ msgbuf - 3, fmtbuf);
		(ਖਾਲੀ)ਲਿਖ(log_stderr_fd, msgbuf, ਲੜੀ_ਲੰਬਾਈ(msgbuf));
	} ਨਹੀਂਤਾਂ {
#ਜੇ defined(HAVE_OPENLOG_R) && defined(SYSLOG_ਅੰਕੜੇ_INIT)
		openlog_r(progname, LOG_PID, log_facility, &sdata);
		syslog_r(pri, &sdata, "%.500s", fmtbuf);
		closelog_r(&sdata);
#ਨਹੀਂਤਾਂ
		openlog(progname, LOG_PID, log_facility);
		syslog(pri, "%.500s", fmtbuf);
		closelog();
#ਜੇ_ਅੰਤ
	}
	errno = saved_errno;
}

ਖਾਲੀ
sshlog(ਅਚਲ ਅੱਖਰ *file, ਅਚਲ ਅੱਖਰ *func, ਪੂਰਨ ਸਤਰ, ਪੂਰਨ showfunc,
    LogLevel level, ਅਚਲ ਅੱਖਰ *suffix, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ਦਲੀਲਾਂ;

	va_start(ਦਲੀਲਾਂ, fmt);
	sshlogv(file, func, ਸਤਰ, showfunc, level, suffix, fmt, ਦਲੀਲਾਂ);
	va_end(ਦਲੀਲਾਂ);
}

ਖਾਲੀ
sshlogdie(ਅਚਲ ਅੱਖਰ *file, ਅਚਲ ਅੱਖਰ *func, ਪੂਰਨ ਸਤਰ, ਪੂਰਨ showfunc,
    LogLevel level, ਅਚਲ ਅੱਖਰ *suffix, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ਦਲੀਲਾਂ;

	va_start(ਦਲੀਲਾਂ, fmt);
	sshlogv(file, func, ਸਤਰ, showfunc, SYSLOG_LEVEL_INFO,
	    suffix, fmt, ਦਲੀਲਾਂ);
	va_end(ਦਲੀਲਾਂ);
	cleanup_exit(255);
}

ਖਾਲੀ
sshlogv(ਅਚਲ ਅੱਖਰ *file, ਅਚਲ ਅੱਖਰ *func, ਪੂਰਨ ਸਤਰ, ਪੂਰਨ showfunc,
    LogLevel level, ਅਚਲ ਅੱਖਰ *suffix, ਅਚਲ ਅੱਖਰ *fmt, va_list ਦਲੀਲਾਂ)
{
	ਅੱਖਰ ਟੈਗ[128], fmt2[MSGBUFSIZ + 128];
	ਪੂਰਨ forced = 0;
	ਅਚਲ ਅੱਖਰ *cp;
	ਮਾਪ_t i;

	/* short circuit processing early if we're not going to log anything */
	ਜੇ (nlog_verbose == 0 && level > log_level)
		ਵਾਪਸ;

	snprintf(ਟੈਗ, ਆਕਾਰ(ਟੈਗ), "%.48s:%.48s():%d (bin=%s, pid=%ld)",
	    (cp = strrchr(file, '/')) == ਨਿਰਾ ? file : cp + 1, func, ਸਤਰ,
	    argv0 == ਨਿਰਾ ? "UNKNOWN" : argv0, (ਲੰਮਾ)getpid());
	ਲਈ (i = 0; i < nlog_verbose; i++) {
		ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list(ਟੈਗ, log_verbose[i], 0) == 1) {
			forced = 1;
			ਰੋਕੋ;
		}
	}

	ਜੇ (forced)
		snprintf(fmt2, ਆਕਾਰ(fmt2), "%s: %s", ਟੈਗ, fmt);
	ਨਹੀਂਤਾਂ ਜੇ (showfunc)
		snprintf(fmt2, ਆਕਾਰ(fmt2), "%s: %s", func, fmt);
	ਨਹੀਂਤਾਂ
		strlcpy(fmt2, fmt, ਆਕਾਰ(fmt2));

	do_log(level, forced, suffix, fmt2, ਦਲੀਲਾਂ);
}

ਖਾਲੀ
sshlogdirect(LogLevel level, ਪੂਰਨ forced, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ਦਲੀਲਾਂ;

	va_start(ਦਲੀਲਾਂ, fmt);
	do_log(level, forced, ਨਿਰਾ, fmt, ਦਲੀਲਾਂ);
	va_end(ਦਲੀਲਾਂ);
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

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ RATELIMIT_DEBUG
# define RLDBG(x) ਕਰੋ { \
		ਲਿਖੋ("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		ਲਿਖੋ x; \
		ਲਿਖੋ("\n"); \
		fflush(stdout); \
	} ਜਦੋਂ (0)
#ਨਹੀਂਤਾਂ
# define RLDBG(x)
#ਜੇ_ਅੰਤ

/* set up a ratelimit */
ਖਾਲੀ
log_ratelimit_init(ਬਣਤਰ log_ratelimit_ctx *rl, u_int ਹੱਦ,
    u_int max_accum, u_int hysteresis, u_int log_every)
{
	memset(rl, 0, ਆਕਾਰ(*rl));
	rl->ਹੱਦ = ਹੱਦ;
	rl->max_accum = max_accum;
	rl->hysteresis = hysteresis;
	rl->log_every = log_every;
	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u",
	    rl, rl->ਹੱਦ, rl->max_accum, rl->hysteresis, rl->log_every));
}

/*
 * check whether a log event should be dropped because of rate-limiting.
 * returns non-zero if the event should be dropped. If events_since_last
 * is supplied then, for periodic logs, it will be set to the number of
 * dropped events since the last message.
 */
ਪੂਰਨ
log_ratelimit(ਬਣਤਰ log_ratelimit_ctx *rl, time_t now, ਪੂਰਨ *ਸਰਗਰਮ,
    u_int *events_dropped)
{
	time_t olast_event;

	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u "
	    "accum=%u since=%ld since_last=%u", rl, rl->ਹੱਦ,
	    rl->max_accum, rl->hysteresis,
	    rl->log_every, rl->accumulated_events,
	    rl->ਆਖਰੀ_event == 0 ? -1 : (ਲੰਮਾ)(now - rl->ਆਖਰੀ_event),
	    rl->ratelimited_events));

	ਜੇ (now < 0)
		ਵਾਪਸ 0;
	ਜੇ (events_dropped != ਨਿਰਾ)
		*events_dropped = 0;
	ਜੇ (ਸਰਗਰਮ != ਨਿਰਾ)
		*ਸਰਗਰਮ = rl->ratelimit_ਸਰਗਰਮ;

	/* First, decay accumulated events */
	ਜੇ (rl->ਆਖਰੀ_event <= 0)
		rl->ਆਖਰੀ_event = now;
	ਜੇ (now > rl->ਆਖਰੀ_event) {
		uint64_t n = now - rl->ਆਖਰੀ_event;

		ਜੇ (n > UINT_MAX)
			n = UINT_MAX;
		ਜੇ (rl->accumulated_events < (u_int)n)
			rl->accumulated_events = 0;
		ਨਹੀਂਤਾਂ
			rl->accumulated_events -= (u_int)n;
		RLDBG(("decay: accum=%u", rl->accumulated_events));
	}
	rl->accumulated_events++; /* add this event */
	ਜੇ (rl->accumulated_events > rl->max_accum)
		rl->accumulated_events = rl->max_accum;
	olast_event = rl->ਆਖਰੀ_event;
	rl->ਆਖਰੀ_event = now;
	RLDBG(("check threshold: accum=%u vs thresh=%u",
	    rl->accumulated_events, rl->ਹੱਦ));

	/* Are we under threshold? */
	ਜੇ (rl->accumulated_events < rl->ਹੱਦ) {
		ਜੇ (!rl->ratelimit_ਸਰਗਰਮ)
			ਵਾਪਸ 0;
		RLDBG(("under threshold: hys=%u since_hys=%ld since_last=%ld",
		    rl->hysteresis, rl->hysteresis_ਸ਼ੁਰੂ == 0 ? -1 :
		    (ਲੰਮਾ)(now - rl->hysteresis_ਸ਼ੁਰੂ),
		    olast_event == 0 ? -1 : (ਲੰਮਾ)(now - olast_event)));
		ਜੇ (rl->hysteresis_ਸ਼ੁਰੂ == 0) {
			/* active, but under threshold; hysteresis */
			ਜੇ (olast_event + rl->hysteresis < now) {
				/* hysteresis expired before this event */
				RLDBG(("hysteresis preexpired"));
				ਜਾਓ inactive;
			}
			RLDBG(("start hysteresis"));
			rl->hysteresis_ਸ਼ੁਰੂ = now;
		} ਨਹੀਂਤਾਂ ਜੇ (rl->hysteresis_ਸ਼ੁਰੂ + rl->hysteresis < now) {
			/* Hysteresis period expired, transition to inactive */
			RLDBG(("complete hysteresis"));
 inactive:
			ਜੇ (events_dropped != ਨਿਰਾ)
				*events_dropped = rl->ratelimited_events;
			ਜੇ (ਸਰਗਰਮ != ਨਿਰਾ)
				*ਸਰਗਰਮ = 0;
			rl->ratelimit_ਸਰਗਰਮ = 0;
			rl->ratelimit_ਸ਼ੁਰੂ = 0;
			rl->ਆਖਰੀ_log = 0;
			rl->hysteresis_ਸ਼ੁਰੂ = 0;
			rl->ratelimited_events = 0;
			ਵਾਪਸ 0;
		}
		/* ratelimiting active, but in hysteresis period */
	} ਨਹੀਂਤਾਂ ਜੇ (!rl->ratelimit_ਸਰਗਰਮ) {
		/* Transition to rate-limiting */
		RLDBG(("start ratelimit"));
		rl->ratelimit_ਸਰਗਰਮ = 1;
		rl->ratelimit_ਸ਼ੁਰੂ = now;
		rl->ਆਖਰੀ_log = now;
		rl->hysteresis_ਸ਼ੁਰੂ = 0;
		rl->ratelimited_events = 1;
		ਜੇ (ਸਰਗਰਮ != ਨਿਰਾ)
			*ਸਰਗਰਮ = 1;
		ਵਾਪਸ 1;
	} ਨਹੀਂਤਾਂ ਜੇ (rl->hysteresis_ਸ਼ੁਰੂ != 0) {
		/* active and over threshold; reset hysteresis timer */
		RLDBG(("clear hysteresis"));
		rl->hysteresis_ਸ਼ੁਰੂ = 0;
	}

	/* over threshold or in hysteresis period; log periodically */
	ਜੇ (ਸਰਗਰਮ != ਨਿਰਾ)
		*ਸਰਗਰਮ = 1;
	RLDBG(("log_every=%u since_log=%ld", rl->log_every,
	    (ਲੰਮਾ)(now - rl->ਆਖਰੀ_log)));
	ਜੇ (rl->log_every > 0 && now >= rl->ਆਖਰੀ_log + rl->log_every) {
		RLDBG(("periodic: since_last=%u", rl->ratelimited_events));
		rl->ਆਖਰੀ_log = now;
		ਜੇ (events_dropped != ਨਿਰਾ) {
			*events_dropped = rl->ratelimited_events;
			rl->ratelimited_events = 0;
		}
		ਵਾਪਸ 0;
	}

	/* drop event */
	rl->ratelimited_events++;
	RLDBG(("drop: ratelimited_events=%u", rl->ratelimited_events));
	ਵਾਪਸ 1;
}
