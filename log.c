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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <syslog.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಯದಿ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "match.h"

ಸ್ಥಿರ LogLevel log_level = SYSLOG_LEVEL_INFO;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ log_on_stderr = 1;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ log_stderr_fd = STDERR_FILENO;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ log_facility = LOG_AUTH;
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *argv0;
ಸ್ಥಿರ log_handler_fn *log_handler;
ಸ್ಥಿರ ಶೂನ್ಯ *log_handler_ctx;
ಸ್ಥಿರ ವರ್ಣ **log_verbose;
ಸ್ಥಿರ size_t nlog_verbose;
ಬಾಹ್ಯ ವರ್ಣ *__progname;

#define LOG_SYSLOG_VIS	(VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL)
#define LOG_STDERR_VIS	(VIS_SAFE|VIS_OCTAL)

/* textual representation of log-facilities/levels */

ಸ್ಥಿರ ಸಂರಚನಾ {
	ಧ್ರುವ ವರ್ಣ *name;
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
	{ ರಿಕ್ತ,		SYSLOG_FACILITY_NOT_SET }
};

ಸ್ಥಿರ ಸಂರಚನಾ {
	ಧ್ರುವ ವರ್ಣ *name;
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
	{ ರಿಕ್ತ,		SYSLOG_LEVEL_NOT_SET }
};

LogLevel
log_level_get(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ log_level;
}

SyslogFacility
log_facility_ಸಂಖ್ಯೆ(ವರ್ಣ *name)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (name != ರಿಕ್ತ)
		ಪ್ರತಿ (i = 0; log_facilities[i].name; i++)
			ಯದಿ (strcasecmp(log_facilities[i].name, name) == 0)
				ಪ್ರತ್ಯಾಗಮ log_facilities[i].val;
	ಪ್ರತ್ಯಾಗಮ SYSLOG_FACILITY_NOT_SET;
}

ಧ್ರುವ ವರ್ಣ *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	ಪ್ರತಿ (i = 0;  log_facilities[i].name; i++)
		ಯದಿ (log_facilities[i].val == facility)
			ಪ್ರತ್ಯಾಗಮ log_facilities[i].name;
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

LogLevel
log_level_ಸಂಖ್ಯೆ(ವರ್ಣ *name)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (name != ರಿಕ್ತ)
		ಪ್ರತಿ (i = 0; log_levels[i].name; i++)
			ಯದಿ (strcasecmp(log_levels[i].name, name) == 0)
				ಪ್ರತ್ಯಾಗಮ log_levels[i].val;
	ಪ್ರತ್ಯಾಗಮ SYSLOG_LEVEL_NOT_SET;
}

ಧ್ರುವ ವರ್ಣ *
log_level_name(LogLevel level)
{
	u_int i;

	ಪ್ರತಿ (i = 0; log_levels[i].name != ರಿಕ್ತ; i++)
		ಯದಿ (log_levels[i].val == level)
			ಪ್ರತ್ಯಾಗಮ log_levels[i].name;
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಶೂನ್ಯ
log_verbose_add(ಧ್ರುವ ವರ್ಣ *s)
{
	ವರ್ಣ **tmp;

	/* Ignore failures here */
	ಯದಿ ((tmp = recallocarray(log_verbose, nlog_verbose, nlog_verbose + 1,
	    ಪರಿಮಾಣ(*log_verbose))) != ರಿಕ್ತ) {
		log_verbose = tmp;
		ಯದಿ ((log_verbose[nlog_verbose] = strdup(s)) != ರಿಕ್ತ)
			nlog_verbose++;
	}
}

ಶೂನ್ಯ
log_verbose_reset(ಶೂನ್ಯ)
{
	size_t i;

	ಪ್ರತಿ (i = 0; i < nlog_verbose; i++)
		ಮುಕ್ತ(log_verbose[i]);
	ಮುಕ್ತ(log_verbose);
	log_verbose = ರಿಕ್ತ;
	nlog_verbose = 0;
}

/*
 * Initialize the log.
 */

ಶೂನ್ಯ
log_init(ಧ್ರುವ ವರ್ಣ *av0, LogLevel level, SyslogFacility facility,
    ಪೂರ್ಣಾಙ್ಕ on_stderr)
{
#ಯದಿ defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	ಸಂರಚನಾ syslog_data sdata = SYSLOG_DATA_INIT;
#endif

	argv0 = av0;

	ಯದಿ (log_change_level(level) != 0) {
		fprintf(stderr, "Unrecognized internal syslog level code %d\n",
		    (ಪೂರ್ಣಾಙ್ಕ) level);
		exit(1);
	}

	log_handler = ರಿಕ್ತ;
	log_handler_ctx = ರಿಕ್ತ;

	log_on_stderr = on_stderr;
	ಯದಿ (on_stderr)
		ಪ್ರತ್ಯಾಗಮ;

	ವಿಕಲ್ಪ (facility) {
	ಪಕ್ಷ SYSLOG_FACILITY_DAEMON:
		log_facility = LOG_DAEMON;
		ಭಙ್ಗ;
	ಪಕ್ಷ SYSLOG_FACILITY_USER:
		log_facility = LOG_USER;
		ಭಙ್ಗ;
	ಪಕ್ಷ SYSLOG_FACILITY_AUTH:
		log_facility = LOG_AUTH;
		ಭಙ್ಗ;
#ifdef LOG_AUTHPRIV
	ಪಕ್ಷ SYSLOG_FACILITY_AUTHPRIV:
		log_facility = LOG_AUTHPRIV;
		ಭಙ್ಗ;
#endif
	ಪಕ್ಷ SYSLOG_FACILITY_LOCAL0:
		log_facility = LOG_LOCAL0;
		ಭಙ್ಗ;
	ಪಕ್ಷ SYSLOG_FACILITY_LOCAL1:
		log_facility = LOG_LOCAL1;
		ಭಙ್ಗ;
	ಪಕ್ಷ SYSLOG_FACILITY_LOCAL2:
		log_facility = LOG_LOCAL2;
		ಭಙ್ಗ;
	ಪಕ್ಷ SYSLOG_FACILITY_LOCAL3:
		log_facility = LOG_LOCAL3;
		ಭಙ್ಗ;
	ಪಕ್ಷ SYSLOG_FACILITY_LOCAL4:
		log_facility = LOG_LOCAL4;
		ಭಙ್ಗ;
	ಪಕ್ಷ SYSLOG_FACILITY_LOCAL5:
		log_facility = LOG_LOCAL5;
		ಭಙ್ಗ;
	ಪಕ್ಷ SYSLOG_FACILITY_LOCAL6:
		log_facility = LOG_LOCAL6;
		ಭಙ್ಗ;
	ಪಕ್ಷ SYSLOG_FACILITY_LOCAL7:
		log_facility = LOG_LOCAL7;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		fprintf(stderr,
		    "Unrecognized internal syslog facility code %d\n",
		    (ಪೂರ್ಣಾಙ್ಕ) facility);
		exit(1);
	}

	/*
	 * If an external library (eg libwrap) attempts to use syslog
	 * immediately after reexec, syslog may be pointing to the wrong
	 * facility, so we force an open/close of syslog here.
	 */
#ಯದಿ defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	openlog_r(argv0 ? argv0 : __progname, LOG_PID, log_facility, &sdata);
	closelog_r(&sdata);
#ಅನ್ಯಥಾ
	openlog(argv0 ? argv0 : __progname, LOG_PID, log_facility);
	closelog();
#endif
}

ಪೂರ್ಣಾಙ್ಕ
log_change_level(LogLevel new_log_level)
{
	/* no-op if log_init has not been called */
	ಯದಿ (argv0 == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;

	ವಿಕಲ್ಪ (new_log_level) {
	ಪಕ್ಷ SYSLOG_LEVEL_QUIET:
	ಪಕ್ಷ SYSLOG_LEVEL_FATAL:
	ಪಕ್ಷ SYSLOG_LEVEL_ERROR:
	ಪಕ್ಷ SYSLOG_LEVEL_INFO:
	ಪಕ್ಷ SYSLOG_LEVEL_VERBOSE:
	ಪಕ್ಷ SYSLOG_LEVEL_DEBUG1:
	ಪಕ್ಷ SYSLOG_LEVEL_DEBUG2:
	ಪಕ್ಷ SYSLOG_LEVEL_DEBUG3:
		log_level = new_log_level;
		ಪ್ರತ್ಯಾಗಮ 0;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ -1;
	}
}

ಪೂರ್ಣಾಙ್ಕ
log_is_on_stderr(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ log_on_stderr && log_stderr_fd == STDERR_FILENO;
}

/* redirect what would usually get written to stderr to specified file */
ಶೂನ್ಯ
log_redirect_stderr_to(ಧ್ರುವ ವರ್ಣ *logfile)
{
	ಪೂರ್ಣಾಙ್ಕ fd;

	ಯದಿ (logfile == ರಿಕ್ತ) {
		ಯದಿ (log_stderr_fd != STDERR_FILENO) {
			close(log_stderr_fd);
			log_stderr_fd = STDERR_FILENO;
		}
		ಪ್ರತ್ಯಾಗಮ;
	}

	ಯದಿ ((fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1) {
		fprintf(stderr, "Couldn't open logfile %s: %s\n", logfile,
		    strerror(errno));
		exit(1);
	}
	log_stderr_fd = fd;
}

#define MSGBUFSIZ 1024

ಶೂನ್ಯ
set_log_handler(log_handler_fn *handler, ಶೂನ್ಯ *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_log(LogLevel level, ಪೂರ್ಣಾಙ್ಕ force, ಧ್ರುವ ವರ್ಣ *suffix, ಧ್ರುವ ವರ್ಣ *fmt,
    va_list args)
{
#ಯದಿ defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	ಸಂರಚನಾ syslog_data sdata = SYSLOG_DATA_INIT;
#endif
	ವರ್ಣ msgbuf[MSGBUFSIZ];
	ವರ್ಣ fmtbuf[MSGBUFSIZ];
	ವರ್ಣ *txt = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ pri = LOG_INFO;
	ಪೂರ್ಣಾಙ್ಕ saved_errno = errno;
	log_handler_fn *tmp_handler;
	ಧ್ರುವ ವರ್ಣ *progname = argv0 != ರಿಕ್ತ ? argv0 : __progname;

	ಯದಿ (!force && level > log_level)
		ಪ್ರತ್ಯಾಗಮ;

	ವಿಕಲ್ಪ (level) {
	ಪಕ್ಷ SYSLOG_LEVEL_FATAL:
		ಯದಿ (!log_on_stderr)
			txt = "fatal";
		pri = LOG_CRIT;
		ಭಙ್ಗ;
	ಪಕ್ಷ SYSLOG_LEVEL_ERROR:
		ಯದಿ (!log_on_stderr)
			txt = "error";
		pri = LOG_ERR;
		ಭಙ್ಗ;
	ಪಕ್ಷ SYSLOG_LEVEL_INFO:
		pri = LOG_INFO;
		ಭಙ್ಗ;
	ಪಕ್ಷ SYSLOG_LEVEL_VERBOSE:
		pri = LOG_INFO;
		ಭಙ್ಗ;
	ಪಕ್ಷ SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		pri = LOG_DEBUG;
		ಭಙ್ಗ;
	ಪಕ್ಷ SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		pri = LOG_DEBUG;
		ಭಙ್ಗ;
	ಪಕ್ಷ SYSLOG_LEVEL_DEBUG3:
		txt = "debug3";
		pri = LOG_DEBUG;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		txt = "internal error";
		pri = LOG_ERR;
		ಭಙ್ಗ;
	}
	ಯದಿ (txt != ರಿಕ್ತ && log_handler == ರಿಕ್ತ) {
		snprintf(fmtbuf, ಪರಿಮಾಣ(fmtbuf), "%s: %s", txt, fmt);
		vsnprintf(msgbuf, ಪರಿಮಾಣ(msgbuf), fmtbuf, args);
	} ಅನ್ಯಥಾ {
		vsnprintf(msgbuf, ಪರಿಮಾಣ(msgbuf), fmt, args);
	}
	ಯದಿ (suffix != ರಿಕ್ತ) {
		snprintf(fmtbuf, ಪರಿಮಾಣ(fmtbuf), "%s: %s", msgbuf, suffix);
		strlcpy(msgbuf, fmtbuf, ಪರಿಮಾಣ(msgbuf));
	}
	strnvis(fmtbuf, msgbuf, ಪರಿಮಾಣ(fmtbuf),
	    log_on_stderr ? LOG_STDERR_VIS : LOG_SYSLOG_VIS);
	ಯದಿ (log_handler != ರಿಕ್ತ) {
		/* Avoid recursion */
		tmp_handler = log_handler;
		log_handler = ರಿಕ್ತ;
		/* Note: this sends the raw (i.e. no strnvis) log message */
		tmp_handler(level, force, msgbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} ಅನ್ಯಥಾ ಯದಿ (log_on_stderr) {
		snprintf(msgbuf, ಪರಿಮಾಣ msgbuf, "%s%s%.*s\r\n",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (ಪೂರ್ಣಾಙ್ಕ)ಪರಿಮಾಣ msgbuf - 3, fmtbuf);
		(ಶೂನ್ಯ)ಲಿಖ(log_stderr_fd, msgbuf, strlen(msgbuf));
	} ಅನ್ಯಥಾ {
#ಯದಿ defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
		openlog_r(progname, LOG_PID, log_facility, &sdata);
		syslog_r(pri, &sdata, "%.500s", fmtbuf);
		closelog_r(&sdata);
#ಅನ್ಯಥಾ
		openlog(progname, LOG_PID, log_facility);
		syslog(pri, "%.500s", fmtbuf);
		closelog();
#endif
	}
	errno = saved_errno;
}

ಶೂನ್ಯ
sshlog(ಧ್ರುವ ವರ್ಣ *file, ಧ್ರುವ ವರ್ಣ *func, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಪೂರ್ಣಾಙ್ಕ showfunc,
    LogLevel level, ಧ್ರುವ ವರ್ಣ *suffix, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, ಸಾಲು, showfunc, level, suffix, fmt, args);
	va_end(args);
}

ಶೂನ್ಯ
sshlogdie(ಧ್ರುವ ವರ್ಣ *file, ಧ್ರುವ ವರ್ಣ *func, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಪೂರ್ಣಾಙ್ಕ showfunc,
    LogLevel level, ಧ್ರುವ ವರ್ಣ *suffix, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, ಸಾಲು, showfunc, SYSLOG_LEVEL_INFO,
	    suffix, fmt, args);
	va_end(args);
	cleanup_exit(255);
}

ಶೂನ್ಯ
sshlogv(ಧ್ರುವ ವರ್ಣ *file, ಧ್ರುವ ವರ್ಣ *func, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಪೂರ್ಣಾಙ್ಕ showfunc,
    LogLevel level, ಧ್ರುವ ವರ್ಣ *suffix, ಧ್ರುವ ವರ್ಣ *fmt, va_list args)
{
	ವರ್ಣ tag[128], fmt2[MSGBUFSIZ + 128];
	ಪೂರ್ಣಾಙ್ಕ forced = 0;
	ಧ್ರುವ ವರ್ಣ *cp;
	size_t i;

	/* short circuit processing early if we're not going to log anything */
	ಯದಿ (nlog_verbose == 0 && level > log_level)
		ಪ್ರತ್ಯಾಗಮ;

	snprintf(tag, ಪರಿಮಾಣ(tag), "%.48s:%.48s():%d (bin=%s, pid=%ld)",
	    (cp = strrchr(file, '/')) == ರಿಕ್ತ ? file : cp + 1, func, ಸಾಲು,
	    argv0 == ರಿಕ್ತ ? "UNKNOWN" : argv0, (long)getpid());
	ಪ್ರತಿ (i = 0; i < nlog_verbose; i++) {
		ಯದಿ (match_pattern_list(tag, log_verbose[i], 0) == 1) {
			forced = 1;
			ಭಙ್ಗ;
		}
	}

	ಯದಿ (forced)
		snprintf(fmt2, ಪರಿಮಾಣ(fmt2), "%s: %s", tag, fmt);
	ಅನ್ಯಥಾ ಯದಿ (showfunc)
		snprintf(fmt2, ಪರಿಮಾಣ(fmt2), "%s: %s", func, fmt);
	ಅನ್ಯಥಾ
		strlcpy(fmt2, fmt, ಪರಿಮಾಣ(fmt2));

	do_log(level, forced, suffix, fmt2, args);
}

ಶೂನ್ಯ
sshlogdirect(LogLevel level, ಪೂರ್ಣಾಙ್ಕ forced, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(level, forced, ರಿಕ್ತ, fmt, args);
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
# define RLDBG(x) ಕುರು { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} ಯಾವತ್ (0)
#ಅನ್ಯಥಾ
# define RLDBG(x)
#endif

/* set up a ratelimit */
ಶೂನ್ಯ
log_ratelimit_init(ಸಂರಚನಾ log_ratelimit_ctx *rl, u_int threshold,
    u_int max_accum, u_int hysteresis, u_int log_every)
{
	memset(rl, 0, ಪರಿಮಾಣ(*rl));
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
ಪೂರ್ಣಾಙ್ಕ
log_ratelimit(ಸಂರಚನಾ log_ratelimit_ctx *rl, time_t now, ಪೂರ್ಣಾಙ್ಕ *active,
    u_int *events_dropped)
{
	time_t olast_event;

	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u "
	    "accum=%u since=%ld since_last=%u", rl, rl->threshold,
	    rl->max_accum, rl->hysteresis,
	    rl->log_every, rl->accumulated_events,
	    rl->last_event == 0 ? -1 : (long)(now - rl->last_event),
	    rl->ratelimited_events));

	ಯದಿ (now < 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (events_dropped != ರಿಕ್ತ)
		*events_dropped = 0;
	ಯದಿ (active != ರಿಕ್ತ)
		*active = rl->ratelimit_active;

	/* First, decay accumulated events */
	ಯದಿ (rl->last_event <= 0)
		rl->last_event = now;
	ಯದಿ (now > rl->last_event) {
		uint64_t n = now - rl->last_event;

		ಯದಿ (n > UINT_MAX)
			n = UINT_MAX;
		ಯದಿ (rl->accumulated_events < (u_int)n)
			rl->accumulated_events = 0;
		ಅನ್ಯಥಾ
			rl->accumulated_events -= (u_int)n;
		RLDBG(("decay: accum=%u", rl->accumulated_events));
	}
	rl->accumulated_events++; /* add this event */
	ಯದಿ (rl->accumulated_events > rl->max_accum)
		rl->accumulated_events = rl->max_accum;
	olast_event = rl->last_event;
	rl->last_event = now;
	RLDBG(("check threshold: accum=%u vs thresh=%u",
	    rl->accumulated_events, rl->threshold));

	/* Are we under threshold? */
	ಯದಿ (rl->accumulated_events < rl->threshold) {
		ಯದಿ (!rl->ratelimit_active)
			ಪ್ರತ್ಯಾಗಮ 0;
		RLDBG(("under threshold: hys=%u since_hys=%ld since_last=%ld",
		    rl->hysteresis, rl->hysteresis_start == 0 ? -1 :
		    (long)(now - rl->hysteresis_start),
		    olast_event == 0 ? -1 : (long)(now - olast_event)));
		ಯದಿ (rl->hysteresis_start == 0) {
			/* active, but under threshold; hysteresis */
			ಯದಿ (olast_event + rl->hysteresis < now) {
				/* hysteresis expired before this event */
				RLDBG(("hysteresis preexpired"));
				ಗಚ್ಛ inactive;
			}
			RLDBG(("start hysteresis"));
			rl->hysteresis_start = now;
		} ಅನ್ಯಥಾ ಯದಿ (rl->hysteresis_start + rl->hysteresis < now) {
			/* Hysteresis period expired, transition to inactive */
			RLDBG(("complete hysteresis"));
 inactive:
			ಯದಿ (events_dropped != ರಿಕ್ತ)
				*events_dropped = rl->ratelimited_events;
			ಯದಿ (active != ರಿಕ್ತ)
				*active = 0;
			rl->ratelimit_active = 0;
			rl->ratelimit_start = 0;
			rl->last_log = 0;
			rl->hysteresis_start = 0;
			rl->ratelimited_events = 0;
			ಪ್ರತ್ಯಾಗಮ 0;
		}
		/* ratelimiting active, but in hysteresis period */
	} ಅನ್ಯಥಾ ಯದಿ (!rl->ratelimit_active) {
		/* Transition to rate-limiting */
		RLDBG(("start ratelimit"));
		rl->ratelimit_active = 1;
		rl->ratelimit_start = now;
		rl->last_log = now;
		rl->hysteresis_start = 0;
		rl->ratelimited_events = 1;
		ಯದಿ (active != ರಿಕ್ತ)
			*active = 1;
		ಪ್ರತ್ಯಾಗಮ 1;
	} ಅನ್ಯಥಾ ಯದಿ (rl->hysteresis_start != 0) {
		/* active and over threshold; reset hysteresis timer */
		RLDBG(("clear hysteresis"));
		rl->hysteresis_start = 0;
	}

	/* over threshold or in hysteresis period; log periodically */
	ಯದಿ (active != ರಿಕ್ತ)
		*active = 1;
	RLDBG(("log_every=%u since_log=%ld", rl->log_every,
	    (long)(now - rl->last_log)));
	ಯದಿ (rl->log_every > 0 && now >= rl->last_log + rl->log_every) {
		RLDBG(("periodic: since_last=%u", rl->ratelimited_events));
		rl->last_log = now;
		ಯದಿ (events_dropped != ರಿಕ್ತ) {
			*events_dropped = rl->ratelimited_events;
			rl->ratelimited_events = 0;
		}
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	/* drop event */
	rl->ratelimited_events++;
	RLDBG(("drop: ratelimited_events=%u", rl->ratelimited_events));
	ಪ್ರತ್ಯಾಗಮ 1;
}
