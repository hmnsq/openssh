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
#ಆದರೆ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "match.h"

ಸ್ಥಿರ LogLevel log_level = SYSLOG_LEVEL_INFO;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ log_on_stderr = 1;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ log_stderr_fd = STDERR_FILENO;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ log_facility = LOG_AUTH;
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *argv0;
ಸ್ಥಿರ log_handler_fn *log_handler;
ಸ್ಥಿರ ಶೂನ್ಯ *log_handler_ctx;
ಸ್ಥಿರ ಅಕ್ಷರ **log_verbose;
ಸ್ಥಿರ ಗಾತ್ರ_t nlog_verbose;
ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

#ವ್ಯಾಖ್ಯಾನಿಸು LOG_SYSLOG_VIS	(VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL)
#ವ್ಯಾಖ್ಯಾನಿಸು LOG_STDERR_VIS	(VIS_ಸುರಕ್ಷಿತ|VIS_OCTAL)

/* textual representation of log-facilities/levels */

ಸ್ಥಿರ ರಚನೆ {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name;
	SyslogFacility val;
} log_facilities[] = {
	{ "DAEMON",	SYSLOG_FACILITY_DAEMON },
	{ "USER",	SYSLOG_FACILITY_USER },
	{ "AUTH",	SYSLOG_FACILITY_AUTH },
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ LOG_AUTHPRIV
	{ "AUTHPRIV",	SYSLOG_FACILITY_AUTHPRIV },
#ಆದರೆ_ಅಂತ್ಯ
	{ "LOCAL0",	SYSLOG_FACILITY_LOCAL0 },
	{ "LOCAL1",	SYSLOG_FACILITY_LOCAL1 },
	{ "LOCAL2",	SYSLOG_FACILITY_LOCAL2 },
	{ "LOCAL3",	SYSLOG_FACILITY_LOCAL3 },
	{ "LOCAL4",	SYSLOG_FACILITY_LOCAL4 },
	{ "LOCAL5",	SYSLOG_FACILITY_LOCAL5 },
	{ "LOCAL6",	SYSLOG_FACILITY_LOCAL6 },
	{ "LOCAL7",	SYSLOG_FACILITY_LOCAL7 },
	{ ಖಾಲಿ,		SYSLOG_FACILITY_NOT_ಗಣ }
};

ಸ್ಥಿರ ರಚನೆ {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name;
	LogLevel val;
} log_ಮಟ್ಟಗಳು[] =
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
	{ ಖಾಲಿ,		SYSLOG_LEVEL_NOT_ಗಣ }
};

LogLevel
log_level_get(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ log_level;
}

SyslogFacility
log_facility_ಸಂಖ್ಯೆ(ಅಕ್ಷರ *name)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (name != ಖಾಲಿ)
		ಗಾಗಿ (i = 0; log_facilities[i].name; i++)
			ಆದರೆ (strcasecmp(log_facilities[i].name, name) == 0)
				ಹಿಂತಿರುಗಿ log_facilities[i].val;
	ಹಿಂತಿರುಗಿ SYSLOG_FACILITY_NOT_ಗಣ;
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	ಗಾಗಿ (i = 0;  log_facilities[i].name; i++)
		ಆದರೆ (log_facilities[i].val == facility)
			ಹಿಂತಿರುಗಿ log_facilities[i].name;
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

LogLevel
log_level_ಸಂಖ್ಯೆ(ಅಕ್ಷರ *name)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (name != ಖಾಲಿ)
		ಗಾಗಿ (i = 0; log_ಮಟ್ಟಗಳು[i].name; i++)
			ಆದರೆ (strcasecmp(log_ಮಟ್ಟಗಳು[i].name, name) == 0)
				ಹಿಂತಿರುಗಿ log_ಮಟ್ಟಗಳು[i].val;
	ಹಿಂತಿರುಗಿ SYSLOG_LEVEL_NOT_ಗಣ;
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
log_level_name(LogLevel level)
{
	u_int i;

	ಗಾಗಿ (i = 0; log_ಮಟ್ಟಗಳು[i].name != ಖಾಲಿ; i++)
		ಆದರೆ (log_ಮಟ್ಟಗಳು[i].val == level)
			ಹಿಂತಿರುಗಿ log_ಮಟ್ಟಗಳು[i].name;
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಶೂನ್ಯ
log_verbose_ಕೂಡಿಸು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	ಅಕ್ಷರ **tmp;

	/* Ignore failures here */
	ಆದರೆ ((tmp = recallocarray(log_verbose, nlog_verbose, nlog_verbose + 1,
	    ಗಾತ್ರ(*log_verbose))) != ಖಾಲಿ) {
		log_verbose = tmp;
		ಆದರೆ ((log_verbose[nlog_verbose] = strdup(s)) != ಖಾಲಿ)
			nlog_verbose++;
	}
}

ಶೂನ್ಯ
log_verbose_reset(ಶೂನ್ಯ)
{
	ಗಾತ್ರ_t i;

	ಗಾಗಿ (i = 0; i < nlog_verbose; i++)
		ಬಿಡುಗಡೆ(log_verbose[i]);
	ಬಿಡುಗಡೆ(log_verbose);
	log_verbose = ಖಾಲಿ;
	nlog_verbose = 0;
}

/*
 * Initialize the log.
 */

ಶೂನ್ಯ
log_init(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *av0, LogLevel level, SyslogFacility facility,
    ಪೂರ್ಣಾಂಕ on_stderr)
{
#ಆದರೆ defined(HAVE_OPENLOG_R) && defined(SYSLOG_ದತ್ತಾಂಶ_INIT)
	ರಚನೆ syslog_ದತ್ತಾಂಶ sdata = SYSLOG_ದತ್ತಾಂಶ_INIT;
#ಆದರೆ_ಅಂತ್ಯ

	argv0 = av0;

	ಆದರೆ (log_change_level(level) != 0) {
		fprintf(stderr, "Unrecognized internal syslog level code %d\n",
		    (ಪೂರ್ಣಾಂಕ) level);
		ನಿರ್ಗಮಿಸು(1);
	}

	log_handler = ಖಾಲಿ;
	log_handler_ctx = ಖಾಲಿ;

	log_on_stderr = on_stderr;
	ಆದರೆ (on_stderr)
		ಹಿಂತಿರುಗಿ;

	ಆಯ್ಕೆ (facility) {
	ಸ್ಥಿತಿ SYSLOG_FACILITY_DAEMON:
		log_facility = LOG_DAEMON;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SYSLOG_FACILITY_USER:
		log_facility = LOG_USER;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SYSLOG_FACILITY_AUTH:
		log_facility = LOG_AUTH;
		ನಿಲ್ಲಿಸು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ LOG_AUTHPRIV
	ಸ್ಥಿತಿ SYSLOG_FACILITY_AUTHPRIV:
		log_facility = LOG_AUTHPRIV;
		ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ
	ಸ್ಥಿತಿ SYSLOG_FACILITY_LOCAL0:
		log_facility = LOG_LOCAL0;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SYSLOG_FACILITY_LOCAL1:
		log_facility = LOG_LOCAL1;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SYSLOG_FACILITY_LOCAL2:
		log_facility = LOG_LOCAL2;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SYSLOG_FACILITY_LOCAL3:
		log_facility = LOG_LOCAL3;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SYSLOG_FACILITY_LOCAL4:
		log_facility = LOG_LOCAL4;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SYSLOG_FACILITY_LOCAL5:
		log_facility = LOG_LOCAL5;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SYSLOG_FACILITY_LOCAL6:
		log_facility = LOG_LOCAL6;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SYSLOG_FACILITY_LOCAL7:
		log_facility = LOG_LOCAL7;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fprintf(stderr,
		    "Unrecognized internal syslog facility code %d\n",
		    (ಪೂರ್ಣಾಂಕ) facility);
		ನಿರ್ಗಮಿಸು(1);
	}

	/*
	 * If an external library (eg libwrap) attempts to use syslog
	 * immediately after reexec, syslog may be pointing to the wrong
	 * facility, so we force an open/close of syslog here.
	 */
#ಆದರೆ defined(HAVE_OPENLOG_R) && defined(SYSLOG_ದತ್ತಾಂಶ_INIT)
	openlog_r(argv0 ? argv0 : __progname, LOG_PID, log_facility, &sdata);
	closelog_r(&sdata);
#ಇಲ್ಲದಿದ್ದರೆ
	openlog(argv0 ? argv0 : __progname, LOG_PID, log_facility);
	closelog();
#ಆದರೆ_ಅಂತ್ಯ
}

ಪೂರ್ಣಾಂಕ
log_change_level(LogLevel new_log_level)
{
	/* no-op if log_init has not been called */
	ಆದರೆ (argv0 == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;

	ಆಯ್ಕೆ (new_log_level) {
	ಸ್ಥಿತಿ SYSLOG_LEVEL_QUIET:
	ಸ್ಥಿತಿ SYSLOG_LEVEL_FATAL:
	ಸ್ಥಿತಿ SYSLOG_LEVEL_ERROR:
	ಸ್ಥಿತಿ SYSLOG_LEVEL_INFO:
	ಸ್ಥಿತಿ SYSLOG_LEVEL_VERBOSE:
	ಸ್ಥಿತಿ SYSLOG_LEVEL_DEBUG1:
	ಸ್ಥಿತಿ SYSLOG_LEVEL_DEBUG2:
	ಸ್ಥಿತಿ SYSLOG_LEVEL_DEBUG3:
		log_level = new_log_level;
		ಹಿಂತಿರುಗಿ 0;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ -1;
	}
}

ಪೂರ್ಣಾಂಕ
log_is_on_stderr(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ log_on_stderr && log_stderr_fd == STDERR_FILENO;
}

/* redirect what would usually get written to stderr to specified file */
ಶೂನ್ಯ
log_redirect_stderr_ಗಮ್ಯ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *logfile)
{
	ಪೂರ್ಣಾಂಕ fd;

	ಆದರೆ (logfile == ಖಾಲಿ) {
		ಆದರೆ (log_stderr_fd != STDERR_FILENO) {
			close(log_stderr_fd);
			log_stderr_fd = STDERR_FILENO;
		}
		ಹಿಂತಿರುಗಿ;
	}

	ಆದರೆ ((fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1) {
		fprintf(stderr, "Couldn't open logfile %s: %s\n", logfile,
		    strerror(errno));
		ನಿರ್ಗಮಿಸು(1);
	}
	log_stderr_fd = fd;
}

#ವ್ಯಾಖ್ಯಾನಿಸು MSGBUFSIZ 1024

ಶೂನ್ಯ
ಗಣ_log_handler(log_handler_fn *handler, ಶೂನ್ಯ *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_log(LogLevel level, ಪೂರ್ಣಾಂಕ force, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *suffix, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt,
    va_list ವಾದಗಳು)
{
#ಆದರೆ defined(HAVE_OPENLOG_R) && defined(SYSLOG_ದತ್ತಾಂಶ_INIT)
	ರಚನೆ syslog_ದತ್ತಾಂಶ sdata = SYSLOG_ದತ್ತಾಂಶ_INIT;
#ಆದರೆ_ಅಂತ್ಯ
	ಅಕ್ಷರ msgbuf[MSGBUFSIZ];
	ಅಕ್ಷರ fmtbuf[MSGBUFSIZ];
	ಅಕ್ಷರ *txt = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ pri = LOG_INFO;
	ಪೂರ್ಣಾಂಕ saved_errno = errno;
	log_handler_fn *tmp_handler;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *progname = argv0 != ಖಾಲಿ ? argv0 : __progname;

	ಆದರೆ (!force && level > log_level)
		ಹಿಂತಿರುಗಿ;

	ಆಯ್ಕೆ (level) {
	ಸ್ಥಿತಿ SYSLOG_LEVEL_FATAL:
		ಆದರೆ (!log_on_stderr)
			txt = "fatal";
		pri = LOG_CRIT;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SYSLOG_LEVEL_ERROR:
		ಆದರೆ (!log_on_stderr)
			txt = "error";
		pri = LOG_ERR;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SYSLOG_LEVEL_INFO:
		pri = LOG_INFO;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SYSLOG_LEVEL_VERBOSE:
		pri = LOG_INFO;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		pri = LOG_DEBUG;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		pri = LOG_DEBUG;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SYSLOG_LEVEL_DEBUG3:
		txt = "debug3";
		pri = LOG_DEBUG;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		txt = "internal error";
		pri = LOG_ERR;
		ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (txt != ಖಾಲಿ && log_handler == ಖಾಲಿ) {
		snprintf(fmtbuf, ಗಾತ್ರ(fmtbuf), "%s: %s", txt, fmt);
		vsnprintf(msgbuf, ಗಾತ್ರ(msgbuf), fmtbuf, ವಾದಗಳು);
	} ಇಲ್ಲದಿದ್ದರೆ {
		vsnprintf(msgbuf, ಗಾತ್ರ(msgbuf), fmt, ವಾದಗಳು);
	}
	ಆದರೆ (suffix != ಖಾಲಿ) {
		snprintf(fmtbuf, ಗಾತ್ರ(fmtbuf), "%s: %s", msgbuf, suffix);
		strlcpy(msgbuf, fmtbuf, ಗಾತ್ರ(msgbuf));
	}
	strnvis(fmtbuf, msgbuf, ಗಾತ್ರ(fmtbuf),
	    log_on_stderr ? LOG_STDERR_VIS : LOG_SYSLOG_VIS);
	ಆದರೆ (log_handler != ಖಾಲಿ) {
		/* Avoid recursion */
		tmp_handler = log_handler;
		log_handler = ಖಾಲಿ;
		/* Note: this sends the raw (i.e. no strnvis) log message */
		tmp_handler(level, force, msgbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (log_on_stderr) {
		snprintf(msgbuf, ಗಾತ್ರ msgbuf, "%s%s%.*s\r\n",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (ಪೂರ್ಣಾಂಕ)ಗಾತ್ರ msgbuf - 3, fmtbuf);
		(ಶೂನ್ಯ)ಲಿಖ(log_stderr_fd, msgbuf, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(msgbuf));
	} ಇಲ್ಲದಿದ್ದರೆ {
#ಆದರೆ defined(HAVE_OPENLOG_R) && defined(SYSLOG_ದತ್ತಾಂಶ_INIT)
		openlog_r(progname, LOG_PID, log_facility, &sdata);
		syslog_r(pri, &sdata, "%.500s", fmtbuf);
		closelog_r(&sdata);
#ಇಲ್ಲದಿದ್ದರೆ
		openlog(progname, LOG_PID, log_facility);
		syslog(pri, "%.500s", fmtbuf);
		closelog();
#ಆದರೆ_ಅಂತ್ಯ
	}
	errno = saved_errno;
}

ಶೂನ್ಯ
sshlog(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *func, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಪೂರ್ಣಾಂಕ showfunc,
    LogLevel level, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *suffix, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list ವಾದಗಳು;

	va_start(ವಾದಗಳು, fmt);
	sshlogv(file, func, ಸಾಲು, showfunc, level, suffix, fmt, ವಾದಗಳು);
	va_end(ವಾದಗಳು);
}

ಶೂನ್ಯ
sshlogdie(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *func, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಪೂರ್ಣಾಂಕ showfunc,
    LogLevel level, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *suffix, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list ವಾದಗಳು;

	va_start(ವಾದಗಳು, fmt);
	sshlogv(file, func, ಸಾಲು, showfunc, SYSLOG_LEVEL_INFO,
	    suffix, fmt, ವಾದಗಳು);
	va_end(ವಾದಗಳು);
	cleanup_exit(255);
}

ಶೂನ್ಯ
sshlogv(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *func, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಪೂರ್ಣಾಂಕ showfunc,
    LogLevel level, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *suffix, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, va_list ವಾದಗಳು)
{
	ಅಕ್ಷರ ಟ್ಯಾಗ್[128], fmt2[MSGBUFSIZ + 128];
	ಪೂರ್ಣಾಂಕ forced = 0;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cp;
	ಗಾತ್ರ_t i;

	/* short circuit processing early if we're not going to log anything */
	ಆದರೆ (nlog_verbose == 0 && level > log_level)
		ಹಿಂತಿರುಗಿ;

	snprintf(ಟ್ಯಾಗ್, ಗಾತ್ರ(ಟ್ಯಾಗ್), "%.48s:%.48s():%d (bin=%s, pid=%ld)",
	    (cp = strrchr(file, '/')) == ಖಾಲಿ ? file : cp + 1, func, ಸಾಲು,
	    argv0 == ಖಾಲಿ ? "UNKNOWN" : argv0, (ದೀರ್ಘ)getpid());
	ಗಾಗಿ (i = 0; i < nlog_verbose; i++) {
		ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list(ಟ್ಯಾಗ್, log_verbose[i], 0) == 1) {
			forced = 1;
			ನಿಲ್ಲಿಸು;
		}
	}

	ಆದರೆ (forced)
		snprintf(fmt2, ಗಾತ್ರ(fmt2), "%s: %s", ಟ್ಯಾಗ್, fmt);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (showfunc)
		snprintf(fmt2, ಗಾತ್ರ(fmt2), "%s: %s", func, fmt);
	ಇಲ್ಲದಿದ್ದರೆ
		strlcpy(fmt2, fmt, ಗಾತ್ರ(fmt2));

	do_log(level, forced, suffix, fmt2, ವಾದಗಳು);
}

ಶೂನ್ಯ
sshlogdirect(LogLevel level, ಪೂರ್ಣಾಂಕ forced, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list ವಾದಗಳು;

	va_start(ವಾದಗಳು, fmt);
	do_log(level, forced, ಖಾಲಿ, fmt, ವಾದಗಳು);
	va_end(ವಾದಗಳು);
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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ RATELIMIT_DEBUG
# define RLDBG(x) ಮಾಡು { \
		ಬರೆ("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		ಬರೆ x; \
		ಬರೆ("\n"); \
		fflush(stdout); \
	} ಆಗ (0)
#ಇಲ್ಲದಿದ್ದರೆ
# define RLDBG(x)
#ಆದರೆ_ಅಂತ್ಯ

/* set up a ratelimit */
ಶೂನ್ಯ
log_ratelimit_init(ರಚನೆ log_ratelimit_ctx *rl, u_int ಮಿತಿ,
    u_int max_accum, u_int hysteresis, u_int log_every)
{
	memset(rl, 0, ಗಾತ್ರ(*rl));
	rl->ಮಿತಿ = ಮಿತಿ;
	rl->max_accum = max_accum;
	rl->hysteresis = hysteresis;
	rl->log_every = log_every;
	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u",
	    rl, rl->ಮಿತಿ, rl->max_accum, rl->hysteresis, rl->log_every));
}

/*
 * check whether a log event should be dropped because of rate-limiting.
 * returns non-zero if the event should be dropped. If events_since_last
 * is supplied then, for periodic logs, it will be set to the number of
 * dropped events since the last message.
 */
ಪೂರ್ಣಾಂಕ
log_ratelimit(ರಚನೆ log_ratelimit_ctx *rl, time_t now, ಪೂರ್ಣಾಂಕ *ಸಕ್ರಿಯ,
    u_int *events_dropped)
{
	time_t olast_event;

	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u "
	    "accum=%u since=%ld since_last=%u", rl, rl->ಮಿತಿ,
	    rl->max_accum, rl->hysteresis,
	    rl->log_every, rl->accumulated_events,
	    rl->ಕೊನೆಯ_event == 0 ? -1 : (ದೀರ್ಘ)(now - rl->ಕೊನೆಯ_event),
	    rl->ratelimited_events));

	ಆದರೆ (now < 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (events_dropped != ಖಾಲಿ)
		*events_dropped = 0;
	ಆದರೆ (ಸಕ್ರಿಯ != ಖಾಲಿ)
		*ಸಕ್ರಿಯ = rl->ratelimit_ಸಕ್ರಿಯ;

	/* First, decay accumulated events */
	ಆದರೆ (rl->ಕೊನೆಯ_event <= 0)
		rl->ಕೊನೆಯ_event = now;
	ಆದರೆ (now > rl->ಕೊನೆಯ_event) {
		uint64_t n = now - rl->ಕೊನೆಯ_event;

		ಆದರೆ (n > UINT_MAX)
			n = UINT_MAX;
		ಆದರೆ (rl->accumulated_events < (u_int)n)
			rl->accumulated_events = 0;
		ಇಲ್ಲದಿದ್ದರೆ
			rl->accumulated_events -= (u_int)n;
		RLDBG(("decay: accum=%u", rl->accumulated_events));
	}
	rl->accumulated_events++; /* add this event */
	ಆದರೆ (rl->accumulated_events > rl->max_accum)
		rl->accumulated_events = rl->max_accum;
	olast_event = rl->ಕೊನೆಯ_event;
	rl->ಕೊನೆಯ_event = now;
	RLDBG(("check threshold: accum=%u vs thresh=%u",
	    rl->accumulated_events, rl->ಮಿತಿ));

	/* Are we under threshold? */
	ಆದರೆ (rl->accumulated_events < rl->ಮಿತಿ) {
		ಆದರೆ (!rl->ratelimit_ಸಕ್ರಿಯ)
			ಹಿಂತಿರುಗಿ 0;
		RLDBG(("under threshold: hys=%u since_hys=%ld since_last=%ld",
		    rl->hysteresis, rl->hysteresis_ಆರಂಭ == 0 ? -1 :
		    (ದೀರ್ಘ)(now - rl->hysteresis_ಆರಂಭ),
		    olast_event == 0 ? -1 : (ದೀರ್ಘ)(now - olast_event)));
		ಆದರೆ (rl->hysteresis_ಆರಂಭ == 0) {
			/* active, but under threshold; hysteresis */
			ಆದರೆ (olast_event + rl->hysteresis < now) {
				/* hysteresis expired before this event */
				RLDBG(("hysteresis preexpired"));
				ಹೋಗು inactive;
			}
			RLDBG(("start hysteresis"));
			rl->hysteresis_ಆರಂಭ = now;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (rl->hysteresis_ಆರಂಭ + rl->hysteresis < now) {
			/* Hysteresis period expired, transition to inactive */
			RLDBG(("complete hysteresis"));
 inactive:
			ಆದರೆ (events_dropped != ಖಾಲಿ)
				*events_dropped = rl->ratelimited_events;
			ಆದರೆ (ಸಕ್ರಿಯ != ಖಾಲಿ)
				*ಸಕ್ರಿಯ = 0;
			rl->ratelimit_ಸಕ್ರಿಯ = 0;
			rl->ratelimit_ಆರಂಭ = 0;
			rl->ಕೊನೆಯ_log = 0;
			rl->hysteresis_ಆರಂಭ = 0;
			rl->ratelimited_events = 0;
			ಹಿಂತಿರುಗಿ 0;
		}
		/* ratelimiting active, but in hysteresis period */
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!rl->ratelimit_ಸಕ್ರಿಯ) {
		/* Transition to rate-limiting */
		RLDBG(("start ratelimit"));
		rl->ratelimit_ಸಕ್ರಿಯ = 1;
		rl->ratelimit_ಆರಂಭ = now;
		rl->ಕೊನೆಯ_log = now;
		rl->hysteresis_ಆರಂಭ = 0;
		rl->ratelimited_events = 1;
		ಆದರೆ (ಸಕ್ರಿಯ != ಖಾಲಿ)
			*ಸಕ್ರಿಯ = 1;
		ಹಿಂತಿರುಗಿ 1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (rl->hysteresis_ಆರಂಭ != 0) {
		/* active and over threshold; reset hysteresis timer */
		RLDBG(("clear hysteresis"));
		rl->hysteresis_ಆರಂಭ = 0;
	}

	/* over threshold or in hysteresis period; log periodically */
	ಆದರೆ (ಸಕ್ರಿಯ != ಖಾಲಿ)
		*ಸಕ್ರಿಯ = 1;
	RLDBG(("log_every=%u since_log=%ld", rl->log_every,
	    (ದೀರ್ಘ)(now - rl->ಕೊನೆಯ_log)));
	ಆದರೆ (rl->log_every > 0 && now >= rl->ಕೊನೆಯ_log + rl->log_every) {
		RLDBG(("periodic: since_last=%u", rl->ratelimited_events));
		rl->ಕೊನೆಯ_log = now;
		ಆದರೆ (events_dropped != ಖಾಲಿ) {
			*events_dropped = rl->ratelimited_events;
			rl->ratelimited_events = 0;
		}
		ಹಿಂತಿರುಗಿ 0;
	}

	/* drop event */
	rl->ratelimited_events++;
	RLDBG(("drop: ratelimited_events=%u", rl->ratelimited_events));
	ಹಿಂತಿರುಗಿ 1;
}
