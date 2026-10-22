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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <limits.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <syslog.h>
#समावेश <unistd.h>
#अगर defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#पूर्ण_अगर

#समावेश "log.h"
#समावेश "match.h"

अटल LogLevel log_level = SYSLOG_LEVEL_INFO;
अटल पूर्णांक log_on_stderr = 1;
अटल पूर्णांक log_stderr_fd = STDERR_FILENO;
अटल पूर्णांक log_facility = LOG_AUTH;
अटल स्थिर अक्षर *argv0;
अटल log_handler_fn *log_handler;
अटल व्योम *log_handler_ctx;
अटल अक्षर **log_verbose;
अटल माप_प्रकार nlog_verbose;
बाह्य अक्षर *__progname;

#घोषणा LOG_SYSLOG_VIS	(VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL)
#घोषणा LOG_STDERR_VIS	(VIS_SAFE|VIS_OCTAL)

/* textual representation of log-facilities/levels */

अटल काष्ठा {
	स्थिर अक्षर *name;
	SyslogFacility val;
} log_facilities[] = {
	{ "DAEMON",	SYSLOG_FACILITY_DAEMON },
	{ "USER",	SYSLOG_FACILITY_USER },
	{ "AUTH",	SYSLOG_FACILITY_AUTH },
#अगर_घोषित LOG_AUTHPRIV
	{ "AUTHPRIV",	SYSLOG_FACILITY_AUTHPRIV },
#पूर्ण_अगर
	{ "LOCAL0",	SYSLOG_FACILITY_LOCAL0 },
	{ "LOCAL1",	SYSLOG_FACILITY_LOCAL1 },
	{ "LOCAL2",	SYSLOG_FACILITY_LOCAL2 },
	{ "LOCAL3",	SYSLOG_FACILITY_LOCAL3 },
	{ "LOCAL4",	SYSLOG_FACILITY_LOCAL4 },
	{ "LOCAL5",	SYSLOG_FACILITY_LOCAL5 },
	{ "LOCAL6",	SYSLOG_FACILITY_LOCAL6 },
	{ "LOCAL7",	SYSLOG_FACILITY_LOCAL7 },
	{ शून्य,		SYSLOG_FACILITY_NOT_SET }
};

अटल काष्ठा {
	स्थिर अक्षर *name;
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
	{ शून्य,		SYSLOG_LEVEL_NOT_SET }
};

LogLevel
log_level_get(व्योम)
{
	वापस log_level;
}

SyslogFacility
log_facility_संख्या(अक्षर *name)
{
	पूर्णांक i;

	अगर (name != शून्य)
		क्रम (i = 0; log_facilities[i].name; i++)
			अगर (strcasecmp(log_facilities[i].name, name) == 0)
				वापस log_facilities[i].val;
	वापस SYSLOG_FACILITY_NOT_SET;
}

स्थिर अक्षर *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	क्रम (i = 0;  log_facilities[i].name; i++)
		अगर (log_facilities[i].val == facility)
			वापस log_facilities[i].name;
	वापस शून्य;
}

LogLevel
log_level_संख्या(अक्षर *name)
{
	पूर्णांक i;

	अगर (name != शून्य)
		क्रम (i = 0; log_levels[i].name; i++)
			अगर (strcasecmp(log_levels[i].name, name) == 0)
				वापस log_levels[i].val;
	वापस SYSLOG_LEVEL_NOT_SET;
}

स्थिर अक्षर *
log_level_name(LogLevel level)
{
	u_int i;

	क्रम (i = 0; log_levels[i].name != शून्य; i++)
		अगर (log_levels[i].val == level)
			वापस log_levels[i].name;
	वापस शून्य;
}

व्योम
log_verbose_add(स्थिर अक्षर *s)
{
	अक्षर **tmp;

	/* Ignore failures here */
	अगर ((tmp = recallocarray(log_verbose, nlog_verbose, nlog_verbose + 1,
	    माप(*log_verbose))) != शून्य) {
		log_verbose = tmp;
		अगर ((log_verbose[nlog_verbose] = strdup(s)) != शून्य)
			nlog_verbose++;
	}
}

व्योम
log_verbose_reset(व्योम)
{
	माप_प्रकार i;

	क्रम (i = 0; i < nlog_verbose; i++)
		मुक्त(log_verbose[i]);
	मुक्त(log_verbose);
	log_verbose = शून्य;
	nlog_verbose = 0;
}

/*
 * Initialize the log.
 */

व्योम
log_init(स्थिर अक्षर *av0, LogLevel level, SyslogFacility facility,
    पूर्णांक on_stderr)
{
#अगर defined(HAVE_OPENLOG_R) && defined(SYSLOG_तथ्य_INIT)
	काष्ठा syslog_तथ्य sdata = SYSLOG_तथ्य_INIT;
#पूर्ण_अगर

	argv0 = av0;

	अगर (log_change_level(level) != 0) {
		ख_लिखो(मानक_त्रुटि, "Unrecognized internal syslog level code %d\n",
		    (पूर्णांक) level);
		निकास(1);
	}

	log_handler = शून्य;
	log_handler_ctx = शून्य;

	log_on_stderr = on_stderr;
	अगर (on_stderr)
		वापस;

	चयन (facility) {
	हाल SYSLOG_FACILITY_DAEMON:
		log_facility = LOG_DAEMON;
		अवरोध;
	हाल SYSLOG_FACILITY_USER:
		log_facility = LOG_USER;
		अवरोध;
	हाल SYSLOG_FACILITY_AUTH:
		log_facility = LOG_AUTH;
		अवरोध;
#अगर_घोषित LOG_AUTHPRIV
	हाल SYSLOG_FACILITY_AUTHPRIV:
		log_facility = LOG_AUTHPRIV;
		अवरोध;
#पूर्ण_अगर
	हाल SYSLOG_FACILITY_LOCAL0:
		log_facility = LOG_LOCAL0;
		अवरोध;
	हाल SYSLOG_FACILITY_LOCAL1:
		log_facility = LOG_LOCAL1;
		अवरोध;
	हाल SYSLOG_FACILITY_LOCAL2:
		log_facility = LOG_LOCAL2;
		अवरोध;
	हाल SYSLOG_FACILITY_LOCAL3:
		log_facility = LOG_LOCAL3;
		अवरोध;
	हाल SYSLOG_FACILITY_LOCAL4:
		log_facility = LOG_LOCAL4;
		अवरोध;
	हाल SYSLOG_FACILITY_LOCAL5:
		log_facility = LOG_LOCAL5;
		अवरोध;
	हाल SYSLOG_FACILITY_LOCAL6:
		log_facility = LOG_LOCAL6;
		अवरोध;
	हाल SYSLOG_FACILITY_LOCAL7:
		log_facility = LOG_LOCAL7;
		अवरोध;
	शेष:
		ख_लिखो(मानक_त्रुटि,
		    "Unrecognized internal syslog facility code %d\n",
		    (पूर्णांक) facility);
		निकास(1);
	}

	/*
	 * If an external library (eg libwrap) attempts to use syslog
	 * immediately after reexec, syslog may be pointing to the wrong
	 * facility, so we force an open/close of syslog here.
	 */
#अगर defined(HAVE_OPENLOG_R) && defined(SYSLOG_तथ्य_INIT)
	openlog_r(argv0 ? argv0 : __progname, LOG_PID, log_facility, &sdata);
	closelog_r(&sdata);
#अन्यथा
	openlog(argv0 ? argv0 : __progname, LOG_PID, log_facility);
	closelog();
#पूर्ण_अगर
}

पूर्णांक
log_change_level(LogLevel new_log_level)
{
	/* no-op if log_init has not been called */
	अगर (argv0 == शून्य)
		वापस 0;

	चयन (new_log_level) {
	हाल SYSLOG_LEVEL_QUIET:
	हाल SYSLOG_LEVEL_FATAL:
	हाल SYSLOG_LEVEL_ERROR:
	हाल SYSLOG_LEVEL_INFO:
	हाल SYSLOG_LEVEL_VERBOSE:
	हाल SYSLOG_LEVEL_DEBUG1:
	हाल SYSLOG_LEVEL_DEBUG2:
	हाल SYSLOG_LEVEL_DEBUG3:
		log_level = new_log_level;
		वापस 0;
	शेष:
		वापस -1;
	}
}

पूर्णांक
log_is_on_stderr(व्योम)
{
	वापस log_on_stderr && log_stderr_fd == STDERR_FILENO;
}

/* redirect what would usually get written to stderr to specified file */
व्योम
log_redirect_stderr_to(स्थिर अक्षर *logfile)
{
	पूर्णांक fd;

	अगर (logfile == शून्य) {
		अगर (log_stderr_fd != STDERR_FILENO) {
			बंद(log_stderr_fd);
			log_stderr_fd = STDERR_FILENO;
		}
		वापस;
	}

	अगर ((fd = खोलो(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1) {
		ख_लिखो(मानक_त्रुटि, "Couldn't open logfile %s: %s\n", logfile,
		    म_त्रुटि(त्रुटि_सं));
		निकास(1);
	}
	log_stderr_fd = fd;
}

#घोषणा MSGBUFSIZ 1024

व्योम
set_log_handler(log_handler_fn *handler, व्योम *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}

अटल व्योम
do_log(LogLevel level, पूर्णांक force, स्थिर अक्षर *suffix, स्थिर अक्षर *fmt,
    बहु_सूची args)
{
#अगर defined(HAVE_OPENLOG_R) && defined(SYSLOG_तथ्य_INIT)
	काष्ठा syslog_तथ्य sdata = SYSLOG_तथ्य_INIT;
#पूर्ण_अगर
	अक्षर msgbuf[MSGBUFSIZ];
	अक्षर fmtbuf[MSGBUFSIZ];
	अक्षर *txt = शून्य;
	पूर्णांक pri = LOG_INFO;
	पूर्णांक saved_errno = त्रुटि_सं;
	log_handler_fn *tmp_handler;
	स्थिर अक्षर *progname = argv0 != शून्य ? argv0 : __progname;

	अगर (!force && level > log_level)
		वापस;

	चयन (level) {
	हाल SYSLOG_LEVEL_FATAL:
		अगर (!log_on_stderr)
			txt = "fatal";
		pri = LOG_CRIT;
		अवरोध;
	हाल SYSLOG_LEVEL_ERROR:
		अगर (!log_on_stderr)
			txt = "error";
		pri = LOG_ERR;
		अवरोध;
	हाल SYSLOG_LEVEL_INFO:
		pri = LOG_INFO;
		अवरोध;
	हाल SYSLOG_LEVEL_VERBOSE:
		pri = LOG_INFO;
		अवरोध;
	हाल SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		pri = LOG_DEBUG;
		अवरोध;
	हाल SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		pri = LOG_DEBUG;
		अवरोध;
	हाल SYSLOG_LEVEL_DEBUG3:
		txt = "debug3";
		pri = LOG_DEBUG;
		अवरोध;
	शेष:
		txt = "internal error";
		pri = LOG_ERR;
		अवरोध;
	}
	अगर (txt != शून्य && log_handler == शून्य) {
		snprintf(fmtbuf, माप(fmtbuf), "%s: %s", txt, fmt);
		vsnprintf(msgbuf, माप(msgbuf), fmtbuf, args);
	} अन्यथा {
		vsnprintf(msgbuf, माप(msgbuf), fmt, args);
	}
	अगर (suffix != शून्य) {
		snprintf(fmtbuf, माप(fmtbuf), "%s: %s", msgbuf, suffix);
		strlcpy(msgbuf, fmtbuf, माप(msgbuf));
	}
	strnvis(fmtbuf, msgbuf, माप(fmtbuf),
	    log_on_stderr ? LOG_STDERR_VIS : LOG_SYSLOG_VIS);
	अगर (log_handler != शून्य) {
		/* Avoid recursion */
		tmp_handler = log_handler;
		log_handler = शून्य;
		/* Note: this sends the raw (i.e. no strnvis) log message */
		tmp_handler(level, force, msgbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} अन्यथा अगर (log_on_stderr) {
		snprintf(msgbuf, माप msgbuf, "%s%s%.*s\r\n",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (पूर्णांक)माप msgbuf - 3, fmtbuf);
		(व्योम)ग_लिखो(log_stderr_fd, msgbuf, म_माप(msgbuf));
	} अन्यथा {
#अगर defined(HAVE_OPENLOG_R) && defined(SYSLOG_तथ्य_INIT)
		openlog_r(progname, LOG_PID, log_facility, &sdata);
		syslog_r(pri, &sdata, "%.500s", fmtbuf);
		closelog_r(&sdata);
#अन्यथा
		openlog(progname, LOG_PID, log_facility);
		syslog(pri, "%.500s", fmtbuf);
		closelog();
#पूर्ण_अगर
	}
	त्रुटि_सं = saved_errno;
}

व्योम
sshlog(स्थिर अक्षर *file, स्थिर अक्षर *func, पूर्णांक पंक्ति, पूर्णांक showfunc,
    LogLevel level, स्थिर अक्षर *suffix, स्थिर अक्षर *fmt, ...)
{
	बहु_सूची args;

	बहु_शुरू(args, fmt);
	sshlogv(file, func, पंक्ति, showfunc, level, suffix, fmt, args);
	बहु_पूर्ण(args);
}

व्योम
sshlogdie(स्थिर अक्षर *file, स्थिर अक्षर *func, पूर्णांक पंक्ति, पूर्णांक showfunc,
    LogLevel level, स्थिर अक्षर *suffix, स्थिर अक्षर *fmt, ...)
{
	बहु_सूची args;

	बहु_शुरू(args, fmt);
	sshlogv(file, func, पंक्ति, showfunc, SYSLOG_LEVEL_INFO,
	    suffix, fmt, args);
	बहु_पूर्ण(args);
	cleanup_exit(255);
}

व्योम
sshlogv(स्थिर अक्षर *file, स्थिर अक्षर *func, पूर्णांक पंक्ति, पूर्णांक showfunc,
    LogLevel level, स्थिर अक्षर *suffix, स्थिर अक्षर *fmt, बहु_सूची args)
{
	अक्षर tag[128], fmt2[MSGBUFSIZ + 128];
	पूर्णांक forced = 0;
	स्थिर अक्षर *cp;
	माप_प्रकार i;

	/* short circuit processing early if we're not going to log anything */
	अगर (nlog_verbose == 0 && level > log_level)
		वापस;

	snprintf(tag, माप(tag), "%.48s:%.48s():%d (bin=%s, pid=%ld)",
	    (cp = म_खोजप(file, '/')) == शून्य ? file : cp + 1, func, पंक्ति,
	    argv0 == शून्य ? "UNKNOWN" : argv0, (दीर्घ)getpid());
	क्रम (i = 0; i < nlog_verbose; i++) {
		अगर (match_pattern_list(tag, log_verbose[i], 0) == 1) {
			forced = 1;
			अवरोध;
		}
	}

	अगर (forced)
		snprintf(fmt2, माप(fmt2), "%s: %s", tag, fmt);
	अन्यथा अगर (showfunc)
		snprintf(fmt2, माप(fmt2), "%s: %s", func, fmt);
	अन्यथा
		strlcpy(fmt2, fmt, माप(fmt2));

	do_log(level, forced, suffix, fmt2, args);
}

व्योम
sshlogdirect(LogLevel level, पूर्णांक forced, स्थिर अक्षर *fmt, ...)
{
	बहु_सूची args;

	बहु_शुरू(args, fmt);
	do_log(level, forced, शून्य, fmt, args);
	बहु_पूर्ण(args);
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

#अगर_घोषित RATELIMIT_DEBUG
# define RLDBG(x) करो { \
		म_लिखो("%s:%d %s: ", __खाता__, __LINE__, __func__); \
		म_लिखो x; \
		म_लिखो("\n"); \
		ख_साफ(मानक_निकास); \
	} जबतक (0)
#अन्यथा
# define RLDBG(x)
#पूर्ण_अगर

/* set up a ratelimit */
व्योम
log_ratelimit_init(काष्ठा log_ratelimit_ctx *rl, u_int threshold,
    u_int max_accum, u_int hysteresis, u_int log_every)
{
	स_रखो(rl, 0, माप(*rl));
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
पूर्णांक
log_ratelimit(काष्ठा log_ratelimit_ctx *rl, समय_प्रकार now, पूर्णांक *active,
    u_int *events_dropped)
{
	समय_प्रकार olast_event;

	RLDBG(("called: rl=%p thresh=%u max=%u hys=%u log_every=%u "
	    "accum=%u since=%ld since_last=%u", rl, rl->threshold,
	    rl->max_accum, rl->hysteresis,
	    rl->log_every, rl->accumulated_events,
	    rl->last_event == 0 ? -1 : (दीर्घ)(now - rl->last_event),
	    rl->ratelimited_events));

	अगर (now < 0)
		वापस 0;
	अगर (events_dropped != शून्य)
		*events_dropped = 0;
	अगर (active != शून्य)
		*active = rl->ratelimit_active;

	/* First, decay accumulated events */
	अगर (rl->last_event <= 0)
		rl->last_event = now;
	अगर (now > rl->last_event) {
		uint64_t n = now - rl->last_event;

		अगर (n > अच_पूर्णांक_उच्च)
			n = अच_पूर्णांक_उच्च;
		अगर (rl->accumulated_events < (u_int)n)
			rl->accumulated_events = 0;
		अन्यथा
			rl->accumulated_events -= (u_int)n;
		RLDBG(("decay: accum=%u", rl->accumulated_events));
	}
	rl->accumulated_events++; /* add this event */
	अगर (rl->accumulated_events > rl->max_accum)
		rl->accumulated_events = rl->max_accum;
	olast_event = rl->last_event;
	rl->last_event = now;
	RLDBG(("check threshold: accum=%u vs thresh=%u",
	    rl->accumulated_events, rl->threshold));

	/* Are we under threshold? */
	अगर (rl->accumulated_events < rl->threshold) {
		अगर (!rl->ratelimit_active)
			वापस 0;
		RLDBG(("under threshold: hys=%u since_hys=%ld since_last=%ld",
		    rl->hysteresis, rl->hysteresis_start == 0 ? -1 :
		    (दीर्घ)(now - rl->hysteresis_start),
		    olast_event == 0 ? -1 : (दीर्घ)(now - olast_event)));
		अगर (rl->hysteresis_start == 0) {
			/* active, but under threshold; hysteresis */
			अगर (olast_event + rl->hysteresis < now) {
				/* hysteresis expired before this event */
				RLDBG(("hysteresis preexpired"));
				जाओ inactive;
			}
			RLDBG(("start hysteresis"));
			rl->hysteresis_start = now;
		} अन्यथा अगर (rl->hysteresis_start + rl->hysteresis < now) {
			/* Hysteresis period expired, transition to inactive */
			RLDBG(("complete hysteresis"));
 inactive:
			अगर (events_dropped != शून्य)
				*events_dropped = rl->ratelimited_events;
			अगर (active != शून्य)
				*active = 0;
			rl->ratelimit_active = 0;
			rl->ratelimit_start = 0;
			rl->last_log = 0;
			rl->hysteresis_start = 0;
			rl->ratelimited_events = 0;
			वापस 0;
		}
		/* ratelimiting active, but in hysteresis period */
	} अन्यथा अगर (!rl->ratelimit_active) {
		/* Transition to rate-limiting */
		RLDBG(("start ratelimit"));
		rl->ratelimit_active = 1;
		rl->ratelimit_start = now;
		rl->last_log = now;
		rl->hysteresis_start = 0;
		rl->ratelimited_events = 1;
		अगर (active != शून्य)
			*active = 1;
		वापस 1;
	} अन्यथा अगर (rl->hysteresis_start != 0) {
		/* active and over threshold; reset hysteresis timer */
		RLDBG(("clear hysteresis"));
		rl->hysteresis_start = 0;
	}

	/* over threshold or in hysteresis period; log periodically */
	अगर (active != शून्य)
		*active = 1;
	RLDBG(("log_every=%u since_log=%ld", rl->log_every,
	    (दीर्घ)(now - rl->last_log)));
	अगर (rl->log_every > 0 && now >= rl->last_log + rl->log_every) {
		RLDBG(("periodic: since_last=%u", rl->ratelimited_events));
		rl->last_log = now;
		अगर (events_dropped != शून्य) {
			*events_dropped = rl->ratelimited_events;
			rl->ratelimited_events = 0;
		}
		वापस 0;
	}

	/* drop event */
	rl->ratelimited_events++;
	RLDBG(("drop: ratelimited_events=%u", rl->ratelimited_events));
	वापस 1;
}
