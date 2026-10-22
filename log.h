/* $OpenBSD: log.h,v 1.35 2024/12/07 10:05:37 djm Exp $ */

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

#अगर_अघोषित SSH_LOG_H
#घोषणा SSH_LOG_H

#समावेश <stdarg.h> /* va_list */
#समावेश "ssherr.h" /* ssh_err() */

/* Supported syslog facilities and levels. */
प्रकार क्रमागत {
	SYSLOG_FACILITY_DAEMON,
	SYSLOG_FACILITY_USER,
	SYSLOG_FACILITY_AUTH,
#अगर_घोषित LOG_AUTHPRIV
	SYSLOG_FACILITY_AUTHPRIV,
#पूर्ण_अगर
	SYSLOG_FACILITY_LOCAL0,
	SYSLOG_FACILITY_LOCAL1,
	SYSLOG_FACILITY_LOCAL2,
	SYSLOG_FACILITY_LOCAL3,
	SYSLOG_FACILITY_LOCAL4,
	SYSLOG_FACILITY_LOCAL5,
	SYSLOG_FACILITY_LOCAL6,
	SYSLOG_FACILITY_LOCAL7,
	SYSLOG_FACILITY_NOT_SET = -1
}       SyslogFacility;

प्रकार क्रमागत {
	SYSLOG_LEVEL_QUIET,
	SYSLOG_LEVEL_FATAL,
	SYSLOG_LEVEL_ERROR,
	SYSLOG_LEVEL_INFO,
	SYSLOG_LEVEL_VERBOSE,
	SYSLOG_LEVEL_DEBUG1,
	SYSLOG_LEVEL_DEBUG2,
	SYSLOG_LEVEL_DEBUG3,
	SYSLOG_LEVEL_NOT_SET = -1
}       LogLevel;

प्रकार व्योम (log_handler_fn)(LogLevel, पूर्णांक, स्थिर अक्षर *, व्योम *);

व्योम     log_init(स्थिर अक्षर *, LogLevel, SyslogFacility, पूर्णांक);
LogLevel log_level_get(व्योम);
पूर्णांक      log_change_level(LogLevel);
पूर्णांक      log_is_on_stderr(व्योम);
व्योम     log_redirect_stderr_to(स्थिर अक्षर *);
व्योम	 log_verbose_add(स्थिर अक्षर *);
व्योम	 log_verbose_reset(व्योम);

SyslogFacility	log_facility_संख्या(अक्षर *);
स्थिर अक्षर *	log_facility_name(SyslogFacility);
LogLevel	log_level_संख्या(अक्षर *);
स्थिर अक्षर *	log_level_name(LogLevel);

व्योम	 set_log_handler(log_handler_fn *, व्योम *);
व्योम	 cleanup_exit(पूर्णांक) __attribute__((noreturn));

व्योम	 sshlog(स्थिर अक्षर *, स्थिर अक्षर *, पूर्णांक, पूर्णांक,
    LogLevel, स्थिर अक्षर *, स्थिर अक्षर *, ...)
    __attribute__((format(म_लिखो, 7, 8)));
व्योम	 sshlogv(स्थिर अक्षर *, स्थिर अक्षर *, पूर्णांक, पूर्णांक,
    LogLevel, स्थिर अक्षर *, स्थिर अक्षर *, बहु_सूची);
व्योम	 sshlogdie(स्थिर अक्षर *, स्थिर अक्षर *, पूर्णांक, पूर्णांक,
    LogLevel, स्थिर अक्षर *, स्थिर अक्षर *, ...) __attribute__((noreturn))
    __attribute__((format(म_लिखो, 7, 8)));
व्योम	 sshfatal(स्थिर अक्षर *, स्थिर अक्षर *, पूर्णांक, पूर्णांक,
    LogLevel, स्थिर अक्षर *, स्थिर अक्षर *, ...) __attribute__((noreturn))
    __attribute__((format(म_लिखो, 7, 8)));
व्योम	 sshlogdirect(LogLevel, पूर्णांक, स्थिर अक्षर *, ...)
    __attribute__((format(म_लिखो, 3, 4)));

काष्ठा log_ratelimit_ctx {
	/* configuration */
	u_int threshold;	/* events per second */
	u_int max_accum;	/* max events to accumulate */
	u_int hysteresis;	/* seconds */
	u_int log_every;	/* seconds */

	/* state */
	समय_प्रकार last_event;
	u_int accumulated_events; /* used for threshold comparisons */

	/* state while actively rate-limiting */
	पूर्णांक ratelimit_active;
	समय_प्रकार ratelimit_start;
	समय_प्रकार last_log;
	समय_प्रकार hysteresis_start;
	u_int ratelimited_events;
};

व्योम log_ratelimit_init(काष्ठा log_ratelimit_ctx *rl, u_int threshold,
    u_int max_accum, u_int hysteresis, u_int log_every);
पूर्णांक log_ratelimit(काष्ठा log_ratelimit_ctx *rl, समय_प्रकार now, पूर्णांक *active,
    u_int *events_dropped);

#घोषणा do_log2(level, ...)	sshlog(__खाता__, __func__, __LINE__, 0, level, शून्य, __VA_ARGS__)
#घोषणा debug3(...)		sshlog(__खाता__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, शून्य, __VA_ARGS__)
#घोषणा debug2(...)		sshlog(__खाता__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, शून्य, __VA_ARGS__)
#घोषणा debug(...)		sshlog(__खाता__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, शून्य, __VA_ARGS__)
#घोषणा verbose(...)		sshlog(__खाता__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, शून्य, __VA_ARGS__)
#घोषणा logit(...)		sshlog(__खाता__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, शून्य, __VA_ARGS__)
#घोषणा error(...)		sshlog(__खाता__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, शून्य, __VA_ARGS__)
#घोषणा fatal(...)		sshfatal(__खाता__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, शून्य, __VA_ARGS__)
#घोषणा logdie(...)		sshlogdie(__खाता__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, शून्य, __VA_ARGS__)

/* Variants that prepend the caller's function */
#घोषणा do_log2_f(level, ...)	sshlog(__खाता__, __func__, __LINE__, 1, level, शून्य, __VA_ARGS__)
#घोषणा debug3_f(...)		sshlog(__खाता__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, शून्य, __VA_ARGS__)
#घोषणा debug2_f(...)		sshlog(__खाता__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, शून्य, __VA_ARGS__)
#घोषणा debug_f(...)		sshlog(__खाता__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, शून्य, __VA_ARGS__)
#घोषणा verbose_f(...)		sshlog(__खाता__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, शून्य, __VA_ARGS__)
#घोषणा logit_f(...)		sshlog(__खाता__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, शून्य, __VA_ARGS__)
#घोषणा error_f(...)		sshlog(__खाता__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, शून्य, __VA_ARGS__)
#घोषणा fatal_f(...)		sshfatal(__खाता__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, शून्य, __VA_ARGS__)
#घोषणा logdie_f(...)		sshlogdie(__खाता__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, शून्य, __VA_ARGS__)

/* Variants that appends a ssh_err message */
#घोषणा do_log2_r(r, level, ...) sshlog(__खाता__, __func__, __LINE__, 0, level, ssh_err(r), __VA_ARGS__)
#घोषणा debug3_r(r, ...)	sshlog(__खाता__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, ssh_err(r), __VA_ARGS__)
#घोषणा debug2_r(r, ...)	sshlog(__खाता__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, ssh_err(r), __VA_ARGS__)
#घोषणा debug_r(r, ...)		sshlog(__खाता__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, ssh_err(r), __VA_ARGS__)
#घोषणा verbose_r(r, ...)	sshlog(__खाता__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, ssh_err(r), __VA_ARGS__)
#घोषणा logit_r(r, ...)		sshlog(__खाता__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, ssh_err(r), __VA_ARGS__)
#घोषणा error_r(r, ...)		sshlog(__खाता__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#घोषणा fatal_r(r, ...)		sshfatal(__खाता__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, ssh_err(r), __VA_ARGS__)
#घोषणा logdie_r(r, ...)	sshlogdie(__खाता__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#घोषणा do_log2_fr(r, level, ...) sshlog(__खाता__, __func__, __LINE__, 1, level, ssh_err(r), __VA_ARGS__)
#घोषणा debug3_fr(r, ...)	sshlog(__खाता__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, ssh_err(r), __VA_ARGS__)
#घोषणा debug2_fr(r, ...)	sshlog(__खाता__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, ssh_err(r), __VA_ARGS__)
#घोषणा debug_fr(r, ...)	sshlog(__खाता__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, ssh_err(r), __VA_ARGS__)
#घोषणा verbose_fr(r, ...)	sshlog(__खाता__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, ssh_err(r), __VA_ARGS__)
#घोषणा logit_fr(r, ...)	sshlog(__खाता__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, ssh_err(r), __VA_ARGS__)
#घोषणा error_fr(r, ...)	sshlog(__खाता__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#घोषणा fatal_fr(r, ...)	sshfatal(__खाता__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, ssh_err(r), __VA_ARGS__)
#घोषणा logdie_fr(r, ...)	sshlogdie(__खाता__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)

#पूर्ण_अगर
