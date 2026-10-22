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

#यदि_अपरिभाषितम् SSH_LOG_H
#परिभाषय SSH_LOG_H

#अन्तर्भाव <stdarg.h> /* va_list */
#अन्तर्भाव "ssherr.h" /* ssh_err() */

/* Supported syslog facilities and levels. */
प्रकारनिर्देश गणना {
	SYSLOG_FACILITY_DAEMON,
	SYSLOG_FACILITY_USER,
	SYSLOG_FACILITY_AUTH,
#यदि_परिभाषितम् LOG_AUTHPRIV
	SYSLOG_FACILITY_AUTHPRIV,
#यदि_अन्तः
	SYSLOG_FACILITY_LOCAL0,
	SYSLOG_FACILITY_LOCAL1,
	SYSLOG_FACILITY_LOCAL2,
	SYSLOG_FACILITY_LOCAL3,
	SYSLOG_FACILITY_LOCAL4,
	SYSLOG_FACILITY_LOCAL5,
	SYSLOG_FACILITY_LOCAL6,
	SYSLOG_FACILITY_LOCAL7,
	SYSLOG_FACILITY_NOT_समुच्चयः = -1
}       SyslogFacility;

प्रकारनिर्देश गणना {
	SYSLOG_LEVEL_QUIET,
	SYSLOG_LEVEL_FATAL,
	SYSLOG_LEVEL_ERROR,
	SYSLOG_LEVEL_INFO,
	SYSLOG_LEVEL_VERBOSE,
	SYSLOG_LEVEL_DEBUG1,
	SYSLOG_LEVEL_DEBUG2,
	SYSLOG_LEVEL_DEBUG3,
	SYSLOG_LEVEL_NOT_समुच्चयः = -1
}       LogLevel;

प्रकारनिर्देश शून्य (log_handler_fn)(LogLevel, पूर्णाङ्क, ध्रुव वर्ण *, शून्य *);

शून्य     log_init(ध्रुव वर्ण *, LogLevel, SyslogFacility, पूर्णाङ्क);
LogLevel log_level_get(शून्य);
पूर्णाङ्क      log_change_level(LogLevel);
पूर्णाङ्क      log_is_on_stderr(शून्य);
शून्य     log_redirect_stderr_गन्तव्यम्(ध्रुव वर्ण *);
शून्य	 log_verbose_सङ्कलय(ध्रुव वर्ण *);
शून्य	 log_verbose_reset(शून्य);

SyslogFacility	log_facility_सङ्ख्या(वर्ण *);
ध्रुव वर्ण *	log_facility_name(SyslogFacility);
LogLevel	log_level_सङ्ख्या(वर्ण *);
ध्रुव वर्ण *	log_level_name(LogLevel);

शून्य	 समुच्चयः_log_handler(log_handler_fn *, शून्य *);
शून्य	 cleanup_exit(पूर्णाङ्क) __attribute__((noreturn));

शून्य	 sshlog(ध्रुव वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क, पूर्णाङ्क,
    LogLevel, ध्रुव वर्ण *, ध्रुव वर्ण *, ...)
    __attribute__((format(प्रारूप_लिख, 7, 8)));
शून्य	 sshlogv(ध्रुव वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क, पूर्णाङ्क,
    LogLevel, ध्रुव वर्ण *, ध्रुव वर्ण *, va_list);
शून्य	 sshlogdie(ध्रुव वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क, पूर्णाङ्क,
    LogLevel, ध्रुव वर्ण *, ध्रुव वर्ण *, ...) __attribute__((noreturn))
    __attribute__((format(प्रारूप_लिख, 7, 8)));
शून्य	 sshfatal(ध्रुव वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क, पूर्णाङ्क,
    LogLevel, ध्रुव वर्ण *, ध्रुव वर्ण *, ...) __attribute__((noreturn))
    __attribute__((format(प्रारूप_लिख, 7, 8)));
शून्य	 sshlogdirect(LogLevel, पूर्णाङ्क, ध्रुव वर्ण *, ...)
    __attribute__((format(प्रारूप_लिख, 3, 4)));

संरचना log_ratelimit_ctx {
	/* configuration */
	u_int देहली;	/* events per second */
	u_int max_accum;	/* max events to accumulate */
	u_int hysteresis;	/* seconds */
	u_int log_every;	/* seconds */

	/* state */
	time_t चरमः_event;
	u_int accumulated_events; /* used for threshold comparisons */

	/* state while actively rate-limiting */
	पूर्णाङ्क ratelimit_सक्रिय;
	time_t ratelimit_start;
	time_t चरमः_log;
	time_t hysteresis_start;
	u_int ratelimited_events;
};

शून्य log_ratelimit_init(संरचना log_ratelimit_ctx *rl, u_int देहली,
    u_int max_accum, u_int hysteresis, u_int log_every);
पूर्णाङ्क log_ratelimit(संरचना log_ratelimit_ctx *rl, time_t now, पूर्णाङ्क *सक्रिय,
    u_int *events_dropped);

#परिभाषय do_log2(level, ...)	sshlog(__FILE__, __func__, __LINE__, 0, level, रिक्त, __VA_ARGS__)
#परिभाषय debug3(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, रिक्त, __VA_ARGS__)
#परिभाषय debug2(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, रिक्त, __VA_ARGS__)
#परिभाषय debug(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, रिक्त, __VA_ARGS__)
#परिभाषय verbose(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, रिक्त, __VA_ARGS__)
#परिभाषय logit(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, रिक्त, __VA_ARGS__)
#परिभाषय error(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, रिक्त, __VA_ARGS__)
#परिभाषय fatal(...)		sshfatal(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, रिक्त, __VA_ARGS__)
#परिभाषय logdie(...)		sshlogdie(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, रिक्त, __VA_ARGS__)

/* Variants that prepend the caller's function */
#परिभाषय do_log2_f(level, ...)	sshlog(__FILE__, __func__, __LINE__, 1, level, रिक्त, __VA_ARGS__)
#परिभाषय debug3_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, रिक्त, __VA_ARGS__)
#परिभाषय debug2_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, रिक्त, __VA_ARGS__)
#परिभाषय debug_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, रिक्त, __VA_ARGS__)
#परिभाषय verbose_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, रिक्त, __VA_ARGS__)
#परिभाषय logit_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, रिक्त, __VA_ARGS__)
#परिभाषय error_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, रिक्त, __VA_ARGS__)
#परिभाषय fatal_f(...)		sshfatal(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, रिक्त, __VA_ARGS__)
#परिभाषय logdie_f(...)		sshlogdie(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, रिक्त, __VA_ARGS__)

/* Variants that appends a ssh_err message */
#परिभाषय do_log2_r(r, level, ...) sshlog(__FILE__, __func__, __LINE__, 0, level, ssh_err(r), __VA_ARGS__)
#परिभाषय debug3_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, ssh_err(r), __VA_ARGS__)
#परिभाषय debug2_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, ssh_err(r), __VA_ARGS__)
#परिभाषय debug_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, ssh_err(r), __VA_ARGS__)
#परिभाषय verbose_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, ssh_err(r), __VA_ARGS__)
#परिभाषय logit_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, ssh_err(r), __VA_ARGS__)
#परिभाषय error_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#परिभाषय fatal_r(r, ...)		sshfatal(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, ssh_err(r), __VA_ARGS__)
#परिभाषय logdie_r(r, ...)	sshlogdie(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#परिभाषय do_log2_fr(r, level, ...) sshlog(__FILE__, __func__, __LINE__, 1, level, ssh_err(r), __VA_ARGS__)
#परिभाषय debug3_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, ssh_err(r), __VA_ARGS__)
#परिभाषय debug2_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, ssh_err(r), __VA_ARGS__)
#परिभाषय debug_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, ssh_err(r), __VA_ARGS__)
#परिभाषय verbose_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, ssh_err(r), __VA_ARGS__)
#परिभाषय logit_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, ssh_err(r), __VA_ARGS__)
#परिभाषय error_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#परिभाषय fatal_fr(r, ...)	sshfatal(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, ssh_err(r), __VA_ARGS__)
#परिभाषय logdie_fr(r, ...)	sshlogdie(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)

#यदि_अन्तः
