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

#جيڪڏهن_وصف_نه_ٿيل SSH_LOG_H
#وصف_ڪريو SSH_LOG_H

#ضمن <stdarg.h> /* va_list */
#ضمن "ssherr.h" /* ssh_err() */

/* Supported syslog facilities and levels. */
تعريفنوع تعداد {
	SYSLOG_FACILITY_DAEMON,
	SYSLOG_FACILITY_USER,
	SYSLOG_FACILITY_AUTH,
#جيڪڏهن_وصف_ٿيل LOG_AUTHPRIV
	SYSLOG_FACILITY_AUTHPRIV,
#جيڪڏهن_پورو
	SYSLOG_FACILITY_LOCAL0,
	SYSLOG_FACILITY_LOCAL1,
	SYSLOG_FACILITY_LOCAL2,
	SYSLOG_FACILITY_LOCAL3,
	SYSLOG_FACILITY_LOCAL4,
	SYSLOG_FACILITY_LOCAL5,
	SYSLOG_FACILITY_LOCAL6,
	SYSLOG_FACILITY_LOCAL7,
	SYSLOG_FACILITY_NOT_سيٽ = -1
}       SyslogFacility;

تعريفنوع تعداد {
	SYSLOG_LEVEL_QUIET,
	SYSLOG_LEVEL_FATAL,
	SYSLOG_LEVEL_ERROR,
	SYSLOG_LEVEL_INFO,
	SYSLOG_LEVEL_VERBOSE,
	SYSLOG_LEVEL_DEBUG1,
	SYSLOG_LEVEL_DEBUG2,
	SYSLOG_LEVEL_DEBUG3,
	SYSLOG_LEVEL_NOT_سيٽ = -1
}       LogLevel;

تعريفنوع فراغ (log_handler_fn)(LogLevel, صحيح, ثابت حرف *, فراغ *);

فراغ     log_init(ثابت حرف *, LogLevel, SyslogFacility, صحيح);
LogLevel log_level_get(فراغ);
صحيح      log_change_level(LogLevel);
صحيح      log_is_on_stderr(فراغ);
فراغ     log_redirect_stderr_منزل(ثابت حرف *);
فراغ	 log_verbose_جوڙيو(ثابت حرف *);
فراغ	 log_verbose_reset(فراغ);

SyslogFacility	log_facility_عدد(حرف *);
ثابت حرف *	log_facility_name(SyslogFacility);
LogLevel	log_level_عدد(حرف *);
ثابت حرف *	log_level_name(LogLevel);

فراغ	 سيٽ_log_handler(log_handler_fn *, فراغ *);
فراغ	 cleanup_exit(صحيح) __attribute__((noreturn));

فراغ	 sshlog(ثابت حرف *, ثابت حرف *, صحيح, صحيح,
    LogLevel, ثابت حرف *, ثابت حرف *, ...)
    __attribute__((format(لکو, 7, 8)));
فراغ	 sshlogv(ثابت حرف *, ثابت حرف *, صحيح, صحيح,
    LogLevel, ثابت حرف *, ثابت حرف *, va_list);
فراغ	 sshlogdie(ثابت حرف *, ثابت حرف *, صحيح, صحيح,
    LogLevel, ثابت حرف *, ثابت حرف *, ...) __attribute__((noreturn))
    __attribute__((format(لکو, 7, 8)));
فراغ	 sshfatal(ثابت حرف *, ثابت حرف *, صحيح, صحيح,
    LogLevel, ثابت حرف *, ثابت حرف *, ...) __attribute__((noreturn))
    __attribute__((format(لکو, 7, 8)));
فراغ	 sshlogdirect(LogLevel, صحيح, ثابت حرف *, ...)
    __attribute__((format(لکو, 3, 4)));

بنية log_ratelimit_ctx {
	/* configuration */
	u_int حد;	/* events per second */
	u_int max_accum;	/* max events to accumulate */
	u_int hysteresis;	/* seconds */
	u_int log_every;	/* seconds */

	/* state */
	time_t آخري_event;
	u_int accumulated_events; /* used for threshold comparisons */

	/* state while actively rate-limiting */
	صحيح ratelimit_سرگرم;
	time_t ratelimit_شروعات;
	time_t آخري_log;
	time_t hysteresis_شروعات;
	u_int ratelimited_events;
};

فراغ log_ratelimit_init(بنية log_ratelimit_ctx *rl, u_int حد,
    u_int max_accum, u_int hysteresis, u_int log_every);
صحيح log_ratelimit(بنية log_ratelimit_ctx *rl, time_t now, صحيح *سرگرم,
    u_int *events_dropped);

#وصف_ڪريو do_log2(level, ...)	sshlog(__FILE__, __func__, __LINE__, 0, level, عدم, __VA_ARGS__)
#وصف_ڪريو debug3(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, عدم, __VA_ARGS__)
#وصف_ڪريو debug2(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, عدم, __VA_ARGS__)
#وصف_ڪريو debug(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, عدم, __VA_ARGS__)
#وصف_ڪريو verbose(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, عدم, __VA_ARGS__)
#وصف_ڪريو logit(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, عدم, __VA_ARGS__)
#وصف_ڪريو error(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, عدم, __VA_ARGS__)
#وصف_ڪريو fatal(...)		sshfatal(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, عدم, __VA_ARGS__)
#وصف_ڪريو logdie(...)		sshlogdie(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, عدم, __VA_ARGS__)

/* Variants that prepend the caller's function */
#وصف_ڪريو do_log2_f(level, ...)	sshlog(__FILE__, __func__, __LINE__, 1, level, عدم, __VA_ARGS__)
#وصف_ڪريو debug3_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, عدم, __VA_ARGS__)
#وصف_ڪريو debug2_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, عدم, __VA_ARGS__)
#وصف_ڪريو debug_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, عدم, __VA_ARGS__)
#وصف_ڪريو verbose_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, عدم, __VA_ARGS__)
#وصف_ڪريو logit_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, عدم, __VA_ARGS__)
#وصف_ڪريو error_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, عدم, __VA_ARGS__)
#وصف_ڪريو fatal_f(...)		sshfatal(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, عدم, __VA_ARGS__)
#وصف_ڪريو logdie_f(...)		sshlogdie(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, عدم, __VA_ARGS__)

/* Variants that appends a ssh_err message */
#وصف_ڪريو do_log2_r(r, level, ...) sshlog(__FILE__, __func__, __LINE__, 0, level, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو debug3_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو debug2_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو debug_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو verbose_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو logit_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو error_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو fatal_r(r, ...)		sshfatal(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو logdie_r(r, ...)	sshlogdie(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو do_log2_fr(r, level, ...) sshlog(__FILE__, __func__, __LINE__, 1, level, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو debug3_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو debug2_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو debug_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو verbose_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو logit_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو error_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو fatal_fr(r, ...)	sshfatal(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, ssh_err(r), __VA_ARGS__)
#وصف_ڪريو logdie_fr(r, ...)	sshlogdie(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)

#جيڪڏهن_پورو
