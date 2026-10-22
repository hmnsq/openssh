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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SSH_LOG_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_LOG_H

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h> /* va_list */
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h" /* ssh_err() */

/* Supported syslog facilities and levels. */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਗਿਣਤੀ {
	SYSLOG_FACILITY_DAEMON,
	SYSLOG_FACILITY_USER,
	SYSLOG_FACILITY_AUTH,
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LOG_AUTHPRIV
	SYSLOG_FACILITY_AUTHPRIV,
#ਜੇ_ਅੰਤ
	SYSLOG_FACILITY_LOCAL0,
	SYSLOG_FACILITY_LOCAL1,
	SYSLOG_FACILITY_LOCAL2,
	SYSLOG_FACILITY_LOCAL3,
	SYSLOG_FACILITY_LOCAL4,
	SYSLOG_FACILITY_LOCAL5,
	SYSLOG_FACILITY_LOCAL6,
	SYSLOG_FACILITY_LOCAL7,
	SYSLOG_FACILITY_NOT_ਸੈੱਟ = -1
}       SyslogFacility;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਗਿਣਤੀ {
	SYSLOG_LEVEL_QUIET,
	SYSLOG_LEVEL_FATAL,
	SYSLOG_LEVEL_ERROR,
	SYSLOG_LEVEL_INFO,
	SYSLOG_LEVEL_VERBOSE,
	SYSLOG_LEVEL_DEBUG1,
	SYSLOG_LEVEL_DEBUG2,
	SYSLOG_LEVEL_DEBUG3,
	SYSLOG_LEVEL_NOT_ਸੈੱਟ = -1
}       LogLevel;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ (log_handler_fn)(LogLevel, ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ਖਾਲੀ *);

ਖਾਲੀ     log_init(ਅਚਲ ਅੱਖਰ *, LogLevel, SyslogFacility, ਪੂਰਨ);
LogLevel log_level_get(ਖਾਲੀ);
ਪੂਰਨ      log_change_level(LogLevel);
ਪੂਰਨ      log_is_on_stderr(ਖਾਲੀ);
ਖਾਲੀ     log_redirect_stderr_ਮੰਜ਼ਿਲ(ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ	 log_verbose_ਜੋੜੋ(ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ	 log_verbose_reset(ਖਾਲੀ);

SyslogFacility	log_facility_ਸੰਖਿਆ(ਅੱਖਰ *);
ਅਚਲ ਅੱਖਰ *	log_facility_name(SyslogFacility);
LogLevel	log_level_ਸੰਖਿਆ(ਅੱਖਰ *);
ਅਚਲ ਅੱਖਰ *	log_level_name(LogLevel);

ਖਾਲੀ	 ਸੈੱਟ_log_handler(log_handler_fn *, ਖਾਲੀ *);
ਖਾਲੀ	 cleanup_exit(ਪੂਰਨ) __attribute__((noreturn));

ਖਾਲੀ	 sshlog(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ, ਪੂਰਨ,
    LogLevel, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ...)
    __attribute__((format(ਲਿਖੋ, 7, 8)));
ਖਾਲੀ	 sshlogv(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ, ਪੂਰਨ,
    LogLevel, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, va_list);
ਖਾਲੀ	 sshlogdie(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ, ਪੂਰਨ,
    LogLevel, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ...) __attribute__((noreturn))
    __attribute__((format(ਲਿਖੋ, 7, 8)));
ਖਾਲੀ	 sshfatal(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ, ਪੂਰਨ,
    LogLevel, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ...) __attribute__((noreturn))
    __attribute__((format(ਲਿਖੋ, 7, 8)));
ਖਾਲੀ	 sshlogdirect(LogLevel, ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ...)
    __attribute__((format(ਲਿਖੋ, 3, 4)));

ਬਣਤਰ log_ratelimit_ctx {
	/* configuration */
	u_int ਹੱਦ;	/* events per second */
	u_int max_accum;	/* max events to accumulate */
	u_int hysteresis;	/* seconds */
	u_int log_every;	/* seconds */

	/* state */
	time_t ਆਖਰੀ_event;
	u_int accumulated_events; /* used for threshold comparisons */

	/* state while actively rate-limiting */
	ਪੂਰਨ ratelimit_ਸਰਗਰਮ;
	time_t ratelimit_ਸ਼ੁਰੂ;
	time_t ਆਖਰੀ_log;
	time_t hysteresis_ਸ਼ੁਰੂ;
	u_int ratelimited_events;
};

ਖਾਲੀ log_ratelimit_init(ਬਣਤਰ log_ratelimit_ctx *rl, u_int ਹੱਦ,
    u_int max_accum, u_int hysteresis, u_int log_every);
ਪੂਰਨ log_ratelimit(ਬਣਤਰ log_ratelimit_ctx *rl, time_t now, ਪੂਰਨ *ਸਰਗਰਮ,
    u_int *events_dropped);

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ do_log2(level, ...)	sshlog(__FILE__, __func__, __LINE__, 0, level, ਨਿਰਾ, __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ debug3(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, ਨਿਰਾ, __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ debug2(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, ਨਿਰਾ, __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ debug(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, ਨਿਰਾ, __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ verbose(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, ਨਿਰਾ, __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ logit(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, ਨਿਰਾ, __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ error(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ਨਿਰਾ, __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ fatal(...)		sshfatal(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, ਨਿਰਾ, __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ logdie(...)		sshlogdie(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ਨਿਰਾ, __VA_ARGS__)

/* Variants that prepend the caller's function */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ do_log2_f(level, ...)	sshlog(__FILE__, __func__, __LINE__, 1, level, ਨਿਰਾ, __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ debug3_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, ਨਿਰਾ, __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ debug2_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, ਨਿਰਾ, __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ debug_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, ਨਿਰਾ, __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ verbose_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, ਨਿਰਾ, __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ logit_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, ਨਿਰਾ, __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ error_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ਨਿਰਾ, __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ fatal_f(...)		sshfatal(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, ਨਿਰਾ, __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ logdie_f(...)		sshlogdie(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ਨਿਰਾ, __VA_ARGS__)

/* Variants that appends a ssh_err message */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ do_log2_r(r, level, ...) sshlog(__FILE__, __func__, __LINE__, 0, level, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ debug3_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ debug2_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ debug_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ verbose_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ logit_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ error_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ fatal_r(r, ...)		sshfatal(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ logdie_r(r, ...)	sshlogdie(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ do_log2_fr(r, level, ...) sshlog(__FILE__, __func__, __LINE__, 1, level, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ debug3_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ debug2_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ debug_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ verbose_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ logit_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ error_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ fatal_fr(r, ...)	sshfatal(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, ssh_err(r), __VA_ARGS__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ logdie_fr(r, ...)	sshlogdie(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)

#ਜੇ_ਅੰਤ
