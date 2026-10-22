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

#ifndef SSH_LOG_H
#define SSH_LOG_H

#அந்தர்பாவ <stdarg.h> /* va_list */
#அந்தர்பாவ "ssherr.h" /* ssh_err() */

/* Supported syslog facilities and levels. */
வகைவரை எண்ணிக்கை {
	SYSLOG_FACILITY_DAEMON,
	SYSLOG_FACILITY_USER,
	SYSLOG_FACILITY_AUTH,
#ifdef LOG_AUTHPRIV
	SYSLOG_FACILITY_AUTHPRIV,
#endif
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

வகைவரை எண்ணிக்கை {
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

வகைவரை வெறுமை (log_handler_fn)(LogLevel, முழு, மாறிலி எழுத்து *, வெறுமை *);

வெறுமை     log_init(மாறிலி எழுத்து *, LogLevel, SyslogFacility, முழு);
LogLevel log_level_get(வெறுமை);
முழு      log_change_level(LogLevel);
முழு      log_is_on_stderr(வெறுமை);
வெறுமை     log_redirect_stderr_to(மாறிலி எழுத்து *);
வெறுமை	 log_verbose_add(மாறிலி எழுத்து *);
வெறுமை	 log_verbose_reset(வெறுமை);

SyslogFacility	log_facility_எண்(எழுத்து *);
மாறிலி எழுத்து *	log_facility_name(SyslogFacility);
LogLevel	log_level_எண்(எழுத்து *);
மாறிலி எழுத்து *	log_level_name(LogLevel);

வெறுமை	 set_log_handler(log_handler_fn *, வெறுமை *);
வெறுமை	 cleanup_exit(முழு) __attribute__((noreturn));

வெறுமை	 sshlog(மாறிலி எழுத்து *, மாறிலி எழுத்து *, முழு, முழு,
    LogLevel, மாறிலி எழுத்து *, மாறிலி எழுத்து *, ...)
    __attribute__((format(printf, 7, 8)));
வெறுமை	 sshlogv(மாறிலி எழுத்து *, மாறிலி எழுத்து *, முழு, முழு,
    LogLevel, மாறிலி எழுத்து *, மாறிலி எழுத்து *, va_list);
வெறுமை	 sshlogdie(மாறிலி எழுத்து *, மாறிலி எழுத்து *, முழு, முழு,
    LogLevel, மாறிலி எழுத்து *, மாறிலி எழுத்து *, ...) __attribute__((noreturn))
    __attribute__((format(printf, 7, 8)));
வெறுமை	 sshfatal(மாறிலி எழுத்து *, மாறிலி எழுத்து *, முழு, முழு,
    LogLevel, மாறிலி எழுத்து *, மாறிலி எழுத்து *, ...) __attribute__((noreturn))
    __attribute__((format(printf, 7, 8)));
வெறுமை	 sshlogdirect(LogLevel, முழு, மாறிலி எழுத்து *, ...)
    __attribute__((format(printf, 3, 4)));

கட்டமைப்பு log_ratelimit_ctx {
	/* configuration */
	u_int threshold;	/* events per second */
	u_int max_accum;	/* max events to accumulate */
	u_int hysteresis;	/* seconds */
	u_int log_every;	/* seconds */

	/* state */
	time_t last_event;
	u_int accumulated_events; /* used for threshold comparisons */

	/* state while actively rate-limiting */
	முழு ratelimit_active;
	time_t ratelimit_start;
	time_t last_log;
	time_t hysteresis_start;
	u_int ratelimited_events;
};

வெறுமை log_ratelimit_init(கட்டமைப்பு log_ratelimit_ctx *rl, u_int threshold,
    u_int max_accum, u_int hysteresis, u_int log_every);
முழு log_ratelimit(கட்டமைப்பு log_ratelimit_ctx *rl, time_t now, முழு *active,
    u_int *events_dropped);

#define do_log2(level, ...)	sshlog(__FILE__, __func__, __LINE__, 0, level, வெற்று, __VA_ARGS__)
#define debug3(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, வெற்று, __VA_ARGS__)
#define debug2(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, வெற்று, __VA_ARGS__)
#define debug(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, வெற்று, __VA_ARGS__)
#define verbose(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, வெற்று, __VA_ARGS__)
#define logit(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, வெற்று, __VA_ARGS__)
#define error(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, வெற்று, __VA_ARGS__)
#define fatal(...)		sshfatal(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, வெற்று, __VA_ARGS__)
#define logdie(...)		sshlogdie(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, வெற்று, __VA_ARGS__)

/* Variants that prepend the caller's function */
#define do_log2_f(level, ...)	sshlog(__FILE__, __func__, __LINE__, 1, level, வெற்று, __VA_ARGS__)
#define debug3_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, வெற்று, __VA_ARGS__)
#define debug2_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, வெற்று, __VA_ARGS__)
#define debug_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, வெற்று, __VA_ARGS__)
#define verbose_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, வெற்று, __VA_ARGS__)
#define logit_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, வெற்று, __VA_ARGS__)
#define error_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, வெற்று, __VA_ARGS__)
#define fatal_f(...)		sshfatal(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, வெற்று, __VA_ARGS__)
#define logdie_f(...)		sshlogdie(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, வெற்று, __VA_ARGS__)

/* Variants that appends a ssh_err message */
#define do_log2_r(r, level, ...) sshlog(__FILE__, __func__, __LINE__, 0, level, ssh_err(r), __VA_ARGS__)
#define debug3_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, ssh_err(r), __VA_ARGS__)
#define debug2_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, ssh_err(r), __VA_ARGS__)
#define debug_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, ssh_err(r), __VA_ARGS__)
#define verbose_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, ssh_err(r), __VA_ARGS__)
#define logit_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, ssh_err(r), __VA_ARGS__)
#define error_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#define fatal_r(r, ...)		sshfatal(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, ssh_err(r), __VA_ARGS__)
#define logdie_r(r, ...)	sshlogdie(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#define do_log2_fr(r, level, ...) sshlog(__FILE__, __func__, __LINE__, 1, level, ssh_err(r), __VA_ARGS__)
#define debug3_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, ssh_err(r), __VA_ARGS__)
#define debug2_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, ssh_err(r), __VA_ARGS__)
#define debug_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, ssh_err(r), __VA_ARGS__)
#define verbose_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, ssh_err(r), __VA_ARGS__)
#define logit_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, ssh_err(r), __VA_ARGS__)
#define error_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#define fatal_fr(r, ...)	sshfatal(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, ssh_err(r), __VA_ARGS__)
#define logdie_fr(r, ...)	sshlogdie(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)

#endif
