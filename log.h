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

#അന്തര്ഭാവ <stdarg.h> /* va_list */
#അന്തര്ഭാവ "ssherr.h" /* ssh_err() */

/* Supported syslog facilities and levels. */
തരനിർവചനം എണ്ണൽ {
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

തരനിർവചനം എണ്ണൽ {
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

തരനിർവചനം ശൂന്യം (log_handler_fn)(LogLevel, പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം *, ശൂന്യം *);

ശൂന്യം     log_init(സ്ഥിരം അക്ഷരം *, LogLevel, SyslogFacility, പൂർണ്ണസംഖ്യ);
LogLevel log_level_get(ശൂന്യം);
പൂർണ്ണസംഖ്യ      log_change_level(LogLevel);
പൂർണ്ണസംഖ്യ      log_is_on_stderr(ശൂന്യം);
ശൂന്യം     log_redirect_stderr_to(സ്ഥിരം അക്ഷരം *);
ശൂന്യം	 log_verbose_add(സ്ഥിരം അക്ഷരം *);
ശൂന്യം	 log_verbose_reset(ശൂന്യം);

SyslogFacility	log_facility_സംഖ്യ(അക്ഷരം *);
സ്ഥിരം അക്ഷരം *	log_facility_name(SyslogFacility);
LogLevel	log_level_സംഖ്യ(അക്ഷരം *);
സ്ഥിരം അക്ഷരം *	log_level_name(LogLevel);

ശൂന്യം	 set_log_handler(log_handler_fn *, ശൂന്യം *);
ശൂന്യം	 cleanup_exit(പൂർണ്ണസംഖ്യ) __attribute__((noreturn));

ശൂന്യം	 sshlog(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ,
    LogLevel, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, ...)
    __attribute__((format(printf, 7, 8)));
ശൂന്യം	 sshlogv(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ,
    LogLevel, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, va_list);
ശൂന്യം	 sshlogdie(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ,
    LogLevel, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, ...) __attribute__((noreturn))
    __attribute__((format(printf, 7, 8)));
ശൂന്യം	 sshfatal(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ,
    LogLevel, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, ...) __attribute__((noreturn))
    __attribute__((format(printf, 7, 8)));
ശൂന്യം	 sshlogdirect(LogLevel, പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം *, ...)
    __attribute__((format(printf, 3, 4)));

ഘടന log_ratelimit_ctx {
	/* configuration */
	u_int threshold;	/* events per second */
	u_int max_accum;	/* max events to accumulate */
	u_int hysteresis;	/* seconds */
	u_int log_every;	/* seconds */

	/* state */
	time_t last_event;
	u_int accumulated_events; /* used for threshold comparisons */

	/* state while actively rate-limiting */
	പൂർണ്ണസംഖ്യ ratelimit_active;
	time_t ratelimit_start;
	time_t last_log;
	time_t hysteresis_start;
	u_int ratelimited_events;
};

ശൂന്യം log_ratelimit_init(ഘടന log_ratelimit_ctx *rl, u_int threshold,
    u_int max_accum, u_int hysteresis, u_int log_every);
പൂർണ്ണസംഖ്യ log_ratelimit(ഘടന log_ratelimit_ctx *rl, time_t now, പൂർണ്ണസംഖ്യ *active,
    u_int *events_dropped);

#define do_log2(level, ...)	sshlog(__FILE__, __func__, __LINE__, 0, level, ശൂന്യ, __VA_ARGS__)
#define debug3(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, ശൂന്യ, __VA_ARGS__)
#define debug2(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, ശൂന്യ, __VA_ARGS__)
#define debug(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, ശൂന്യ, __VA_ARGS__)
#define verbose(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, ശൂന്യ, __VA_ARGS__)
#define logit(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, ശൂന്യ, __VA_ARGS__)
#define error(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ശൂന്യ, __VA_ARGS__)
#define fatal(...)		sshfatal(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, ശൂന്യ, __VA_ARGS__)
#define logdie(...)		sshlogdie(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ശൂന്യ, __VA_ARGS__)

/* Variants that prepend the caller's function */
#define do_log2_f(level, ...)	sshlog(__FILE__, __func__, __LINE__, 1, level, ശൂന്യ, __VA_ARGS__)
#define debug3_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, ശൂന്യ, __VA_ARGS__)
#define debug2_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, ശൂന്യ, __VA_ARGS__)
#define debug_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, ശൂന്യ, __VA_ARGS__)
#define verbose_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, ശൂന്യ, __VA_ARGS__)
#define logit_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, ശൂന്യ, __VA_ARGS__)
#define error_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ശൂന്യ, __VA_ARGS__)
#define fatal_f(...)		sshfatal(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, ശൂന്യ, __VA_ARGS__)
#define logdie_f(...)		sshlogdie(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ശൂന്യ, __VA_ARGS__)

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
