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

#અન્તર્ભાવ <stdarg.h> /* va_list */
#અન્તર્ભાવ "ssherr.h" /* ssh_err() */

/* Supported syslog facilities and levels. */
પ્રકારવ્યાખ્યા ગણના {
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

પ્રકારવ્યાખ્યા ગણના {
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

પ્રકારવ્યાખ્યા શૂન્ય (log_handler_fn)(LogLevel, પૂર્ણાંક, અચલ અક્ષર *, શૂન્ય *);

શૂન્ય     log_init(અચલ અક્ષર *, LogLevel, SyslogFacility, પૂર્ણાંક);
LogLevel log_level_get(શૂન્ય);
પૂર્ણાંક      log_change_level(LogLevel);
પૂર્ણાંક      log_is_on_stderr(શૂન્ય);
શૂન્ય     log_redirect_stderr_to(અચલ અક્ષર *);
શૂન્ય	 log_verbose_add(અચલ અક્ષર *);
શૂન્ય	 log_verbose_reset(શૂન્ય);

SyslogFacility	log_facility_સંખ્યા(અક્ષર *);
અચલ અક્ષર *	log_facility_name(SyslogFacility);
LogLevel	log_level_સંખ્યા(અક્ષર *);
અચલ અક્ષર *	log_level_name(LogLevel);

શૂન્ય	 set_log_handler(log_handler_fn *, શૂન્ય *);
શૂન્ય	 cleanup_exit(પૂર્ણાંક) __attribute__((noreturn));

શૂન્ય	 sshlog(અચલ અક્ષર *, અચલ અક્ષર *, પૂર્ણાંક, પૂર્ણાંક,
    LogLevel, અચલ અક્ષર *, અચલ અક્ષર *, ...)
    __attribute__((format(printf, 7, 8)));
શૂન્ય	 sshlogv(અચલ અક્ષર *, અચલ અક્ષર *, પૂર્ણાંક, પૂર્ણાંક,
    LogLevel, અચલ અક્ષર *, અચલ અક્ષર *, va_list);
શૂન્ય	 sshlogdie(અચલ અક્ષર *, અચલ અક્ષર *, પૂર્ણાંક, પૂર્ણાંક,
    LogLevel, અચલ અક્ષર *, અચલ અક્ષર *, ...) __attribute__((noreturn))
    __attribute__((format(printf, 7, 8)));
શૂન્ય	 sshfatal(અચલ અક્ષર *, અચલ અક્ષર *, પૂર્ણાંક, પૂર્ણાંક,
    LogLevel, અચલ અક્ષર *, અચલ અક્ષર *, ...) __attribute__((noreturn))
    __attribute__((format(printf, 7, 8)));
શૂન્ય	 sshlogdirect(LogLevel, પૂર્ણાંક, અચલ અક્ષર *, ...)
    __attribute__((format(printf, 3, 4)));

સંરચના log_ratelimit_ctx {
	/* configuration */
	u_int threshold;	/* events per second */
	u_int max_accum;	/* max events to accumulate */
	u_int hysteresis;	/* seconds */
	u_int log_every;	/* seconds */

	/* state */
	time_t last_event;
	u_int accumulated_events; /* used for threshold comparisons */

	/* state while actively rate-limiting */
	પૂર્ણાંક ratelimit_active;
	time_t ratelimit_start;
	time_t last_log;
	time_t hysteresis_start;
	u_int ratelimited_events;
};

શૂન્ય log_ratelimit_init(સંરચના log_ratelimit_ctx *rl, u_int threshold,
    u_int max_accum, u_int hysteresis, u_int log_every);
પૂર્ણાંક log_ratelimit(સંરચના log_ratelimit_ctx *rl, time_t now, પૂર્ણાંક *active,
    u_int *events_dropped);

#define do_log2(level, ...)	sshlog(__FILE__, __func__, __LINE__, 0, level, ખાલી, __VA_ARGS__)
#define debug3(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, ખાલી, __VA_ARGS__)
#define debug2(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, ખાલી, __VA_ARGS__)
#define debug(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, ખાલી, __VA_ARGS__)
#define verbose(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, ખાલી, __VA_ARGS__)
#define logit(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, ખાલી, __VA_ARGS__)
#define error(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ખાલી, __VA_ARGS__)
#define fatal(...)		sshfatal(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, ખાલી, __VA_ARGS__)
#define logdie(...)		sshlogdie(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ખાલી, __VA_ARGS__)

/* Variants that prepend the caller's function */
#define do_log2_f(level, ...)	sshlog(__FILE__, __func__, __LINE__, 1, level, ખાલી, __VA_ARGS__)
#define debug3_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, ખાલી, __VA_ARGS__)
#define debug2_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, ખાલી, __VA_ARGS__)
#define debug_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, ખાલી, __VA_ARGS__)
#define verbose_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, ખાલી, __VA_ARGS__)
#define logit_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, ખાલી, __VA_ARGS__)
#define error_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ખાલી, __VA_ARGS__)
#define fatal_f(...)		sshfatal(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, ખાલી, __VA_ARGS__)
#define logdie_f(...)		sshlogdie(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ખાલી, __VA_ARGS__)

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
