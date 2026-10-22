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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SSH_LOG_H
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_LOG_H

#ಅನ್ತರ್ಭಾವ <stdarg.h> /* va_list */
#ಅನ್ತರ್ಭಾವ "ssherr.h" /* ssh_err() */

/* Supported syslog facilities and levels. */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಎಣಿಕೆ {
	SYSLOG_FACILITY_DAEMON,
	SYSLOG_FACILITY_USER,
	SYSLOG_FACILITY_AUTH,
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ LOG_AUTHPRIV
	SYSLOG_FACILITY_AUTHPRIV,
#ಆದರೆ_ಅಂತ್ಯ
	SYSLOG_FACILITY_LOCAL0,
	SYSLOG_FACILITY_LOCAL1,
	SYSLOG_FACILITY_LOCAL2,
	SYSLOG_FACILITY_LOCAL3,
	SYSLOG_FACILITY_LOCAL4,
	SYSLOG_FACILITY_LOCAL5,
	SYSLOG_FACILITY_LOCAL6,
	SYSLOG_FACILITY_LOCAL7,
	SYSLOG_FACILITY_NOT_ಗಣ = -1
}       SyslogFacility;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಎಣಿಕೆ {
	SYSLOG_LEVEL_QUIET,
	SYSLOG_LEVEL_FATAL,
	SYSLOG_LEVEL_ERROR,
	SYSLOG_LEVEL_INFO,
	SYSLOG_LEVEL_VERBOSE,
	SYSLOG_LEVEL_DEBUG1,
	SYSLOG_LEVEL_DEBUG2,
	SYSLOG_LEVEL_DEBUG3,
	SYSLOG_LEVEL_NOT_ಗಣ = -1
}       LogLevel;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ (log_handler_fn)(LogLevel, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಶೂನ್ಯ *);

ಶೂನ್ಯ     log_init(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, LogLevel, SyslogFacility, ಪೂರ್ಣಾಂಕ);
LogLevel log_level_get(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ      log_change_level(LogLevel);
ಪೂರ್ಣಾಂಕ      log_is_on_stderr(ಶೂನ್ಯ);
ಶೂನ್ಯ     log_redirect_stderr_ಗಮ್ಯ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ	 log_verbose_ಕೂಡಿಸು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ	 log_verbose_reset(ಶೂನ್ಯ);

SyslogFacility	log_facility_ಸಂಖ್ಯೆ(ಅಕ್ಷರ *);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *	log_facility_name(SyslogFacility);
LogLevel	log_level_ಸಂಖ್ಯೆ(ಅಕ್ಷರ *);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *	log_level_name(LogLevel);

ಶೂನ್ಯ	 ಗಣ_log_handler(log_handler_fn *, ಶೂನ್ಯ *);
ಶೂನ್ಯ	 cleanup_exit(ಪೂರ್ಣಾಂಕ) __attribute__((noreturn));

ಶೂನ್ಯ	 sshlog(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ,
    LogLevel, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...)
    __attribute__((format(ಬರೆ, 7, 8)));
ಶೂನ್ಯ	 sshlogv(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ,
    LogLevel, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, va_list);
ಶೂನ್ಯ	 sshlogdie(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ,
    LogLevel, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...) __attribute__((noreturn))
    __attribute__((format(ಬರೆ, 7, 8)));
ಶೂನ್ಯ	 sshfatal(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ,
    LogLevel, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...) __attribute__((noreturn))
    __attribute__((format(ಬರೆ, 7, 8)));
ಶೂನ್ಯ	 sshlogdirect(LogLevel, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...)
    __attribute__((format(ಬರೆ, 3, 4)));

ರಚನೆ log_ratelimit_ctx {
	/* configuration */
	u_int ಮಿತಿ;	/* events per second */
	u_int max_accum;	/* max events to accumulate */
	u_int hysteresis;	/* seconds */
	u_int log_every;	/* seconds */

	/* state */
	time_t ಕೊನೆಯ_event;
	u_int accumulated_events; /* used for threshold comparisons */

	/* state while actively rate-limiting */
	ಪೂರ್ಣಾಂಕ ratelimit_ಸಕ್ರಿಯ;
	time_t ratelimit_ಆರಂಭ;
	time_t ಕೊನೆಯ_log;
	time_t hysteresis_ಆರಂಭ;
	u_int ratelimited_events;
};

ಶೂನ್ಯ log_ratelimit_init(ರಚನೆ log_ratelimit_ctx *rl, u_int ಮಿತಿ,
    u_int max_accum, u_int hysteresis, u_int log_every);
ಪೂರ್ಣಾಂಕ log_ratelimit(ರಚನೆ log_ratelimit_ctx *rl, time_t now, ಪೂರ್ಣಾಂಕ *ಸಕ್ರಿಯ,
    u_int *events_dropped);

#ವ್ಯಾಖ್ಯಾನಿಸು do_log2(level, ...)	sshlog(__FILE__, __func__, __LINE__, 0, level, ಖಾಲಿ, __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು debug3(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, ಖಾಲಿ, __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು debug2(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, ಖಾಲಿ, __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು debug(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, ಖಾಲಿ, __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು verbose(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, ಖಾಲಿ, __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು logit(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, ಖಾಲಿ, __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು error(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ಖಾಲಿ, __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು fatal(...)		sshfatal(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, ಖಾಲಿ, __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು logdie(...)		sshlogdie(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ಖಾಲಿ, __VA_ARGS__)

/* Variants that prepend the caller's function */
#ವ್ಯಾಖ್ಯಾನಿಸು do_log2_f(level, ...)	sshlog(__FILE__, __func__, __LINE__, 1, level, ಖಾಲಿ, __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು debug3_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, ಖಾಲಿ, __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು debug2_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, ಖಾಲಿ, __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು debug_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, ಖಾಲಿ, __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು verbose_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, ಖಾಲಿ, __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು logit_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, ಖಾಲಿ, __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು error_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ಖಾಲಿ, __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು fatal_f(...)		sshfatal(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, ಖಾಲಿ, __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು logdie_f(...)		sshlogdie(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ಖಾಲಿ, __VA_ARGS__)

/* Variants that appends a ssh_err message */
#ವ್ಯಾಖ್ಯಾನಿಸು do_log2_r(r, level, ...) sshlog(__FILE__, __func__, __LINE__, 0, level, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು debug3_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು debug2_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು debug_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು verbose_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು logit_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು error_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು fatal_r(r, ...)		sshfatal(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು logdie_r(r, ...)	sshlogdie(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು do_log2_fr(r, level, ...) sshlog(__FILE__, __func__, __LINE__, 1, level, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು debug3_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು debug2_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು debug_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು verbose_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು logit_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು error_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು fatal_fr(r, ...)	sshfatal(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, ssh_err(r), __VA_ARGS__)
#ವ್ಯಾಖ್ಯಾನಿಸು logdie_fr(r, ...)	sshlogdie(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)

#ಆದರೆ_ಅಂತ್ಯ
