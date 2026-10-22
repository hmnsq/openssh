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

#నిర్వచితం_కాకపోతే SSH_LOG_H
#నిర్వచించు SSH_LOG_H

#అన్తర్భావ <stdarg.h> /* va_list */
#అన్తర్భావ "ssherr.h" /* ssh_err() */

/* Supported syslog facilities and levels. */
రకనిర్వచనం గణన {
	SYSLOG_FACILITY_DAEMON,
	SYSLOG_FACILITY_USER,
	SYSLOG_FACILITY_AUTH,
#నిర్వచితమైతే LOG_AUTHPRIV
	SYSLOG_FACILITY_AUTHPRIV,
#అయితే_ముగింపు
	SYSLOG_FACILITY_LOCAL0,
	SYSLOG_FACILITY_LOCAL1,
	SYSLOG_FACILITY_LOCAL2,
	SYSLOG_FACILITY_LOCAL3,
	SYSLOG_FACILITY_LOCAL4,
	SYSLOG_FACILITY_LOCAL5,
	SYSLOG_FACILITY_LOCAL6,
	SYSLOG_FACILITY_LOCAL7,
	SYSLOG_FACILITY_NOT_సమితి = -1
}       SyslogFacility;

రకనిర్వచనం గణన {
	SYSLOG_LEVEL_QUIET,
	SYSLOG_LEVEL_FATAL,
	SYSLOG_LEVEL_ERROR,
	SYSLOG_LEVEL_INFO,
	SYSLOG_LEVEL_VERBOSE,
	SYSLOG_LEVEL_DEBUG1,
	SYSLOG_LEVEL_DEBUG2,
	SYSLOG_LEVEL_DEBUG3,
	SYSLOG_LEVEL_NOT_సమితి = -1
}       LogLevel;

రకనిర్వచనం శూన్య (log_handler_fn)(LogLevel, పూర్ణాంకం, స్థిరరాశి అక్షరం *, శూన్య *);

శూన్య     log_init(స్థిరరాశి అక్షరం *, LogLevel, SyslogFacility, పూర్ణాంకం);
LogLevel log_level_get(శూన్య);
పూర్ణాంకం      log_change_level(LogLevel);
పూర్ణాంకం      log_is_on_stderr(శూన్య);
శూన్య     log_redirect_stderr_గమ్యం(స్థిరరాశి అక్షరం *);
శూన్య	 log_verbose_కూడు(స్థిరరాశి అక్షరం *);
శూన్య	 log_verbose_reset(శూన్య);

SyslogFacility	log_facility_సంఖ్య(అక్షరం *);
స్థిరరాశి అక్షరం *	log_facility_name(SyslogFacility);
LogLevel	log_level_సంఖ్య(అక్షరం *);
స్థిరరాశి అక్షరం *	log_level_name(LogLevel);

శూన్య	 సమితి_log_handler(log_handler_fn *, శూన్య *);
శూన్య	 cleanup_exit(పూర్ణాంకం) __attribute__((noreturn));

శూన్య	 sshlog(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం, పూర్ణాంకం,
    LogLevel, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, ...)
    __attribute__((format(రాయి, 7, 8)));
శూన్య	 sshlogv(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం, పూర్ణాంకం,
    LogLevel, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, va_list);
శూన్య	 sshlogdie(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం, పూర్ణాంకం,
    LogLevel, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, ...) __attribute__((noreturn))
    __attribute__((format(రాయి, 7, 8)));
శూన్య	 sshfatal(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం, పూర్ణాంకం,
    LogLevel, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, ...) __attribute__((noreturn))
    __attribute__((format(రాయి, 7, 8)));
శూన్య	 sshlogdirect(LogLevel, పూర్ణాంకం, స్థిరరాశి అక్షరం *, ...)
    __attribute__((format(రాయి, 3, 4)));

నిర్మాణం log_ratelimit_ctx {
	/* configuration */
	u_int పరిమితి;	/* events per second */
	u_int max_accum;	/* max events to accumulate */
	u_int hysteresis;	/* seconds */
	u_int log_every;	/* seconds */

	/* state */
	time_t చివరి_event;
	u_int accumulated_events; /* used for threshold comparisons */

	/* state while actively rate-limiting */
	పూర్ణాంకం ratelimit_చురుకైన;
	time_t ratelimit_ప్రారంభం;
	time_t చివరి_log;
	time_t hysteresis_ప్రారంభం;
	u_int ratelimited_events;
};

శూన్య log_ratelimit_init(నిర్మాణం log_ratelimit_ctx *rl, u_int పరిమితి,
    u_int max_accum, u_int hysteresis, u_int log_every);
పూర్ణాంకం log_ratelimit(నిర్మాణం log_ratelimit_ctx *rl, time_t now, పూర్ణాంకం *చురుకైన,
    u_int *events_dropped);

#నిర్వచించు do_log2(level, ...)	sshlog(__FILE__, __func__, __LINE__, 0, level, ఖాళీ, __VA_ARGS__)
#నిర్వచించు debug3(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, ఖాళీ, __VA_ARGS__)
#నిర్వచించు debug2(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, ఖాళీ, __VA_ARGS__)
#నిర్వచించు debug(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, ఖాళీ, __VA_ARGS__)
#నిర్వచించు verbose(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, ఖాళీ, __VA_ARGS__)
#నిర్వచించు logit(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, ఖాళీ, __VA_ARGS__)
#నిర్వచించు error(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ఖాళీ, __VA_ARGS__)
#నిర్వచించు fatal(...)		sshfatal(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, ఖాళీ, __VA_ARGS__)
#నిర్వచించు logdie(...)		sshlogdie(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ఖాళీ, __VA_ARGS__)

/* Variants that prepend the caller's function */
#నిర్వచించు do_log2_f(level, ...)	sshlog(__FILE__, __func__, __LINE__, 1, level, ఖాళీ, __VA_ARGS__)
#నిర్వచించు debug3_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, ఖాళీ, __VA_ARGS__)
#నిర్వచించు debug2_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, ఖాళీ, __VA_ARGS__)
#నిర్వచించు debug_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, ఖాళీ, __VA_ARGS__)
#నిర్వచించు verbose_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, ఖాళీ, __VA_ARGS__)
#నిర్వచించు logit_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, ఖాళీ, __VA_ARGS__)
#నిర్వచించు error_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ఖాళీ, __VA_ARGS__)
#నిర్వచించు fatal_f(...)		sshfatal(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, ఖాళీ, __VA_ARGS__)
#నిర్వచించు logdie_f(...)		sshlogdie(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ఖాళీ, __VA_ARGS__)

/* Variants that appends a ssh_err message */
#నిర్వచించు do_log2_r(r, level, ...) sshlog(__FILE__, __func__, __LINE__, 0, level, ssh_err(r), __VA_ARGS__)
#నిర్వచించు debug3_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, ssh_err(r), __VA_ARGS__)
#నిర్వచించు debug2_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, ssh_err(r), __VA_ARGS__)
#నిర్వచించు debug_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, ssh_err(r), __VA_ARGS__)
#నిర్వచించు verbose_r(r, ...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, ssh_err(r), __VA_ARGS__)
#నిర్వచించు logit_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, ssh_err(r), __VA_ARGS__)
#నిర్వచించు error_r(r, ...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#నిర్వచించు fatal_r(r, ...)		sshfatal(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, ssh_err(r), __VA_ARGS__)
#నిర్వచించు logdie_r(r, ...)	sshlogdie(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#నిర్వచించు do_log2_fr(r, level, ...) sshlog(__FILE__, __func__, __LINE__, 1, level, ssh_err(r), __VA_ARGS__)
#నిర్వచించు debug3_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, ssh_err(r), __VA_ARGS__)
#నిర్వచించు debug2_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, ssh_err(r), __VA_ARGS__)
#నిర్వచించు debug_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, ssh_err(r), __VA_ARGS__)
#నిర్వచించు verbose_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, ssh_err(r), __VA_ARGS__)
#నిర్వచించు logit_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, ssh_err(r), __VA_ARGS__)
#నిర్వచించు error_fr(r, ...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)
#నిర్వచించు fatal_fr(r, ...)	sshfatal(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, ssh_err(r), __VA_ARGS__)
#నిర్వచించు logdie_fr(r, ...)	sshlogdie(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, ssh_err(r), __VA_ARGS__)

#అయితే_ముగింపు
