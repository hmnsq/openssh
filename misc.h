/* $OpenBSD: misc.h,v 1.120 2026/09/16 06:23:16 djm Exp $ */

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

#ifndef _MISC_H
#define _MISC_H

#અન્તર્ભાવ <sys/time.h>
#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <signal.h>

/* special-case port number meaning allow any port */
#define FWD_PERMIT_ANY_PORT	0

/* special-case wildcard meaning allow any host */
#define FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
સંરચના Forward {
	અક્ષર	 *listen_host;		/* Host (address) to listen on. */
	પૂર્ણાંક	  listen_port;		/* Port to forward. */
	અક્ષર	 *listen_path;		/* Path to bind domain socket. */
	અક્ષર	 *connect_host;		/* Host to connect. */
	પૂર્ણાંક	  connect_port;		/* Port to connect on connect_host. */
	અક્ષર	 *connect_path;		/* Path to connect domain socket. */
	પૂર્ણાંક	  allocated_port;	/* Dynamically allocated listen port */
	પૂર્ણાંક	  handle;		/* Handle for dynamic listen ports */
};

પૂર્ણાંક forward_equals(અચલ સંરચના Forward *, અચલ સંરચના Forward *);
પૂર્ણાંક permitopen_port(અચલ અક્ષર *p);

પૂર્ણાંક daemonized(શૂન્ય);

/* Common server and client forwarding options. */
સંરચના ForwardOptions {
	પૂર્ણાંક	 gateway_ports; /* Allow remote connects to forwarded ports. */
	mode_t	 streamlocal_bind_mask; /* umask for streamlocal binds */
	પૂર્ણાંક	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

અક્ષર	*chop(અક્ષર *);
શૂન્ય	 rtrim(અક્ષર *);
શૂન્ય	skip_space(અક્ષર **);
અચલ અક્ષર *strprefix(અચલ અક્ષર *, અચલ અક્ષર *, પૂર્ણાંક);
અક્ષર	*strdelim(અક્ષર **);
અક્ષર	*strdelimw(અક્ષર **);
શૂન્ય	 stringlist_append(અક્ષર ***listp, અચલ અક્ષર *s);
શૂન્ય	 stringlist_free(અક્ષર **list);
પૂર્ણાંક	 set_nonblock(પૂર્ણાંક);
પૂર્ણાંક	 unset_nonblock(પૂર્ણાંક);
શૂન્ય	 set_nodelay(પૂર્ણાંક);
પૂર્ણાંક	 set_reuseaddr(પૂર્ણાંક);
પૂર્ણાંક	 set_keepalive(પૂર્ણાંક);
અક્ષર	*get_rdomain(પૂર્ણાંક);
પૂર્ણાંક	 set_rdomain(પૂર્ણાંક, અચલ અક્ષર *);
પૂર્ણાંક	 get_sock_af(પૂર્ણાંક);
શૂન્ય	 set_sock_tos(પૂર્ણાંક, પૂર્ણાંક);
પૂર્ણાંક	 waitrfd(પૂર્ણાંક, પૂર્ણાંક *, અસ્થિર sig_atomic_t *);
પૂર્ણાંક	 timeout_connect(પૂર્ણાંક, અચલ સંરચના sockaddr *, socklen_t, પૂર્ણાંક *);
પૂર્ણાંક	 a2port(અચલ અક્ષર *);
પૂર્ણાંક	 a2tun(અચલ અક્ષર *, પૂર્ણાંક *);
અક્ષર	*put_host_port(અચલ અક્ષર *, u_short);
અક્ષર	*hpdelim2(અક્ષર **, અક્ષર *);
અક્ષર	*hpdelim(અક્ષર **);
અક્ષર	*cleanhostname(અક્ષર *);
અક્ષર	*colon(અક્ષર *);
પૂર્ણાંક	 parse_user_host_path(અચલ અક્ષર *, અક્ષર **, અક્ષર **, અક્ષર **);
પૂર્ણાંક	 parse_user_host_port(અચલ અક્ષર *, અક્ષર **, અક્ષર **, પૂર્ણાંક *);
પૂર્ણાંક	 parse_uri(અચલ અક્ષર *, અચલ અક્ષર *, અક્ષર **, અક્ષર **, પૂર્ણાંક *, અક્ષર **);
દ્વિગુણ	 convtime_double(અચલ અક્ષર *);
પૂર્ણાંક	 convtime(અચલ અક્ષર *);
દ્વિગુણ	 convtime_double(અચલ અક્ષર *);
અચલ અક્ષર *fmt_timeframe(time_t t);
પૂર્ણાંક	 tilde_expand(અચલ અક્ષર *, uid_t, અક્ષર **);
અક્ષર	*tilde_expand_filename(અચલ અક્ષર *, uid_t);

અક્ષર	*dollar_expand(પૂર્ણાંક *, અચલ અક્ષર *string, ...);
અક્ષર	*percent_expand(અચલ અક્ષર *, ...) __attribute__((__sentinel__));
અક્ષર	*percent_dollar_expand(અચલ અક્ષર *, ...) __attribute__((__sentinel__));
અક્ષર	*tohex(અચલ શૂન્ય *, size_t);
શૂન્ય	 xextendf(અક્ષર **s, અચલ અક્ષર *sep, અચલ અક્ષર *fmt, ...)
    __attribute__((__format__ (printf, 3, 4))) __attribute__((__nonnull__ (3)));
શૂન્ય	 sanitise_stdfd(શૂન્ય);
શૂન્ય	 ms_subtract_diff(સંરચના timeval *, પૂર્ણાંક *);
શૂન્ય	 ms_to_timespec(સંરચના timespec *, પૂર્ણાંક);
શૂન્ય	 monotime_ts(સંરચના timespec *);
શૂન્ય	 monotime_tv(સંરચના timeval *);
time_t	 monotime(શૂન્ય);
દ્વિગુણ	 monotime_double(શૂન્ય);
શૂન્ય	 lowercase(અક્ષર *s);
પૂર્ણાંક	 unix_listener(અચલ અક્ષર *, પૂર્ણાંક, પૂર્ણાંક);
પૂર્ણાંક	 valid_domain(અક્ષર *, પૂર્ણાંક, અચલ અક્ષર **);
પૂર્ણાંક	 valid_env_name(અચલ અક્ષર *);
અચલ અક્ષર *atoi_err(અચલ અક્ષર *, પૂર્ણાંક *);
પૂર્ણાંક	 parse_absolute_time(અચલ અક્ષર *, uint64_t *);
શૂન્ય	 format_absolute_time(uint64_t, અક્ષર *, size_t);
પૂર્ણાંક	 parse_pattern_interval(અચલ અક્ષર *, અક્ષર **, દ્વિગુણ *);
પૂર્ણાંક	 path_absolute(અચલ અક્ષર *);
પૂર્ણાંક	 stdfd_devnull(પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક);
પૂર્ણાંક	 lib_contains_પ્રતીક(અચલ અક્ષર *, અચલ અક્ષર *);
અક્ષર	*get_homedir(શૂન્ય);
પૂર્ણાંક	 mkdir_path(અચલ અક્ષર *, mode_t);

શૂન્ય	 sock_set_v6only(પૂર્ણાંક);

સંરચના passwd *pwcopy(સંરચના passwd *);
શૂન્ય	 pwfree(સંરચના passwd *); /* NB. only use with pwcopy */

અચલ અક્ષર *ssh_gai_strerror(પૂર્ણાંક);

પ્રકારવ્યાખ્યા શૂન્ય privdrop_fn(સંરચના passwd *);
પ્રકારવ્યાખ્યા શૂન્ય privrestore_fn(શૂન્ય);
#define	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#define	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#define	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#define	SSH_SUBPROCESS_UNSAFE_PATH	(1<<3)	/* Don't check for safe cmd */
#define	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(અચલ અક્ષર *, અચલ અક્ષર *, પૂર્ણાંક, અક્ષર **, FILE **, u_int,
    સંરચના passwd *, privdrop_fn *, privrestore_fn *);

પ્રકારવ્યાખ્યા સંરચના arglist arglist;
સંરચના arglist {
	અક્ષર    **list;
	u_int   અંક;
	u_int   nalloc;
};
શૂન્ય	 addargs(arglist *, અક્ષર *, ...)
	    __attribute__((format(printf, 2, 3)));
શૂન્ય	 replacearg(arglist *, u_int, અક્ષર *, ...)
	    __attribute__((format(printf, 3, 4)));
શૂન્ય	 freeargs(arglist *);

પૂર્ણાંક	 tun_open(પૂર્ણાંક, પૂર્ણાંક, અક્ષર **);

/* Common definitions for ssh tunnel device forwarding */
#define SSH_TUNMODE_NO		0x00
#define SSH_TUNMODE_POINTOPOINT	0x01
#define SSH_TUNMODE_ETHERNET	0x02
#define SSH_TUNMODE_DEFAULT	SSH_TUNMODE_POINTOPOINT
#define SSH_TUNMODE_YES		(SSH_TUNMODE_POINTOPOINT|SSH_TUNMODE_ETHERNET)

#define SSH_TUNID_ANY		0x7fffffff
#define SSH_TUNID_ERR		(SSH_TUNID_ANY - 1)
#define SSH_TUNID_MAX		(SSH_TUNID_ANY - 2)

/* Fake port to indicate that host field is really a path. */
#define PORT_STREAMLOCAL	-2

/* Functions to extract or store big-endian words of various sizes */
uint64_t	get_u64(અચલ શૂન્ય *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(અચલ શૂન્ય *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(અચલ શૂન્ય *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
શૂન્ય		put_u64(શૂન્ય *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
શૂન્ય		put_u32(શૂન્ય *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
શૂન્ય		put_u16(શૂન્ય *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(અચલ શૂન્ય *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
શૂન્ય		put_u32_le(શૂન્ય *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

સંરચના bwlimit {
	size_t buflen;
	uint64_t rate;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	સંરચના timeval bwstart, bwend;
};

શૂન્ય bandwidth_limit_init(સંરચના bwlimit *, uint64_t, size_t);
શૂન્ય bandwidth_limit(સંરચના bwlimit *, size_t);

પૂર્ણાંક parse_ipqos(અચલ અક્ષર *);
અચલ અક્ષર *iptos2str(પૂર્ણાંક);
શૂન્ય mktemp_proto(અક્ષર *, size_t);

શૂન્ય	 child_set_env(અક્ષર ***envp, u_int *envsizep, અચલ અક્ષર *name,
	    અચલ અક્ષર *કિંમત);
અચલ અક્ષર *lookup_env_in_list(અચલ અક્ષર *env,
	    અક્ષર * અચલ *envs, size_t nenvs);
અચલ અક્ષર *lookup_setenv_in_list(અચલ અક્ષર *env,
	    અક્ષર * અચલ *envs, size_t nenvs);

પૂર્ણાંક	 argv_split(અચલ અક્ષર *, પૂર્ણાંક *, અક્ષર ***, પૂર્ણાંક);
અક્ષર	*argv_assemble(પૂર્ણાંક, અક્ષર **argv);
અક્ષર	*argv_next(પૂર્ણાંક *, અક્ષર ***);
શૂન્ય	 argv_consume(પૂર્ણાંક *);
શૂન્ય	 argv_free(અક્ષર **, પૂર્ણાંક);

પૂર્ણાંક	 exited_cleanly(pid_t, અચલ અક્ષર *, અચલ અક્ષર *, પૂર્ણાંક);

સંરચના stat;
પૂર્ણાંક	 safe_path(અચલ અક્ષર *, સંરચના stat *, અચલ અક્ષર *, uid_t,
	    અક્ષર *, size_t);
પૂર્ણાંક	 safe_path_fd(પૂર્ણાંક, અચલ અક્ષર *, સંરચના passwd *,
	    અક્ષર *err, size_t errlen);

/* authorized_key-style options parsing helpers */
પૂર્ણાંક	opt_flag(અચલ અક્ષર *opt, પૂર્ણાંક allow_negate, અચલ અક્ષર **optsp);
અક્ષર	*opt_dequote(અચલ અક્ષર **sp, અચલ અક્ષર **errstrp);
પૂર્ણાંક	opt_match(અચલ અક્ષર **opts, અચલ અક્ષર *term);

/* readconf/servconf option lists */
શૂન્ય	opt_array_append(અચલ અક્ષર *file, અચલ પૂર્ણાંક લીટી,
	    અચલ અક્ષર *directive, અક્ષર ***array, u_int *lp, અચલ અક્ષર *s);
શૂન્ય	opt_array_append2(અચલ અક્ષર *file, અચલ પૂર્ણાંક લીટી,
	    અચલ અક્ષર *directive, અક્ષર ***array, પૂર્ણાંક **iarray, u_int *lp,
	    અચલ અક્ષર *s, પૂર્ણાંક i);
શૂન્ય	opt_array_free2(અક્ષર **array, પૂર્ણાંક **iarray, u_int l);

સંરચના timespec;
શૂન્ય ptimeout_init(સંરચના timespec *pt);
શૂન્ય ptimeout_deadline_sec(સંરચના timespec *pt, long sec);
શૂન્ય ptimeout_deadline_ms(સંરચના timespec *pt, long ms);
શૂન્ય ptimeout_deadline_sec_double(સંરચના timespec *pt, દ્વિગુણ sec);
શૂન્ય ptimeout_deadline_monotime_tsp(સંરચના timespec *pt, સંરચના timespec *when);
શૂન્ય ptimeout_deadline_monotime(સંરચના timespec *pt, time_t when);
શૂન્ય ptimeout_deadline_monotime_double(સંરચના timespec *pt, દ્વિગુણ when);
પૂર્ણાંક ptimeout_get_ms(સંરચના timespec *pt);
સંરચના timespec *ptimeout_get_tsp(સંરચના timespec *pt);
પૂર્ણાંક ptimeout_isset(સંરચના timespec *pt);

/* misc-agent.c */
પૂર્ણાંક	 agent_listener(અચલ અક્ષર *, અચલ અક્ષર *, uid_t, અચલ અક્ષર *,
	    pid_t, અચલ અક્ષર *, પૂર્ણાંક *, અક્ષર **, અક્ષર **);
શૂન્ય	 agent_cleanup_stale(અચલ અક્ષર *, અચલ અક્ષર *, uid_t,
	    અચલ અક્ષર *, પૂર્ણાંક);
પૂર્ણાંક	 agent_listener_cleanup(અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *);

/* readpass.c */

#define RP_ECHO			0x0001
#define RP_ALLOW_STDIN		0x0002
#define RP_ALLOW_EOF		0x0004
#define RP_USE_ASKPASS		0x0008

સંરચના notifier_ctx;

અક્ષર	*read_passphrase(અચલ અક્ષર *, પૂર્ણાંક);
પૂર્ણાંક	 ask_permission(અચલ અક્ષર *, ...) __attribute__((format(printf, 1, 2)));
સંરચના notifier_ctx *notify_start(પૂર્ણાંક, અચલ અક્ષર *, ...)
	__attribute__((format(printf, 2, 3)));
શૂન્ય	notify_complete(સંરચના notifier_ctx *, અચલ અક્ષર *, ...)
	__attribute__((format(printf, 2, 3)));

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))
#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

પ્રકારવ્યાખ્યા શૂન્ય (*sshsig_t)(પૂર્ણાંક);
sshsig_t ssh_signal(પૂર્ણાંક, sshsig_t);
પૂર્ણાંક signal_is_crash(પૂર્ણાંક);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#define FD_CLOSEONEXEC(x) કરો { \
	જો (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    strerror(errno)); \
} જ્યારે (0)

#endif /* _MISC_H */
