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

#شامل <sys/time.h>
#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <stdio.h>
#شامل <signal.h>

/* special-case port number meaning allow any port */
#define FWD_PERMIT_ANY_PORT	0

/* special-case wildcard meaning allow any host */
#define FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
ساختار Forward {
	نویسه	 *listen_host;		/* Host (address) to listen on. */
	صحیح	  listen_port;		/* Port to forward. */
	نویسه	 *listen_path;		/* Path to bind domain socket. */
	نویسه	 *connect_host;		/* Host to connect. */
	صحیح	  connect_port;		/* Port to connect on connect_host. */
	نویسه	 *connect_path;		/* Path to connect domain socket. */
	صحیح	  allocated_port;	/* Dynamically allocated listen port */
	صحیح	  handle;		/* Handle for dynamic listen ports */
};

صحیح forward_equals(ثابت ساختار Forward *, ثابت ساختار Forward *);
صحیح permitopen_port(ثابت نویسه *p);

صحیح daemonized(تهی);

/* Common server and client forwarding options. */
ساختار ForwardOptions {
	صحیح	 gateway_ports; /* Allow remote connects to forwarded ports. */
	mode_t	 streamlocal_bind_mask; /* umask for streamlocal binds */
	صحیح	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

نویسه	*chop(نویسه *);
تهی	 rtrim(نویسه *);
تهی	skip_space(نویسه **);
ثابت نویسه *strprefix(ثابت نویسه *, ثابت نویسه *, صحیح);
نویسه	*strdelim(نویسه **);
نویسه	*strdelimw(نویسه **);
تهی	 stringlist_append(نویسه ***listp, ثابت نویسه *s);
تهی	 stringlist_free(نویسه **list);
صحیح	 set_nonblock(صحیح);
صحیح	 unset_nonblock(صحیح);
تهی	 set_nodelay(صحیح);
صحیح	 set_reuseaddr(صحیح);
صحیح	 set_keepalive(صحیح);
نویسه	*get_rdomain(صحیح);
صحیح	 set_rdomain(صحیح, ثابت نویسه *);
صحیح	 get_sock_af(صحیح);
تهی	 set_sock_tos(صحیح, صحیح);
صحیح	 waitrfd(صحیح, صحیح *, فرار sig_atomic_t *);
صحیح	 timeout_connect(صحیح, ثابت ساختار sockaddr *, socklen_t, صحیح *);
صحیح	 a2port(ثابت نویسه *);
صحیح	 a2tun(ثابت نویسه *, صحیح *);
نویسه	*put_host_port(ثابت نویسه *, u_short);
نویسه	*hpdelim2(نویسه **, نویسه *);
نویسه	*hpdelim(نویسه **);
نویسه	*cleanhostname(نویسه *);
نویسه	*colon(نویسه *);
صحیح	 parse_user_host_path(ثابت نویسه *, نویسه **, نویسه **, نویسه **);
صحیح	 parse_user_host_port(ثابت نویسه *, نویسه **, نویسه **, صحیح *);
صحیح	 parse_uri(ثابت نویسه *, ثابت نویسه *, نویسه **, نویسه **, صحیح *, نویسه **);
دوگانه	 convtime_double(ثابت نویسه *);
صحیح	 convtime(ثابت نویسه *);
دوگانه	 convtime_double(ثابت نویسه *);
ثابت نویسه *fmt_timeframe(time_t t);
صحیح	 tilde_expand(ثابت نویسه *, uid_t, نویسه **);
نویسه	*tilde_expand_filename(ثابت نویسه *, uid_t);

نویسه	*dollar_expand(صحیح *, ثابت نویسه *string, ...);
نویسه	*percent_expand(ثابت نویسه *, ...) __attribute__((__sentinel__));
نویسه	*percent_dollar_expand(ثابت نویسه *, ...) __attribute__((__sentinel__));
نویسه	*tohex(ثابت تهی *, size_t);
تهی	 xextendf(نویسه **s, ثابت نویسه *sep, ثابت نویسه *fmt, ...)
    __attribute__((__format__ (printf, 3, 4))) __attribute__((__nonnull__ (3)));
تهی	 sanitise_stdfd(تهی);
تهی	 ms_subtract_diff(ساختار timeval *, صحیح *);
تهی	 ms_to_timespec(ساختار timespec *, صحیح);
تهی	 monotime_ts(ساختار timespec *);
تهی	 monotime_tv(ساختار timeval *);
time_t	 monotime(تهی);
دوگانه	 monotime_double(تهی);
تهی	 lowercase(نویسه *s);
صحیح	 unix_listener(ثابت نویسه *, صحیح, صحیح);
صحیح	 valid_domain(نویسه *, صحیح, ثابت نویسه **);
صحیح	 valid_env_name(ثابت نویسه *);
ثابت نویسه *atoi_err(ثابت نویسه *, صحیح *);
صحیح	 parse_absolute_time(ثابت نویسه *, uint64_t *);
تهی	 format_absolute_time(uint64_t, نویسه *, size_t);
صحیح	 parse_pattern_interval(ثابت نویسه *, نویسه **, دوگانه *);
صحیح	 path_absolute(ثابت نویسه *);
صحیح	 stdfd_devnull(صحیح, صحیح, صحیح);
صحیح	 lib_contains_نماد(ثابت نویسه *, ثابت نویسه *);
نویسه	*get_homedir(تهی);
صحیح	 mkdir_path(ثابت نویسه *, mode_t);

تهی	 sock_set_v6only(صحیح);

ساختار passwd *pwcopy(ساختار passwd *);
تهی	 pwfree(ساختار passwd *); /* NB. only use with pwcopy */

ثابت نویسه *ssh_gai_strerror(صحیح);

تعریفنوع تهی privdrop_fn(ساختار passwd *);
تعریفنوع تهی privrestore_fn(تهی);
#define	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#define	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#define	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#define	SSH_SUBPROCESS_UNSAFE_PATH	(1<<3)	/* Don't check for safe cmd */
#define	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(ثابت نویسه *, ثابت نویسه *, صحیح, نویسه **, FILE **, u_int,
    ساختار passwd *, privdrop_fn *, privrestore_fn *);

تعریفنوع ساختار arglist arglist;
ساختار arglist {
	نویسه    **list;
	u_int   رقم;
	u_int   nalloc;
};
تهی	 addargs(arglist *, نویسه *, ...)
	    __attribute__((format(printf, 2, 3)));
تهی	 replacearg(arglist *, u_int, نویسه *, ...)
	    __attribute__((format(printf, 3, 4)));
تهی	 freeargs(arglist *);

صحیح	 tun_open(صحیح, صحیح, نویسه **);

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
uint64_t	get_u64(ثابت تهی *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(ثابت تهی *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(ثابت تهی *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
تهی		put_u64(تهی *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
تهی		put_u32(تهی *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
تهی		put_u16(تهی *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(ثابت تهی *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
تهی		put_u32_le(تهی *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

ساختار bwlimit {
	size_t buflen;
	uint64_t rate;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	ساختار timeval bwstart, bwend;
};

تهی bandwidth_limit_init(ساختار bwlimit *, uint64_t, size_t);
تهی bandwidth_limit(ساختار bwlimit *, size_t);

صحیح parse_ipqos(ثابت نویسه *);
ثابت نویسه *iptos2str(صحیح);
تهی mktemp_proto(نویسه *, size_t);

تهی	 child_set_env(نویسه ***envp, u_int *envsizep, ثابت نویسه *name,
	    ثابت نویسه *مقدار);
ثابت نویسه *lookup_env_in_list(ثابت نویسه *env,
	    نویسه * ثابت *envs, size_t nenvs);
ثابت نویسه *lookup_setenv_in_list(ثابت نویسه *env,
	    نویسه * ثابت *envs, size_t nenvs);

صحیح	 argv_split(ثابت نویسه *, صحیح *, نویسه ***, صحیح);
نویسه	*argv_assemble(صحیح, نویسه **argv);
نویسه	*argv_next(صحیح *, نویسه ***);
تهی	 argv_consume(صحیح *);
تهی	 argv_free(نویسه **, صحیح);

صحیح	 exited_cleanly(pid_t, ثابت نویسه *, ثابت نویسه *, صحیح);

ساختار stat;
صحیح	 safe_path(ثابت نویسه *, ساختار stat *, ثابت نویسه *, uid_t,
	    نویسه *, size_t);
صحیح	 safe_path_fd(صحیح, ثابت نویسه *, ساختار passwd *,
	    نویسه *err, size_t errlen);

/* authorized_key-style options parsing helpers */
صحیح	opt_flag(ثابت نویسه *opt, صحیح allow_negate, ثابت نویسه **optsp);
نویسه	*opt_dequote(ثابت نویسه **sp, ثابت نویسه **errstrp);
صحیح	opt_match(ثابت نویسه **opts, ثابت نویسه *term);

/* readconf/servconf option lists */
تهی	opt_array_append(ثابت نویسه *file, ثابت صحیح سطر,
	    ثابت نویسه *directive, نویسه ***array, u_int *lp, ثابت نویسه *s);
تهی	opt_array_append2(ثابت نویسه *file, ثابت صحیح سطر,
	    ثابت نویسه *directive, نویسه ***array, صحیح **iarray, u_int *lp,
	    ثابت نویسه *s, صحیح i);
تهی	opt_array_free2(نویسه **array, صحیح **iarray, u_int l);

ساختار timespec;
تهی ptimeout_init(ساختار timespec *pt);
تهی ptimeout_deadline_sec(ساختار timespec *pt, long sec);
تهی ptimeout_deadline_ms(ساختار timespec *pt, long ms);
تهی ptimeout_deadline_sec_double(ساختار timespec *pt, دوگانه sec);
تهی ptimeout_deadline_monotime_tsp(ساختار timespec *pt, ساختار timespec *when);
تهی ptimeout_deadline_monotime(ساختار timespec *pt, time_t when);
تهی ptimeout_deadline_monotime_double(ساختار timespec *pt, دوگانه when);
صحیح ptimeout_get_ms(ساختار timespec *pt);
ساختار timespec *ptimeout_get_tsp(ساختار timespec *pt);
صحیح ptimeout_isset(ساختار timespec *pt);

/* misc-agent.c */
صحیح	 agent_listener(ثابت نویسه *, ثابت نویسه *, uid_t, ثابت نویسه *,
	    pid_t, ثابت نویسه *, صحیح *, نویسه **, نویسه **);
تهی	 agent_cleanup_stale(ثابت نویسه *, ثابت نویسه *, uid_t,
	    ثابت نویسه *, صحیح);
صحیح	 agent_listener_cleanup(ثابت نویسه *, ثابت نویسه *, ثابت نویسه *);

/* readpass.c */

#define RP_ECHO			0x0001
#define RP_ALLOW_STDIN		0x0002
#define RP_ALLOW_EOF		0x0004
#define RP_USE_ASKPASS		0x0008

ساختار notifier_ctx;

نویسه	*read_passphrase(ثابت نویسه *, صحیح);
صحیح	 ask_permission(ثابت نویسه *, ...) __attribute__((format(printf, 1, 2)));
ساختار notifier_ctx *notify_start(صحیح, ثابت نویسه *, ...)
	__attribute__((format(printf, 2, 3)));
تهی	notify_complete(ساختار notifier_ctx *, ثابت نویسه *, ...)
	__attribute__((format(printf, 2, 3)));

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))
#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

تعریفنوع تهی (*sshsig_t)(صحیح);
sshsig_t ssh_signal(صحیح, sshsig_t);
صحیح signal_is_crash(صحیح);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#define FD_CLOSEONEXEC(x) انجامبده { \
	اگر (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    strerror(errno)); \
} وقتی (0)

#endif /* _MISC_H */
