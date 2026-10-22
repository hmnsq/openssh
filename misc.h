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

#অন্তর্ভাৱ <sys/time.h>
#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/socket.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <signal.h>

/* special-case port number meaning allow any port */
#define FWD_PERMIT_ANY_PORT	0

/* special-case wildcard meaning allow any host */
#define FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
সংরচনা Forward {
	ৱর্ণ	 *listen_host;		/* Host (address) to listen on. */
	পূর্ণাঙ্ক	  listen_port;		/* Port to forward. */
	ৱর্ণ	 *listen_path;		/* Path to bind domain socket. */
	ৱর্ণ	 *connect_host;		/* Host to connect. */
	পূর্ণাঙ্ক	  connect_port;		/* Port to connect on connect_host. */
	ৱর্ণ	 *connect_path;		/* Path to connect domain socket. */
	পূর্ণাঙ্ক	  allocated_port;	/* Dynamically allocated listen port */
	পূর্ণাঙ্ক	  handle;		/* Handle for dynamic listen ports */
};

পূর্ণাঙ্ক forward_equals(ধ্রুৱ সংরচনা Forward *, ধ্রুৱ সংরচনা Forward *);
পূর্ণাঙ্ক permitopen_port(ধ্রুৱ ৱর্ণ *p);

পূর্ণাঙ্ক daemonized(শূন্য);

/* Common server and client forwarding options. */
সংরচনা ForwardOptions {
	পূর্ণাঙ্ক	 gateway_ports; /* Allow remote connects to forwarded ports. */
	mode_t	 streamlocal_bind_mask; /* umask for streamlocal binds */
	পূর্ণাঙ্ক	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

ৱর্ণ	*chop(ৱর্ণ *);
শূন্য	 rtrim(ৱর্ণ *);
শূন্য	skip_space(ৱর্ণ **);
ধ্রুৱ ৱর্ণ *strprefix(ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক);
ৱর্ণ	*strdelim(ৱর্ণ **);
ৱর্ণ	*strdelimw(ৱর্ণ **);
শূন্য	 stringlist_append(ৱর্ণ ***listp, ধ্রুৱ ৱর্ণ *s);
শূন্য	 stringlist_free(ৱর্ণ **list);
পূর্ণাঙ্ক	 set_nonblock(পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 unset_nonblock(পূর্ণাঙ্ক);
শূন্য	 set_nodelay(পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 set_reuseaddr(পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 set_keepalive(পূর্ণাঙ্ক);
ৱর্ণ	*get_rdomain(পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 set_rdomain(পূর্ণাঙ্ক, ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 get_sock_af(পূর্ণাঙ্ক);
শূন্য	 set_sock_tos(পূর্ণাঙ্ক, পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 waitrfd(পূর্ণাঙ্ক, পূর্ণাঙ্ক *, চঞ্চল sig_atomic_t *);
পূর্ণাঙ্ক	 timeout_connect(পূর্ণাঙ্ক, ধ্রুৱ সংরচনা sockaddr *, socklen_t, পূর্ণাঙ্ক *);
পূর্ণাঙ্ক	 a2port(ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 a2tun(ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক *);
ৱর্ণ	*put_host_port(ধ্রুৱ ৱর্ণ *, u_short);
ৱর্ণ	*hpdelim2(ৱর্ণ **, ৱর্ণ *);
ৱর্ণ	*hpdelim(ৱর্ণ **);
ৱর্ণ	*cleanhostname(ৱর্ণ *);
ৱর্ণ	*colon(ৱর্ণ *);
পূর্ণাঙ্ক	 parse_user_host_path(ধ্রুৱ ৱর্ণ *, ৱর্ণ **, ৱর্ণ **, ৱর্ণ **);
পূর্ণাঙ্ক	 parse_user_host_port(ধ্রুৱ ৱর্ণ *, ৱর্ণ **, ৱর্ণ **, পূর্ণাঙ্ক *);
পূর্ণাঙ্ক	 parse_uri(ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, ৱর্ণ **, ৱর্ণ **, পূর্ণাঙ্ক *, ৱর্ণ **);
দ্ৱিগুণ	 convtime_double(ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 convtime(ধ্রুৱ ৱর্ণ *);
দ্ৱিগুণ	 convtime_double(ধ্রুৱ ৱর্ণ *);
ধ্রুৱ ৱর্ণ *fmt_timeframe(time_t t);
পূর্ণাঙ্ক	 tilde_expand(ধ্রুৱ ৱর্ণ *, uid_t, ৱর্ণ **);
ৱর্ণ	*tilde_expand_filename(ধ্রুৱ ৱর্ণ *, uid_t);

ৱর্ণ	*dollar_expand(পূর্ণাঙ্ক *, ধ্রুৱ ৱর্ণ *string, ...);
ৱর্ণ	*percent_expand(ধ্রুৱ ৱর্ণ *, ...) __attribute__((__sentinel__));
ৱর্ণ	*percent_dollar_expand(ধ্রুৱ ৱর্ণ *, ...) __attribute__((__sentinel__));
ৱর্ণ	*tohex(ধ্রুৱ শূন্য *, size_t);
শূন্য	 xextendf(ৱর্ণ **s, ধ্রুৱ ৱর্ণ *sep, ধ্রুৱ ৱর্ণ *fmt, ...)
    __attribute__((__format__ (printf, 3, 4))) __attribute__((__nonnull__ (3)));
শূন্য	 sanitise_stdfd(শূন্য);
শূন্য	 ms_subtract_diff(সংরচনা timeval *, পূর্ণাঙ্ক *);
শূন্য	 ms_to_timespec(সংরচনা timespec *, পূর্ণাঙ্ক);
শূন্য	 monotime_ts(সংরচনা timespec *);
শূন্য	 monotime_tv(সংরচনা timeval *);
time_t	 monotime(শূন্য);
দ্ৱিগুণ	 monotime_double(শূন্য);
শূন্য	 lowercase(ৱর্ণ *s);
পূর্ণাঙ্ক	 unix_listener(ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক, পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 valid_domain(ৱর্ণ *, পূর্ণাঙ্ক, ধ্রুৱ ৱর্ণ **);
পূর্ণাঙ্ক	 valid_env_name(ধ্রুৱ ৱর্ণ *);
ধ্রুৱ ৱর্ণ *atoi_err(ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক *);
পূর্ণাঙ্ক	 parse_absolute_time(ধ্রুৱ ৱর্ণ *, uint64_t *);
শূন্য	 format_absolute_time(uint64_t, ৱর্ণ *, size_t);
পূর্ণাঙ্ক	 parse_pattern_interval(ধ্রুৱ ৱর্ণ *, ৱর্ণ **, দ্ৱিগুণ *);
পূর্ণাঙ্ক	 path_absolute(ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 stdfd_devnull(পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 lib_contains_প্ৰতীক(ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *);
ৱর্ণ	*get_homedir(শূন্য);
পূর্ণাঙ্ক	 mkdir_path(ধ্রুৱ ৱর্ণ *, mode_t);

শূন্য	 sock_set_v6only(পূর্ণাঙ্ক);

সংরচনা passwd *pwcopy(সংরচনা passwd *);
শূন্য	 pwfree(সংরচনা passwd *); /* NB. only use with pwcopy */

ধ্রুৱ ৱর্ণ *ssh_gai_strerror(পূর্ণাঙ্ক);

প্রকারনির্দেশ শূন্য privdrop_fn(সংরচনা passwd *);
প্রকারনির্দেশ শূন্য privrestore_fn(শূন্য);
#define	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#define	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#define	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#define	SSH_SUBPROCESS_UNSAFE_PATH	(1<<3)	/* Don't check for safe cmd */
#define	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক, ৱর্ণ **, FILE **, u_int,
    সংরচনা passwd *, privdrop_fn *, privrestore_fn *);

প্রকারনির্দেশ সংরচনা arglist arglist;
সংরচনা arglist {
	ৱর্ণ    **list;
	u_int   অঙ্ক;
	u_int   nalloc;
};
শূন্য	 addargs(arglist *, ৱর্ণ *, ...)
	    __attribute__((format(printf, 2, 3)));
শূন্য	 replacearg(arglist *, u_int, ৱর্ণ *, ...)
	    __attribute__((format(printf, 3, 4)));
শূন্য	 freeargs(arglist *);

পূর্ণাঙ্ক	 tun_open(পূর্ণাঙ্ক, পূর্ণাঙ্ক, ৱর্ণ **);

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
uint64_t	get_u64(ধ্রুৱ শূন্য *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(ধ্রুৱ শূন্য *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(ধ্রুৱ শূন্য *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
শূন্য		put_u64(শূন্য *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
শূন্য		put_u32(শূন্য *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
শূন্য		put_u16(শূন্য *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(ধ্রুৱ শূন্য *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
শূন্য		put_u32_le(শূন্য *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

সংরচনা bwlimit {
	size_t buflen;
	uint64_t rate;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	সংরচনা timeval bwstart, bwend;
};

শূন্য bandwidth_limit_init(সংরচনা bwlimit *, uint64_t, size_t);
শূন্য bandwidth_limit(সংরচনা bwlimit *, size_t);

পূর্ণাঙ্ক parse_ipqos(ধ্রুৱ ৱর্ণ *);
ধ্রুৱ ৱর্ণ *iptos2str(পূর্ণাঙ্ক);
শূন্য mktemp_proto(ৱর্ণ *, size_t);

শূন্য	 child_set_env(ৱর্ণ ***envp, u_int *envsizep, ধ্রুৱ ৱর্ণ *name,
	    ধ্রুৱ ৱর্ণ *মান);
ধ্রুৱ ৱর্ণ *lookup_env_in_list(ধ্রুৱ ৱর্ণ *env,
	    ৱর্ণ * ধ্রুৱ *envs, size_t nenvs);
ধ্রুৱ ৱর্ণ *lookup_setenv_in_list(ধ্রুৱ ৱর্ণ *env,
	    ৱর্ণ * ধ্রুৱ *envs, size_t nenvs);

পূর্ণাঙ্ক	 argv_split(ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক *, ৱর্ণ ***, পূর্ণাঙ্ক);
ৱর্ণ	*argv_assemble(পূর্ণাঙ্ক, ৱর্ণ **argv);
ৱর্ণ	*argv_next(পূর্ণাঙ্ক *, ৱর্ণ ***);
শূন্য	 argv_consume(পূর্ণাঙ্ক *);
শূন্য	 argv_free(ৱর্ণ **, পূর্ণাঙ্ক);

পূর্ণাঙ্ক	 exited_cleanly(pid_t, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক);

সংরচনা stat;
পূর্ণাঙ্ক	 safe_path(ধ্রুৱ ৱর্ণ *, সংরচনা stat *, ধ্রুৱ ৱর্ণ *, uid_t,
	    ৱর্ণ *, size_t);
পূর্ণাঙ্ক	 safe_path_fd(পূর্ণাঙ্ক, ধ্রুৱ ৱর্ণ *, সংরচনা passwd *,
	    ৱর্ণ *err, size_t errlen);

/* authorized_key-style options parsing helpers */
পূর্ণাঙ্ক	opt_flag(ধ্রুৱ ৱর্ণ *opt, পূর্ণাঙ্ক allow_negate, ধ্রুৱ ৱর্ণ **optsp);
ৱর্ণ	*opt_dequote(ধ্রুৱ ৱর্ণ **sp, ধ্রুৱ ৱর্ণ **errstrp);
পূর্ণাঙ্ক	opt_match(ধ্রুৱ ৱর্ণ **opts, ধ্রুৱ ৱর্ণ *term);

/* readconf/servconf option lists */
শূন্য	opt_array_append(ধ্রুৱ ৱর্ণ *file, ধ্রুৱ পূর্ণাঙ্ক সাৰি,
	    ধ্রুৱ ৱর্ণ *directive, ৱর্ণ ***array, u_int *lp, ধ্রুৱ ৱর্ণ *s);
শূন্য	opt_array_append2(ধ্রুৱ ৱর্ণ *file, ধ্রুৱ পূর্ণাঙ্ক সাৰি,
	    ধ্রুৱ ৱর্ণ *directive, ৱর্ণ ***array, পূর্ণাঙ্ক **iarray, u_int *lp,
	    ধ্রুৱ ৱর্ণ *s, পূর্ণাঙ্ক i);
শূন্য	opt_array_free2(ৱর্ণ **array, পূর্ণাঙ্ক **iarray, u_int l);

সংরচনা timespec;
শূন্য ptimeout_init(সংরচনা timespec *pt);
শূন্য ptimeout_deadline_sec(সংরচনা timespec *pt, long sec);
শূন্য ptimeout_deadline_ms(সংরচনা timespec *pt, long ms);
শূন্য ptimeout_deadline_sec_double(সংরচনা timespec *pt, দ্ৱিগুণ sec);
শূন্য ptimeout_deadline_monotime_tsp(সংরচনা timespec *pt, সংরচনা timespec *when);
শূন্য ptimeout_deadline_monotime(সংরচনা timespec *pt, time_t when);
শূন্য ptimeout_deadline_monotime_double(সংরচনা timespec *pt, দ্ৱিগুণ when);
পূর্ণাঙ্ক ptimeout_get_ms(সংরচনা timespec *pt);
সংরচনা timespec *ptimeout_get_tsp(সংরচনা timespec *pt);
পূর্ণাঙ্ক ptimeout_isset(সংরচনা timespec *pt);

/* misc-agent.c */
পূর্ণাঙ্ক	 agent_listener(ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, uid_t, ধ্রুৱ ৱর্ণ *,
	    pid_t, ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক *, ৱর্ণ **, ৱর্ণ **);
শূন্য	 agent_cleanup_stale(ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, uid_t,
	    ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 agent_listener_cleanup(ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *);

/* readpass.c */

#define RP_ECHO			0x0001
#define RP_ALLOW_STDIN		0x0002
#define RP_ALLOW_EOF		0x0004
#define RP_USE_ASKPASS		0x0008

সংরচনা notifier_ctx;

ৱর্ণ	*read_passphrase(ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 ask_permission(ধ্রুৱ ৱর্ণ *, ...) __attribute__((format(printf, 1, 2)));
সংরচনা notifier_ctx *notify_start(পূর্ণাঙ্ক, ধ্রুৱ ৱর্ণ *, ...)
	__attribute__((format(printf, 2, 3)));
শূন্য	notify_complete(সংরচনা notifier_ctx *, ধ্রুৱ ৱর্ণ *, ...)
	__attribute__((format(printf, 2, 3)));

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))
#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

প্রকারনির্দেশ শূন্য (*sshsig_t)(পূর্ণাঙ্ক);
sshsig_t ssh_signal(পূর্ণাঙ্ক, sshsig_t);
পূর্ণাঙ্ক signal_is_crash(পূর্ণাঙ্ক);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#define FD_CLOSEONEXEC(x) কৰা { \
	যদি (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    strerror(errno)); \
} যেতিয়ালৈ (0)

#endif /* _MISC_H */
