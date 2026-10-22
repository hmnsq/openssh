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

#অন্তর্ভাব <sys/time.h>
#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <signal.h>

/* special-case port number meaning allow any port */
#define FWD_PERMIT_ANY_PORT	0

/* special-case wildcard meaning allow any host */
#define FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
কাঠামো Forward {
	অক্ষর	 *listen_host;		/* Host (address) to listen on. */
	পূর্ণসংখ্যা	  listen_port;		/* Port to forward. */
	অক্ষর	 *listen_path;		/* Path to bind domain socket. */
	অক্ষর	 *connect_host;		/* Host to connect. */
	পূর্ণসংখ্যা	  connect_port;		/* Port to connect on connect_host. */
	অক্ষর	 *connect_path;		/* Path to connect domain socket. */
	পূর্ণসংখ্যা	  allocated_port;	/* Dynamically allocated listen port */
	পূর্ণসংখ্যা	  handle;		/* Handle for dynamic listen ports */
};

পূর্ণসংখ্যা forward_equals(ধ্রুবক কাঠামো Forward *, ধ্রুবক কাঠামো Forward *);
পূর্ণসংখ্যা permitopen_port(ধ্রুবক অক্ষর *p);

পূর্ণসংখ্যা daemonized(শূন্য);

/* Common server and client forwarding options. */
কাঠামো ForwardOptions {
	পূর্ণসংখ্যা	 gateway_ports; /* Allow remote connects to forwarded ports. */
	mode_t	 streamlocal_bind_mask; /* umask for streamlocal binds */
	পূর্ণসংখ্যা	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

অক্ষর	*chop(অক্ষর *);
শূন্য	 rtrim(অক্ষর *);
শূন্য	skip_space(অক্ষর **);
ধ্রুবক অক্ষর *strprefix(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);
অক্ষর	*strdelim(অক্ষর **);
অক্ষর	*strdelimw(অক্ষর **);
শূন্য	 stringlist_append(অক্ষর ***listp, ধ্রুবক অক্ষর *s);
শূন্য	 stringlist_free(অক্ষর **list);
পূর্ণসংখ্যা	 set_nonblock(পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 unset_nonblock(পূর্ণসংখ্যা);
শূন্য	 set_nodelay(পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 set_reuseaddr(পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 set_keepalive(পূর্ণসংখ্যা);
অক্ষর	*get_rdomain(পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 set_rdomain(পূর্ণসংখ্যা, ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 get_sock_af(পূর্ণসংখ্যা);
শূন্য	 set_sock_tos(পূর্ণসংখ্যা, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 waitrfd(পূর্ণসংখ্যা, পূর্ণসংখ্যা *, অস্থির sig_atomic_t *);
পূর্ণসংখ্যা	 timeout_connect(পূর্ণসংখ্যা, ধ্রুবক কাঠামো sockaddr *, socklen_t, পূর্ণসংখ্যা *);
পূর্ণসংখ্যা	 a2port(ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 a2tun(ধ্রুবক অক্ষর *, পূর্ণসংখ্যা *);
অক্ষর	*put_host_port(ধ্রুবক অক্ষর *, u_short);
অক্ষর	*hpdelim2(অক্ষর **, অক্ষর *);
অক্ষর	*hpdelim(অক্ষর **);
অক্ষর	*cleanhostname(অক্ষর *);
অক্ষর	*colon(অক্ষর *);
পূর্ণসংখ্যা	 parse_user_host_path(ধ্রুবক অক্ষর *, অক্ষর **, অক্ষর **, অক্ষর **);
পূর্ণসংখ্যা	 parse_user_host_port(ধ্রুবক অক্ষর *, অক্ষর **, অক্ষর **, পূর্ণসংখ্যা *);
পূর্ণসংখ্যা	 parse_uri(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, অক্ষর **, অক্ষর **, পূর্ণসংখ্যা *, অক্ষর **);
দ্বিগুণ	 convtime_double(ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 convtime(ধ্রুবক অক্ষর *);
দ্বিগুণ	 convtime_double(ধ্রুবক অক্ষর *);
ধ্রুবক অক্ষর *fmt_timeframe(time_t t);
পূর্ণসংখ্যা	 tilde_expand(ধ্রুবক অক্ষর *, uid_t, অক্ষর **);
অক্ষর	*tilde_expand_filename(ধ্রুবক অক্ষর *, uid_t);

অক্ষর	*dollar_expand(পূর্ণসংখ্যা *, ধ্রুবক অক্ষর *string, ...);
অক্ষর	*percent_expand(ধ্রুবক অক্ষর *, ...) __attribute__((__sentinel__));
অক্ষর	*percent_dollar_expand(ধ্রুবক অক্ষর *, ...) __attribute__((__sentinel__));
অক্ষর	*tohex(ধ্রুবক শূন্য *, আকার_t);
শূন্য	 xextendf(অক্ষর **s, ধ্রুবক অক্ষর *sep, ধ্রুবক অক্ষর *fmt, ...)
    __attribute__((__format__ (printf, 3, 4))) __attribute__((__nonnull__ (3)));
শূন্য	 sanitise_stdfd(শূন্য);
শূন্য	 ms_subtract_diff(কাঠামো timeval *, পূর্ণসংখ্যা *);
শূন্য	 ms_to_timespec(কাঠামো timespec *, পূর্ণসংখ্যা);
শূন্য	 monotime_ts(কাঠামো timespec *);
শূন্য	 monotime_tv(কাঠামো timeval *);
time_t	 monotime(শূন্য);
দ্বিগুণ	 monotime_double(শূন্য);
শূন্য	 lowercase(অক্ষর *s);
পূর্ণসংখ্যা	 unix_listener(ধ্রুবক অক্ষর *, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 valid_domain(অক্ষর *, পূর্ণসংখ্যা, ধ্রুবক অক্ষর **);
পূর্ণসংখ্যা	 valid_env_name(ধ্রুবক অক্ষর *);
ধ্রুবক অক্ষর *atoi_err(ধ্রুবক অক্ষর *, পূর্ণসংখ্যা *);
পূর্ণসংখ্যা	 parse_absolute_time(ধ্রুবক অক্ষর *, uint64_t *);
শূন্য	 format_absolute_time(uint64_t, অক্ষর *, আকার_t);
পূর্ণসংখ্যা	 parse_pattern_interval(ধ্রুবক অক্ষর *, অক্ষর **, দ্বিগুণ *);
পূর্ণসংখ্যা	 path_absolute(ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 stdfd_devnull(পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 lib_contains_প্রতীক(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
অক্ষর	*get_homedir(শূন্য);
পূর্ণসংখ্যা	 mkdir_path(ধ্রুবক অক্ষর *, mode_t);

শূন্য	 sock_set_v6only(পূর্ণসংখ্যা);

কাঠামো passwd *pwcopy(কাঠামো passwd *);
শূন্য	 pwfree(কাঠামো passwd *); /* NB. only use with pwcopy */

ধ্রুবক অক্ষর *ssh_gai_strerror(পূর্ণসংখ্যা);

প্রকারলেখ শূন্য privdrop_fn(কাঠামো passwd *);
প্রকারলেখ শূন্য privrestore_fn(শূন্য);
#define	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#define	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#define	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#define	SSH_SUBPROCESS_UNSAFE_PATH	(1<<3)	/* Don't check for safe cmd */
#define	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা, অক্ষর **, FILE **, u_int,
    কাঠামো passwd *, privdrop_fn *, privrestore_fn *);

প্রকারলেখ কাঠামো arglist arglist;
কাঠামো arglist {
	অক্ষর    **list;
	u_int   অঙ্ক;
	u_int   nalloc;
};
শূন্য	 addargs(arglist *, অক্ষর *, ...)
	    __attribute__((format(printf, 2, 3)));
শূন্য	 replacearg(arglist *, u_int, অক্ষর *, ...)
	    __attribute__((format(printf, 3, 4)));
শূন্য	 freeargs(arglist *);

পূর্ণসংখ্যা	 tun_open(পূর্ণসংখ্যা, পূর্ণসংখ্যা, অক্ষর **);

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
uint64_t	get_u64(ধ্রুবক শূন্য *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(ধ্রুবক শূন্য *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(ধ্রুবক শূন্য *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
শূন্য		put_u64(শূন্য *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
শূন্য		put_u32(শূন্য *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
শূন্য		put_u16(শূন্য *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(ধ্রুবক শূন্য *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
শূন্য		put_u32_le(শূন্য *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

কাঠামো bwlimit {
	আকার_t buflen;
	uint64_t rate;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	কাঠামো timeval bwstart, bwend;
};

শূন্য bandwidth_limit_init(কাঠামো bwlimit *, uint64_t, আকার_t);
শূন্য bandwidth_limit(কাঠামো bwlimit *, আকার_t);

পূর্ণসংখ্যা parse_ipqos(ধ্রুবক অক্ষর *);
ধ্রুবক অক্ষর *iptos2str(পূর্ণসংখ্যা);
শূন্য mktemp_proto(অক্ষর *, আকার_t);

শূন্য	 child_set_env(অক্ষর ***envp, u_int *envsizep, ধ্রুবক অক্ষর *name,
	    ধ্রুবক অক্ষর *মান);
ধ্রুবক অক্ষর *lookup_env_in_list(ধ্রুবক অক্ষর *env,
	    অক্ষর * ধ্রুবক *envs, আকার_t nenvs);
ধ্রুবক অক্ষর *lookup_setenv_in_list(ধ্রুবক অক্ষর *env,
	    অক্ষর * ধ্রুবক *envs, আকার_t nenvs);

পূর্ণসংখ্যা	 argv_split(ধ্রুবক অক্ষর *, পূর্ণসংখ্যা *, অক্ষর ***, পূর্ণসংখ্যা);
অক্ষর	*argv_assemble(পূর্ণসংখ্যা, অক্ষর **argv);
অক্ষর	*argv_পরবর্তী(পূর্ণসংখ্যা *, অক্ষর ***);
শূন্য	 argv_consume(পূর্ণসংখ্যা *);
শূন্য	 argv_free(অক্ষর **, পূর্ণসংখ্যা);

পূর্ণসংখ্যা	 exited_cleanly(pid_t, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);

কাঠামো stat;
পূর্ণসংখ্যা	 safe_path(ধ্রুবক অক্ষর *, কাঠামো stat *, ধ্রুবক অক্ষর *, uid_t,
	    অক্ষর *, আকার_t);
পূর্ণসংখ্যা	 safe_path_fd(পূর্ণসংখ্যা, ধ্রুবক অক্ষর *, কাঠামো passwd *,
	    অক্ষর *err, আকার_t errlen);

/* authorized_key-style options parsing helpers */
পূর্ণসংখ্যা	opt_flag(ধ্রুবক অক্ষর *opt, পূর্ণসংখ্যা allow_negate, ধ্রুবক অক্ষর **optsp);
অক্ষর	*opt_dequote(ধ্রুবক অক্ষর **sp, ধ্রুবক অক্ষর **errstrp);
পূর্ণসংখ্যা	opt_match(ধ্রুবক অক্ষর **opts, ধ্রুবক অক্ষর *term);

/* readconf/servconf option lists */
শূন্য	opt_array_append(ধ্রুবক অক্ষর *file, ধ্রুবক পূর্ণসংখ্যা সারি,
	    ধ্রুবক অক্ষর *directive, অক্ষর ***array, u_int *lp, ধ্রুবক অক্ষর *s);
শূন্য	opt_array_append2(ধ্রুবক অক্ষর *file, ধ্রুবক পূর্ণসংখ্যা সারি,
	    ধ্রুবক অক্ষর *directive, অক্ষর ***array, পূর্ণসংখ্যা **iarray, u_int *lp,
	    ধ্রুবক অক্ষর *s, পূর্ণসংখ্যা i);
শূন্য	opt_array_free2(অক্ষর **array, পূর্ণসংখ্যা **iarray, u_int l);

কাঠামো timespec;
শূন্য ptimeout_init(কাঠামো timespec *pt);
শূন্য ptimeout_deadline_sec(কাঠামো timespec *pt, long sec);
শূন্য ptimeout_deadline_ms(কাঠামো timespec *pt, long ms);
শূন্য ptimeout_deadline_sec_double(কাঠামো timespec *pt, দ্বিগুণ sec);
শূন্য ptimeout_deadline_monotime_tsp(কাঠামো timespec *pt, কাঠামো timespec *when);
শূন্য ptimeout_deadline_monotime(কাঠামো timespec *pt, time_t when);
শূন্য ptimeout_deadline_monotime_double(কাঠামো timespec *pt, দ্বিগুণ when);
পূর্ণসংখ্যা ptimeout_get_ms(কাঠামো timespec *pt);
কাঠামো timespec *ptimeout_get_tsp(কাঠামো timespec *pt);
পূর্ণসংখ্যা ptimeout_isset(কাঠামো timespec *pt);

/* misc-agent.c */
পূর্ণসংখ্যা	 agent_listener(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, uid_t, ধ্রুবক অক্ষর *,
	    pid_t, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা *, অক্ষর **, অক্ষর **);
শূন্য	 agent_cleanup_stale(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, uid_t,
	    ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 agent_listener_cleanup(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);

/* readpass.c */

#define RP_ECHO			0x0001
#define RP_ALLOW_STDIN		0x0002
#define RP_ALLOW_EOF		0x0004
#define RP_USE_ASKPASS		0x0008

কাঠামো notifier_ctx;

অক্ষর	*read_passphrase(ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 ask_permission(ধ্রুবক অক্ষর *, ...) __attribute__((format(printf, 1, 2)));
কাঠামো notifier_ctx *notify_start(পূর্ণসংখ্যা, ধ্রুবক অক্ষর *, ...)
	__attribute__((format(printf, 2, 3)));
শূন্য	notify_complete(কাঠামো notifier_ctx *, ধ্রুবক অক্ষর *, ...)
	__attribute__((format(printf, 2, 3)));

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))
#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

প্রকারলেখ শূন্য (*sshsig_t)(পূর্ণসংখ্যা);
sshsig_t ssh_signal(পূর্ণসংখ্যা, sshsig_t);
পূর্ণসংখ্যা signal_is_crash(পূর্ণসংখ্যা);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#define FD_CLOSEONEXEC(x) করো { \
	যদি (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    strerror(errno)); \
} যখন (0)

#endif /* _MISC_H */
