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

#அந்தர்பாவ <sys/time.h>
#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <signal.h>

/* special-case port number meaning allow any port */
#define FWD_PERMIT_ANY_PORT	0

/* special-case wildcard meaning allow any host */
#define FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
கட்டமைப்பு Forward {
	எழுத்து	 *listen_host;		/* Host (address) to listen on. */
	முழு	  listen_port;		/* Port to forward. */
	எழுத்து	 *listen_path;		/* Path to bind domain socket. */
	எழுத்து	 *connect_host;		/* Host to connect. */
	முழு	  connect_port;		/* Port to connect on connect_host. */
	எழுத்து	 *connect_path;		/* Path to connect domain socket. */
	முழு	  allocated_port;	/* Dynamically allocated listen port */
	முழு	  handle;		/* Handle for dynamic listen ports */
};

முழு forward_equals(மாறிலி கட்டமைப்பு Forward *, மாறிலி கட்டமைப்பு Forward *);
முழு permitopen_port(மாறிலி எழுத்து *p);

முழு daemonized(வெறுமை);

/* Common server and client forwarding options. */
கட்டமைப்பு ForwardOptions {
	முழு	 gateway_ports; /* Allow remote connects to forwarded ports. */
	mode_t	 streamlocal_bind_mask; /* umask for streamlocal binds */
	முழு	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

எழுத்து	*chop(எழுத்து *);
வெறுமை	 rtrim(எழுத்து *);
வெறுமை	skip_space(எழுத்து **);
மாறிலி எழுத்து *strprefix(மாறிலி எழுத்து *, மாறிலி எழுத்து *, முழு);
எழுத்து	*strdelim(எழுத்து **);
எழுத்து	*strdelimw(எழுத்து **);
வெறுமை	 stringlist_append(எழுத்து ***listp, மாறிலி எழுத்து *s);
வெறுமை	 stringlist_free(எழுத்து **list);
முழு	 set_nonblock(முழு);
முழு	 unset_nonblock(முழு);
வெறுமை	 set_nodelay(முழு);
முழு	 set_reuseaddr(முழு);
முழு	 set_keepalive(முழு);
எழுத்து	*get_rdomain(முழு);
முழு	 set_rdomain(முழு, மாறிலி எழுத்து *);
முழு	 get_sock_af(முழு);
வெறுமை	 set_sock_tos(முழு, முழு);
முழு	 waitrfd(முழு, முழு *, நிலையற்ற sig_atomic_t *);
முழு	 timeout_connect(முழு, மாறிலி கட்டமைப்பு sockaddr *, socklen_t, முழு *);
முழு	 a2port(மாறிலி எழுத்து *);
முழு	 a2tun(மாறிலி எழுத்து *, முழு *);
எழுத்து	*put_host_port(மாறிலி எழுத்து *, u_short);
எழுத்து	*hpdelim2(எழுத்து **, எழுத்து *);
எழுத்து	*hpdelim(எழுத்து **);
எழுத்து	*cleanhostname(எழுத்து *);
எழுத்து	*colon(எழுத்து *);
முழு	 parse_user_host_path(மாறிலி எழுத்து *, எழுத்து **, எழுத்து **, எழுத்து **);
முழு	 parse_user_host_port(மாறிலி எழுத்து *, எழுத்து **, எழுத்து **, முழு *);
முழு	 parse_uri(மாறிலி எழுத்து *, மாறிலி எழுத்து *, எழுத்து **, எழுத்து **, முழு *, எழுத்து **);
இரட்டை	 convtime_double(மாறிலி எழுத்து *);
முழு	 convtime(மாறிலி எழுத்து *);
இரட்டை	 convtime_double(மாறிலி எழுத்து *);
மாறிலி எழுத்து *fmt_timeframe(time_t t);
முழு	 tilde_expand(மாறிலி எழுத்து *, uid_t, எழுத்து **);
எழுத்து	*tilde_expand_filename(மாறிலி எழுத்து *, uid_t);

எழுத்து	*dollar_expand(முழு *, மாறிலி எழுத்து *string, ...);
எழுத்து	*percent_expand(மாறிலி எழுத்து *, ...) __attribute__((__sentinel__));
எழுத்து	*percent_dollar_expand(மாறிலி எழுத்து *, ...) __attribute__((__sentinel__));
எழுத்து	*tohex(மாறிலி வெறுமை *, size_t);
வெறுமை	 xextendf(எழுத்து **s, மாறிலி எழுத்து *sep, மாறிலி எழுத்து *fmt, ...)
    __attribute__((__format__ (printf, 3, 4))) __attribute__((__nonnull__ (3)));
வெறுமை	 sanitise_stdfd(வெறுமை);
வெறுமை	 ms_subtract_diff(கட்டமைப்பு timeval *, முழு *);
வெறுமை	 ms_to_timespec(கட்டமைப்பு timespec *, முழு);
வெறுமை	 monotime_ts(கட்டமைப்பு timespec *);
வெறுமை	 monotime_tv(கட்டமைப்பு timeval *);
time_t	 monotime(வெறுமை);
இரட்டை	 monotime_double(வெறுமை);
வெறுமை	 lowercase(எழுத்து *s);
முழு	 unix_listener(மாறிலி எழுத்து *, முழு, முழு);
முழு	 valid_domain(எழுத்து *, முழு, மாறிலி எழுத்து **);
முழு	 valid_env_name(மாறிலி எழுத்து *);
மாறிலி எழுத்து *atoi_err(மாறிலி எழுத்து *, முழு *);
முழு	 parse_absolute_time(மாறிலி எழுத்து *, uint64_t *);
வெறுமை	 format_absolute_time(uint64_t, எழுத்து *, size_t);
முழு	 parse_pattern_interval(மாறிலி எழுத்து *, எழுத்து **, இரட்டை *);
முழு	 path_absolute(மாறிலி எழுத்து *);
முழு	 stdfd_devnull(முழு, முழு, முழு);
முழு	 lib_contains_குறியீடு(மாறிலி எழுத்து *, மாறிலி எழுத்து *);
எழுத்து	*get_homedir(வெறுமை);
முழு	 mkdir_path(மாறிலி எழுத்து *, mode_t);

வெறுமை	 sock_set_v6only(முழு);

கட்டமைப்பு passwd *pwcopy(கட்டமைப்பு passwd *);
வெறுமை	 pwfree(கட்டமைப்பு passwd *); /* NB. only use with pwcopy */

மாறிலி எழுத்து *ssh_gai_strerror(முழு);

வகைவரை வெறுமை privdrop_fn(கட்டமைப்பு passwd *);
வகைவரை வெறுமை privrestore_fn(வெறுமை);
#define	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#define	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#define	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#define	SSH_SUBPROCESS_UNSAFE_PATH	(1<<3)	/* Don't check for safe cmd */
#define	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(மாறிலி எழுத்து *, மாறிலி எழுத்து *, முழு, எழுத்து **, FILE **, u_int,
    கட்டமைப்பு passwd *, privdrop_fn *, privrestore_fn *);

வகைவரை கட்டமைப்பு arglist arglist;
கட்டமைப்பு arglist {
	எழுத்து    **list;
	u_int   இலக்கம்;
	u_int   nalloc;
};
வெறுமை	 addargs(arglist *, எழுத்து *, ...)
	    __attribute__((format(printf, 2, 3)));
வெறுமை	 replacearg(arglist *, u_int, எழுத்து *, ...)
	    __attribute__((format(printf, 3, 4)));
வெறுமை	 freeargs(arglist *);

முழு	 tun_open(முழு, முழு, எழுத்து **);

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
uint64_t	get_u64(மாறிலி வெறுமை *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(மாறிலி வெறுமை *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(மாறிலி வெறுமை *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
வெறுமை		put_u64(வெறுமை *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
வெறுமை		put_u32(வெறுமை *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
வெறுமை		put_u16(வெறுமை *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(மாறிலி வெறுமை *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
வெறுமை		put_u32_le(வெறுமை *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

கட்டமைப்பு bwlimit {
	size_t buflen;
	uint64_t rate;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	கட்டமைப்பு timeval bwstart, bwend;
};

வெறுமை bandwidth_limit_init(கட்டமைப்பு bwlimit *, uint64_t, size_t);
வெறுமை bandwidth_limit(கட்டமைப்பு bwlimit *, size_t);

முழு parse_ipqos(மாறிலி எழுத்து *);
மாறிலி எழுத்து *iptos2str(முழு);
வெறுமை mktemp_proto(எழுத்து *, size_t);

வெறுமை	 child_set_env(எழுத்து ***envp, u_int *envsizep, மாறிலி எழுத்து *name,
	    மாறிலி எழுத்து *மதிப்பு);
மாறிலி எழுத்து *lookup_env_in_list(மாறிலி எழுத்து *env,
	    எழுத்து * மாறிலி *envs, size_t nenvs);
மாறிலி எழுத்து *lookup_setenv_in_list(மாறிலி எழுத்து *env,
	    எழுத்து * மாறிலி *envs, size_t nenvs);

முழு	 argv_split(மாறிலி எழுத்து *, முழு *, எழுத்து ***, முழு);
எழுத்து	*argv_assemble(முழு, எழுத்து **argv);
எழுத்து	*argv_next(முழு *, எழுத்து ***);
வெறுமை	 argv_consume(முழு *);
வெறுமை	 argv_free(எழுத்து **, முழு);

முழு	 exited_cleanly(pid_t, மாறிலி எழுத்து *, மாறிலி எழுத்து *, முழு);

கட்டமைப்பு stat;
முழு	 safe_path(மாறிலி எழுத்து *, கட்டமைப்பு stat *, மாறிலி எழுத்து *, uid_t,
	    எழுத்து *, size_t);
முழு	 safe_path_fd(முழு, மாறிலி எழுத்து *, கட்டமைப்பு passwd *,
	    எழுத்து *err, size_t errlen);

/* authorized_key-style options parsing helpers */
முழு	opt_flag(மாறிலி எழுத்து *opt, முழு allow_negate, மாறிலி எழுத்து **optsp);
எழுத்து	*opt_dequote(மாறிலி எழுத்து **sp, மாறிலி எழுத்து **errstrp);
முழு	opt_match(மாறிலி எழுத்து **opts, மாறிலி எழுத்து *term);

/* readconf/servconf option lists */
வெறுமை	opt_array_append(மாறிலி எழுத்து *file, மாறிலி முழு வரி,
	    மாறிலி எழுத்து *directive, எழுத்து ***array, u_int *lp, மாறிலி எழுத்து *s);
வெறுமை	opt_array_append2(மாறிலி எழுத்து *file, மாறிலி முழு வரி,
	    மாறிலி எழுத்து *directive, எழுத்து ***array, முழு **iarray, u_int *lp,
	    மாறிலி எழுத்து *s, முழு i);
வெறுமை	opt_array_free2(எழுத்து **array, முழு **iarray, u_int l);

கட்டமைப்பு timespec;
வெறுமை ptimeout_init(கட்டமைப்பு timespec *pt);
வெறுமை ptimeout_deadline_sec(கட்டமைப்பு timespec *pt, long sec);
வெறுமை ptimeout_deadline_ms(கட்டமைப்பு timespec *pt, long ms);
வெறுமை ptimeout_deadline_sec_double(கட்டமைப்பு timespec *pt, இரட்டை sec);
வெறுமை ptimeout_deadline_monotime_tsp(கட்டமைப்பு timespec *pt, கட்டமைப்பு timespec *when);
வெறுமை ptimeout_deadline_monotime(கட்டமைப்பு timespec *pt, time_t when);
வெறுமை ptimeout_deadline_monotime_double(கட்டமைப்பு timespec *pt, இரட்டை when);
முழு ptimeout_get_ms(கட்டமைப்பு timespec *pt);
கட்டமைப்பு timespec *ptimeout_get_tsp(கட்டமைப்பு timespec *pt);
முழு ptimeout_isset(கட்டமைப்பு timespec *pt);

/* misc-agent.c */
முழு	 agent_listener(மாறிலி எழுத்து *, மாறிலி எழுத்து *, uid_t, மாறிலி எழுத்து *,
	    pid_t, மாறிலி எழுத்து *, முழு *, எழுத்து **, எழுத்து **);
வெறுமை	 agent_cleanup_stale(மாறிலி எழுத்து *, மாறிலி எழுத்து *, uid_t,
	    மாறிலி எழுத்து *, முழு);
முழு	 agent_listener_cleanup(மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *);

/* readpass.c */

#define RP_ECHO			0x0001
#define RP_ALLOW_STDIN		0x0002
#define RP_ALLOW_EOF		0x0004
#define RP_USE_ASKPASS		0x0008

கட்டமைப்பு notifier_ctx;

எழுத்து	*read_passphrase(மாறிலி எழுத்து *, முழு);
முழு	 ask_permission(மாறிலி எழுத்து *, ...) __attribute__((format(printf, 1, 2)));
கட்டமைப்பு notifier_ctx *notify_start(முழு, மாறிலி எழுத்து *, ...)
	__attribute__((format(printf, 2, 3)));
வெறுமை	notify_complete(கட்டமைப்பு notifier_ctx *, மாறிலி எழுத்து *, ...)
	__attribute__((format(printf, 2, 3)));

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))
#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

வகைவரை வெறுமை (*sshsig_t)(முழு);
sshsig_t ssh_signal(முழு, sshsig_t);
முழு signal_is_crash(முழு);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#define FD_CLOSEONEXEC(x) செய் { \
	எனில் (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    strerror(errno)); \
} போது (0)

#endif /* _MISC_H */
