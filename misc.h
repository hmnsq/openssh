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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _MISC_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _MISC_H

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>

/* special-case port number meaning allow any port */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FWD_PERMIT_ANY_ਪੋਰਟ	0

/* special-case wildcard meaning allow any host */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
ਬਣਤਰ Forward {
	ਅੱਖਰ	 *listen_host;		/* Host (address) to listen on. */
	ਪੂਰਨ	  listen_ਪੋਰਟ;		/* Port to forward. */
	ਅੱਖਰ	 *listen_ਰਸਤਾ;		/* Path to bind domain socket. */
	ਅੱਖਰ	 *connect_host;		/* Host to connect. */
	ਪੂਰਨ	  connect_ਪੋਰਟ;		/* Port to connect on connect_host. */
	ਅੱਖਰ	 *connect_ਰਸਤਾ;		/* Path to connect domain socket. */
	ਪੂਰਨ	  allocated_ਪੋਰਟ;	/* Dynamically allocated listen port */
	ਪੂਰਨ	  handle;		/* Handle for dynamic listen ports */
};

ਪੂਰਨ forward_equals(ਅਚਲ ਬਣਤਰ Forward *, ਅਚਲ ਬਣਤਰ Forward *);
ਪੂਰਨ permitopen_ਪੋਰਟ(ਅਚਲ ਅੱਖਰ *p);

ਪੂਰਨ daemonized(ਖਾਲੀ);

/* Common server and client forwarding options. */
ਬਣਤਰ ForwardOptions {
	ਪੂਰਨ	 gateway_ports; /* Allow remote connects to forwarded ports. */
	ਬਹੁਲਕ_t	 streamlocal_bind_ਨਕਾਬ; /* umask for streamlocal binds */
	ਪੂਰਨ	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

ਅੱਖਰ	*chop(ਅੱਖਰ *);
ਖਾਲੀ	 rtrim(ਅੱਖਰ *);
ਖਾਲੀ	skip_space(ਅੱਖਰ **);
ਅਚਲ ਅੱਖਰ *strprefix(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);
ਅੱਖਰ	*strdelim(ਅੱਖਰ **);
ਅੱਖਰ	*strdelimw(ਅੱਖਰ **);
ਖਾਲੀ	 stringlist_append(ਅੱਖਰ ***listp, ਅਚਲ ਅੱਖਰ *s);
ਖਾਲੀ	 stringlist_free(ਅੱਖਰ **list);
ਪੂਰਨ	 ਸੈੱਟ_nonblock(ਪੂਰਨ);
ਪੂਰਨ	 unset_nonblock(ਪੂਰਨ);
ਖਾਲੀ	 ਸੈੱਟ_nodelay(ਪੂਰਨ);
ਪੂਰਨ	 ਸੈੱਟ_reuseaddr(ਪੂਰਨ);
ਪੂਰਨ	 ਸੈੱਟ_keepalive(ਪੂਰਨ);
ਅੱਖਰ	*get_rdomain(ਪੂਰਨ);
ਪੂਰਨ	 ਸੈੱਟ_rdomain(ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 get_sock_af(ਪੂਰਨ);
ਖਾਲੀ	 ਸੈੱਟ_sock_tos(ਪੂਰਨ, ਪੂਰਨ);
ਪੂਰਨ	 waitrfd(ਪੂਰਨ, ਪੂਰਨ *, ਅਸਥਿਰ sig_atomic_t *);
ਪੂਰਨ	 timeout_connect(ਪੂਰਨ, ਅਚਲ ਬਣਤਰ sockaddr *, socklen_t, ਪੂਰਨ *);
ਪੂਰਨ	 a2port(ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 a2tun(ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ *);
ਅੱਖਰ	*put_host_ਪੋਰਟ(ਅਚਲ ਅੱਖਰ *, u_short);
ਅੱਖਰ	*hpdelim2(ਅੱਖਰ **, ਅੱਖਰ *);
ਅੱਖਰ	*hpdelim(ਅੱਖਰ **);
ਅੱਖਰ	*cleanhostname(ਅੱਖਰ *);
ਅੱਖਰ	*colon(ਅੱਖਰ *);
ਪੂਰਨ	 parse_user_host_ਰਸਤਾ(ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ **, ਅੱਖਰ **, ਅੱਖਰ **);
ਪੂਰਨ	 parse_user_host_ਪੋਰਟ(ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ **, ਅੱਖਰ **, ਪੂਰਨ *);
ਪੂਰਨ	 parse_uri(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ **, ਅੱਖਰ **, ਪੂਰਨ *, ਅੱਖਰ **);
ਦੁੱਗਣਾ	 convtime_double(ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 convtime(ਅਚਲ ਅੱਖਰ *);
ਦੁੱਗਣਾ	 convtime_double(ਅਚਲ ਅੱਖਰ *);
ਅਚਲ ਅੱਖਰ *fmt_timeframe(time_t t);
ਪੂਰਨ	 tilde_expand(ਅਚਲ ਅੱਖਰ *, uid_t, ਅੱਖਰ **);
ਅੱਖਰ	*tilde_expand_filename(ਅਚਲ ਅੱਖਰ *, uid_t);

ਅੱਖਰ	*dollar_expand(ਪੂਰਨ *, ਅਚਲ ਅੱਖਰ *string, ...);
ਅੱਖਰ	*percent_expand(ਅਚਲ ਅੱਖਰ *, ...) __attribute__((__sentinel__));
ਅੱਖਰ	*percent_dollar_expand(ਅਚਲ ਅੱਖਰ *, ...) __attribute__((__sentinel__));
ਅੱਖਰ	*tohex(ਅਚਲ ਖਾਲੀ *, ਮਾਪ_t);
ਖਾਲੀ	 xextendf(ਅੱਖਰ **s, ਅਚਲ ਅੱਖਰ *sep, ਅਚਲ ਅੱਖਰ *fmt, ...)
    __attribute__((__format__ (ਲਿਖੋ, 3, 4))) __attribute__((__nonnull__ (3)));
ਖਾਲੀ	 sanitise_stdfd(ਖਾਲੀ);
ਖਾਲੀ	 ms_ਘਟਾਓ_diff(ਬਣਤਰ timeval *, ਪੂਰਨ *);
ਖਾਲੀ	 ms_ਮੰਜ਼ਿਲ_timespec(ਬਣਤਰ timespec *, ਪੂਰਨ);
ਖਾਲੀ	 monotime_ts(ਬਣਤਰ timespec *);
ਖਾਲੀ	 monotime_tv(ਬਣਤਰ timeval *);
time_t	 monotime(ਖਾਲੀ);
ਦੁੱਗਣਾ	 monotime_double(ਖਾਲੀ);
ਖਾਲੀ	 lowercase(ਅੱਖਰ *s);
ਪੂਰਨ	 unix_listener(ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ, ਪੂਰਨ);
ਪੂਰਨ	 valid_domain(ਅੱਖਰ *, ਪੂਰਨ, ਅਚਲ ਅੱਖਰ **);
ਪੂਰਨ	 valid_env_name(ਅਚਲ ਅੱਖਰ *);
ਅਚਲ ਅੱਖਰ *atoi_err(ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ *);
ਪੂਰਨ	 parse_absolute_ਸਮਾਂ(ਅਚਲ ਅੱਖਰ *, uint64_t *);
ਖਾਲੀ	 format_absolute_ਸਮਾਂ(uint64_t, ਅੱਖਰ *, ਮਾਪ_t);
ਪੂਰਨ	 parse_ਨਮੂਨਾ_interval(ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ **, ਦੁੱਗਣਾ *);
ਪੂਰਨ	 ਰਸਤਾ_absolute(ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 stdfd_devnull(ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ);
ਪੂਰਨ	 lib_ਸ਼ਾਮਲ_ਹੈ_ਚਿੰਨ੍ਹ(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਅੱਖਰ	*get_homedir(ਖਾਲੀ);
ਪੂਰਨ	 mkdir_ਰਸਤਾ(ਅਚਲ ਅੱਖਰ *, ਬਹੁਲਕ_t);

ਖਾਲੀ	 sock_ਸੈੱਟ_v6only(ਪੂਰਨ);

ਬਣਤਰ passwd *pwcopy(ਬਣਤਰ passwd *);
ਖਾਲੀ	 pwfree(ਬਣਤਰ passwd *); /* NB. only use with pwcopy */

ਅਚਲ ਅੱਖਰ *ssh_gai_strerror(ਪੂਰਨ);

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ privdrop_fn(ਬਣਤਰ passwd *);
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ privrestore_fn(ਖਾਲੀ);
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_SUBPROCESS_UNSAFE_ਰਸਤਾ	(1<<3)	/* Don't check for safe cmd */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ, ਅੱਖਰ **, FILE **, u_int,
    ਬਣਤਰ passwd *, privdrop_fn *, privrestore_fn *);

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ arglist arglist;
ਬਣਤਰ arglist {
	ਅੱਖਰ    **list;
	u_int   ਅੰਕ;
	u_int   nalloc;
};
ਖਾਲੀ	 addargs(arglist *, ਅੱਖਰ *, ...)
	    __attribute__((format(ਲਿਖੋ, 2, 3)));
ਖਾਲੀ	 replacearg(arglist *, u_int, ਅੱਖਰ *, ...)
	    __attribute__((format(ਲਿਖੋ, 3, 4)));
ਖਾਲੀ	 freeargs(arglist *);

ਪੂਰਨ	 tun_open(ਪੂਰਨ, ਪੂਰਨ, ਅੱਖਰ **);

/* Common definitions for ssh tunnel device forwarding */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_TUNMODE_NO		0x00
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_TUNMODE_POINTOPOINT	0x01
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_TUNMODE_ETHERNET	0x02
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_TUNMODE_DEFAULT	SSH_TUNMODE_POINTOPOINT
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_TUNMODE_YES		(SSH_TUNMODE_POINTOPOINT|SSH_TUNMODE_ETHERNET)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_TUNID_ANY		0x7fffffff
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_TUNID_ERR		(SSH_TUNID_ANY - 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_TUNID_MAX		(SSH_TUNID_ANY - 2)

/* Fake port to indicate that host field is really a path. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਪੋਰਟ_STREAMLOCAL	-2

/* Functions to extract or store big-endian words of various sizes */
uint64_t	get_u64(ਅਚਲ ਖਾਲੀ *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(ਅਚਲ ਖਾਲੀ *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(ਅਚਲ ਖਾਲੀ *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
ਖਾਲੀ		put_u64(ਖਾਲੀ *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
ਖਾਲੀ		put_u32(ਖਾਲੀ *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
ਖਾਲੀ		put_u16(ਖਾਲੀ *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(ਅਚਲ ਖਾਲੀ *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
ਖਾਲੀ		put_u32_le(ਖਾਲੀ *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

ਬਣਤਰ bwlimit {
	ਮਾਪ_t buflen;
	uint64_t ਦਰ;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	ਬਣਤਰ timeval bwstart, bwend;
};

ਖਾਲੀ bandwidth_ਹੱਦਬੰਦੀ_init(ਬਣਤਰ bwlimit *, uint64_t, ਮਾਪ_t);
ਖਾਲੀ bandwidth_ਹੱਦਬੰਦੀ(ਬਣਤਰ bwlimit *, ਮਾਪ_t);

ਪੂਰਨ parse_ipqos(ਅਚਲ ਅੱਖਰ *);
ਅਚਲ ਅੱਖਰ *iptos2str(ਪੂਰਨ);
ਖਾਲੀ mktemp_proto(ਅੱਖਰ *, ਮਾਪ_t);

ਖਾਲੀ	 ਬੱਚਾ_ਸੈੱਟ_env(ਅੱਖਰ ***envp, u_int *envsizep, ਅਚਲ ਅੱਖਰ *name,
	    ਅਚਲ ਅੱਖਰ *ਮੁੱਲ);
ਅਚਲ ਅੱਖਰ *lookup_env_ਵਿੱਚ_list(ਅਚਲ ਅੱਖਰ *env,
	    ਅੱਖਰ * ਅਚਲ *envs, ਮਾਪ_t nenvs);
ਅਚਲ ਅੱਖਰ *lookup_setenv_ਵਿੱਚ_list(ਅਚਲ ਅੱਖਰ *env,
	    ਅੱਖਰ * ਅਚਲ *envs, ਮਾਪ_t nenvs);

ਪੂਰਨ	 argv_ਵੰਡੋ(ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ *, ਅੱਖਰ ***, ਪੂਰਨ);
ਅੱਖਰ	*argv_assemble(ਪੂਰਨ, ਅੱਖਰ **argv);
ਅੱਖਰ	*argv_ਅਗਲਾ(ਪੂਰਨ *, ਅੱਖਰ ***);
ਖਾਲੀ	 argv_consume(ਪੂਰਨ *);
ਖਾਲੀ	 argv_free(ਅੱਖਰ **, ਪੂਰਨ);

ਪੂਰਨ	 exited_cleanly(pid_t, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);

ਬਣਤਰ stat;
ਪੂਰਨ	 ਸੁਰੱਖਿਅਤ_ਰਸਤਾ(ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ stat *, ਅਚਲ ਅੱਖਰ *, uid_t,
	    ਅੱਖਰ *, ਮਾਪ_t);
ਪੂਰਨ	 ਸੁਰੱਖਿਅਤ_ਰਸਤਾ_fd(ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ passwd *,
	    ਅੱਖਰ *err, ਮਾਪ_t errlen);

/* authorized_key-style options parsing helpers */
ਪੂਰਨ	opt_flag(ਅਚਲ ਅੱਖਰ *opt, ਪੂਰਨ allow_negate, ਅਚਲ ਅੱਖਰ **optsp);
ਅੱਖਰ	*opt_dequote(ਅਚਲ ਅੱਖਰ **sp, ਅਚਲ ਅੱਖਰ **errstrp);
ਪੂਰਨ	opt_ਮੇਲ(ਅਚਲ ਅੱਖਰ **opts, ਅਚਲ ਅੱਖਰ *ਪਦ);

/* readconf/servconf option lists */
ਖਾਲੀ	opt_array_append(ਅਚਲ ਅੱਖਰ *file, ਅਚਲ ਪੂਰਨ ਸਤਰ,
	    ਅਚਲ ਅੱਖਰ *directive, ਅੱਖਰ ***array, u_int *lp, ਅਚਲ ਅੱਖਰ *s);
ਖਾਲੀ	opt_array_append2(ਅਚਲ ਅੱਖਰ *file, ਅਚਲ ਪੂਰਨ ਸਤਰ,
	    ਅਚਲ ਅੱਖਰ *directive, ਅੱਖਰ ***array, ਪੂਰਨ **iarray, u_int *lp,
	    ਅਚਲ ਅੱਖਰ *s, ਪੂਰਨ i);
ਖਾਲੀ	opt_array_free2(ਅੱਖਰ **array, ਪੂਰਨ **iarray, u_int l);

ਬਣਤਰ timespec;
ਖਾਲੀ ptimeout_init(ਬਣਤਰ timespec *pt);
ਖਾਲੀ ptimeout_deadline_sec(ਬਣਤਰ timespec *pt, ਲੰਮਾ sec);
ਖਾਲੀ ptimeout_deadline_ms(ਬਣਤਰ timespec *pt, ਲੰਮਾ ms);
ਖਾਲੀ ptimeout_deadline_sec_double(ਬਣਤਰ timespec *pt, ਦੁੱਗਣਾ sec);
ਖਾਲੀ ptimeout_deadline_monotime_tsp(ਬਣਤਰ timespec *pt, ਬਣਤਰ timespec *when);
ਖਾਲੀ ptimeout_deadline_monotime(ਬਣਤਰ timespec *pt, time_t when);
ਖਾਲੀ ptimeout_deadline_monotime_double(ਬਣਤਰ timespec *pt, ਦੁੱਗਣਾ when);
ਪੂਰਨ ptimeout_get_ms(ਬਣਤਰ timespec *pt);
ਬਣਤਰ timespec *ptimeout_get_tsp(ਬਣਤਰ timespec *pt);
ਪੂਰਨ ptimeout_isset(ਬਣਤਰ timespec *pt);

/* misc-agent.c */
ਪੂਰਨ	 agent_listener(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, uid_t, ਅਚਲ ਅੱਖਰ *,
	    pid_t, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ *, ਅੱਖਰ **, ਅੱਖਰ **);
ਖਾਲੀ	 agent_cleanup_stale(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, uid_t,
	    ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);
ਪੂਰਨ	 agent_listener_cleanup(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);

/* readpass.c */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RP_ECHO			0x0001
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RP_ALLOW_STDIN		0x0002
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RP_ALLOW_EOF		0x0004
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RP_USE_ASKPASS		0x0008

ਬਣਤਰ notifier_ctx;

ਅੱਖਰ	*read_passphrase(ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);
ਪੂਰਨ	 ask_permission(ਅਚਲ ਅੱਖਰ *, ...) __attribute__((format(ਲਿਖੋ, 1, 2)));
ਬਣਤਰ notifier_ctx *notify_ਸ਼ੁਰੂ(ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ...)
	__attribute__((format(ਲਿਖੋ, 2, 3)));
ਖਾਲੀ	notify_complete(ਬਣਤਰ notifier_ctx *, ਅਚਲ ਅੱਖਰ *, ...)
	__attribute__((format(ਲਿਖੋ, 2, 3)));

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਵੱਧ_ਤੋਂ_ਵੱਧ(a, b)	(((a) > (b)) ? (a) : (b))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ (*sshsig_t)(ਪੂਰਨ);
sshsig_t ssh_signal(ਪੂਰਨ, sshsig_t);
ਪੂਰਨ signal_is_crash(ਪੂਰਨ);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FD_CLOSEONEXEC(x) ਕਰੋ { \
	ਜੇ (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    strerror(errno)); \
} ਜਦੋਂ (0)

#ਜੇ_ਅੰਤ /* _MISC_H */
