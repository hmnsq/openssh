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

#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <signal.h>

/* special-case port number meaning allow any port */
#define FWD_PERMIT_ANY_PORT	0

/* special-case wildcard meaning allow any host */
#define FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
ಸಂರಚನಾ Forward {
	ವರ್ಣ	 *listen_host;		/* Host (address) to listen on. */
	ಪೂರ್ಣಾಙ್ಕ	  listen_port;		/* Port to forward. */
	ವರ್ಣ	 *listen_path;		/* Path to bind domain socket. */
	ವರ್ಣ	 *connect_host;		/* Host to connect. */
	ಪೂರ್ಣಾಙ್ಕ	  connect_port;		/* Port to connect on connect_host. */
	ವರ್ಣ	 *connect_path;		/* Path to connect domain socket. */
	ಪೂರ್ಣಾಙ್ಕ	  allocated_port;	/* Dynamically allocated listen port */
	ಪೂರ್ಣಾಙ್ಕ	  handle;		/* Handle for dynamic listen ports */
};

ಪೂರ್ಣಾಙ್ಕ forward_equals(ಧ್ರುವ ಸಂರಚನಾ Forward *, ಧ್ರುವ ಸಂರಚನಾ Forward *);
ಪೂರ್ಣಾಙ್ಕ permitopen_port(ಧ್ರುವ ವರ್ಣ *p);

ಪೂರ್ಣಾಙ್ಕ daemonized(ಶೂನ್ಯ);

/* Common server and client forwarding options. */
ಸಂರಚನಾ ForwardOptions {
	ಪೂರ್ಣಾಙ್ಕ	 gateway_ports; /* Allow remote connects to forwarded ports. */
	mode_t	 streamlocal_bind_mask; /* umask for streamlocal binds */
	ಪೂರ್ಣಾಙ್ಕ	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

ವರ್ಣ	*chop(ವರ್ಣ *);
ಶೂನ್ಯ	 rtrim(ವರ್ಣ *);
ಶೂನ್ಯ	skip_space(ವರ್ಣ **);
ಧ್ರುವ ವರ್ಣ *strprefix(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
ವರ್ಣ	*strdelim(ವರ್ಣ **);
ವರ್ಣ	*strdelimw(ವರ್ಣ **);
ಶೂನ್ಯ	 stringlist_append(ವರ್ಣ ***listp, ಧ್ರುವ ವರ್ಣ *s);
ಶೂನ್ಯ	 stringlist_free(ವರ್ಣ **list);
ಪೂರ್ಣಾಙ್ಕ	 set_nonblock(ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 unset_nonblock(ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 set_nodelay(ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 set_reuseaddr(ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 set_keepalive(ಪೂರ್ಣಾಙ್ಕ);
ವರ್ಣ	*get_rdomain(ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 set_rdomain(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 get_sock_af(ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 set_sock_tos(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 waitrfd(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ *, ಚಞ್ಚಲ sig_atomic_t *);
ಪೂರ್ಣಾಙ್ಕ	 timeout_connect(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ಸಂರಚನಾ sockaddr *, socklen_t, ಪೂರ್ಣಾಙ್ಕ *);
ಪೂರ್ಣಾಙ್ಕ	 a2port(ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 a2tun(ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ *);
ವರ್ಣ	*put_host_port(ಧ್ರುವ ವರ್ಣ *, u_short);
ವರ್ಣ	*hpdelim2(ವರ್ಣ **, ವರ್ಣ *);
ವರ್ಣ	*hpdelim(ವರ್ಣ **);
ವರ್ಣ	*cleanhostname(ವರ್ಣ *);
ವರ್ಣ	*colon(ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 parse_user_host_path(ಧ್ರುವ ವರ್ಣ *, ವರ್ಣ **, ವರ್ಣ **, ವರ್ಣ **);
ಪೂರ್ಣಾಙ್ಕ	 parse_user_host_port(ಧ್ರುವ ವರ್ಣ *, ವರ್ಣ **, ವರ್ಣ **, ಪೂರ್ಣಾಙ್ಕ *);
ಪೂರ್ಣಾಙ್ಕ	 parse_uri(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ವರ್ಣ **, ವರ್ಣ **, ಪೂರ್ಣಾಙ್ಕ *, ವರ್ಣ **);
ದ್ವಿಗುಣ	 convtime_double(ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 convtime(ಧ್ರುವ ವರ್ಣ *);
ದ್ವಿಗುಣ	 convtime_double(ಧ್ರುವ ವರ್ಣ *);
ಧ್ರುವ ವರ್ಣ *fmt_timeframe(time_t t);
ಪೂರ್ಣಾಙ್ಕ	 tilde_expand(ಧ್ರುವ ವರ್ಣ *, uid_t, ವರ್ಣ **);
ವರ್ಣ	*tilde_expand_filename(ಧ್ರುವ ವರ್ಣ *, uid_t);

ವರ್ಣ	*dollar_expand(ಪೂರ್ಣಾಙ್ಕ *, ಧ್ರುವ ವರ್ಣ *string, ...);
ವರ್ಣ	*percent_expand(ಧ್ರುವ ವರ್ಣ *, ...) __attribute__((__sentinel__));
ವರ್ಣ	*percent_dollar_expand(ಧ್ರುವ ವರ್ಣ *, ...) __attribute__((__sentinel__));
ವರ್ಣ	*tohex(ಧ್ರುವ ಶೂನ್ಯ *, size_t);
ಶೂನ್ಯ	 xextendf(ವರ್ಣ **s, ಧ್ರುವ ವರ್ಣ *sep, ಧ್ರುವ ವರ್ಣ *fmt, ...)
    __attribute__((__format__ (printf, 3, 4))) __attribute__((__nonnull__ (3)));
ಶೂನ್ಯ	 sanitise_stdfd(ಶೂನ್ಯ);
ಶೂನ್ಯ	 ms_subtract_diff(ಸಂರಚನಾ timeval *, ಪೂರ್ಣಾಙ್ಕ *);
ಶೂನ್ಯ	 ms_to_timespec(ಸಂರಚನಾ timespec *, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 monotime_ts(ಸಂರಚನಾ timespec *);
ಶೂನ್ಯ	 monotime_tv(ಸಂರಚನಾ timeval *);
time_t	 monotime(ಶೂನ್ಯ);
ದ್ವಿಗುಣ	 monotime_double(ಶೂನ್ಯ);
ಶೂನ್ಯ	 lowercase(ವರ್ಣ *s);
ಪೂರ್ಣಾಙ್ಕ	 unix_listener(ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 valid_domain(ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ **);
ಪೂರ್ಣಾಙ್ಕ	 valid_env_name(ಧ್ರುವ ವರ್ಣ *);
ಧ್ರುವ ವರ್ಣ *atoi_err(ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ *);
ಪೂರ್ಣಾಙ್ಕ	 parse_absolute_time(ಧ್ರುವ ವರ್ಣ *, uint64_t *);
ಶೂನ್ಯ	 format_absolute_time(uint64_t, ವರ್ಣ *, size_t);
ಪೂರ್ಣಾಙ್ಕ	 parse_pattern_interval(ಧ್ರುವ ವರ್ಣ *, ವರ್ಣ **, ದ್ವಿಗುಣ *);
ಪೂರ್ಣಾಙ್ಕ	 path_absolute(ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 stdfd_devnull(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 lib_contains_ಚಿಹ್ನೆ(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
ವರ್ಣ	*get_homedir(ಶೂನ್ಯ);
ಪೂರ್ಣಾಙ್ಕ	 mkdir_path(ಧ್ರುವ ವರ್ಣ *, mode_t);

ಶೂನ್ಯ	 sock_set_v6only(ಪೂರ್ಣಾಙ್ಕ);

ಸಂರಚನಾ passwd *pwcopy(ಸಂರಚನಾ passwd *);
ಶೂನ್ಯ	 pwfree(ಸಂರಚನಾ passwd *); /* NB. only use with pwcopy */

ಧ್ರುವ ವರ್ಣ *ssh_gai_strerror(ಪೂರ್ಣಾಙ್ಕ);

ಪ್ರಕಾರನಿರ್ದೇಶ ಶೂನ್ಯ privdrop_fn(ಸಂರಚನಾ passwd *);
ಪ್ರಕಾರನಿರ್ದೇಶ ಶೂನ್ಯ privrestore_fn(ಶೂನ್ಯ);
#define	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#define	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#define	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#define	SSH_SUBPROCESS_UNSAFE_PATH	(1<<3)	/* Don't check for safe cmd */
#define	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ **, FILE **, u_int,
    ಸಂರಚನಾ passwd *, privdrop_fn *, privrestore_fn *);

ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ arglist arglist;
ಸಂರಚನಾ arglist {
	ವರ್ಣ    **list;
	u_int   ಅಂಕೆ;
	u_int   nalloc;
};
ಶೂನ್ಯ	 addargs(arglist *, ವರ್ಣ *, ...)
	    __attribute__((format(printf, 2, 3)));
ಶೂನ್ಯ	 replacearg(arglist *, u_int, ವರ್ಣ *, ...)
	    __attribute__((format(printf, 3, 4)));
ಶೂನ್ಯ	 freeargs(arglist *);

ಪೂರ್ಣಾಙ್ಕ	 tun_open(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ **);

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
uint64_t	get_u64(ಧ್ರುವ ಶೂನ್ಯ *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(ಧ್ರುವ ಶೂನ್ಯ *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(ಧ್ರುವ ಶೂನ್ಯ *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
ಶೂನ್ಯ		put_u64(ಶೂನ್ಯ *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
ಶೂನ್ಯ		put_u32(ಶೂನ್ಯ *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
ಶೂನ್ಯ		put_u16(ಶೂನ್ಯ *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(ಧ್ರುವ ಶೂನ್ಯ *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
ಶೂನ್ಯ		put_u32_le(ಶೂನ್ಯ *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

ಸಂರಚನಾ bwlimit {
	size_t buflen;
	uint64_t rate;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	ಸಂರಚನಾ timeval bwstart, bwend;
};

ಶೂನ್ಯ bandwidth_limit_init(ಸಂರಚನಾ bwlimit *, uint64_t, size_t);
ಶೂನ್ಯ bandwidth_limit(ಸಂರಚನಾ bwlimit *, size_t);

ಪೂರ್ಣಾಙ್ಕ parse_ipqos(ಧ್ರುವ ವರ್ಣ *);
ಧ್ರುವ ವರ್ಣ *iptos2str(ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ mktemp_proto(ವರ್ಣ *, size_t);

ಶೂನ್ಯ	 child_set_env(ವರ್ಣ ***envp, u_int *envsizep, ಧ್ರುವ ವರ್ಣ *name,
	    ಧ್ರುವ ವರ್ಣ *ಮೌಲ್ಯ);
ಧ್ರುವ ವರ್ಣ *lookup_env_in_list(ಧ್ರುವ ವರ್ಣ *env,
	    ವರ್ಣ * ಧ್ರುವ *envs, size_t nenvs);
ಧ್ರುವ ವರ್ಣ *lookup_setenv_in_list(ಧ್ರುವ ವರ್ಣ *env,
	    ವರ್ಣ * ಧ್ರುವ *envs, size_t nenvs);

ಪೂರ್ಣಾಙ್ಕ	 argv_split(ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ *, ವರ್ಣ ***, ಪೂರ್ಣಾಙ್ಕ);
ವರ್ಣ	*argv_assemble(ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ **argv);
ವರ್ಣ	*argv_next(ಪೂರ್ಣಾಙ್ಕ *, ವರ್ಣ ***);
ಶೂನ್ಯ	 argv_consume(ಪೂರ್ಣಾಙ್ಕ *);
ಶೂನ್ಯ	 argv_free(ವರ್ಣ **, ಪೂರ್ಣಾಙ್ಕ);

ಪೂರ್ಣಾಙ್ಕ	 exited_cleanly(pid_t, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);

ಸಂರಚನಾ stat;
ಪೂರ್ಣಾಙ್ಕ	 safe_path(ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ stat *, ಧ್ರುವ ವರ್ಣ *, uid_t,
	    ವರ್ಣ *, size_t);
ಪೂರ್ಣಾಙ್ಕ	 safe_path_fd(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ passwd *,
	    ವರ್ಣ *err, size_t errlen);

/* authorized_key-style options parsing helpers */
ಪೂರ್ಣಾಙ್ಕ	opt_flag(ಧ್ರುವ ವರ್ಣ *opt, ಪೂರ್ಣಾಙ್ಕ allow_negate, ಧ್ರುವ ವರ್ಣ **optsp);
ವರ್ಣ	*opt_dequote(ಧ್ರುವ ವರ್ಣ **sp, ಧ್ರುವ ವರ್ಣ **errstrp);
ಪೂರ್ಣಾಙ್ಕ	opt_match(ಧ್ರುವ ವರ್ಣ **opts, ಧ್ರುವ ವರ್ಣ *term);

/* readconf/servconf option lists */
ಶೂನ್ಯ	opt_array_append(ಧ್ರುವ ವರ್ಣ *file, ಧ್ರುವ ಪೂರ್ಣಾಙ್ಕ ಸಾಲು,
	    ಧ್ರುವ ವರ್ಣ *directive, ವರ್ಣ ***array, u_int *lp, ಧ್ರುವ ವರ್ಣ *s);
ಶೂನ್ಯ	opt_array_append2(ಧ್ರುವ ವರ್ಣ *file, ಧ್ರುವ ಪೂರ್ಣಾಙ್ಕ ಸಾಲು,
	    ಧ್ರುವ ವರ್ಣ *directive, ವರ್ಣ ***array, ಪೂರ್ಣಾಙ್ಕ **iarray, u_int *lp,
	    ಧ್ರುವ ವರ್ಣ *s, ಪೂರ್ಣಾಙ್ಕ i);
ಶೂನ್ಯ	opt_array_free2(ವರ್ಣ **array, ಪೂರ್ಣಾಙ್ಕ **iarray, u_int l);

ಸಂರಚನಾ timespec;
ಶೂನ್ಯ ptimeout_init(ಸಂರಚನಾ timespec *pt);
ಶೂನ್ಯ ptimeout_deadline_sec(ಸಂರಚನಾ timespec *pt, long sec);
ಶೂನ್ಯ ptimeout_deadline_ms(ಸಂರಚನಾ timespec *pt, long ms);
ಶೂನ್ಯ ptimeout_deadline_sec_double(ಸಂರಚನಾ timespec *pt, ದ್ವಿಗುಣ sec);
ಶೂನ್ಯ ptimeout_deadline_monotime_tsp(ಸಂರಚನಾ timespec *pt, ಸಂರಚನಾ timespec *when);
ಶೂನ್ಯ ptimeout_deadline_monotime(ಸಂರಚನಾ timespec *pt, time_t when);
ಶೂನ್ಯ ptimeout_deadline_monotime_double(ಸಂರಚನಾ timespec *pt, ದ್ವಿಗುಣ when);
ಪೂರ್ಣಾಙ್ಕ ptimeout_get_ms(ಸಂರಚನಾ timespec *pt);
ಸಂರಚನಾ timespec *ptimeout_get_tsp(ಸಂರಚನಾ timespec *pt);
ಪೂರ್ಣಾಙ್ಕ ptimeout_isset(ಸಂರಚನಾ timespec *pt);

/* misc-agent.c */
ಪೂರ್ಣಾಙ್ಕ	 agent_listener(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, uid_t, ಧ್ರುವ ವರ್ಣ *,
	    pid_t, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ *, ವರ್ಣ **, ವರ್ಣ **);
ಶೂನ್ಯ	 agent_cleanup_stale(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, uid_t,
	    ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 agent_listener_cleanup(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);

/* readpass.c */

#define RP_ECHO			0x0001
#define RP_ALLOW_STDIN		0x0002
#define RP_ALLOW_EOF		0x0004
#define RP_USE_ASKPASS		0x0008

ಸಂರಚನಾ notifier_ctx;

ವರ್ಣ	*read_passphrase(ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 ask_permission(ಧ್ರುವ ವರ್ಣ *, ...) __attribute__((format(printf, 1, 2)));
ಸಂರಚನಾ notifier_ctx *notify_start(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, ...)
	__attribute__((format(printf, 2, 3)));
ಶೂನ್ಯ	notify_complete(ಸಂರಚನಾ notifier_ctx *, ಧ್ರುವ ವರ್ಣ *, ...)
	__attribute__((format(printf, 2, 3)));

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))
#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

ಪ್ರಕಾರನಿರ್ದೇಶ ಶೂನ್ಯ (*sshsig_t)(ಪೂರ್ಣಾಙ್ಕ);
sshsig_t ssh_signal(ಪೂರ್ಣಾಙ್ಕ, sshsig_t);
ಪೂರ್ಣಾಙ್ಕ signal_is_crash(ಪೂರ್ಣಾಙ್ಕ);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#define FD_CLOSEONEXEC(x) ಕುರು { \
	ಯದಿ (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    strerror(errno)); \
} ಯಾವತ್ (0)

#endif /* _MISC_H */
