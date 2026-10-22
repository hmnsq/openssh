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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _MISC_H
#ವ್ಯಾಖ್ಯಾನಿಸು _MISC_H

#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <signal.h>

/* special-case port number meaning allow any port */
#ವ್ಯಾಖ್ಯಾನಿಸು FWD_PERMIT_ANY_ಪೋರ್ಟ್	0

/* special-case wildcard meaning allow any host */
#ವ್ಯಾಖ್ಯಾನಿಸು FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
ರಚನೆ Forward {
	ಅಕ್ಷರ	 *listen_host;		/* Host (address) to listen on. */
	ಪೂರ್ಣಾಂಕ	  listen_ಪೋರ್ಟ್;		/* Port to forward. */
	ಅಕ್ಷರ	 *listen_ಮಾರ್ಗ;		/* Path to bind domain socket. */
	ಅಕ್ಷರ	 *connect_host;		/* Host to connect. */
	ಪೂರ್ಣಾಂಕ	  connect_ಪೋರ್ಟ್;		/* Port to connect on connect_host. */
	ಅಕ್ಷರ	 *connect_ಮಾರ್ಗ;		/* Path to connect domain socket. */
	ಪೂರ್ಣಾಂಕ	  allocated_ಪೋರ್ಟ್;	/* Dynamically allocated listen port */
	ಪೂರ್ಣಾಂಕ	  handle;		/* Handle for dynamic listen ports */
};

ಪೂರ್ಣಾಂಕ forward_equals(ಸ್ಥಿರಾಂಕ ರಚನೆ Forward *, ಸ್ಥಿರಾಂಕ ರಚನೆ Forward *);
ಪೂರ್ಣಾಂಕ permitopen_ಪೋರ್ಟ್(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p);

ಪೂರ್ಣಾಂಕ daemonized(ಶೂನ್ಯ);

/* Common server and client forwarding options. */
ರಚನೆ ForwardOptions {
	ಪೂರ್ಣಾಂಕ	 gateway_ports; /* Allow remote connects to forwarded ports. */
	ಬಹುಲಕ_t	 streamlocal_bind_ಮುಖವಾಡ; /* umask for streamlocal binds */
	ಪೂರ್ಣಾಂಕ	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

ಅಕ್ಷರ	*chop(ಅಕ್ಷರ *);
ಶೂನ್ಯ	 rtrim(ಅಕ್ಷರ *);
ಶೂನ್ಯ	skip_space(ಅಕ್ಷರ **);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *strprefix(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
ಅಕ್ಷರ	*strdelim(ಅಕ್ಷರ **);
ಅಕ್ಷರ	*strdelimw(ಅಕ್ಷರ **);
ಶೂನ್ಯ	 stringlist_append(ಅಕ್ಷರ ***listp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s);
ಶೂನ್ಯ	 stringlist_free(ಅಕ್ಷರ **list);
ಪೂರ್ಣಾಂಕ	 ಗಣ_nonblock(ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 unset_nonblock(ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 ಗಣ_nodelay(ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 ಗಣ_reuseaddr(ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 ಗಣ_keepalive(ಪೂರ್ಣಾಂಕ);
ಅಕ್ಷರ	*get_rdomain(ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 ಗಣ_rdomain(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 get_sock_af(ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 ಗಣ_sock_tos(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 waitrfd(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ *, ಅಸ್ಥಿರ sig_atomic_t *);
ಪೂರ್ಣಾಂಕ	 timeout_connect(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ರಚನೆ sockaddr *, socklen_t, ಪೂರ್ಣಾಂಕ *);
ಪೂರ್ಣಾಂಕ	 a2port(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 a2tun(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ *);
ಅಕ್ಷರ	*put_host_ಪೋರ್ಟ್(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, u_short);
ಅಕ್ಷರ	*hpdelim2(ಅಕ್ಷರ **, ಅಕ್ಷರ *);
ಅಕ್ಷರ	*hpdelim(ಅಕ್ಷರ **);
ಅಕ್ಷರ	*cleanhostname(ಅಕ್ಷರ *);
ಅಕ್ಷರ	*colon(ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 parse_user_host_ಮಾರ್ಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ **, ಅಕ್ಷರ **, ಅಕ್ಷರ **);
ಪೂರ್ಣಾಂಕ	 parse_user_host_ಪೋರ್ಟ್(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ **, ಅಕ್ಷರ **, ಪೂರ್ಣಾಂಕ *);
ಪೂರ್ಣಾಂಕ	 parse_uri(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ **, ಅಕ್ಷರ **, ಪೂರ್ಣಾಂಕ *, ಅಕ್ಷರ **);
ದ್ವಿಗುಣ	 convtime_double(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 convtime(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ದ್ವಿಗುಣ	 convtime_double(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt_timeframe(time_t t);
ಪೂರ್ಣಾಂಕ	 tilde_expand(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, uid_t, ಅಕ್ಷರ **);
ಅಕ್ಷರ	*tilde_expand_filename(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, uid_t);

ಅಕ್ಷರ	*dollar_expand(ಪೂರ್ಣಾಂಕ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *string, ...);
ಅಕ್ಷರ	*percent_expand(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...) __attribute__((__sentinel__));
ಅಕ್ಷರ	*percent_dollar_expand(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...) __attribute__((__sentinel__));
ಅಕ್ಷರ	*tohex(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *, ಗಾತ್ರ_t);
ಶೂನ್ಯ	 xextendf(ಅಕ್ಷರ **s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sep, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
    __attribute__((__format__ (ಬರೆ, 3, 4))) __attribute__((__nonnull__ (3)));
ಶೂನ್ಯ	 sanitise_stdfd(ಶೂನ್ಯ);
ಶೂನ್ಯ	 ms_ಕಳೆ_diff(ರಚನೆ timeval *, ಪೂರ್ಣಾಂಕ *);
ಶೂನ್ಯ	 ms_ಗಮ್ಯ_timespec(ರಚನೆ timespec *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 monotime_ts(ರಚನೆ timespec *);
ಶೂನ್ಯ	 monotime_tv(ರಚನೆ timeval *);
time_t	 monotime(ಶೂನ್ಯ);
ದ್ವಿಗುಣ	 monotime_double(ಶೂನ್ಯ);
ಶೂನ್ಯ	 lowercase(ಅಕ್ಷರ *s);
ಪೂರ್ಣಾಂಕ	 unix_listener(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 valid_domain(ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **);
ಪೂರ್ಣಾಂಕ	 valid_env_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *atoi_err(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ *);
ಪೂರ್ಣಾಂಕ	 parse_absolute_ಸಮಯ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, uint64_t *);
ಶೂನ್ಯ	 format_absolute_ಸಮಯ(uint64_t, ಅಕ್ಷರ *, ಗಾತ್ರ_t);
ಪೂರ್ಣಾಂಕ	 parse_ನಮೂನೆ_interval(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ **, ದ್ವಿಗುಣ *);
ಪೂರ್ಣಾಂಕ	 ಮಾರ್ಗ_absolute(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 stdfd_devnull(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 lib_ಒಳಗೊಂಡಿದೆ_ಚಿಹ್ನೆ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಅಕ್ಷರ	*get_homedir(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ	 mkdir_ಮಾರ್ಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಬಹುಲಕ_t);

ಶೂನ್ಯ	 sock_ಗಣ_v6only(ಪೂರ್ಣಾಂಕ);

ರಚನೆ passwd *pwcopy(ರಚನೆ passwd *);
ಶೂನ್ಯ	 pwfree(ರಚನೆ passwd *); /* NB. only use with pwcopy */

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ssh_gai_strerror(ಪೂರ್ಣಾಂಕ);

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ privdrop_fn(ರಚನೆ passwd *);
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ privrestore_fn(ಶೂನ್ಯ);
#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_SUBPROCESS_UNSAFE_ಮಾರ್ಗ	(1<<3)	/* Don't check for safe cmd */
#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ **, FILE **, u_int,
    ರಚನೆ passwd *, privdrop_fn *, privrestore_fn *);

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ arglist arglist;
ರಚನೆ arglist {
	ಅಕ್ಷರ    **list;
	u_int   ಅಂಕೆ;
	u_int   nalloc;
};
ಶೂನ್ಯ	 addargs(arglist *, ಅಕ್ಷರ *, ...)
	    __attribute__((format(ಬರೆ, 2, 3)));
ಶೂನ್ಯ	 replacearg(arglist *, u_int, ಅಕ್ಷರ *, ...)
	    __attribute__((format(ಬರೆ, 3, 4)));
ಶೂನ್ಯ	 freeargs(arglist *);

ಪೂರ್ಣಾಂಕ	 tun_open(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ **);

/* Common definitions for ssh tunnel device forwarding */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_TUNMODE_NO		0x00
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_TUNMODE_POINTOPOINT	0x01
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_TUNMODE_ETHERNET	0x02
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_TUNMODE_DEFAULT	SSH_TUNMODE_POINTOPOINT
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_TUNMODE_YES		(SSH_TUNMODE_POINTOPOINT|SSH_TUNMODE_ETHERNET)

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_TUNID_ANY		0x7fffffff
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_TUNID_ERR		(SSH_TUNID_ANY - 1)
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_TUNID_MAX		(SSH_TUNID_ANY - 2)

/* Fake port to indicate that host field is really a path. */
#ವ್ಯಾಖ್ಯಾನಿಸು ಪೋರ್ಟ್_STREAMLOCAL	-2

/* Functions to extract or store big-endian words of various sizes */
uint64_t	get_u64(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
ಶೂನ್ಯ		put_u64(ಶೂನ್ಯ *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
ಶೂನ್ಯ		put_u32(ಶೂನ್ಯ *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
ಶೂನ್ಯ		put_u16(ಶೂನ್ಯ *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
ಶೂನ್ಯ		put_u32_le(ಶೂನ್ಯ *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

ರಚನೆ bwlimit {
	ಗಾತ್ರ_t buflen;
	uint64_t ದರ;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	ರಚನೆ timeval bwstart, bwend;
};

ಶೂನ್ಯ bandwidth_ಎಲ್ಲೆ_init(ರಚನೆ bwlimit *, uint64_t, ಗಾತ್ರ_t);
ಶೂನ್ಯ bandwidth_ಎಲ್ಲೆ(ರಚನೆ bwlimit *, ಗಾತ್ರ_t);

ಪೂರ್ಣಾಂಕ parse_ipqos(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *iptos2str(ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ mktemp_proto(ಅಕ್ಷರ *, ಗಾತ್ರ_t);

ಶೂನ್ಯ	 ಮಗು_ಗಣ_env(ಅಕ್ಷರ ***envp, u_int *envsizep, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮೌಲ್ಯ);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *lookup_env_ಒಳ_list(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *env,
	    ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *envs, ಗಾತ್ರ_t nenvs);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *lookup_setenv_ಒಳ_list(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *env,
	    ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *envs, ಗಾತ್ರ_t nenvs);

ಪೂರ್ಣಾಂಕ	 argv_ವಿಭಜಿಸು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ *, ಅಕ್ಷರ ***, ಪೂರ್ಣಾಂಕ);
ಅಕ್ಷರ	*argv_assemble(ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ **argv);
ಅಕ್ಷರ	*argv_ಮುಂದಿನ(ಪೂರ್ಣಾಂಕ *, ಅಕ್ಷರ ***);
ಶೂನ್ಯ	 argv_consume(ಪೂರ್ಣಾಂಕ *);
ಶೂನ್ಯ	 argv_free(ಅಕ್ಷರ **, ಪೂರ್ಣಾಂಕ);

ಪೂರ್ಣಾಂಕ	 exited_cleanly(pid_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);

ರಚನೆ stat;
ಪೂರ್ಣಾಂಕ	 ಸುರಕ್ಷಿತ_ಮಾರ್ಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ stat *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, uid_t,
	    ಅಕ್ಷರ *, ಗಾತ್ರ_t);
ಪೂರ್ಣಾಂಕ	 ಸುರಕ್ಷಿತ_ಮಾರ್ಗ_fd(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ passwd *,
	    ಅಕ್ಷರ *err, ಗಾತ್ರ_t errlen);

/* authorized_key-style options parsing helpers */
ಪೂರ್ಣಾಂಕ	opt_flag(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *opt, ಪೂರ್ಣಾಂಕ allow_negate, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **optsp);
ಅಕ್ಷರ	*opt_dequote(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **sp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **errstrp);
ಪೂರ್ಣಾಂಕ	opt_ಹೊಂದಿಕೆ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **opts, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಪದ);

/* readconf/servconf option lists */
ಶೂನ್ಯ	opt_array_append(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ ಸಾಲು,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *directive, ಅಕ್ಷರ ***array, u_int *lp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s);
ಶೂನ್ಯ	opt_array_append2(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ ಸಾಲು,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *directive, ಅಕ್ಷರ ***array, ಪೂರ್ಣಾಂಕ **iarray, u_int *lp,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ಪೂರ್ಣಾಂಕ i);
ಶೂನ್ಯ	opt_array_free2(ಅಕ್ಷರ **array, ಪೂರ್ಣಾಂಕ **iarray, u_int l);

ರಚನೆ timespec;
ಶೂನ್ಯ ptimeout_init(ರಚನೆ timespec *pt);
ಶೂನ್ಯ ptimeout_deadline_sec(ರಚನೆ timespec *pt, ದೀರ್ಘ sec);
ಶೂನ್ಯ ptimeout_deadline_ms(ರಚನೆ timespec *pt, ದೀರ್ಘ ms);
ಶೂನ್ಯ ptimeout_deadline_sec_double(ರಚನೆ timespec *pt, ದ್ವಿಗುಣ sec);
ಶೂನ್ಯ ptimeout_deadline_monotime_tsp(ರಚನೆ timespec *pt, ರಚನೆ timespec *when);
ಶೂನ್ಯ ptimeout_deadline_monotime(ರಚನೆ timespec *pt, time_t when);
ಶೂನ್ಯ ptimeout_deadline_monotime_double(ರಚನೆ timespec *pt, ದ್ವಿಗುಣ when);
ಪೂರ್ಣಾಂಕ ptimeout_get_ms(ರಚನೆ timespec *pt);
ರಚನೆ timespec *ptimeout_get_tsp(ರಚನೆ timespec *pt);
ಪೂರ್ಣಾಂಕ ptimeout_isset(ರಚನೆ timespec *pt);

/* misc-agent.c */
ಪೂರ್ಣಾಂಕ	 agent_listener(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, uid_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
	    pid_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ *, ಅಕ್ಷರ **, ಅಕ್ಷರ **);
ಶೂನ್ಯ	 agent_cleanup_stale(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, uid_t,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 agent_listener_cleanup(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

/* readpass.c */

#ವ್ಯಾಖ್ಯಾನಿಸು RP_ECHO			0x0001
#ವ್ಯಾಖ್ಯಾನಿಸು RP_ALLOW_STDIN		0x0002
#ವ್ಯಾಖ್ಯಾನಿಸು RP_ALLOW_EOF		0x0004
#ವ್ಯಾಖ್ಯಾನಿಸು RP_USE_ASKPASS		0x0008

ರಚನೆ notifier_ctx;

ಅಕ್ಷರ	*read_passphrase(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 ask_permission(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...) __attribute__((format(ಬರೆ, 1, 2)));
ರಚನೆ notifier_ctx *notify_ಆರಂಭ(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...)
	__attribute__((format(ಬರೆ, 2, 3)));
ಶೂನ್ಯ	notify_complete(ರಚನೆ notifier_ctx *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...)
	__attribute__((format(ಬರೆ, 2, 3)));

#ವ್ಯಾಖ್ಯಾನಿಸು MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#ವ್ಯಾಖ್ಯಾನಿಸು ಗರಿಷ್ಠ(a, b)	(((a) > (b)) ? (a) : (b))
#ವ್ಯಾಖ್ಯಾನಿಸು ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ (*sshsig_t)(ಪೂರ್ಣಾಂಕ);
sshsig_t ssh_signal(ಪೂರ್ಣಾಂಕ, sshsig_t);
ಪೂರ್ಣಾಂಕ signal_is_crash(ಪೂರ್ಣಾಂಕ);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#ವ್ಯಾಖ್ಯಾನಿಸು FD_CLOSEONEXEC(x) ಮಾಡು { \
	ಆದರೆ (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    strerror(errno)); \
} ಆಗ (0)

#ಆದರೆ_ಅಂತ್ಯ /* _MISC_H */
