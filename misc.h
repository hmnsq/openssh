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

#ଅନ୍ତର୍ଭାଵ <sys/time.h>
#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>

/* special-case port number meaning allow any port */
#define FWD_PERMIT_ANY_PORT	0

/* special-case wildcard meaning allow any host */
#define FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
ସଂରଚନା Forward {
	ଅକ୍ଷର	 *listen_host;		/* Host (address) to listen on. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	  listen_port;		/* Port to forward. */
	ଅକ୍ଷର	 *listen_path;		/* Path to bind domain socket. */
	ଅକ୍ଷର	 *connect_host;		/* Host to connect. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	  connect_port;		/* Port to connect on connect_host. */
	ଅକ୍ଷର	 *connect_path;		/* Path to connect domain socket. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	  allocated_port;	/* Dynamically allocated listen port */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	  handle;		/* Handle for dynamic listen ports */
};

ପୂର୍ଣ୍ଣସଂଖ୍ୟା forward_equals(ଅଚଳ ସଂରଚନା Forward *, ଅଚଳ ସଂରଚନା Forward *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା permitopen_port(ଅଚଳ ଅକ୍ଷର *p);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା daemonized(ଶୂନ୍ୟ);

/* Common server and client forwarding options. */
ସଂରଚନା ForwardOptions {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 gateway_ports; /* Allow remote connects to forwarded ports. */
	mode_t	 streamlocal_bind_mask; /* umask for streamlocal binds */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

ଅକ୍ଷର	*chop(ଅକ୍ଷର *);
ଶୂନ୍ୟ	 rtrim(ଅକ୍ଷର *);
ଶୂନ୍ୟ	skip_space(ଅକ୍ଷର **);
ଅଚଳ ଅକ୍ଷର *strprefix(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଅକ୍ଷର	*strdelim(ଅକ୍ଷର **);
ଅକ୍ଷର	*strdelimw(ଅକ୍ଷର **);
ଶୂନ୍ୟ	 stringlist_append(ଅକ୍ଷର ***listp, ଅଚଳ ଅକ୍ଷର *s);
ଶୂନ୍ୟ	 stringlist_free(ଅକ୍ଷର **list);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 set_nonblock(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 unset_nonblock(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 set_nodelay(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 set_reuseaddr(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 set_keepalive(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଅକ୍ଷର	*get_rdomain(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 set_rdomain(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 get_sock_af(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 set_sock_tos(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 waitrfd(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ଅସ୍ଥିର sig_atomic_t *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 timeout_connect(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ସଂରଚନା sockaddr *, socklen_t, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 a2port(ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 a2tun(ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *);
ଅକ୍ଷର	*put_host_port(ଅଚଳ ଅକ୍ଷର *, u_short);
ଅକ୍ଷର	*hpdelim2(ଅକ୍ଷର **, ଅକ୍ଷର *);
ଅକ୍ଷର	*hpdelim(ଅକ୍ଷର **);
ଅକ୍ଷର	*cleanhostname(ଅକ୍ଷର *);
ଅକ୍ଷର	*colon(ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 parse_user_host_path(ଅଚଳ ଅକ୍ଷର *, ଅକ୍ଷର **, ଅକ୍ଷର **, ଅକ୍ଷର **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 parse_user_host_port(ଅଚଳ ଅକ୍ଷର *, ଅକ୍ଷର **, ଅକ୍ଷର **, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 parse_uri(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅକ୍ଷର **, ଅକ୍ଷର **, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ଅକ୍ଷର **);
ଦ୍ୱିଗୁଣ	 convtime_double(ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 convtime(ଅଚଳ ଅକ୍ଷର *);
ଦ୍ୱିଗୁଣ	 convtime_double(ଅଚଳ ଅକ୍ଷର *);
ଅଚଳ ଅକ୍ଷର *fmt_timeframe(time_t t);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 tilde_expand(ଅଚଳ ଅକ୍ଷର *, uid_t, ଅକ୍ଷର **);
ଅକ୍ଷର	*tilde_expand_filename(ଅଚଳ ଅକ୍ଷର *, uid_t);

ଅକ୍ଷର	*dollar_expand(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ଅଚଳ ଅକ୍ଷର *string, ...);
ଅକ୍ଷର	*percent_expand(ଅଚଳ ଅକ୍ଷର *, ...) __attribute__((__sentinel__));
ଅକ୍ଷର	*percent_dollar_expand(ଅଚଳ ଅକ୍ଷର *, ...) __attribute__((__sentinel__));
ଅକ୍ଷର	*tohex(ଅଚଳ ଶୂନ୍ୟ *, size_t);
ଶୂନ୍ୟ	 xextendf(ଅକ୍ଷର **s, ଅଚଳ ଅକ୍ଷର *sep, ଅଚଳ ଅକ୍ଷର *fmt, ...)
    __attribute__((__format__ (printf, 3, 4))) __attribute__((__nonnull__ (3)));
ଶୂନ୍ୟ	 sanitise_stdfd(ଶୂନ୍ୟ);
ଶୂନ୍ୟ	 ms_subtract_diff(ସଂରଚନା timeval *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *);
ଶୂନ୍ୟ	 ms_to_timespec(ସଂରଚନା timespec *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 monotime_ts(ସଂରଚନା timespec *);
ଶୂନ୍ୟ	 monotime_tv(ସଂରଚନା timeval *);
time_t	 monotime(ଶୂନ୍ୟ);
ଦ୍ୱିଗୁଣ	 monotime_double(ଶୂନ୍ୟ);
ଶୂନ୍ୟ	 lowercase(ଅକ୍ଷର *s);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 unix_listener(ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 valid_domain(ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ଅକ୍ଷର **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 valid_env_name(ଅଚଳ ଅକ୍ଷର *);
ଅଚଳ ଅକ୍ଷର *atoi_err(ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 parse_absolute_time(ଅଚଳ ଅକ୍ଷର *, uint64_t *);
ଶୂନ୍ୟ	 format_absolute_time(uint64_t, ଅକ୍ଷର *, size_t);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 parse_pattern_interval(ଅଚଳ ଅକ୍ଷର *, ଅକ୍ଷର **, ଦ୍ୱିଗୁଣ *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 path_absolute(ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 stdfd_devnull(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 lib_contains_ପ୍ରତୀକ(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ଅକ୍ଷର	*get_homedir(ଶୂନ୍ୟ);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 mkdir_path(ଅଚଳ ଅକ୍ଷର *, mode_t);

ଶୂନ୍ୟ	 sock_set_v6only(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

ସଂରଚନା passwd *pwcopy(ସଂରଚନା passwd *);
ଶୂନ୍ୟ	 pwfree(ସଂରଚନା passwd *); /* NB. only use with pwcopy */

ଅଚଳ ଅକ୍ଷର *ssh_gai_strerror(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

ପ୍ରକାରବ୍ୟାଖ୍ୟା ଶୂନ୍ୟ privdrop_fn(ସଂରଚନା passwd *);
ପ୍ରକାରବ୍ୟାଖ୍ୟା ଶୂନ୍ୟ privrestore_fn(ଶୂନ୍ୟ);
#define	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#define	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#define	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#define	SSH_SUBPROCESS_UNSAFE_PATH	(1<<3)	/* Don't check for safe cmd */
#define	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର **, FILE **, u_int,
    ସଂରଚନା passwd *, privdrop_fn *, privrestore_fn *);

ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା arglist arglist;
ସଂରଚନା arglist {
	ଅକ୍ଷର    **list;
	u_int   ଅଙ୍କ;
	u_int   nalloc;
};
ଶୂନ୍ୟ	 addargs(arglist *, ଅକ୍ଷର *, ...)
	    __attribute__((format(printf, 2, 3)));
ଶୂନ୍ୟ	 replacearg(arglist *, u_int, ଅକ୍ଷର *, ...)
	    __attribute__((format(printf, 3, 4)));
ଶୂନ୍ୟ	 freeargs(arglist *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 tun_open(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର **);

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
uint64_t	get_u64(ଅଚଳ ଶୂନ୍ୟ *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(ଅଚଳ ଶୂନ୍ୟ *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(ଅଚଳ ଶୂନ୍ୟ *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
ଶୂନ୍ୟ		put_u64(ଶୂନ୍ୟ *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
ଶୂନ୍ୟ		put_u32(ଶୂନ୍ୟ *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
ଶୂନ୍ୟ		put_u16(ଶୂନ୍ୟ *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(ଅଚଳ ଶୂନ୍ୟ *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
ଶୂନ୍ୟ		put_u32_le(ଶୂନ୍ୟ *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

ସଂରଚନା bwlimit {
	size_t buflen;
	uint64_t rate;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	ସଂରଚନା timeval bwstart, bwend;
};

ଶୂନ୍ୟ bandwidth_limit_init(ସଂରଚନା bwlimit *, uint64_t, size_t);
ଶୂନ୍ୟ bandwidth_limit(ସଂରଚନା bwlimit *, size_t);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା parse_ipqos(ଅଚଳ ଅକ୍ଷର *);
ଅଚଳ ଅକ୍ଷର *iptos2str(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ mktemp_proto(ଅକ୍ଷର *, size_t);

ଶୂନ୍ୟ	 child_set_env(ଅକ୍ଷର ***envp, u_int *envsizep, ଅଚଳ ଅକ୍ଷର *name,
	    ଅଚଳ ଅକ୍ଷର *ମୂଲ୍ୟ);
ଅଚଳ ଅକ୍ଷର *lookup_env_in_list(ଅଚଳ ଅକ୍ଷର *env,
	    ଅକ୍ଷର * ଅଚଳ *envs, size_t nenvs);
ଅଚଳ ଅକ୍ଷର *lookup_setenv_in_list(ଅଚଳ ଅକ୍ଷର *env,
	    ଅକ୍ଷର * ଅଚଳ *envs, size_t nenvs);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 argv_split(ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ଅକ୍ଷର ***, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଅକ୍ଷର	*argv_assemble(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର **argv);
ଅକ୍ଷର	*argv_next(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ଅକ୍ଷର ***);
ଶୂନ୍ୟ	 argv_consume(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *);
ଶୂନ୍ୟ	 argv_free(ଅକ୍ଷର **, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 exited_cleanly(pid_t, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

ସଂରଚନା stat;
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 safe_path(ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା stat *, ଅଚଳ ଅକ୍ଷର *, uid_t,
	    ଅକ୍ଷର *, size_t);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 safe_path_fd(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା passwd *,
	    ଅକ୍ଷର *err, size_t errlen);

/* authorized_key-style options parsing helpers */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	opt_flag(ଅଚଳ ଅକ୍ଷର *opt, ପୂର୍ଣ୍ଣସଂଖ୍ୟା allow_negate, ଅଚଳ ଅକ୍ଷର **optsp);
ଅକ୍ଷର	*opt_dequote(ଅଚଳ ଅକ୍ଷର **sp, ଅଚଳ ଅକ୍ଷର **errstrp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	opt_match(ଅଚଳ ଅକ୍ଷର **opts, ଅଚଳ ଅକ୍ଷର *term);

/* readconf/servconf option lists */
ଶୂନ୍ୟ	opt_array_append(ଅଚଳ ଅକ୍ଷର *file, ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି,
	    ଅଚଳ ଅକ୍ଷର *directive, ଅକ୍ଷର ***array, u_int *lp, ଅଚଳ ଅକ୍ଷର *s);
ଶୂନ୍ୟ	opt_array_append2(ଅଚଳ ଅକ୍ଷର *file, ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି,
	    ଅଚଳ ଅକ୍ଷର *directive, ଅକ୍ଷର ***array, ପୂର୍ଣ୍ଣସଂଖ୍ୟା **iarray, u_int *lp,
	    ଅଚଳ ଅକ୍ଷର *s, ପୂର୍ଣ୍ଣସଂଖ୍ୟା i);
ଶୂନ୍ୟ	opt_array_free2(ଅକ୍ଷର **array, ପୂର୍ଣ୍ଣସଂଖ୍ୟା **iarray, u_int l);

ସଂରଚନା timespec;
ଶୂନ୍ୟ ptimeout_init(ସଂରଚନା timespec *pt);
ଶୂନ୍ୟ ptimeout_deadline_sec(ସଂରଚନା timespec *pt, long sec);
ଶୂନ୍ୟ ptimeout_deadline_ms(ସଂରଚନା timespec *pt, long ms);
ଶୂନ୍ୟ ptimeout_deadline_sec_double(ସଂରଚନା timespec *pt, ଦ୍ୱିଗୁଣ sec);
ଶୂନ୍ୟ ptimeout_deadline_monotime_tsp(ସଂରଚନା timespec *pt, ସଂରଚନା timespec *when);
ଶୂନ୍ୟ ptimeout_deadline_monotime(ସଂରଚନା timespec *pt, time_t when);
ଶୂନ୍ୟ ptimeout_deadline_monotime_double(ସଂରଚନା timespec *pt, ଦ୍ୱିଗୁଣ when);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ptimeout_get_ms(ସଂରଚନା timespec *pt);
ସଂରଚନା timespec *ptimeout_get_tsp(ସଂରଚନା timespec *pt);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ptimeout_isset(ସଂରଚନା timespec *pt);

/* misc-agent.c */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 agent_listener(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, uid_t, ଅଚଳ ଅକ୍ଷର *,
	    pid_t, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ଅକ୍ଷର **, ଅକ୍ଷର **);
ଶୂନ୍ୟ	 agent_cleanup_stale(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, uid_t,
	    ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 agent_listener_cleanup(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);

/* readpass.c */

#define RP_ECHO			0x0001
#define RP_ALLOW_STDIN		0x0002
#define RP_ALLOW_EOF		0x0004
#define RP_USE_ASKPASS		0x0008

ସଂରଚନା notifier_ctx;

ଅକ୍ଷର	*read_passphrase(ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ask_permission(ଅଚଳ ଅକ୍ଷର *, ...) __attribute__((format(printf, 1, 2)));
ସଂରଚନା notifier_ctx *notify_start(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ଅକ୍ଷର *, ...)
	__attribute__((format(printf, 2, 3)));
ଶୂନ୍ୟ	notify_complete(ସଂରଚନା notifier_ctx *, ଅଚଳ ଅକ୍ଷର *, ...)
	__attribute__((format(printf, 2, 3)));

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))
#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

ପ୍ରକାରବ୍ୟାଖ୍ୟା ଶୂନ୍ୟ (*sshsig_t)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
sshsig_t ssh_signal(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, sshsig_t);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା signal_is_crash(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#define FD_CLOSEONEXEC(x) କର { \
	ଯଦି (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    strerror(errno)); \
} ଯେତେବେଳେ (0)

#endif /* _MISC_H */
