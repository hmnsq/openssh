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

#അന്തര്ഭാവ <sys/time.h>
#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <signal.h>

/* special-case port number meaning allow any port */
#define FWD_PERMIT_ANY_PORT	0

/* special-case wildcard meaning allow any host */
#define FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
ഘടന Forward {
	അക്ഷരം	 *listen_host;		/* Host (address) to listen on. */
	പൂർണ്ണസംഖ്യ	  listen_port;		/* Port to forward. */
	അക്ഷരം	 *listen_path;		/* Path to bind domain socket. */
	അക്ഷരം	 *connect_host;		/* Host to connect. */
	പൂർണ്ണസംഖ്യ	  connect_port;		/* Port to connect on connect_host. */
	അക്ഷരം	 *connect_path;		/* Path to connect domain socket. */
	പൂർണ്ണസംഖ്യ	  allocated_port;	/* Dynamically allocated listen port */
	പൂർണ്ണസംഖ്യ	  handle;		/* Handle for dynamic listen ports */
};

പൂർണ്ണസംഖ്യ forward_equals(സ്ഥിരം ഘടന Forward *, സ്ഥിരം ഘടന Forward *);
പൂർണ്ണസംഖ്യ permitopen_port(സ്ഥിരം അക്ഷരം *p);

പൂർണ്ണസംഖ്യ daemonized(ശൂന്യം);

/* Common server and client forwarding options. */
ഘടന ForwardOptions {
	പൂർണ്ണസംഖ്യ	 gateway_ports; /* Allow remote connects to forwarded ports. */
	mode_t	 streamlocal_bind_mask; /* umask for streamlocal binds */
	പൂർണ്ണസംഖ്യ	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

അക്ഷരം	*chop(അക്ഷരം *);
ശൂന്യം	 rtrim(അക്ഷരം *);
ശൂന്യം	skip_space(അക്ഷരം **);
സ്ഥിരം അക്ഷരം *strprefix(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ);
അക്ഷരം	*strdelim(അക്ഷരം **);
അക്ഷരം	*strdelimw(അക്ഷരം **);
ശൂന്യം	 stringlist_append(അക്ഷരം ***listp, സ്ഥിരം അക്ഷരം *s);
ശൂന്യം	 stringlist_free(അക്ഷരം **list);
പൂർണ്ണസംഖ്യ	 set_nonblock(പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 unset_nonblock(പൂർണ്ണസംഖ്യ);
ശൂന്യം	 set_nodelay(പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 set_reuseaddr(പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 set_keepalive(പൂർണ്ണസംഖ്യ);
അക്ഷരം	*get_rdomain(പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 set_rdomain(പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 get_sock_af(പൂർണ്ണസംഖ്യ);
ശൂന്യം	 set_sock_tos(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 waitrfd(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ *, അസ്ഥിര sig_atomic_t *);
പൂർണ്ണസംഖ്യ	 timeout_connect(പൂർണ്ണസംഖ്യ, സ്ഥിരം ഘടന sockaddr *, socklen_t, പൂർണ്ണസംഖ്യ *);
പൂർണ്ണസംഖ്യ	 a2port(സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 a2tun(സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ *);
അക്ഷരം	*put_host_port(സ്ഥിരം അക്ഷരം *, u_short);
അക്ഷരം	*hpdelim2(അക്ഷരം **, അക്ഷരം *);
അക്ഷരം	*hpdelim(അക്ഷരം **);
അക്ഷരം	*cleanhostname(അക്ഷരം *);
അക്ഷരം	*colon(അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 parse_user_host_path(സ്ഥിരം അക്ഷരം *, അക്ഷരം **, അക്ഷരം **, അക്ഷരം **);
പൂർണ്ണസംഖ്യ	 parse_user_host_port(സ്ഥിരം അക്ഷരം *, അക്ഷരം **, അക്ഷരം **, പൂർണ്ണസംഖ്യ *);
പൂർണ്ണസംഖ്യ	 parse_uri(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, അക്ഷരം **, അക്ഷരം **, പൂർണ്ണസംഖ്യ *, അക്ഷരം **);
ഇരട്ട	 convtime_double(സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 convtime(സ്ഥിരം അക്ഷരം *);
ഇരട്ട	 convtime_double(സ്ഥിരം അക്ഷരം *);
സ്ഥിരം അക്ഷരം *fmt_timeframe(time_t t);
പൂർണ്ണസംഖ്യ	 tilde_expand(സ്ഥിരം അക്ഷരം *, uid_t, അക്ഷരം **);
അക്ഷരം	*tilde_expand_filename(സ്ഥിരം അക്ഷരം *, uid_t);

അക്ഷരം	*dollar_expand(പൂർണ്ണസംഖ്യ *, സ്ഥിരം അക്ഷരം *string, ...);
അക്ഷരം	*percent_expand(സ്ഥിരം അക്ഷരം *, ...) __attribute__((__sentinel__));
അക്ഷരം	*percent_dollar_expand(സ്ഥിരം അക്ഷരം *, ...) __attribute__((__sentinel__));
അക്ഷരം	*tohex(സ്ഥിരം ശൂന്യം *, size_t);
ശൂന്യം	 xextendf(അക്ഷരം **s, സ്ഥിരം അക്ഷരം *sep, സ്ഥിരം അക്ഷരം *fmt, ...)
    __attribute__((__format__ (printf, 3, 4))) __attribute__((__nonnull__ (3)));
ശൂന്യം	 sanitise_stdfd(ശൂന്യം);
ശൂന്യം	 ms_subtract_diff(ഘടന timeval *, പൂർണ്ണസംഖ്യ *);
ശൂന്യം	 ms_to_timespec(ഘടന timespec *, പൂർണ്ണസംഖ്യ);
ശൂന്യം	 monotime_ts(ഘടന timespec *);
ശൂന്യം	 monotime_tv(ഘടന timeval *);
time_t	 monotime(ശൂന്യം);
ഇരട്ട	 monotime_double(ശൂന്യം);
ശൂന്യം	 lowercase(അക്ഷരം *s);
പൂർണ്ണസംഖ്യ	 unix_listener(സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 valid_domain(അക്ഷരം *, പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം **);
പൂർണ്ണസംഖ്യ	 valid_env_name(സ്ഥിരം അക്ഷരം *);
സ്ഥിരം അക്ഷരം *atoi_err(സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ *);
പൂർണ്ണസംഖ്യ	 parse_absolute_time(സ്ഥിരം അക്ഷരം *, uint64_t *);
ശൂന്യം	 format_absolute_time(uint64_t, അക്ഷരം *, size_t);
പൂർണ്ണസംഖ്യ	 parse_pattern_interval(സ്ഥിരം അക്ഷരം *, അക്ഷരം **, ഇരട്ട *);
പൂർണ്ണസംഖ്യ	 path_absolute(സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 stdfd_devnull(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 lib_contains_ചിഹ്നം(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
അക്ഷരം	*get_homedir(ശൂന്യം);
പൂർണ്ണസംഖ്യ	 mkdir_path(സ്ഥിരം അക്ഷരം *, mode_t);

ശൂന്യം	 sock_set_v6only(പൂർണ്ണസംഖ്യ);

ഘടന passwd *pwcopy(ഘടന passwd *);
ശൂന്യം	 pwfree(ഘടന passwd *); /* NB. only use with pwcopy */

സ്ഥിരം അക്ഷരം *ssh_gai_strerror(പൂർണ്ണസംഖ്യ);

തരനിർവചനം ശൂന്യം privdrop_fn(ഘടന passwd *);
തരനിർവചനം ശൂന്യം privrestore_fn(ശൂന്യം);
#define	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#define	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#define	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#define	SSH_SUBPROCESS_UNSAFE_PATH	(1<<3)	/* Don't check for safe cmd */
#define	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ, അക്ഷരം **, FILE **, u_int,
    ഘടന passwd *, privdrop_fn *, privrestore_fn *);

തരനിർവചനം ഘടന arglist arglist;
ഘടന arglist {
	അക്ഷരം    **list;
	u_int   അക്കം;
	u_int   nalloc;
};
ശൂന്യം	 addargs(arglist *, അക്ഷരം *, ...)
	    __attribute__((format(printf, 2, 3)));
ശൂന്യം	 replacearg(arglist *, u_int, അക്ഷരം *, ...)
	    __attribute__((format(printf, 3, 4)));
ശൂന്യം	 freeargs(arglist *);

പൂർണ്ണസംഖ്യ	 tun_open(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, അക്ഷരം **);

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
uint64_t	get_u64(സ്ഥിരം ശൂന്യം *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(സ്ഥിരം ശൂന്യം *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(സ്ഥിരം ശൂന്യം *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
ശൂന്യം		put_u64(ശൂന്യം *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
ശൂന്യം		put_u32(ശൂന്യം *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
ശൂന്യം		put_u16(ശൂന്യം *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(സ്ഥിരം ശൂന്യം *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
ശൂന്യം		put_u32_le(ശൂന്യം *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

ഘടന bwlimit {
	size_t buflen;
	uint64_t rate;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	ഘടന timeval bwstart, bwend;
};

ശൂന്യം bandwidth_limit_init(ഘടന bwlimit *, uint64_t, size_t);
ശൂന്യം bandwidth_limit(ഘടന bwlimit *, size_t);

പൂർണ്ണസംഖ്യ parse_ipqos(സ്ഥിരം അക്ഷരം *);
സ്ഥിരം അക്ഷരം *iptos2str(പൂർണ്ണസംഖ്യ);
ശൂന്യം mktemp_proto(അക്ഷരം *, size_t);

ശൂന്യം	 child_set_env(അക്ഷരം ***envp, u_int *envsizep, സ്ഥിരം അക്ഷരം *name,
	    സ്ഥിരം അക്ഷരം *മൂല്യം);
സ്ഥിരം അക്ഷരം *lookup_env_in_list(സ്ഥിരം അക്ഷരം *env,
	    അക്ഷരം * സ്ഥിരം *envs, size_t nenvs);
സ്ഥിരം അക്ഷരം *lookup_setenv_in_list(സ്ഥിരം അക്ഷരം *env,
	    അക്ഷരം * സ്ഥിരം *envs, size_t nenvs);

പൂർണ്ണസംഖ്യ	 argv_split(സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ *, അക്ഷരം ***, പൂർണ്ണസംഖ്യ);
അക്ഷരം	*argv_assemble(പൂർണ്ണസംഖ്യ, അക്ഷരം **argv);
അക്ഷരം	*argv_next(പൂർണ്ണസംഖ്യ *, അക്ഷരം ***);
ശൂന്യം	 argv_consume(പൂർണ്ണസംഖ്യ *);
ശൂന്യം	 argv_free(അക്ഷരം **, പൂർണ്ണസംഖ്യ);

പൂർണ്ണസംഖ്യ	 exited_cleanly(pid_t, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ);

ഘടന stat;
പൂർണ്ണസംഖ്യ	 safe_path(സ്ഥിരം അക്ഷരം *, ഘടന stat *, സ്ഥിരം അക്ഷരം *, uid_t,
	    അക്ഷരം *, size_t);
പൂർണ്ണസംഖ്യ	 safe_path_fd(പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം *, ഘടന passwd *,
	    അക്ഷരം *err, size_t errlen);

/* authorized_key-style options parsing helpers */
പൂർണ്ണസംഖ്യ	opt_flag(സ്ഥിരം അക്ഷരം *opt, പൂർണ്ണസംഖ്യ allow_negate, സ്ഥിരം അക്ഷരം **optsp);
അക്ഷരം	*opt_dequote(സ്ഥിരം അക്ഷരം **sp, സ്ഥിരം അക്ഷരം **errstrp);
പൂർണ്ണസംഖ്യ	opt_match(സ്ഥിരം അക്ഷരം **opts, സ്ഥിരം അക്ഷരം *term);

/* readconf/servconf option lists */
ശൂന്യം	opt_array_append(സ്ഥിരം അക്ഷരം *file, സ്ഥിരം പൂർണ്ണസംഖ്യ വരി,
	    സ്ഥിരം അക്ഷരം *directive, അക്ഷരം ***array, u_int *lp, സ്ഥിരം അക്ഷരം *s);
ശൂന്യം	opt_array_append2(സ്ഥിരം അക്ഷരം *file, സ്ഥിരം പൂർണ്ണസംഖ്യ വരി,
	    സ്ഥിരം അക്ഷരം *directive, അക്ഷരം ***array, പൂർണ്ണസംഖ്യ **iarray, u_int *lp,
	    സ്ഥിരം അക്ഷരം *s, പൂർണ്ണസംഖ്യ i);
ശൂന്യം	opt_array_free2(അക്ഷരം **array, പൂർണ്ണസംഖ്യ **iarray, u_int l);

ഘടന timespec;
ശൂന്യം ptimeout_init(ഘടന timespec *pt);
ശൂന്യം ptimeout_deadline_sec(ഘടന timespec *pt, long sec);
ശൂന്യം ptimeout_deadline_ms(ഘടന timespec *pt, long ms);
ശൂന്യം ptimeout_deadline_sec_double(ഘടന timespec *pt, ഇരട്ട sec);
ശൂന്യം ptimeout_deadline_monotime_tsp(ഘടന timespec *pt, ഘടന timespec *when);
ശൂന്യം ptimeout_deadline_monotime(ഘടന timespec *pt, time_t when);
ശൂന്യം ptimeout_deadline_monotime_double(ഘടന timespec *pt, ഇരട്ട when);
പൂർണ്ണസംഖ്യ ptimeout_get_ms(ഘടന timespec *pt);
ഘടന timespec *ptimeout_get_tsp(ഘടന timespec *pt);
പൂർണ്ണസംഖ്യ ptimeout_isset(ഘടന timespec *pt);

/* misc-agent.c */
പൂർണ്ണസംഖ്യ	 agent_listener(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, uid_t, സ്ഥിരം അക്ഷരം *,
	    pid_t, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ *, അക്ഷരം **, അക്ഷരം **);
ശൂന്യം	 agent_cleanup_stale(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, uid_t,
	    സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 agent_listener_cleanup(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);

/* readpass.c */

#define RP_ECHO			0x0001
#define RP_ALLOW_STDIN		0x0002
#define RP_ALLOW_EOF		0x0004
#define RP_USE_ASKPASS		0x0008

ഘടന notifier_ctx;

അക്ഷരം	*read_passphrase(സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 ask_permission(സ്ഥിരം അക്ഷരം *, ...) __attribute__((format(printf, 1, 2)));
ഘടന notifier_ctx *notify_start(പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം *, ...)
	__attribute__((format(printf, 2, 3)));
ശൂന്യം	notify_complete(ഘടന notifier_ctx *, സ്ഥിരം അക്ഷരം *, ...)
	__attribute__((format(printf, 2, 3)));

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))
#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

തരനിർവചനം ശൂന്യം (*sshsig_t)(പൂർണ്ണസംഖ്യ);
sshsig_t ssh_signal(പൂർണ്ണസംഖ്യ, sshsig_t);
പൂർണ്ണസംഖ്യ signal_is_crash(പൂർണ്ണസംഖ്യ);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#define FD_CLOSEONEXEC(x) ചെയ്യുക { \
	എങ്കിൽ (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    strerror(errno)); \
} ആകുമ്പോൾ (0)

#endif /* _MISC_H */
