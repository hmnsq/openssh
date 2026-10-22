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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <signal.h>

/* special-case port number meaning allow any port */
#define FWD_PERMIT_ANY_PORT	0

/* special-case wildcard meaning allow any host */
#define FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
sa_nracanaa Forward {
	var_na	 *listen_host;		/* Host (address) to listen on. */
	puur_naa_nka	  listen_port;		/* Port to forward. */
	var_na	 *listen_path;		/* Path to bind domain socket. */
	var_na	 *connect_host;		/* Host to connect. */
	puur_naa_nka	  connect_port;		/* Port to connect on connect_host. */
	var_na	 *connect_path;		/* Path to connect domain socket. */
	puur_naa_nka	  allocated_port;	/* Dynamically allocated listen port */
	puur_naa_nka	  handle;		/* Handle for dynamic listen ports */
};

puur_naa_nka forward_equals(const sa_nracanaa Forward *, const sa_nracanaa Forward *);
puur_naa_nka permitopen_port(const var_na *p);

puur_naa_nka daemonized(void);

/* Common server and client forwarding options. */
sa_nracanaa ForwardOptions {
	puur_naa_nka	 gateway_ports; /* Allow remote connects to forwarded ports. */
	mode_t	 streamlocal_bind_mask; /* umask for streamlocal binds */
	puur_naa_nka	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

var_na	*chop(var_na *);
void	 rtrim(var_na *);
void	skip_space(var_na **);
const var_na *strprefix(const var_na *, const var_na *, puur_naa_nka);
var_na	*strdelim(var_na **);
var_na	*strdelimw(var_na **);
void	 stringlist_append(var_na ***listp, const var_na *s);
void	 stringlist_free(var_na **list);
puur_naa_nka	 set_nonblock(puur_naa_nka);
puur_naa_nka	 unset_nonblock(puur_naa_nka);
void	 set_nodelay(puur_naa_nka);
puur_naa_nka	 set_reuseaddr(puur_naa_nka);
puur_naa_nka	 set_keepalive(puur_naa_nka);
var_na	*get_rdomain(puur_naa_nka);
puur_naa_nka	 set_rdomain(puur_naa_nka, const var_na *);
puur_naa_nka	 get_sock_af(puur_naa_nka);
void	 set_sock_tos(puur_naa_nka, puur_naa_nka);
puur_naa_nka	 waitrfd(puur_naa_nka, puur_naa_nka *, ca_ncala sig_atomic_t *);
puur_naa_nka	 timeout_connect(puur_naa_nka, const sa_nracanaa sockaddr *, socklen_t, puur_naa_nka *);
puur_naa_nka	 a2port(const var_na *);
puur_naa_nka	 a2tun(const var_na *, puur_naa_nka *);
var_na	*put_host_port(const var_na *, u_short);
var_na	*hpdelim2(var_na **, var_na *);
var_na	*hpdelim(var_na **);
var_na	*cleanhostname(var_na *);
var_na	*colon(var_na *);
puur_naa_nka	 parse_user_host_path(const var_na *, var_na **, var_na **, var_na **);
puur_naa_nka	 parse_user_host_port(const var_na *, var_na **, var_na **, puur_naa_nka *);
puur_naa_nka	 parse_uri(const var_na *, const var_na *, var_na **, var_na **, puur_naa_nka *, var_na **);
dviguu_na	 convtime_double(const var_na *);
puur_naa_nka	 convtime(const var_na *);
dviguu_na	 convtime_double(const var_na *);
const var_na *fmt_timeframe(time_t t);
puur_naa_nka	 tilde_expand(const var_na *, uid_t, var_na **);
var_na	*tilde_expand_filename(const var_na *, uid_t);

var_na	*dollar_expand(puur_naa_nka *, const var_na *string, ...);
var_na	*percent_expand(const var_na *, ...) __attribute__((__sentinel__));
var_na	*percent_dollar_expand(const var_na *, ...) __attribute__((__sentinel__));
var_na	*tohex(const void *, size_t);
void	 xextendf(var_na **s, const var_na *sep, const var_na *fmt, ...)
    __attribute__((__format__ (printf, 3, 4))) __attribute__((__nonnull__ (3)));
void	 sanitise_stdfd(void);
void	 ms_subtract_diff(sa_nracanaa timeval *, puur_naa_nka *);
void	 ms_to_timespec(sa_nracanaa timespec *, puur_naa_nka);
void	 monotime_ts(sa_nracanaa timespec *);
void	 monotime_tv(sa_nracanaa timeval *);
time_t	 monotime(void);
dviguu_na	 monotime_double(void);
void	 lowercase(var_na *s);
puur_naa_nka	 unix_listener(const var_na *, puur_naa_nka, puur_naa_nka);
puur_naa_nka	 valid_domain(var_na *, puur_naa_nka, const var_na **);
puur_naa_nka	 valid_env_name(const var_na *);
const var_na *atoi_err(const var_na *, puur_naa_nka *);
puur_naa_nka	 parse_absolute_time(const var_na *, uint64_t *);
void	 format_absolute_time(uint64_t, var_na *, size_t);
puur_naa_nka	 parse_pattern_interval(const var_na *, var_na **, dviguu_na *);
puur_naa_nka	 path_absolute(const var_na *);
puur_naa_nka	 stdfd_devnull(puur_naa_nka, puur_naa_nka, puur_naa_nka);
puur_naa_nka	 lib_contains_symbol(const var_na *, const var_na *);
var_na	*get_homedir(void);
puur_naa_nka	 mkdir_path(const var_na *, mode_t);

void	 sock_set_v6only(puur_naa_nka);

sa_nracanaa passwd *pwcopy(sa_nracanaa passwd *);
void	 pwfree(sa_nracanaa passwd *); /* NB. only use with pwcopy */

const var_na *ssh_gai_strerror(puur_naa_nka);

typedef void privdrop_fn(sa_nracanaa passwd *);
typedef void privrestore_fn(void);
#define	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#define	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#define	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#define	SSH_SUBPROCESS_UNSAFE_PATH	(1<<3)	/* Don't check for safe cmd */
#define	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(const var_na *, const var_na *, puur_naa_nka, var_na **, FILE **, u_int,
    sa_nracanaa passwd *, privdrop_fn *, privrestore_fn *);

typedef sa_nracanaa arglist arglist;
sa_nracanaa arglist {
	var_na    **list;
	u_int   num;
	u_int   nalloc;
};
void	 addargs(arglist *, var_na *, ...)
	    __attribute__((format(printf, 2, 3)));
void	 replacearg(arglist *, u_int, var_na *, ...)
	    __attribute__((format(printf, 3, 4)));
void	 freeargs(arglist *);

puur_naa_nka	 tun_open(puur_naa_nka, puur_naa_nka, var_na **);

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
uint64_t	get_u64(const void *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(const void *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(const void *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
void		put_u64(void *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
void		put_u32(void *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
void		put_u16(void *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(const void *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
void		put_u32_le(void *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

sa_nracanaa bwlimit {
	size_t buflen;
	uint64_t rate;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	sa_nracanaa timeval bwstart, bwend;
};

void bandwidth_limit_init(sa_nracanaa bwlimit *, uint64_t, size_t);
void bandwidth_limit(sa_nracanaa bwlimit *, size_t);

puur_naa_nka parse_ipqos(const var_na *);
const var_na *iptos2str(puur_naa_nka);
void mktemp_proto(var_na *, size_t);

void	 child_set_env(var_na ***envp, u_int *envsizep, const var_na *name,
	    const var_na *value);
const var_na *lookup_env_in_list(const var_na *env,
	    var_na * const *envs, size_t nenvs);
const var_na *lookup_setenv_in_list(const var_na *env,
	    var_na * const *envs, size_t nenvs);

puur_naa_nka	 argv_split(const var_na *, puur_naa_nka *, var_na ***, puur_naa_nka);
var_na	*argv_assemble(puur_naa_nka, var_na **argv);
var_na	*argv_next(puur_naa_nka *, var_na ***);
void	 argv_consume(puur_naa_nka *);
void	 argv_free(var_na **, puur_naa_nka);

puur_naa_nka	 exited_cleanly(pid_t, const var_na *, const var_na *, puur_naa_nka);

sa_nracanaa stat;
puur_naa_nka	 safe_path(const var_na *, sa_nracanaa stat *, const var_na *, uid_t,
	    var_na *, size_t);
puur_naa_nka	 safe_path_fd(puur_naa_nka, const var_na *, sa_nracanaa passwd *,
	    var_na *err, size_t errlen);

/* authorized_key-style options parsing helpers */
puur_naa_nka	opt_flag(const var_na *opt, puur_naa_nka allow_negate, const var_na **optsp);
var_na	*opt_dequote(const var_na **sp, const var_na **errstrp);
puur_naa_nka	opt_match(const var_na **opts, const var_na *term);

/* readconf/servconf option lists */
void	opt_array_append(const var_na *file, const puur_naa_nka line,
	    const var_na *directive, var_na ***array, u_int *lp, const var_na *s);
void	opt_array_append2(const var_na *file, const puur_naa_nka line,
	    const var_na *directive, var_na ***array, puur_naa_nka **iarray, u_int *lp,
	    const var_na *s, puur_naa_nka i);
void	opt_array_free2(var_na **array, puur_naa_nka **iarray, u_int l);

sa_nracanaa timespec;
void ptimeout_init(sa_nracanaa timespec *pt);
void ptimeout_deadline_sec(sa_nracanaa timespec *pt, long sec);
void ptimeout_deadline_ms(sa_nracanaa timespec *pt, long ms);
void ptimeout_deadline_sec_double(sa_nracanaa timespec *pt, dviguu_na sec);
void ptimeout_deadline_monotime_tsp(sa_nracanaa timespec *pt, sa_nracanaa timespec *when);
void ptimeout_deadline_monotime(sa_nracanaa timespec *pt, time_t when);
void ptimeout_deadline_monotime_double(sa_nracanaa timespec *pt, dviguu_na when);
puur_naa_nka ptimeout_get_ms(sa_nracanaa timespec *pt);
sa_nracanaa timespec *ptimeout_get_tsp(sa_nracanaa timespec *pt);
puur_naa_nka ptimeout_isset(sa_nracanaa timespec *pt);

/* misc-agent.c */
puur_naa_nka	 agent_listener(const var_na *, const var_na *, uid_t, const var_na *,
	    pid_t, const var_na *, puur_naa_nka *, var_na **, var_na **);
void	 agent_cleanup_stale(const var_na *, const var_na *, uid_t,
	    const var_na *, puur_naa_nka);
puur_naa_nka	 agent_listener_cleanup(const var_na *, const var_na *, const var_na *);

/* readpass.c */

#define RP_ECHO			0x0001
#define RP_ALLOW_STDIN		0x0002
#define RP_ALLOW_EOF		0x0004
#define RP_USE_ASKPASS		0x0008

sa_nracanaa notifier_ctx;

var_na	*read_passphrase(const var_na *, puur_naa_nka);
puur_naa_nka	 ask_permission(const var_na *, ...) __attribute__((format(printf, 1, 2)));
sa_nracanaa notifier_ctx *notify_start(puur_naa_nka, const var_na *, ...)
	__attribute__((format(printf, 2, 3)));
void	notify_complete(sa_nracanaa notifier_ctx *, const var_na *, ...)
	__attribute__((format(printf, 2, 3)));

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))
#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

typedef void (*sshsig_t)(puur_naa_nka);
sshsig_t ssh_signal(puur_naa_nka, sshsig_t);
puur_naa_nka signal_is_crash(puur_naa_nka);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#define FD_CLOSEONEXEC(x) do { \
	ᰀᰧ (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    strerror(errno)); \
} ᰀᰬ (0)

#endif /* _MISC_H */
