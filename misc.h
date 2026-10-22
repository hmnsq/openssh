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
struct Forward {
	char	 *listen_host;		/* Host (address) to listen on. */
	整数	  listen_port;		/* Port to forward. */
	char	 *listen_path;		/* Path to bind domain socket. */
	char	 *connect_host;		/* Host to connect. */
	整数	  connect_port;		/* Port to connect on connect_host. */
	char	 *connect_path;		/* Path to connect domain socket. */
	整数	  allocated_port;	/* Dynamically allocated listen port */
	整数	  handle;		/* Handle for dynamic listen ports */
};

整数 forward_equals(const struct Forward *, const struct Forward *);
整数 permitopen_port(const char *p);

整数 daemonized(void);

/* Common server and client forwarding options. */
struct ForwardOptions {
	整数	 gateway_ports; /* Allow remote connects to forwarded ports. */
	mode_t	 streamlocal_bind_mask; /* umask for streamlocal binds */
	整数	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

char	*chop(char *);
void	 rtrim(char *);
void	skip_space(char **);
const char *strprefix(const char *, const char *, 整数);
char	*strdelim(char **);
char	*strdelimw(char **);
void	 stringlist_append(char ***listp, const char *s);
void	 stringlist_free(char **list);
整数	 set_nonblock(整数);
整数	 unset_nonblock(整数);
void	 set_nodelay(整数);
整数	 set_reuseaddr(整数);
整数	 set_keepalive(整数);
char	*get_rdomain(整数);
整数	 set_rdomain(整数, const char *);
整数	 get_sock_af(整数);
void	 set_sock_tos(整数, 整数);
整数	 waitrfd(整数, 整数 *, volatile sig_atomic_t *);
整数	 timeout_connect(整数, const struct sockaddr *, socklen_t, 整数 *);
整数	 a2port(const char *);
整数	 a2tun(const char *, 整数 *);
char	*put_host_port(const char *, u_short);
char	*hpdelim2(char **, char *);
char	*hpdelim(char **);
char	*cleanhostname(char *);
char	*colon(char *);
整数	 parse_user_host_path(const char *, char **, char **, char **);
整数	 parse_user_host_port(const char *, char **, char **, 整数 *);
整数	 parse_uri(const char *, const char *, char **, char **, 整数 *, char **);
double	 convtime_double(const char *);
整数	 convtime(const char *);
double	 convtime_double(const char *);
const char *fmt_timeframe(time_t t);
整数	 tilde_expand(const char *, uid_t, char **);
char	*tilde_expand_filename(const char *, uid_t);

char	*dollar_expand(整数 *, const char *string, ...);
char	*percent_expand(const char *, ...) __attribute__((__sentinel__));
char	*percent_dollar_expand(const char *, ...) __attribute__((__sentinel__));
char	*tohex(const void *, size_t);
void	 xextendf(char **s, const char *sep, const char *fmt, ...)
    __attribute__((__format__ (printf, 3, 4))) __attribute__((__nonnull__ (3)));
void	 sanitise_stdfd(void);
void	 ms_subtract_diff(struct timeval *, 整数 *);
void	 ms_to_timespec(struct timespec *, 整数);
void	 monotime_ts(struct timespec *);
void	 monotime_tv(struct timeval *);
time_t	 monotime(void);
double	 monotime_double(void);
void	 lowercase(char *s);
整数	 unix_listener(const char *, 整数, 整数);
整数	 valid_domain(char *, 整数, const char **);
整数	 valid_env_name(const char *);
const char *atoi_err(const char *, 整数 *);
整数	 parse_absolute_time(const char *, uint64_t *);
void	 format_absolute_time(uint64_t, char *, size_t);
整数	 parse_pattern_interval(const char *, char **, double *);
整数	 path_absolute(const char *);
整数	 stdfd_devnull(整数, 整数, 整数);
整数	 lib_contains_symbol(const char *, const char *);
char	*get_homedir(void);
整数	 mkdir_path(const char *, mode_t);

void	 sock_set_v6only(整数);

struct passwd *pwcopy(struct passwd *);
void	 pwfree(struct passwd *); /* NB. only use with pwcopy */

const char *ssh_gai_strerror(整数);

typedef void privdrop_fn(struct passwd *);
typedef void privrestore_fn(void);
#define	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#define	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#define	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#define	SSH_SUBPROCESS_UNSAFE_PATH	(1<<3)	/* Don't check for safe cmd */
#define	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(const char *, const char *, 整数, char **, FILE **, u_int,
    struct passwd *, privdrop_fn *, privrestore_fn *);

typedef struct arglist arglist;
struct arglist {
	char    **list;
	u_int   num;
	u_int   nalloc;
};
void	 addargs(arglist *, char *, ...)
	    __attribute__((format(printf, 2, 3)));
void	 replacearg(arglist *, u_int, char *, ...)
	    __attribute__((format(printf, 3, 4)));
void	 freeargs(arglist *);

整数	 tun_open(整数, 整数, char **);

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

struct bwlimit {
	size_t buflen;
	uint64_t rate;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	struct timeval bwstart, bwend;
};

void bandwidth_limit_init(struct bwlimit *, uint64_t, size_t);
void bandwidth_limit(struct bwlimit *, size_t);

整数 parse_ipqos(const char *);
const char *iptos2str(整数);
void mktemp_proto(char *, size_t);

void	 child_set_env(char ***envp, u_int *envsizep, const char *name,
	    const char *value);
const char *lookup_env_in_list(const char *env,
	    char * const *envs, size_t nenvs);
const char *lookup_setenv_in_list(const char *env,
	    char * const *envs, size_t nenvs);

整数	 argv_split(const char *, 整数 *, char ***, 整数);
char	*argv_assemble(整数, char **argv);
char	*argv_next(整数 *, char ***);
void	 argv_consume(整数 *);
void	 argv_free(char **, 整数);

整数	 exited_cleanly(pid_t, const char *, const char *, 整数);

struct stat;
整数	 safe_path(const char *, struct stat *, const char *, uid_t,
	    char *, size_t);
整数	 safe_path_fd(整数, const char *, struct passwd *,
	    char *err, size_t errlen);

/* authorized_key-style options parsing helpers */
整数	opt_flag(const char *opt, 整数 allow_negate, const char **optsp);
char	*opt_dequote(const char **sp, const char **errstrp);
整数	opt_match(const char **opts, const char *term);

/* readconf/servconf option lists */
void	opt_array_append(const char *file, const 整数 line,
	    const char *directive, char ***array, u_int *lp, const char *s);
void	opt_array_append2(const char *file, const 整数 line,
	    const char *directive, char ***array, 整数 **iarray, u_int *lp,
	    const char *s, 整数 i);
void	opt_array_free2(char **array, 整数 **iarray, u_int l);

struct timespec;
void ptimeout_init(struct timespec *pt);
void ptimeout_deadline_sec(struct timespec *pt, long sec);
void ptimeout_deadline_ms(struct timespec *pt, long ms);
void ptimeout_deadline_sec_double(struct timespec *pt, double sec);
void ptimeout_deadline_monotime_tsp(struct timespec *pt, struct timespec *when);
void ptimeout_deadline_monotime(struct timespec *pt, time_t when);
void ptimeout_deadline_monotime_double(struct timespec *pt, double when);
整数 ptimeout_get_ms(struct timespec *pt);
struct timespec *ptimeout_get_tsp(struct timespec *pt);
整数 ptimeout_isset(struct timespec *pt);

/* misc-agent.c */
整数	 agent_listener(const char *, const char *, uid_t, const char *,
	    pid_t, const char *, 整数 *, char **, char **);
void	 agent_cleanup_stale(const char *, const char *, uid_t,
	    const char *, 整数);
整数	 agent_listener_cleanup(const char *, const char *, const char *);

/* readpass.c */

#define RP_ECHO			0x0001
#define RP_ALLOW_STDIN		0x0002
#define RP_ALLOW_EOF		0x0004
#define RP_USE_ASKPASS		0x0008

struct notifier_ctx;

char	*read_passphrase(const char *, 整数);
整数	 ask_permission(const char *, ...) __attribute__((format(printf, 1, 2)));
struct notifier_ctx *notify_start(整数, const char *, ...)
	__attribute__((format(printf, 2, 3)));
void	notify_complete(struct notifier_ctx *, const char *, ...)
	__attribute__((format(printf, 2, 3)));

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))
#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

typedef void (*sshsig_t)(整数);
sshsig_t ssh_signal(整数, sshsig_t);
整数 signal_is_crash(整数);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#define FD_CLOSEONEXEC(x) do { \
	如果 (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    strerror(errno)); \
} 当 (0)

#endif /* _MISC_H */
