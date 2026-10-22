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

#اگر_غیر_تعریف_شدہ _MISC_H
#تعریف_کرو _MISC_H

#شامل <sys/time.h>
#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <stdio.h>
#شامل <signal.h>

/* special-case port number meaning allow any port */
#تعریف_کرو FWD_PERMIT_ANY_پورٹ	0

/* special-case wildcard meaning allow any host */
#تعریف_کرو FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
ساخت Forward {
	حرف	 *listen_host;		/* Host (address) to listen on. */
	صحیح	  listen_پورٹ;		/* Port to forward. */
	حرف	 *listen_راستہ;		/* Path to bind domain socket. */
	حرف	 *connect_host;		/* Host to connect. */
	صحیح	  connect_پورٹ;		/* Port to connect on connect_host. */
	حرف	 *connect_راستہ;		/* Path to connect domain socket. */
	صحیح	  allocated_پورٹ;	/* Dynamically allocated listen port */
	صحیح	  handle;		/* Handle for dynamic listen ports */
};

صحیح forward_equals(ثابت ساخت Forward *, ثابت ساخت Forward *);
صحیح permitopen_پورٹ(ثابت حرف *p);

صحیح daemonized(خالی);

/* Common server and client forwarding options. */
ساخت ForwardOptions {
	صحیح	 gateway_ports; /* Allow remote connects to forwarded ports. */
	منوال_t	 streamlocal_bind_نقاب; /* umask for streamlocal binds */
	صحیح	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

حرف	*chop(حرف *);
خالی	 rtrim(حرف *);
خالی	skip_space(حرف **);
ثابت حرف *strprefix(ثابت حرف *, ثابت حرف *, صحیح);
حرف	*strdelim(حرف **);
حرف	*strdelimw(حرف **);
خالی	 stringlist_append(حرف ***listp, ثابت حرف *s);
خالی	 stringlist_free(حرف **list);
صحیح	 سیٹ_nonblock(صحیح);
صحیح	 unset_nonblock(صحیح);
خالی	 سیٹ_nodelay(صحیح);
صحیح	 سیٹ_reuseaddr(صحیح);
صحیح	 سیٹ_keepalive(صحیح);
حرف	*get_rdomain(صحیح);
صحیح	 سیٹ_rdomain(صحیح, ثابت حرف *);
صحیح	 get_sock_af(صحیح);
خالی	 سیٹ_sock_tos(صحیح, صحیح);
صحیح	 waitrfd(صحیح, صحیح *, متلون sig_atomic_t *);
صحیح	 timeout_connect(صحیح, ثابت ساخت sockaddr *, socklen_t, صحیح *);
صحیح	 a2port(ثابت حرف *);
صحیح	 a2tun(ثابت حرف *, صحیح *);
حرف	*put_host_پورٹ(ثابت حرف *, u_short);
حرف	*hpdelim2(حرف **, حرف *);
حرف	*hpdelim(حرف **);
حرف	*cleanhostname(حرف *);
حرف	*colon(حرف *);
صحیح	 parse_user_host_راستہ(ثابت حرف *, حرف **, حرف **, حرف **);
صحیح	 parse_user_host_پورٹ(ثابت حرف *, حرف **, حرف **, صحیح *);
صحیح	 parse_uri(ثابت حرف *, ثابت حرف *, حرف **, حرف **, صحیح *, حرف **);
دوہرا	 convtime_double(ثابت حرف *);
صحیح	 convtime(ثابت حرف *);
دوہرا	 convtime_double(ثابت حرف *);
ثابت حرف *fmt_timeframe(time_t t);
صحیح	 tilde_expand(ثابت حرف *, uid_t, حرف **);
حرف	*tilde_expand_filename(ثابت حرف *, uid_t);

حرف	*dollar_expand(صحیح *, ثابت حرف *string, ...);
حرف	*percent_expand(ثابت حرف *, ...) __attribute__((__sentinel__));
حرف	*percent_dollar_expand(ثابت حرف *, ...) __attribute__((__sentinel__));
حرف	*tohex(ثابت خالی *, سائز_t);
خالی	 xextendf(حرف **s, ثابت حرف *sep, ثابت حرف *fmt, ...)
    __attribute__((__format__ (لکھو, 3, 4))) __attribute__((__nonnull__ (3)));
خالی	 sanitise_stdfd(خالی);
خالی	 ms_تفریق_diff(ساخت timeval *, صحیح *);
خالی	 ms_مقصد_timespec(ساخت timespec *, صحیح);
خالی	 monotime_ts(ساخت timespec *);
خالی	 monotime_tv(ساخت timeval *);
time_t	 monotime(خالی);
دوہرا	 monotime_double(خالی);
خالی	 lowercase(حرف *s);
صحیح	 unix_listener(ثابت حرف *, صحیح, صحیح);
صحیح	 valid_domain(حرف *, صحیح, ثابت حرف **);
صحیح	 valid_env_name(ثابت حرف *);
ثابت حرف *atoi_err(ثابت حرف *, صحیح *);
صحیح	 parse_absolute_وقت(ثابت حرف *, uint64_t *);
خالی	 format_absolute_وقت(uint64_t, حرف *, سائز_t);
صحیح	 parse_نمونہ_interval(ثابت حرف *, حرف **, دوہرا *);
صحیح	 راستہ_absolute(ثابت حرف *);
صحیح	 stdfd_devnull(صحیح, صحیح, صحیح);
صحیح	 lib_شامل_ہے_علامت(ثابت حرف *, ثابت حرف *);
حرف	*get_homedir(خالی);
صحیح	 mkdir_راستہ(ثابت حرف *, منوال_t);

خالی	 sock_سیٹ_v6only(صحیح);

ساخت passwd *pwcopy(ساخت passwd *);
خالی	 pwfree(ساخت passwd *); /* NB. only use with pwcopy */

ثابت حرف *ssh_gai_strerror(صحیح);

قسمتعریف خالی privdrop_fn(ساخت passwd *);
قسمتعریف خالی privrestore_fn(خالی);
#تعریف_کرو	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#تعریف_کرو	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#تعریف_کرو	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#تعریف_کرو	SSH_SUBPROCESS_UNSAFE_راستہ	(1<<3)	/* Don't check for safe cmd */
#تعریف_کرو	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(ثابت حرف *, ثابت حرف *, صحیح, حرف **, FILE **, u_int,
    ساخت passwd *, privdrop_fn *, privrestore_fn *);

قسمتعریف ساخت arglist arglist;
ساخت arglist {
	حرف    **list;
	u_int   عدد;
	u_int   nalloc;
};
خالی	 addargs(arglist *, حرف *, ...)
	    __attribute__((format(لکھو, 2, 3)));
خالی	 replacearg(arglist *, u_int, حرف *, ...)
	    __attribute__((format(لکھو, 3, 4)));
خالی	 freeargs(arglist *);

صحیح	 tun_open(صحیح, صحیح, حرف **);

/* Common definitions for ssh tunnel device forwarding */
#تعریف_کرو SSH_TUNMODE_NO		0x00
#تعریف_کرو SSH_TUNMODE_POINTOPOINT	0x01
#تعریف_کرو SSH_TUNMODE_ETHERNET	0x02
#تعریف_کرو SSH_TUNMODE_DEFAULT	SSH_TUNMODE_POINTOPOINT
#تعریف_کرو SSH_TUNMODE_YES		(SSH_TUNMODE_POINTOPOINT|SSH_TUNMODE_ETHERNET)

#تعریف_کرو SSH_TUNID_ANY		0x7fffffff
#تعریف_کرو SSH_TUNID_ERR		(SSH_TUNID_ANY - 1)
#تعریف_کرو SSH_TUNID_MAX		(SSH_TUNID_ANY - 2)

/* Fake port to indicate that host field is really a path. */
#تعریف_کرو پورٹ_STREAMLOCAL	-2

/* Functions to extract or store big-endian words of various sizes */
uint64_t	get_u64(ثابت خالی *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(ثابت خالی *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(ثابت خالی *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
خالی		put_u64(خالی *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
خالی		put_u32(خالی *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
خالی		put_u16(خالی *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(ثابت خالی *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
خالی		put_u32_le(خالی *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

ساخت bwlimit {
	سائز_t buflen;
	uint64_t شرح;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	ساخت timeval bwstart, bwend;
};

خالی bandwidth_حد_بندی_init(ساخت bwlimit *, uint64_t, سائز_t);
خالی bandwidth_حد_بندی(ساخت bwlimit *, سائز_t);

صحیح parse_ipqos(ثابت حرف *);
ثابت حرف *iptos2str(صحیح);
خالی mktemp_proto(حرف *, سائز_t);

خالی	 بچہ_سیٹ_env(حرف ***envp, u_int *envsizep, ثابت حرف *name,
	    ثابت حرف *قدر);
ثابت حرف *lookup_env_اندر_list(ثابت حرف *env,
	    حرف * ثابت *envs, سائز_t nenvs);
ثابت حرف *lookup_setenv_اندر_list(ثابت حرف *env,
	    حرف * ثابت *envs, سائز_t nenvs);

صحیح	 argv_بانٹو(ثابت حرف *, صحیح *, حرف ***, صحیح);
حرف	*argv_assemble(صحیح, حرف **argv);
حرف	*argv_اگلا(صحیح *, حرف ***);
خالی	 argv_consume(صحیح *);
خالی	 argv_free(حرف **, صحیح);

صحیح	 exited_cleanly(pid_t, ثابت حرف *, ثابت حرف *, صحیح);

ساخت stat;
صحیح	 محفوظ_راستہ(ثابت حرف *, ساخت stat *, ثابت حرف *, uid_t,
	    حرف *, سائز_t);
صحیح	 محفوظ_راستہ_fd(صحیح, ثابت حرف *, ساخت passwd *,
	    حرف *err, سائز_t errlen);

/* authorized_key-style options parsing helpers */
صحیح	opt_flag(ثابت حرف *opt, صحیح allow_negate, ثابت حرف **optsp);
حرف	*opt_dequote(ثابت حرف **sp, ثابت حرف **errstrp);
صحیح	opt_مطابقت(ثابت حرف **opts, ثابت حرف *رکن);

/* readconf/servconf option lists */
خالی	opt_array_append(ثابت حرف *file, ثابت صحیح سطر,
	    ثابت حرف *directive, حرف ***array, u_int *lp, ثابت حرف *s);
خالی	opt_array_append2(ثابت حرف *file, ثابت صحیح سطر,
	    ثابت حرف *directive, حرف ***array, صحیح **iarray, u_int *lp,
	    ثابت حرف *s, صحیح i);
خالی	opt_array_free2(حرف **array, صحیح **iarray, u_int l);

ساخت timespec;
خالی ptimeout_init(ساخت timespec *pt);
خالی ptimeout_deadline_sec(ساخت timespec *pt, طویل sec);
خالی ptimeout_deadline_ms(ساخت timespec *pt, طویل ms);
خالی ptimeout_deadline_sec_double(ساخت timespec *pt, دوہرا sec);
خالی ptimeout_deadline_monotime_tsp(ساخت timespec *pt, ساخت timespec *when);
خالی ptimeout_deadline_monotime(ساخت timespec *pt, time_t when);
خالی ptimeout_deadline_monotime_double(ساخت timespec *pt, دوہرا when);
صحیح ptimeout_get_ms(ساخت timespec *pt);
ساخت timespec *ptimeout_get_tsp(ساخت timespec *pt);
صحیح ptimeout_isset(ساخت timespec *pt);

/* misc-agent.c */
صحیح	 agent_listener(ثابت حرف *, ثابت حرف *, uid_t, ثابت حرف *,
	    pid_t, ثابت حرف *, صحیح *, حرف **, حرف **);
خالی	 agent_cleanup_stale(ثابت حرف *, ثابت حرف *, uid_t,
	    ثابت حرف *, صحیح);
صحیح	 agent_listener_cleanup(ثابت حرف *, ثابت حرف *, ثابت حرف *);

/* readpass.c */

#تعریف_کرو RP_ECHO			0x0001
#تعریف_کرو RP_ALLOW_STDIN		0x0002
#تعریف_کرو RP_ALLOW_EOF		0x0004
#تعریف_کرو RP_USE_ASKPASS		0x0008

ساخت notifier_ctx;

حرف	*read_passphrase(ثابت حرف *, صحیح);
صحیح	 ask_permission(ثابت حرف *, ...) __attribute__((format(لکھو, 1, 2)));
ساخت notifier_ctx *notify_آغاز(صحیح, ثابت حرف *, ...)
	__attribute__((format(لکھو, 2, 3)));
خالی	notify_complete(ساخت notifier_ctx *, ثابت حرف *, ...)
	__attribute__((format(لکھو, 2, 3)));

#تعریف_کرو MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#تعریف_کرو زیادہ_سے_زیادہ(a, b)	(((a) > (b)) ? (a) : (b))
#تعریف_کرو ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

قسمتعریف خالی (*sshsig_t)(صحیح);
sshsig_t ssh_signal(صحیح, sshsig_t);
صحیح signal_is_crash(صحیح);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#تعریف_کرو FD_CLOSEONEXEC(x) کرو { \
	اگر (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    strerror(errno)); \
} جب (0)

#اگر_ختم /* _MISC_H */
