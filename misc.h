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

#جے_بنا_تعریف _MISC_H
#تعریف_کرو _MISC_H

#ضمن <sys/time.h>
#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <stdio.h>
#ضمن <signal.h>

/* special-case port number meaning allow any port */
#تعریف_کرو FWD_PERMIT_ANY_پورٹ	0

/* special-case wildcard meaning allow any host */
#تعریف_کرو FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
بنية Forward {
	حرف	 *listen_host;		/* Host (address) to listen on. */
	صحيح	  listen_پورٹ;		/* Port to forward. */
	حرف	 *listen_رستہ;		/* Path to bind domain socket. */
	حرف	 *connect_host;		/* Host to connect. */
	صحيح	  connect_پورٹ;		/* Port to connect on connect_host. */
	حرف	 *connect_رستہ;		/* Path to connect domain socket. */
	صحيح	  allocated_پورٹ;	/* Dynamically allocated listen port */
	صحيح	  handle;		/* Handle for dynamic listen ports */
};

صحيح forward_equals(ثابت بنية Forward *, ثابت بنية Forward *);
صحيح permitopen_پورٹ(ثابت حرف *p);

صحيح daemonized(فراغ);

/* Common server and client forwarding options. */
بنية ForwardOptions {
	صحيح	 gateway_ports; /* Allow remote connects to forwarded ports. */
	منوال_t	 streamlocal_bind_نقاب; /* umask for streamlocal binds */
	صحيح	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

حرف	*chop(حرف *);
فراغ	 rtrim(حرف *);
فراغ	skip_space(حرف **);
ثابت حرف *strprefix(ثابت حرف *, ثابت حرف *, صحيح);
حرف	*strdelim(حرف **);
حرف	*strdelimw(حرف **);
فراغ	 stringlist_append(حرف ***listp, ثابت حرف *s);
فراغ	 stringlist_free(حرف **list);
صحيح	 سیٹ_nonblock(صحيح);
صحيح	 unset_nonblock(صحيح);
فراغ	 سیٹ_nodelay(صحيح);
صحيح	 سیٹ_reuseaddr(صحيح);
صحيح	 سیٹ_keepalive(صحيح);
حرف	*get_rdomain(صحيح);
صحيح	 سیٹ_rdomain(صحيح, ثابت حرف *);
صحيح	 get_sock_af(صحيح);
فراغ	 سیٹ_sock_tos(صحيح, صحيح);
صحيح	 waitrfd(صحيح, صحيح *, متطاير sig_atomic_t *);
صحيح	 timeout_connect(صحيح, ثابت بنية sockaddr *, socklen_t, صحيح *);
صحيح	 a2port(ثابت حرف *);
صحيح	 a2tun(ثابت حرف *, صحيح *);
حرف	*put_host_پورٹ(ثابت حرف *, u_short);
حرف	*hpdelim2(حرف **, حرف *);
حرف	*hpdelim(حرف **);
حرف	*cleanhostname(حرف *);
حرف	*colon(حرف *);
صحيح	 parse_user_host_رستہ(ثابت حرف *, حرف **, حرف **, حرف **);
صحيح	 parse_user_host_پورٹ(ثابت حرف *, حرف **, حرف **, صحيح *);
صحيح	 parse_uri(ثابت حرف *, ثابت حرف *, حرف **, حرف **, صحيح *, حرف **);
مزدوج	 convtime_double(ثابت حرف *);
صحيح	 convtime(ثابت حرف *);
مزدوج	 convtime_double(ثابت حرف *);
ثابت حرف *fmt_timeframe(time_t t);
صحيح	 tilde_expand(ثابت حرف *, uid_t, حرف **);
حرف	*tilde_expand_filename(ثابت حرف *, uid_t);

حرف	*dollar_expand(صحيح *, ثابت حرف *string, ...);
حرف	*percent_expand(ثابت حرف *, ...) __attribute__((__sentinel__));
حرف	*percent_dollar_expand(ثابت حرف *, ...) __attribute__((__sentinel__));
حرف	*tohex(ثابت فراغ *, ناپ_t);
فراغ	 xextendf(حرف **s, ثابت حرف *sep, ثابت حرف *fmt, ...)
    __attribute__((__format__ (لکھو, 3, 4))) __attribute__((__nonnull__ (3)));
فراغ	 sanitise_stdfd(فراغ);
فراغ	 ms_گھٹاؤ_diff(بنية timeval *, صحيح *);
فراغ	 ms_منزل_timespec(بنية timespec *, صحيح);
فراغ	 monotime_ts(بنية timespec *);
فراغ	 monotime_tv(بنية timeval *);
time_t	 monotime(فراغ);
مزدوج	 monotime_double(فراغ);
فراغ	 lowercase(حرف *s);
صحيح	 unix_listener(ثابت حرف *, صحيح, صحيح);
صحيح	 valid_domain(حرف *, صحيح, ثابت حرف **);
صحيح	 valid_env_name(ثابت حرف *);
ثابت حرف *atoi_err(ثابت حرف *, صحيح *);
صحيح	 parse_absolute_ویلا(ثابت حرف *, uint64_t *);
فراغ	 format_absolute_ویلا(uint64_t, حرف *, ناپ_t);
صحيح	 parse_نمونہ_interval(ثابت حرف *, حرف **, مزدوج *);
صحيح	 رستہ_absolute(ثابت حرف *);
صحيح	 stdfd_devnull(صحيح, صحيح, صحيح);
صحيح	 lib_شامل_اے_علامت(ثابت حرف *, ثابت حرف *);
حرف	*get_homedir(فراغ);
صحيح	 mkdir_رستہ(ثابت حرف *, منوال_t);

فراغ	 sock_سیٹ_v6only(صحيح);

بنية passwd *pwcopy(بنية passwd *);
فراغ	 pwfree(بنية passwd *); /* NB. only use with pwcopy */

ثابت حرف *ssh_gai_strerror(صحيح);

تعريفنوع فراغ privdrop_fn(بنية passwd *);
تعريفنوع فراغ privrestore_fn(فراغ);
#تعریف_کرو	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#تعریف_کرو	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#تعریف_کرو	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#تعریف_کرو	SSH_SUBPROCESS_UNSAFE_رستہ	(1<<3)	/* Don't check for safe cmd */
#تعریف_کرو	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(ثابت حرف *, ثابت حرف *, صحيح, حرف **, FILE **, u_int,
    بنية passwd *, privdrop_fn *, privrestore_fn *);

تعريفنوع بنية arglist arglist;
بنية arglist {
	حرف    **list;
	u_int   عدد;
	u_int   nalloc;
};
فراغ	 addargs(arglist *, حرف *, ...)
	    __attribute__((format(لکھو, 2, 3)));
فراغ	 replacearg(arglist *, u_int, حرف *, ...)
	    __attribute__((format(لکھو, 3, 4)));
فراغ	 freeargs(arglist *);

صحيح	 tun_open(صحيح, صحيح, حرف **);

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
uint64_t	get_u64(ثابت فراغ *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(ثابت فراغ *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(ثابت فراغ *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
فراغ		put_u64(فراغ *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
فراغ		put_u32(فراغ *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
فراغ		put_u16(فراغ *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(ثابت فراغ *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
فراغ		put_u32_le(فراغ *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

بنية bwlimit {
	ناپ_t buflen;
	uint64_t شرح;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	بنية timeval bwstart, bwend;
};

فراغ bandwidth_حد_بندی_init(بنية bwlimit *, uint64_t, ناپ_t);
فراغ bandwidth_حد_بندی(بنية bwlimit *, ناپ_t);

صحيح parse_ipqos(ثابت حرف *);
ثابت حرف *iptos2str(صحيح);
فراغ mktemp_proto(حرف *, ناپ_t);

فراغ	 بچہ_سیٹ_env(حرف ***envp, u_int *envsizep, ثابت حرف *name,
	    ثابت حرف *قدر);
ثابت حرف *lookup_env_وچ_list(ثابت حرف *env,
	    حرف * ثابت *envs, ناپ_t nenvs);
ثابت حرف *lookup_setenv_وچ_list(ثابت حرف *env,
	    حرف * ثابت *envs, ناپ_t nenvs);

صحيح	 argv_ونڈو(ثابت حرف *, صحيح *, حرف ***, صحيح);
حرف	*argv_assemble(صحيح, حرف **argv);
حرف	*argv_اگلا(صحيح *, حرف ***);
فراغ	 argv_consume(صحيح *);
فراغ	 argv_free(حرف **, صحيح);

صحيح	 exited_cleanly(pid_t, ثابت حرف *, ثابت حرف *, صحيح);

بنية stat;
صحيح	 محفوظ_رستہ(ثابت حرف *, بنية stat *, ثابت حرف *, uid_t,
	    حرف *, ناپ_t);
صحيح	 محفوظ_رستہ_fd(صحيح, ثابت حرف *, بنية passwd *,
	    حرف *err, ناپ_t errlen);

/* authorized_key-style options parsing helpers */
صحيح	opt_flag(ثابت حرف *opt, صحيح allow_negate, ثابت حرف **optsp);
حرف	*opt_dequote(ثابت حرف **sp, ثابت حرف **errstrp);
صحيح	opt_میل(ثابت حرف **opts, ثابت حرف *رکن);

/* readconf/servconf option lists */
فراغ	opt_array_append(ثابت حرف *file, ثابت صحيح سطر,
	    ثابت حرف *directive, حرف ***array, u_int *lp, ثابت حرف *s);
فراغ	opt_array_append2(ثابت حرف *file, ثابت صحيح سطر,
	    ثابت حرف *directive, حرف ***array, صحيح **iarray, u_int *lp,
	    ثابت حرف *s, صحيح i);
فراغ	opt_array_free2(حرف **array, صحيح **iarray, u_int l);

بنية timespec;
فراغ ptimeout_init(بنية timespec *pt);
فراغ ptimeout_deadline_sec(بنية timespec *pt, لما sec);
فراغ ptimeout_deadline_ms(بنية timespec *pt, لما ms);
فراغ ptimeout_deadline_sec_double(بنية timespec *pt, مزدوج sec);
فراغ ptimeout_deadline_monotime_tsp(بنية timespec *pt, بنية timespec *when);
فراغ ptimeout_deadline_monotime(بنية timespec *pt, time_t when);
فراغ ptimeout_deadline_monotime_double(بنية timespec *pt, مزدوج when);
صحيح ptimeout_get_ms(بنية timespec *pt);
بنية timespec *ptimeout_get_tsp(بنية timespec *pt);
صحيح ptimeout_isset(بنية timespec *pt);

/* misc-agent.c */
صحيح	 agent_listener(ثابت حرف *, ثابت حرف *, uid_t, ثابت حرف *,
	    pid_t, ثابت حرف *, صحيح *, حرف **, حرف **);
فراغ	 agent_cleanup_stale(ثابت حرف *, ثابت حرف *, uid_t,
	    ثابت حرف *, صحيح);
صحيح	 agent_listener_cleanup(ثابت حرف *, ثابت حرف *, ثابت حرف *);

/* readpass.c */

#تعریف_کرو RP_ECHO			0x0001
#تعریف_کرو RP_ALLOW_STDIN		0x0002
#تعریف_کرو RP_ALLOW_EOF		0x0004
#تعریف_کرو RP_USE_ASKPASS		0x0008

بنية notifier_ctx;

حرف	*read_passphrase(ثابت حرف *, صحيح);
صحيح	 ask_permission(ثابت حرف *, ...) __attribute__((format(لکھو, 1, 2)));
بنية notifier_ctx *notify_شروع(صحيح, ثابت حرف *, ...)
	__attribute__((format(لکھو, 2, 3)));
فراغ	notify_complete(بنية notifier_ctx *, ثابت حرف *, ...)
	__attribute__((format(لکھو, 2, 3)));

#تعریف_کرو MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#تعریف_کرو ودھ_توں_ودھ(a, b)	(((a) > (b)) ? (a) : (b))
#تعریف_کرو ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

تعريفنوع فراغ (*sshsig_t)(صحيح);
sshsig_t ssh_signal(صحيح, sshsig_t);
صحيح signal_is_crash(صحيح);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#تعریف_کرو FD_CLOSEONEXEC(x) افعل { \
	إذا (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    strerror(errno)); \
} طالما (0)

#جے_انت /* _MISC_H */
