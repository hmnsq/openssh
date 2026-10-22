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

#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <signal.h>

/* special-case port number meaning allow any port */
#define FWD_PERMIT_ANY_PORT	0

/* special-case wildcard meaning allow any host */
#define FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
संरचना Forward {
	अक्षर	 *listen_host;		/* Host (address) to listen on. */
	पूर्णांक	  listen_port;		/* Port to forward. */
	अक्षर	 *listen_path;		/* Path to bind domain socket. */
	अक्षर	 *connect_host;		/* Host to connect. */
	पूर्णांक	  connect_port;		/* Port to connect on connect_host. */
	अक्षर	 *connect_path;		/* Path to connect domain socket. */
	पूर्णांक	  allocated_port;	/* Dynamically allocated listen port */
	पूर्णांक	  handle;		/* Handle for dynamic listen ports */
};

पूर्णांक forward_equals(स्थिरांक संरचना Forward *, स्थिरांक संरचना Forward *);
पूर्णांक permitopen_port(स्थिरांक अक्षर *p);

पूर्णांक daemonized(शून्य);

/* Common server and client forwarding options. */
संरचना ForwardOptions {
	पूर्णांक	 gateway_ports; /* Allow remote connects to forwarded ports. */
	mode_t	 streamlocal_bind_mask; /* umask for streamlocal binds */
	पूर्णांक	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

अक्षर	*chop(अक्षर *);
शून्य	 rtrim(अक्षर *);
शून्य	skip_space(अक्षर **);
स्थिरांक अक्षर *strprefix(स्थिरांक अक्षर *, स्थिरांक अक्षर *, पूर्णांक);
अक्षर	*strdelim(अक्षर **);
अक्षर	*strdelimw(अक्षर **);
शून्य	 stringlist_append(अक्षर ***listp, स्थिरांक अक्षर *s);
शून्य	 stringlist_free(अक्षर **list);
पूर्णांक	 set_nonblock(पूर्णांक);
पूर्णांक	 unset_nonblock(पूर्णांक);
शून्य	 set_nodelay(पूर्णांक);
पूर्णांक	 set_reuseaddr(पूर्णांक);
पूर्णांक	 set_keepalive(पूर्णांक);
अक्षर	*get_rdomain(पूर्णांक);
पूर्णांक	 set_rdomain(पूर्णांक, स्थिरांक अक्षर *);
पूर्णांक	 get_sock_af(पूर्णांक);
शून्य	 set_sock_tos(पूर्णांक, पूर्णांक);
पूर्णांक	 waitrfd(पूर्णांक, पूर्णांक *, अस्थिर संक_पूर्ण_प्रकार *);
पूर्णांक	 timeout_connect(पूर्णांक, स्थिरांक संरचना sockaddr *, socklen_t, पूर्णांक *);
पूर्णांक	 a2port(स्थिरांक अक्षर *);
पूर्णांक	 a2tun(स्थिरांक अक्षर *, पूर्णांक *);
अक्षर	*put_host_port(स्थिरांक अक्षर *, u_short);
अक्षर	*hpdelim2(अक्षर **, अक्षर *);
अक्षर	*hpdelim(अक्षर **);
अक्षर	*cleanhostname(अक्षर *);
अक्षर	*colon(अक्षर *);
पूर्णांक	 parse_user_host_path(स्थिरांक अक्षर *, अक्षर **, अक्षर **, अक्षर **);
पूर्णांक	 parse_user_host_port(स्थिरांक अक्षर *, अक्षर **, अक्षर **, पूर्णांक *);
पूर्णांक	 parse_uri(स्थिरांक अक्षर *, स्थिरांक अक्षर *, अक्षर **, अक्षर **, पूर्णांक *, अक्षर **);
द्विगुण	 convtime_double(स्थिरांक अक्षर *);
पूर्णांक	 convtime(स्थिरांक अक्षर *);
द्विगुण	 convtime_double(स्थिरांक अक्षर *);
स्थिरांक अक्षर *fmt_timeframe(समय_प्रकार t);
पूर्णांक	 tilde_expand(स्थिरांक अक्षर *, uid_t, अक्षर **);
अक्षर	*tilde_expand_filename(स्थिरांक अक्षर *, uid_t);

अक्षर	*dollar_expand(पूर्णांक *, स्थिरांक अक्षर *string, ...);
अक्षर	*percent_expand(स्थिरांक अक्षर *, ...) __attribute__((__sentinel__));
अक्षर	*percent_dollar_expand(स्थिरांक अक्षर *, ...) __attribute__((__sentinel__));
अक्षर	*tohex(स्थिरांक शून्य *, माप_प्रकार);
शून्य	 xextendf(अक्षर **s, स्थिरांक अक्षर *sep, स्थिरांक अक्षर *fmt, ...)
    __attribute__((__format__ (म_लिखो, 3, 4))) __attribute__((__nonnull__ (3)));
शून्य	 sanitise_stdfd(शून्य);
शून्य	 ms_subtract_diff(संरचना timeval *, पूर्णांक *);
शून्य	 ms_to_timespec(संरचना timespec *, पूर्णांक);
शून्य	 monotime_ts(संरचना timespec *);
शून्य	 monotime_tv(संरचना timeval *);
समय_प्रकार	 monotime(शून्य);
द्विगुण	 monotime_double(शून्य);
शून्य	 lowercase(अक्षर *s);
पूर्णांक	 unix_listener(स्थिरांक अक्षर *, पूर्णांक, पूर्णांक);
पूर्णांक	 valid_domain(अक्षर *, पूर्णांक, स्थिरांक अक्षर **);
पूर्णांक	 valid_env_name(स्थिरांक अक्षर *);
स्थिरांक अक्षर *atoi_err(स्थिरांक अक्षर *, पूर्णांक *);
पूर्णांक	 parse_absolute_time(स्थिरांक अक्षर *, uint64_t *);
शून्य	 format_absolute_time(uint64_t, अक्षर *, माप_प्रकार);
पूर्णांक	 parse_pattern_interval(स्थिरांक अक्षर *, अक्षर **, द्विगुण *);
पूर्णांक	 path_absolute(स्थिरांक अक्षर *);
पूर्णांक	 stdfd_devnull(पूर्णांक, पूर्णांक, पूर्णांक);
पूर्णांक	 lib_contains_चिन्ह(स्थिरांक अक्षर *, स्थिरांक अक्षर *);
अक्षर	*get_homedir(शून्य);
पूर्णांक	 mkdir_path(स्थिरांक अक्षर *, mode_t);

शून्य	 sock_set_v6only(पूर्णांक);

संरचना passwd *pwcopy(संरचना passwd *);
शून्य	 pwfree(संरचना passwd *); /* NB. only use with pwcopy */

स्थिरांक अक्षर *ssh_gai_strerror(पूर्णांक);

प्रकारव्याख्या शून्य privdrop_fn(संरचना passwd *);
प्रकारव्याख्या शून्य privrestore_fn(शून्य);
#define	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#define	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#define	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#define	SSH_SUBPROCESS_UNSAFE_PATH	(1<<3)	/* Don't check for safe cmd */
#define	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(स्थिरांक अक्षर *, स्थिरांक अक्षर *, पूर्णांक, अक्षर **, खाता **, u_int,
    संरचना passwd *, privdrop_fn *, privrestore_fn *);

प्रकारव्याख्या संरचना arglist arglist;
संरचना arglist {
	अक्षर    **list;
	u_int   अंक;
	u_int   nalloc;
};
शून्य	 addargs(arglist *, अक्षर *, ...)
	    __attribute__((format(म_लिखो, 2, 3)));
शून्य	 replacearg(arglist *, u_int, अक्षर *, ...)
	    __attribute__((format(म_लिखो, 3, 4)));
शून्य	 freeargs(arglist *);

पूर्णांक	 tun_open(पूर्णांक, पूर्णांक, अक्षर **);

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
uint64_t	get_u64(स्थिरांक शून्य *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(स्थिरांक शून्य *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(स्थिरांक शून्य *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
शून्य		put_u64(शून्य *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
शून्य		put_u32(शून्य *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
शून्य		put_u16(शून्य *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(स्थिरांक शून्य *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
शून्य		put_u32_le(शून्य *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

संरचना bwlimit {
	माप_प्रकार buflen;
	uint64_t rate;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	संरचना timeval bwstart, bwend;
};

शून्य bandwidth_limit_init(संरचना bwlimit *, uint64_t, माप_प्रकार);
शून्य bandwidth_limit(संरचना bwlimit *, माप_प्रकार);

पूर्णांक parse_ipqos(स्थिरांक अक्षर *);
स्थिरांक अक्षर *iptos2str(पूर्णांक);
शून्य mktemp_proto(अक्षर *, माप_प्रकार);

शून्य	 child_set_env(अक्षर ***envp, u_int *envsizep, स्थिरांक अक्षर *name,
	    स्थिरांक अक्षर *मूल्य);
स्थिरांक अक्षर *lookup_env_in_list(स्थिरांक अक्षर *env,
	    अक्षर * स्थिरांक *envs, माप_प्रकार nenvs);
स्थिरांक अक्षर *lookup_setenv_in_list(स्थिरांक अक्षर *env,
	    अक्षर * स्थिरांक *envs, माप_प्रकार nenvs);

पूर्णांक	 argv_split(स्थिरांक अक्षर *, पूर्णांक *, अक्षर ***, पूर्णांक);
अक्षर	*argv_assemble(पूर्णांक, अक्षर **argv);
अक्षर	*argv_next(पूर्णांक *, अक्षर ***);
शून्य	 argv_consume(पूर्णांक *);
शून्य	 argv_free(अक्षर **, पूर्णांक);

पूर्णांक	 exited_cleanly(pid_t, स्थिरांक अक्षर *, स्थिरांक अक्षर *, पूर्णांक);

संरचना stat;
पूर्णांक	 safe_path(स्थिरांक अक्षर *, संरचना stat *, स्थिरांक अक्षर *, uid_t,
	    अक्षर *, माप_प्रकार);
पूर्णांक	 safe_path_fd(पूर्णांक, स्थिरांक अक्षर *, संरचना passwd *,
	    अक्षर *err, माप_प्रकार errlen);

/* authorized_key-style options parsing helpers */
पूर्णांक	opt_flag(स्थिरांक अक्षर *opt, पूर्णांक allow_negate, स्थिरांक अक्षर **optsp);
अक्षर	*opt_dequote(स्थिरांक अक्षर **sp, स्थिरांक अक्षर **errstrp);
पूर्णांक	opt_match(स्थिरांक अक्षर **opts, स्थिरांक अक्षर *term);

/* readconf/servconf option lists */
शून्य	opt_array_append(स्थिरांक अक्षर *file, स्थिरांक पूर्णांक ओळ,
	    स्थिरांक अक्षर *directive, अक्षर ***array, u_int *lp, स्थिरांक अक्षर *s);
शून्य	opt_array_append2(स्थिरांक अक्षर *file, स्थिरांक पूर्णांक ओळ,
	    स्थिरांक अक्षर *directive, अक्षर ***array, पूर्णांक **iarray, u_int *lp,
	    स्थिरांक अक्षर *s, पूर्णांक i);
शून्य	opt_array_free2(अक्षर **array, पूर्णांक **iarray, u_int l);

संरचना timespec;
शून्य ptimeout_init(संरचना timespec *pt);
शून्य ptimeout_deadline_sec(संरचना timespec *pt, दीर्घ sec);
शून्य ptimeout_deadline_ms(संरचना timespec *pt, दीर्घ ms);
शून्य ptimeout_deadline_sec_double(संरचना timespec *pt, द्विगुण sec);
शून्य ptimeout_deadline_monotime_tsp(संरचना timespec *pt, संरचना timespec *when);
शून्य ptimeout_deadline_monotime(संरचना timespec *pt, समय_प्रकार when);
शून्य ptimeout_deadline_monotime_double(संरचना timespec *pt, द्विगुण when);
पूर्णांक ptimeout_get_ms(संरचना timespec *pt);
संरचना timespec *ptimeout_get_tsp(संरचना timespec *pt);
पूर्णांक ptimeout_isset(संरचना timespec *pt);

/* misc-agent.c */
पूर्णांक	 agent_listener(स्थिरांक अक्षर *, स्थिरांक अक्षर *, uid_t, स्थिरांक अक्षर *,
	    pid_t, स्थिरांक अक्षर *, पूर्णांक *, अक्षर **, अक्षर **);
शून्य	 agent_cleanup_stale(स्थिरांक अक्षर *, स्थिरांक अक्षर *, uid_t,
	    स्थिरांक अक्षर *, पूर्णांक);
पूर्णांक	 agent_listener_cleanup(स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *);

/* readpass.c */

#define RP_ECHO			0x0001
#define RP_ALLOW_STDIN		0x0002
#define RP_ALLOW_EOF		0x0004
#define RP_USE_ASKPASS		0x0008

संरचना notifier_ctx;

अक्षर	*read_passphrase(स्थिरांक अक्षर *, पूर्णांक);
पूर्णांक	 ask_permission(स्थिरांक अक्षर *, ...) __attribute__((format(म_लिखो, 1, 2)));
संरचना notifier_ctx *notify_start(पूर्णांक, स्थिरांक अक्षर *, ...)
	__attribute__((format(म_लिखो, 2, 3)));
शून्य	notify_complete(संरचना notifier_ctx *, स्थिरांक अक्षर *, ...)
	__attribute__((format(म_लिखो, 2, 3)));

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))
#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

प्रकारव्याख्या शून्य (*sshsig_t)(पूर्णांक);
sshsig_t ssh_signal(पूर्णांक, sshsig_t);
पूर्णांक signal_is_crash(पूर्णांक);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#define FD_CLOSEONEXEC(x) करा { \
	जर (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    म_त्रुटि(त्रुटि_सं)); \
} पर्यंत (0)

#endif /* _MISC_H */
