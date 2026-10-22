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

#अगर_अघोषित _MISC_H
#घोषणा _MISC_H

#समावेश <sys/time.h>
#समावेश <sys/types.h>
#समावेश <sys/socket.h>
#समावेश <stdio.h>
#समावेश <signal.h>

/* special-case port number meaning allow any port */
#घोषणा FWD_PERMIT_ANY_PORT	0

/* special-case wildcard meaning allow any host */
#घोषणा FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
काष्ठा Forward {
	अक्षर	 *listen_host;		/* Host (address) to listen on. */
	पूर्णांक	  listen_port;		/* Port to forward. */
	अक्षर	 *listen_path;		/* Path to bind domain socket. */
	अक्षर	 *connect_host;		/* Host to connect. */
	पूर्णांक	  connect_port;		/* Port to connect on connect_host. */
	अक्षर	 *connect_path;		/* Path to connect domain socket. */
	पूर्णांक	  allocated_port;	/* Dynamically allocated listen port */
	पूर्णांक	  handle;		/* Handle for dynamic listen ports */
};

पूर्णांक forward_equals(स्थिर काष्ठा Forward *, स्थिर काष्ठा Forward *);
पूर्णांक permitopen_port(स्थिर अक्षर *p);

पूर्णांक daemonized(व्योम);

/* Common server and client forwarding options. */
काष्ठा ForwardOptions {
	पूर्णांक	 gateway_ports; /* Allow remote connects to forwarded ports. */
	mode_t	 streamlocal_bind_mask; /* umask for streamlocal binds */
	पूर्णांक	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

अक्षर	*chop(अक्षर *);
व्योम	 rtrim(अक्षर *);
व्योम	skip_space(अक्षर **);
स्थिर अक्षर *strprefix(स्थिर अक्षर *, स्थिर अक्षर *, पूर्णांक);
अक्षर	*strdelim(अक्षर **);
अक्षर	*strdelimw(अक्षर **);
व्योम	 stringlist_append(अक्षर ***listp, स्थिर अक्षर *s);
व्योम	 stringlist_free(अक्षर **list);
पूर्णांक	 set_nonblock(पूर्णांक);
पूर्णांक	 unset_nonblock(पूर्णांक);
व्योम	 set_nodelay(पूर्णांक);
पूर्णांक	 set_reuseaddr(पूर्णांक);
पूर्णांक	 set_keepalive(पूर्णांक);
अक्षर	*get_rdomain(पूर्णांक);
पूर्णांक	 set_rdomain(पूर्णांक, स्थिर अक्षर *);
पूर्णांक	 get_sock_af(पूर्णांक);
व्योम	 set_sock_tos(पूर्णांक, पूर्णांक);
पूर्णांक	 waitrfd(पूर्णांक, पूर्णांक *, अस्थिर संक_पूर्ण_प्रकार *);
पूर्णांक	 timeout_connect(पूर्णांक, स्थिर काष्ठा sockaddr *, socklen_t, पूर्णांक *);
पूर्णांक	 a2port(स्थिर अक्षर *);
पूर्णांक	 a2tun(स्थिर अक्षर *, पूर्णांक *);
अक्षर	*put_host_port(स्थिर अक्षर *, u_short);
अक्षर	*hpdelim2(अक्षर **, अक्षर *);
अक्षर	*hpdelim(अक्षर **);
अक्षर	*cleanhostname(अक्षर *);
अक्षर	*colon(अक्षर *);
पूर्णांक	 parse_user_host_path(स्थिर अक्षर *, अक्षर **, अक्षर **, अक्षर **);
पूर्णांक	 parse_user_host_port(स्थिर अक्षर *, अक्षर **, अक्षर **, पूर्णांक *);
पूर्णांक	 parse_uri(स्थिर अक्षर *, स्थिर अक्षर *, अक्षर **, अक्षर **, पूर्णांक *, अक्षर **);
द्विगुन	 convtime_double(स्थिर अक्षर *);
पूर्णांक	 convtime(स्थिर अक्षर *);
द्विगुन	 convtime_double(स्थिर अक्षर *);
स्थिर अक्षर *fmt_timeframe(समय_प्रकार t);
पूर्णांक	 tilde_expand(स्थिर अक्षर *, uid_t, अक्षर **);
अक्षर	*tilde_expand_filename(स्थिर अक्षर *, uid_t);

अक्षर	*dollar_expand(पूर्णांक *, स्थिर अक्षर *string, ...);
अक्षर	*percent_expand(स्थिर अक्षर *, ...) __attribute__((__sentinel__));
अक्षर	*percent_dollar_expand(स्थिर अक्षर *, ...) __attribute__((__sentinel__));
अक्षर	*tohex(स्थिर व्योम *, माप_प्रकार);
व्योम	 xextendf(अक्षर **s, स्थिर अक्षर *sep, स्थिर अक्षर *fmt, ...)
    __attribute__((__format__ (म_लिखो, 3, 4))) __attribute__((__nonnull__ (3)));
व्योम	 sanitise_stdfd(व्योम);
व्योम	 ms_subtract_diff(काष्ठा timeval *, पूर्णांक *);
व्योम	 ms_to_timespec(काष्ठा timespec *, पूर्णांक);
व्योम	 monotime_ts(काष्ठा timespec *);
व्योम	 monotime_tv(काष्ठा timeval *);
समय_प्रकार	 monotime(व्योम);
द्विगुन	 monotime_double(व्योम);
व्योम	 lowercase(अक्षर *s);
पूर्णांक	 unix_listener(स्थिर अक्षर *, पूर्णांक, पूर्णांक);
पूर्णांक	 valid_domain(अक्षर *, पूर्णांक, स्थिर अक्षर **);
पूर्णांक	 valid_env_name(स्थिर अक्षर *);
स्थिर अक्षर *atoi_err(स्थिर अक्षर *, पूर्णांक *);
पूर्णांक	 parse_absolute_time(स्थिर अक्षर *, uint64_t *);
व्योम	 format_absolute_time(uint64_t, अक्षर *, माप_प्रकार);
पूर्णांक	 parse_pattern_interval(स्थिर अक्षर *, अक्षर **, द्विगुन *);
पूर्णांक	 path_absolute(स्थिर अक्षर *);
पूर्णांक	 stdfd_devnull(पूर्णांक, पूर्णांक, पूर्णांक);
पूर्णांक	 lib_contains_प्रतीक(स्थिर अक्षर *, स्थिर अक्षर *);
अक्षर	*get_homedir(व्योम);
पूर्णांक	 mkdir_path(स्थिर अक्षर *, mode_t);

व्योम	 sock_set_v6only(पूर्णांक);

काष्ठा passwd *pwcopy(काष्ठा passwd *);
व्योम	 pwfree(काष्ठा passwd *); /* NB. only use with pwcopy */

स्थिर अक्षर *ssh_gai_strerror(पूर्णांक);

प्रकार व्योम privdrop_fn(काष्ठा passwd *);
प्रकार व्योम privrestore_fn(व्योम);
#घोषणा	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#घोषणा	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#घोषणा	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#घोषणा	SSH_SUBPROCESS_UNSAFE_PATH	(1<<3)	/* Don't check for safe cmd */
#घोषणा	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(स्थिर अक्षर *, स्थिर अक्षर *, पूर्णांक, अक्षर **, खाता **, u_int,
    काष्ठा passwd *, privdrop_fn *, privrestore_fn *);

प्रकार काष्ठा arglist arglist;
काष्ठा arglist {
	अक्षर    **list;
	u_int   अंक;
	u_int   nalloc;
};
व्योम	 addargs(arglist *, अक्षर *, ...)
	    __attribute__((format(म_लिखो, 2, 3)));
व्योम	 replacearg(arglist *, u_int, अक्षर *, ...)
	    __attribute__((format(म_लिखो, 3, 4)));
व्योम	 freeargs(arglist *);

पूर्णांक	 tun_open(पूर्णांक, पूर्णांक, अक्षर **);

/* Common definitions for ssh tunnel device forwarding */
#घोषणा SSH_TUNMODE_NO		0x00
#घोषणा SSH_TUNMODE_POINTOPOINT	0x01
#घोषणा SSH_TUNMODE_ETHERNET	0x02
#घोषणा SSH_TUNMODE_DEFAULT	SSH_TUNMODE_POINTOPOINT
#घोषणा SSH_TUNMODE_YES		(SSH_TUNMODE_POINTOPOINT|SSH_TUNMODE_ETHERNET)

#घोषणा SSH_TUNID_ANY		0x7fffffff
#घोषणा SSH_TUNID_ERR		(SSH_TUNID_ANY - 1)
#घोषणा SSH_TUNID_MAX		(SSH_TUNID_ANY - 2)

/* Fake port to indicate that host field is really a path. */
#घोषणा PORT_STREAMLOCAL	-2

/* Functions to extract or store big-endian words of various sizes */
uint64_t	get_u64(स्थिर व्योम *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(स्थिर व्योम *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(स्थिर व्योम *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
व्योम		put_u64(व्योम *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
व्योम		put_u32(व्योम *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
व्योम		put_u16(व्योम *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(स्थिर व्योम *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
व्योम		put_u32_le(व्योम *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

काष्ठा bwlimit {
	माप_प्रकार buflen;
	uint64_t rate;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	काष्ठा timeval bwstart, bwend;
};

व्योम bandwidth_limit_init(काष्ठा bwlimit *, uint64_t, माप_प्रकार);
व्योम bandwidth_limit(काष्ठा bwlimit *, माप_प्रकार);

पूर्णांक parse_ipqos(स्थिर अक्षर *);
स्थिर अक्षर *iptos2str(पूर्णांक);
व्योम mktemp_proto(अक्षर *, माप_प्रकार);

व्योम	 child_set_env(अक्षर ***envp, u_int *envsizep, स्थिर अक्षर *name,
	    स्थिर अक्षर *मूल्य);
स्थिर अक्षर *lookup_env_in_list(स्थिर अक्षर *env,
	    अक्षर * स्थिर *envs, माप_प्रकार nenvs);
स्थिर अक्षर *lookup_setenv_in_list(स्थिर अक्षर *env,
	    अक्षर * स्थिर *envs, माप_प्रकार nenvs);

पूर्णांक	 argv_split(स्थिर अक्षर *, पूर्णांक *, अक्षर ***, पूर्णांक);
अक्षर	*argv_assemble(पूर्णांक, अक्षर **argv);
अक्षर	*argv_अग्र(पूर्णांक *, अक्षर ***);
व्योम	 argv_consume(पूर्णांक *);
व्योम	 argv_free(अक्षर **, पूर्णांक);

पूर्णांक	 exited_cleanly(pid_t, स्थिर अक्षर *, स्थिर अक्षर *, पूर्णांक);

काष्ठा stat;
पूर्णांक	 safe_path(स्थिर अक्षर *, काष्ठा stat *, स्थिर अक्षर *, uid_t,
	    अक्षर *, माप_प्रकार);
पूर्णांक	 safe_path_fd(पूर्णांक, स्थिर अक्षर *, काष्ठा passwd *,
	    अक्षर *err, माप_प्रकार errlen);

/* authorized_key-style options parsing helpers */
पूर्णांक	opt_flag(स्थिर अक्षर *opt, पूर्णांक allow_negate, स्थिर अक्षर **optsp);
अक्षर	*opt_dequote(स्थिर अक्षर **sp, स्थिर अक्षर **errstrp);
पूर्णांक	opt_match(स्थिर अक्षर **opts, स्थिर अक्षर *term);

/* readconf/servconf option lists */
व्योम	opt_array_append(स्थिर अक्षर *file, स्थिर पूर्णांक पंक्ति,
	    स्थिर अक्षर *directive, अक्षर ***array, u_int *lp, स्थिर अक्षर *s);
व्योम	opt_array_append2(स्थिर अक्षर *file, स्थिर पूर्णांक पंक्ति,
	    स्थिर अक्षर *directive, अक्षर ***array, पूर्णांक **iarray, u_int *lp,
	    स्थिर अक्षर *s, पूर्णांक i);
व्योम	opt_array_free2(अक्षर **array, पूर्णांक **iarray, u_int l);

काष्ठा timespec;
व्योम ptimeout_init(काष्ठा timespec *pt);
व्योम ptimeout_deadline_sec(काष्ठा timespec *pt, दीर्घ sec);
व्योम ptimeout_deadline_ms(काष्ठा timespec *pt, दीर्घ ms);
व्योम ptimeout_deadline_sec_double(काष्ठा timespec *pt, द्विगुन sec);
व्योम ptimeout_deadline_monotime_tsp(काष्ठा timespec *pt, काष्ठा timespec *when);
व्योम ptimeout_deadline_monotime(काष्ठा timespec *pt, समय_प्रकार when);
व्योम ptimeout_deadline_monotime_double(काष्ठा timespec *pt, द्विगुन when);
पूर्णांक ptimeout_get_ms(काष्ठा timespec *pt);
काष्ठा timespec *ptimeout_get_tsp(काष्ठा timespec *pt);
पूर्णांक ptimeout_isset(काष्ठा timespec *pt);

/* misc-agent.c */
पूर्णांक	 agent_listener(स्थिर अक्षर *, स्थिर अक्षर *, uid_t, स्थिर अक्षर *,
	    pid_t, स्थिर अक्षर *, पूर्णांक *, अक्षर **, अक्षर **);
व्योम	 agent_cleanup_stale(स्थिर अक्षर *, स्थिर अक्षर *, uid_t,
	    स्थिर अक्षर *, पूर्णांक);
पूर्णांक	 agent_listener_cleanup(स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *);

/* readpass.c */

#घोषणा RP_ECHO			0x0001
#घोषणा RP_ALLOW_STDIN		0x0002
#घोषणा RP_ALLOW_EOF		0x0004
#घोषणा RP_USE_ASKPASS		0x0008

काष्ठा notifier_ctx;

अक्षर	*read_passphrase(स्थिर अक्षर *, पूर्णांक);
पूर्णांक	 ask_permission(स्थिर अक्षर *, ...) __attribute__((format(म_लिखो, 1, 2)));
काष्ठा notifier_ctx *notify_start(पूर्णांक, स्थिर अक्षर *, ...)
	__attribute__((format(म_लिखो, 2, 3)));
व्योम	notify_complete(काष्ठा notifier_ctx *, स्थिर अक्षर *, ...)
	__attribute__((format(म_लिखो, 2, 3)));

#घोषणा MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#घोषणा MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))
#घोषणा ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

प्रकार व्योम (*sshsig_t)(पूर्णांक);
sshsig_t ssh_signal(पूर्णांक, sshsig_t);
पूर्णांक signal_is_crash(पूर्णांक);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#घोषणा FD_CLOSEONEXEC(x) करो { \
	अगर (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    म_त्रुटि(त्रुटि_सं)); \
} जबतक (0)

#पूर्ण_अगर /* _MISC_H */
