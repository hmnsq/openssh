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

#यदि_अपरिभाषितम् _MISC_H
#परिभाषय _MISC_H

#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <signal.h>

/* special-case port number meaning allow any port */
#परिभाषय FWD_PERMIT_ANY_पत्तनम्	0

/* special-case wildcard meaning allow any host */
#परिभाषय FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
संरचना Forward {
	वर्ण	 *listen_host;		/* Host (address) to listen on. */
	पूर्णाङ्क	  listen_पत्तनम्;		/* Port to forward. */
	वर्ण	 *listen_मार्गः;		/* Path to bind domain socket. */
	वर्ण	 *connect_host;		/* Host to connect. */
	पूर्णाङ्क	  connect_पत्तनम्;		/* Port to connect on connect_host. */
	वर्ण	 *connect_मार्गः;		/* Path to connect domain socket. */
	पूर्णाङ्क	  allocated_पत्तनम्;	/* Dynamically allocated listen port */
	पूर्णाङ्क	  handle;		/* Handle for dynamic listen ports */
};

पूर्णाङ्क forward_equals(ध्रुव संरचना Forward *, ध्रुव संरचना Forward *);
पूर्णाङ्क permitopen_पत्तनम्(ध्रुव वर्ण *p);

पूर्णाङ्क daemonized(शून्य);

/* Common server and client forwarding options. */
संरचना ForwardOptions {
	पूर्णाङ्क	 gateway_ports; /* Allow remote connects to forwarded ports. */
	बहुलकम्_t	 streamlocal_bind_आवरणम्; /* umask for streamlocal binds */
	पूर्णाङ्क	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

वर्ण	*chop(वर्ण *);
शून्य	 rtrim(वर्ण *);
शून्य	skip_space(वर्ण **);
ध्रुव वर्ण *strprefix(ध्रुव वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क);
वर्ण	*strdelim(वर्ण **);
वर्ण	*strdelimw(वर्ण **);
शून्य	 stringlist_append(वर्ण ***listp, ध्रुव वर्ण *s);
शून्य	 stringlist_free(वर्ण **list);
पूर्णाङ्क	 समुच्चयः_nonblock(पूर्णाङ्क);
पूर्णाङ्क	 unset_nonblock(पूर्णाङ्क);
शून्य	 समुच्चयः_nodelay(पूर्णाङ्क);
पूर्णाङ्क	 समुच्चयः_reuseaddr(पूर्णाङ्क);
पूर्णाङ्क	 समुच्चयः_keepalive(पूर्णाङ्क);
वर्ण	*get_rdomain(पूर्णाङ्क);
पूर्णाङ्क	 समुच्चयः_rdomain(पूर्णाङ्क, ध्रुव वर्ण *);
पूर्णाङ्क	 get_sock_af(पूर्णाङ्क);
शून्य	 समुच्चयः_sock_tos(पूर्णाङ्क, पूर्णाङ्क);
पूर्णाङ्क	 waitrfd(पूर्णाङ्क, पूर्णाङ्क *, चञ्चल sig_atomic_t *);
पूर्णाङ्क	 timeout_connect(पूर्णाङ्क, ध्रुव संरचना sockaddr *, socklen_t, पूर्णाङ्क *);
पूर्णाङ्क	 a2port(ध्रुव वर्ण *);
पूर्णाङ्क	 a2tun(ध्रुव वर्ण *, पूर्णाङ्क *);
वर्ण	*put_host_पत्तनम्(ध्रुव वर्ण *, u_short);
वर्ण	*hpdelim2(वर्ण **, वर्ण *);
वर्ण	*hpdelim(वर्ण **);
वर्ण	*cleanhostname(वर्ण *);
वर्ण	*colon(वर्ण *);
पूर्णाङ्क	 parse_user_host_मार्गः(ध्रुव वर्ण *, वर्ण **, वर्ण **, वर्ण **);
पूर्णाङ्क	 parse_user_host_पत्तनम्(ध्रुव वर्ण *, वर्ण **, वर्ण **, पूर्णाङ्क *);
पूर्णाङ्क	 parse_uri(ध्रुव वर्ण *, ध्रुव वर्ण *, वर्ण **, वर्ण **, पूर्णाङ्क *, वर्ण **);
द्विगुण	 convtime_double(ध्रुव वर्ण *);
पूर्णाङ्क	 convtime(ध्रुव वर्ण *);
द्विगुण	 convtime_double(ध्रुव वर्ण *);
ध्रुव वर्ण *fmt_timeframe(time_t t);
पूर्णाङ्क	 tilde_expand(ध्रुव वर्ण *, uid_t, वर्ण **);
वर्ण	*tilde_expand_filename(ध्रुव वर्ण *, uid_t);

वर्ण	*dollar_expand(पूर्णाङ्क *, ध्रुव वर्ण *string, ...);
वर्ण	*percent_expand(ध्रुव वर्ण *, ...) __attribute__((__sentinel__));
वर्ण	*percent_dollar_expand(ध्रुव वर्ण *, ...) __attribute__((__sentinel__));
वर्ण	*tohex(ध्रुव शून्य *, आकार_t);
शून्य	 xextendf(वर्ण **s, ध्रुव वर्ण *sep, ध्रुव वर्ण *fmt, ...)
    __attribute__((__format__ (प्रारूप_लिख, 3, 4))) __attribute__((__nonnull__ (3)));
शून्य	 sanitise_stdfd(शून्य);
शून्य	 ms_व्यवकलय_diff(संरचना timeval *, पूर्णाङ्क *);
शून्य	 ms_गन्तव्यम्_timespec(संरचना timespec *, पूर्णाङ्क);
शून्य	 monotime_ts(संरचना timespec *);
शून्य	 monotime_tv(संरचना timeval *);
time_t	 monotime(शून्य);
द्विगुण	 monotime_double(शून्य);
शून्य	 lowercase(वर्ण *s);
पूर्णाङ्क	 unix_listener(ध्रुव वर्ण *, पूर्णाङ्क, पूर्णाङ्क);
पूर्णाङ्क	 valid_domain(वर्ण *, पूर्णाङ्क, ध्रुव वर्ण **);
पूर्णाङ्क	 valid_env_name(ध्रुव वर्ण *);
ध्रुव वर्ण *atoi_err(ध्रुव वर्ण *, पूर्णाङ्क *);
पूर्णाङ्क	 parse_absolute_time(ध्रुव वर्ण *, uint64_t *);
शून्य	 format_absolute_time(uint64_t, वर्ण *, आकार_t);
पूर्णाङ्क	 parse_आदर्शः_interval(ध्रुव वर्ण *, वर्ण **, द्विगुण *);
पूर्णाङ्क	 मार्गः_absolute(ध्रुव वर्ण *);
पूर्णाङ्क	 stdfd_devnull(पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क);
पूर्णाङ्क	 lib_अन्तर्भवति_चिह्नम्(ध्रुव वर्ण *, ध्रुव वर्ण *);
वर्ण	*get_homedir(शून्य);
पूर्णाङ्क	 mkdir_मार्गः(ध्रुव वर्ण *, बहुलकम्_t);

शून्य	 sock_समुच्चयः_v6only(पूर्णाङ्क);

संरचना passwd *pwcopy(संरचना passwd *);
शून्य	 pwfree(संरचना passwd *); /* NB. only use with pwcopy */

ध्रुव वर्ण *ssh_gai_strerror(पूर्णाङ्क);

प्रकारनिर्देश शून्य privdrop_fn(संरचना passwd *);
प्रकारनिर्देश शून्य privrestore_fn(शून्य);
#परिभाषय	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#परिभाषय	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#परिभाषय	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#परिभाषय	SSH_SUBPROCESS_UNSAFE_मार्गः	(1<<3)	/* Don't check for safe cmd */
#परिभाषय	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(ध्रुव वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क, वर्ण **, FILE **, u_int,
    संरचना passwd *, privdrop_fn *, privrestore_fn *);

प्रकारनिर्देश संरचना arglist arglist;
संरचना arglist {
	वर्ण    **list;
	u_int   अङ्कः;
	u_int   nalloc;
};
शून्य	 addargs(arglist *, वर्ण *, ...)
	    __attribute__((format(प्रारूप_लिख, 2, 3)));
शून्य	 replacearg(arglist *, u_int, वर्ण *, ...)
	    __attribute__((format(प्रारूप_लिख, 3, 4)));
शून्य	 freeargs(arglist *);

पूर्णाङ्क	 tun_open(पूर्णाङ्क, पूर्णाङ्क, वर्ण **);

/* Common definitions for ssh tunnel device forwarding */
#परिभाषय SSH_TUNMODE_NO		0x00
#परिभाषय SSH_TUNMODE_POINTOPOINT	0x01
#परिभाषय SSH_TUNMODE_ETHERNET	0x02
#परिभाषय SSH_TUNMODE_DEFAULT	SSH_TUNMODE_POINTOPOINT
#परिभाषय SSH_TUNMODE_YES		(SSH_TUNMODE_POINTOPOINT|SSH_TUNMODE_ETHERNET)

#परिभाषय SSH_TUNID_ANY		0x7fffffff
#परिभाषय SSH_TUNID_ERR		(SSH_TUNID_ANY - 1)
#परिभाषय SSH_TUNID_MAX		(SSH_TUNID_ANY - 2)

/* Fake port to indicate that host field is really a path. */
#परिभाषय पत्तनम्_STREAMLOCAL	-2

/* Functions to extract or store big-endian words of various sizes */
uint64_t	get_u64(ध्रुव शून्य *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(ध्रुव शून्य *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(ध्रुव शून्य *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
शून्य		put_u64(शून्य *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
शून्य		put_u32(शून्य *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
शून्य		put_u16(शून्य *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(ध्रुव शून्य *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
शून्य		put_u32_le(शून्य *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

संरचना bwlimit {
	आकार_t buflen;
	uint64_t दरः;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	संरचना timeval bwstart, bwend;
};

शून्य bandwidth_सीमा_init(संरचना bwlimit *, uint64_t, आकार_t);
शून्य bandwidth_सीमा(संरचना bwlimit *, आकार_t);

पूर्णाङ्क parse_ipqos(ध्रुव वर्ण *);
ध्रुव वर्ण *iptos2str(पूर्णाङ्क);
शून्य mktemp_proto(वर्ण *, आकार_t);

शून्य	 child_समुच्चयः_env(वर्ण ***envp, u_int *envsizep, ध्रुव वर्ण *name,
	    ध्रुव वर्ण *मानम्);
ध्रुव वर्ण *lookup_env_अन्तर्_list(ध्रुव वर्ण *env,
	    वर्ण * ध्रुव *envs, आकार_t nenvs);
ध्रुव वर्ण *lookup_setenv_अन्तर्_list(ध्रुव वर्ण *env,
	    वर्ण * ध्रुव *envs, आकार_t nenvs);

पूर्णाङ्क	 argv_विभज(ध्रुव वर्ण *, पूर्णाङ्क *, वर्ण ***, पूर्णाङ्क);
वर्ण	*argv_assemble(पूर्णाङ्क, वर्ण **argv);
वर्ण	*argv_अग्र(पूर्णाङ्क *, वर्ण ***);
शून्य	 argv_consume(पूर्णाङ्क *);
शून्य	 argv_free(वर्ण **, पूर्णाङ्क);

पूर्णाङ्क	 exited_cleanly(pid_t, ध्रुव वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क);

संरचना stat;
पूर्णाङ्क	 safe_मार्गः(ध्रुव वर्ण *, संरचना stat *, ध्रुव वर्ण *, uid_t,
	    वर्ण *, आकार_t);
पूर्णाङ्क	 safe_मार्गः_fd(पूर्णाङ्क, ध्रुव वर्ण *, संरचना passwd *,
	    वर्ण *err, आकार_t errlen);

/* authorized_key-style options parsing helpers */
पूर्णाङ्क	opt_flag(ध्रुव वर्ण *opt, पूर्णाङ्क allow_negate, ध्रुव वर्ण **optsp);
वर्ण	*opt_dequote(ध्रुव वर्ण **sp, ध्रुव वर्ण **errstrp);
पूर्णाङ्क	opt_मेलनम्(ध्रुव वर्ण **opts, ध्रुव वर्ण *पदांशः);

/* readconf/servconf option lists */
शून्य	opt_array_append(ध्रुव वर्ण *file, ध्रुव पूर्णाङ्क पङ्क्तिः,
	    ध्रुव वर्ण *directive, वर्ण ***array, u_int *lp, ध्रुव वर्ण *s);
शून्य	opt_array_append2(ध्रुव वर्ण *file, ध्रुव पूर्णाङ्क पङ्क्तिः,
	    ध्रुव वर्ण *directive, वर्ण ***array, पूर्णाङ्क **iarray, u_int *lp,
	    ध्रुव वर्ण *s, पूर्णाङ्क i);
शून्य	opt_array_free2(वर्ण **array, पूर्णाङ्क **iarray, u_int l);

संरचना timespec;
शून्य ptimeout_init(संरचना timespec *pt);
शून्य ptimeout_deadline_sec(संरचना timespec *pt, दीर्घ sec);
शून्य ptimeout_deadline_ms(संरचना timespec *pt, दीर्घ ms);
शून्य ptimeout_deadline_sec_double(संरचना timespec *pt, द्विगुण sec);
शून्य ptimeout_deadline_monotime_tsp(संरचना timespec *pt, संरचना timespec *when);
शून्य ptimeout_deadline_monotime(संरचना timespec *pt, time_t when);
शून्य ptimeout_deadline_monotime_double(संरचना timespec *pt, द्विगुण when);
पूर्णाङ्क ptimeout_get_ms(संरचना timespec *pt);
संरचना timespec *ptimeout_get_tsp(संरचना timespec *pt);
पूर्णाङ्क ptimeout_isset(संरचना timespec *pt);

/* misc-agent.c */
पूर्णाङ्क	 agent_listener(ध्रुव वर्ण *, ध्रुव वर्ण *, uid_t, ध्रुव वर्ण *,
	    pid_t, ध्रुव वर्ण *, पूर्णाङ्क *, वर्ण **, वर्ण **);
शून्य	 agent_cleanup_stale(ध्रुव वर्ण *, ध्रुव वर्ण *, uid_t,
	    ध्रुव वर्ण *, पूर्णाङ्क);
पूर्णाङ्क	 agent_listener_cleanup(ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *);

/* readpass.c */

#परिभाषय RP_ECHO			0x0001
#परिभाषय RP_ALLOW_STDIN		0x0002
#परिभाषय RP_ALLOW_EOF		0x0004
#परिभाषय RP_USE_ASKPASS		0x0008

संरचना notifier_ctx;

वर्ण	*read_passphrase(ध्रुव वर्ण *, पूर्णाङ्क);
पूर्णाङ्क	 ask_permission(ध्रुव वर्ण *, ...) __attribute__((format(प्रारूप_लिख, 1, 2)));
संरचना notifier_ctx *notify_start(पूर्णाङ्क, ध्रुव वर्ण *, ...)
	__attribute__((format(प्रारूप_लिख, 2, 3)));
शून्य	notify_complete(संरचना notifier_ctx *, ध्रुव वर्ण *, ...)
	__attribute__((format(प्रारूप_लिख, 2, 3)));

#परिभाषय MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#परिभाषय अधिकतमम्(a, b)	(((a) > (b)) ? (a) : (b))
#परिभाषय ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

प्रकारनिर्देश शून्य (*sshsig_t)(पूर्णाङ्क);
sshsig_t ssh_signal(पूर्णाङ्क, sshsig_t);
पूर्णाङ्क signal_is_crash(पूर्णाङ्क);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#परिभाषय FD_CLOSEONEXEC(x) कुरु { \
	यदि (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    strerror(errno)); \
} यावत् (0)

#यदि_अन्तः /* _MISC_H */
