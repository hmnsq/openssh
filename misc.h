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

#నిర్వచితం_కాకపోతే _MISC_H
#నిర్వచించు _MISC_H

#అన్తర్భావ <sys/time.h>
#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <signal.h>

/* special-case port number meaning allow any port */
#నిర్వచించు FWD_PERMIT_ANY_పోర్టు	0

/* special-case wildcard meaning allow any host */
#నిర్వచించు FWD_PERMIT_ANY_HOST	"*"

/* Data structure for representing a forwarding request. */
నిర్మాణం Forward {
	అక్షరం	 *listen_host;		/* Host (address) to listen on. */
	పూర్ణాంకం	  listen_పోర్టు;		/* Port to forward. */
	అక్షరం	 *listen_మార్గం;		/* Path to bind domain socket. */
	అక్షరం	 *connect_host;		/* Host to connect. */
	పూర్ణాంకం	  connect_పోర్టు;		/* Port to connect on connect_host. */
	అక్షరం	 *connect_మార్గం;		/* Path to connect domain socket. */
	పూర్ణాంకం	  allocated_పోర్టు;	/* Dynamically allocated listen port */
	పూర్ణాంకం	  handle;		/* Handle for dynamic listen ports */
};

పూర్ణాంకం forward_equals(స్థిరరాశి నిర్మాణం Forward *, స్థిరరాశి నిర్మాణం Forward *);
పూర్ణాంకం permitopen_పోర్టు(స్థిరరాశి అక్షరం *p);

పూర్ణాంకం daemonized(శూన్య);

/* Common server and client forwarding options. */
నిర్మాణం ForwardOptions {
	పూర్ణాంకం	 gateway_ports; /* Allow remote connects to forwarded ports. */
	బహుళకం_t	 streamlocal_bind_ముసుగు; /* umask for streamlocal binds */
	పూర్ణాంకం	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

అక్షరం	*chop(అక్షరం *);
శూన్య	 rtrim(అక్షరం *);
శూన్య	skip_space(అక్షరం **);
స్థిరరాశి అక్షరం *strprefix(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం);
అక్షరం	*strdelim(అక్షరం **);
అక్షరం	*strdelimw(అక్షరం **);
శూన్య	 stringlist_append(అక్షరం ***listp, స్థిరరాశి అక్షరం *s);
శూన్య	 stringlist_free(అక్షరం **list);
పూర్ణాంకం	 సమితి_nonblock(పూర్ణాంకం);
పూర్ణాంకం	 unset_nonblock(పూర్ణాంకం);
శూన్య	 సమితి_nodelay(పూర్ణాంకం);
పూర్ణాంకం	 సమితి_reuseaddr(పూర్ణాంకం);
పూర్ణాంకం	 సమితి_keepalive(పూర్ణాంకం);
అక్షరం	*get_rdomain(పూర్ణాంకం);
పూర్ణాంకం	 సమితి_rdomain(పూర్ణాంకం, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 get_sock_af(పూర్ణాంకం);
శూన్య	 సమితి_sock_tos(పూర్ణాంకం, పూర్ణాంకం);
పూర్ణాంకం	 waitrfd(పూర్ణాంకం, పూర్ణాంకం *, అస్థిర sig_atomic_t *);
పూర్ణాంకం	 timeout_connect(పూర్ణాంకం, స్థిరరాశి నిర్మాణం sockaddr *, socklen_t, పూర్ణాంకం *);
పూర్ణాంకం	 a2port(స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 a2tun(స్థిరరాశి అక్షరం *, పూర్ణాంకం *);
అక్షరం	*put_host_పోర్టు(స్థిరరాశి అక్షరం *, u_short);
అక్షరం	*hpdelim2(అక్షరం **, అక్షరం *);
అక్షరం	*hpdelim(అక్షరం **);
అక్షరం	*cleanhostname(అక్షరం *);
అక్షరం	*colon(అక్షరం *);
పూర్ణాంకం	 parse_user_host_మార్గం(స్థిరరాశి అక్షరం *, అక్షరం **, అక్షరం **, అక్షరం **);
పూర్ణాంకం	 parse_user_host_పోర్టు(స్థిరరాశి అక్షరం *, అక్షరం **, అక్షరం **, పూర్ణాంకం *);
పూర్ణాంకం	 parse_uri(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, అక్షరం **, అక్షరం **, పూర్ణాంకం *, అక్షరం **);
ద్విగుణ	 convtime_double(స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 convtime(స్థిరరాశి అక్షరం *);
ద్విగుణ	 convtime_double(స్థిరరాశి అక్షరం *);
స్థిరరాశి అక్షరం *fmt_timeframe(time_t t);
పూర్ణాంకం	 tilde_expand(స్థిరరాశి అక్షరం *, uid_t, అక్షరం **);
అక్షరం	*tilde_expand_filename(స్థిరరాశి అక్షరం *, uid_t);

అక్షరం	*dollar_expand(పూర్ణాంకం *, స్థిరరాశి అక్షరం *string, ...);
అక్షరం	*percent_expand(స్థిరరాశి అక్షరం *, ...) __attribute__((__sentinel__));
అక్షరం	*percent_dollar_expand(స్థిరరాశి అక్షరం *, ...) __attribute__((__sentinel__));
అక్షరం	*tohex(స్థిరరాశి శూన్య *, కొలత_t);
శూన్య	 xextendf(అక్షరం **s, స్థిరరాశి అక్షరం *sep, స్థిరరాశి అక్షరం *fmt, ...)
    __attribute__((__format__ (రాయి, 3, 4))) __attribute__((__nonnull__ (3)));
శూన్య	 sanitise_stdfd(శూన్య);
శూన్య	 ms_వ్యవకలనం_diff(నిర్మాణం timeval *, పూర్ణాంకం *);
శూన్య	 ms_గమ్యం_timespec(నిర్మాణం timespec *, పూర్ణాంకం);
శూన్య	 monotime_ts(నిర్మాణం timespec *);
శూన్య	 monotime_tv(నిర్మాణం timeval *);
time_t	 monotime(శూన్య);
ద్విగుణ	 monotime_double(శూన్య);
శూన్య	 lowercase(అక్షరం *s);
పూర్ణాంకం	 unix_listener(స్థిరరాశి అక్షరం *, పూర్ణాంకం, పూర్ణాంకం);
పూర్ణాంకం	 valid_domain(అక్షరం *, పూర్ణాంకం, స్థిరరాశి అక్షరం **);
పూర్ణాంకం	 valid_env_name(స్థిరరాశి అక్షరం *);
స్థిరరాశి అక్షరం *atoi_err(స్థిరరాశి అక్షరం *, పూర్ణాంకం *);
పూర్ణాంకం	 parse_absolute_సమయం(స్థిరరాశి అక్షరం *, uint64_t *);
శూన్య	 format_absolute_సమయం(uint64_t, అక్షరం *, కొలత_t);
పూర్ణాంకం	 parse_నమూనా_interval(స్థిరరాశి అక్షరం *, అక్షరం **, ద్విగుణ *);
పూర్ణాంకం	 మార్గం_absolute(స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 stdfd_devnull(పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం);
పూర్ణాంకం	 lib_కలిగియుంది_చిహ్నం(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
అక్షరం	*get_homedir(శూన్య);
పూర్ణాంకం	 mkdir_మార్గం(స్థిరరాశి అక్షరం *, బహుళకం_t);

శూన్య	 sock_సమితి_v6only(పూర్ణాంకం);

నిర్మాణం passwd *pwcopy(నిర్మాణం passwd *);
శూన్య	 pwfree(నిర్మాణం passwd *); /* NB. only use with pwcopy */

స్థిరరాశి అక్షరం *ssh_gai_strerror(పూర్ణాంకం);

రకనిర్వచనం శూన్య privdrop_fn(నిర్మాణం passwd *);
రకనిర్వచనం శూన్య privrestore_fn(శూన్య);
#నిర్వచించు	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#నిర్వచించు	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#నిర్వచించు	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#నిర్వచించు	SSH_SUBPROCESS_UNSAFE_మార్గం	(1<<3)	/* Don't check for safe cmd */
#నిర్వచించు	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */
pid_t subprocess(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం, అక్షరం **, FILE **, u_int,
    నిర్మాణం passwd *, privdrop_fn *, privrestore_fn *);

రకనిర్వచనం నిర్మాణం arglist arglist;
నిర్మాణం arglist {
	అక్షరం    **list;
	u_int   అంకె;
	u_int   nalloc;
};
శూన్య	 addargs(arglist *, అక్షరం *, ...)
	    __attribute__((format(రాయి, 2, 3)));
శూన్య	 replacearg(arglist *, u_int, అక్షరం *, ...)
	    __attribute__((format(రాయి, 3, 4)));
శూన్య	 freeargs(arglist *);

పూర్ణాంకం	 tun_open(పూర్ణాంకం, పూర్ణాంకం, అక్షరం **);

/* Common definitions for ssh tunnel device forwarding */
#నిర్వచించు SSH_TUNMODE_NO		0x00
#నిర్వచించు SSH_TUNMODE_POINTOPOINT	0x01
#నిర్వచించు SSH_TUNMODE_ETHERNET	0x02
#నిర్వచించు SSH_TUNMODE_DEFAULT	SSH_TUNMODE_POINTOPOINT
#నిర్వచించు SSH_TUNMODE_YES		(SSH_TUNMODE_POINTOPOINT|SSH_TUNMODE_ETHERNET)

#నిర్వచించు SSH_TUNID_ANY		0x7fffffff
#నిర్వచించు SSH_TUNID_ERR		(SSH_TUNID_ANY - 1)
#నిర్వచించు SSH_TUNID_MAX		(SSH_TUNID_ANY - 2)

/* Fake port to indicate that host field is really a path. */
#నిర్వచించు పోర్టు_STREAMLOCAL	-2

/* Functions to extract or store big-endian words of various sizes */
uint64_t	get_u64(స్థిరరాశి శూన్య *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
uint32_t	get_u32(స్థిరరాశి శూన్య *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
uint16_t	get_u16(స్థిరరాశి శూన్య *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
శూన్య		put_u64(శూన్య *, uint64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
శూన్య		put_u32(శూన్య *, uint32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
శూన్య		put_u16(శూన్య *, uint16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

/* Little-endian store/load, used by umac.c */
uint32_t	get_u32_le(స్థిరరాశి శూన్య *)
    __attribute__((__bounded__(__minbytes__, 1, 4)));
శూన్య		put_u32_le(శూన్య *, uint32_t)
    __attribute__((__bounded__(__minbytes__, 1, 4)));

నిర్మాణం bwlimit {
	కొలత_t buflen;
	uint64_t రేటు;		/* desired rate in kbit/s */
	uint64_t thresh;	/* threshold after which we'll check timers */
	uint64_t lamt;		/* amount written in last timer interval */
	నిర్మాణం timeval bwstart, bwend;
};

శూన్య bandwidth_హద్దు_init(నిర్మాణం bwlimit *, uint64_t, కొలత_t);
శూన్య bandwidth_హద్దు(నిర్మాణం bwlimit *, కొలత_t);

పూర్ణాంకం parse_ipqos(స్థిరరాశి అక్షరం *);
స్థిరరాశి అక్షరం *iptos2str(పూర్ణాంకం);
శూన్య mktemp_proto(అక్షరం *, కొలత_t);

శూన్య	 బిడ్డ_సమితి_env(అక్షరం ***envp, u_int *envsizep, స్థిరరాశి అక్షరం *name,
	    స్థిరరాశి అక్షరం *విలువ);
స్థిరరాశి అక్షరం *lookup_env_లోపల_list(స్థిరరాశి అక్షరం *env,
	    అక్షరం * స్థిరరాశి *envs, కొలత_t nenvs);
స్థిరరాశి అక్షరం *lookup_setenv_లోపల_list(స్థిరరాశి అక్షరం *env,
	    అక్షరం * స్థిరరాశి *envs, కొలత_t nenvs);

పూర్ణాంకం	 argv_విభజించు(స్థిరరాశి అక్షరం *, పూర్ణాంకం *, అక్షరం ***, పూర్ణాంకం);
అక్షరం	*argv_assemble(పూర్ణాంకం, అక్షరం **argv);
అక్షరం	*argv_తదుపరి(పూర్ణాంకం *, అక్షరం ***);
శూన్య	 argv_consume(పూర్ణాంకం *);
శూన్య	 argv_free(అక్షరం **, పూర్ణాంకం);

పూర్ణాంకం	 exited_cleanly(pid_t, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం);

నిర్మాణం stat;
పూర్ణాంకం	 సురక్షిత_మార్గం(స్థిరరాశి అక్షరం *, నిర్మాణం stat *, స్థిరరాశి అక్షరం *, uid_t,
	    అక్షరం *, కొలత_t);
పూర్ణాంకం	 సురక్షిత_మార్గం_fd(పూర్ణాంకం, స్థిరరాశి అక్షరం *, నిర్మాణం passwd *,
	    అక్షరం *err, కొలత_t errlen);

/* authorized_key-style options parsing helpers */
పూర్ణాంకం	opt_flag(స్థిరరాశి అక్షరం *opt, పూర్ణాంకం allow_negate, స్థిరరాశి అక్షరం **optsp);
అక్షరం	*opt_dequote(స్థిరరాశి అక్షరం **sp, స్థిరరాశి అక్షరం **errstrp);
పూర్ణాంకం	opt_సరిపోలిక(స్థిరరాశి అక్షరం **opts, స్థిరరాశి అక్షరం *పదం);

/* readconf/servconf option lists */
శూన్య	opt_array_append(స్థిరరాశి అక్షరం *file, స్థిరరాశి పూర్ణాంకం పంక్తి,
	    స్థిరరాశి అక్షరం *directive, అక్షరం ***array, u_int *lp, స్థిరరాశి అక్షరం *s);
శూన్య	opt_array_append2(స్థిరరాశి అక్షరం *file, స్థిరరాశి పూర్ణాంకం పంక్తి,
	    స్థిరరాశి అక్షరం *directive, అక్షరం ***array, పూర్ణాంకం **iarray, u_int *lp,
	    స్థిరరాశి అక్షరం *s, పూర్ణాంకం i);
శూన్య	opt_array_free2(అక్షరం **array, పూర్ణాంకం **iarray, u_int l);

నిర్మాణం timespec;
శూన్య ptimeout_init(నిర్మాణం timespec *pt);
శూన్య ptimeout_deadline_sec(నిర్మాణం timespec *pt, దీర్ఘ sec);
శూన్య ptimeout_deadline_ms(నిర్మాణం timespec *pt, దీర్ఘ ms);
శూన్య ptimeout_deadline_sec_double(నిర్మాణం timespec *pt, ద్విగుణ sec);
శూన్య ptimeout_deadline_monotime_tsp(నిర్మాణం timespec *pt, నిర్మాణం timespec *when);
శూన్య ptimeout_deadline_monotime(నిర్మాణం timespec *pt, time_t when);
శూన్య ptimeout_deadline_monotime_double(నిర్మాణం timespec *pt, ద్విగుణ when);
పూర్ణాంకం ptimeout_get_ms(నిర్మాణం timespec *pt);
నిర్మాణం timespec *ptimeout_get_tsp(నిర్మాణం timespec *pt);
పూర్ణాంకం ptimeout_isset(నిర్మాణం timespec *pt);

/* misc-agent.c */
పూర్ణాంకం	 agent_listener(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, uid_t, స్థిరరాశి అక్షరం *,
	    pid_t, స్థిరరాశి అక్షరం *, పూర్ణాంకం *, అక్షరం **, అక్షరం **);
శూన్య	 agent_cleanup_stale(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, uid_t,
	    స్థిరరాశి అక్షరం *, పూర్ణాంకం);
పూర్ణాంకం	 agent_listener_cleanup(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);

/* readpass.c */

#నిర్వచించు RP_ECHO			0x0001
#నిర్వచించు RP_ALLOW_STDIN		0x0002
#నిర్వచించు RP_ALLOW_EOF		0x0004
#నిర్వచించు RP_USE_ASKPASS		0x0008

నిర్మాణం notifier_ctx;

అక్షరం	*read_passphrase(స్థిరరాశి అక్షరం *, పూర్ణాంకం);
పూర్ణాంకం	 ask_permission(స్థిరరాశి అక్షరం *, ...) __attribute__((format(రాయి, 1, 2)));
నిర్మాణం notifier_ctx *notify_ప్రారంభం(పూర్ణాంకం, స్థిరరాశి అక్షరం *, ...)
	__attribute__((format(రాయి, 2, 3)));
శూన్య	notify_complete(నిర్మాణం notifier_ctx *, స్థిరరాశి అక్షరం *, ...)
	__attribute__((format(రాయి, 2, 3)));

#నిర్వచించు MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#నిర్వచించు గరిష్ఠ(a, b)	(((a) > (b)) ? (a) : (b))
#నిర్వచించు ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

రకనిర్వచనం శూన్య (*sshsig_t)(పూర్ణాంకం);
sshsig_t ssh_signal(పూర్ణాంకం, sshsig_t);
పూర్ణాంకం signal_is_crash(పూర్ణాంకం);

/* On OpenBSD time_t is int64_t which is long long. */
/* #define SSH_TIME_T_MAX LLONG_MAX */

#నిర్వచించు FD_CLOSEONEXEC(x) చేయి { \
	ఒకవేళ (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal_f("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", x, \
		    strerror(errno)); \
} అయితే (0)

#అయితే_ముగింపు /* _MISC_H */
