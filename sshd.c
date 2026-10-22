/* $OpenBSD: sshd.c,v 1.635 2026/09/16 07:47:29 jsg Exp $ */
/*
 * Copyright (c) 2000, 2001, 2002 Markus Friedl.  All rights reserved.
 * Copyright (c) 2002 Niels Provos.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/ioctl.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/time.h>
#અન્તર્ભાવ <sys/queue.h>
#અન્તર્ભાવ <sys/wait.h>
#અન્તર્ભાવ <sys/utsname.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <grp.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <limits.h>

#ifdef HAVE_SECUREWARE
#અન્તર્ભાવ <sys/security.h>
#અન્તર્ભાવ <prot.h>
#endif

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "sshpty.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "compat.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "msg.h"
#અન્તર્ભાવ "version.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sk-api.h"
#અન્તર્ભાવ "addr.h"
#અન્તર્ભાવ "srclimit.h"
#અન્તર્ભાવ "atomicio.h"
#ifdef GSSAPI
#અન્તર્ભાવ "ssh-gss.h"
#endif
#અન્તર્ભાવ "monitor_wrap.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

બાહ્ય અક્ષર *__progname;

/* Server configuration options. */
ServerOptions options;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
પૂર્ણાંક debug_flag = 0;

/* Saved arguments to main(). */
સ્થિર અક્ષર execpath[PATH_MAX];
સ્થિર અક્ષર **saved_argv;
સ્થિર પૂર્ણાંક saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#define	MAX_LISTEN_SOCKS	16
સ્થિર પૂર્ણાંક listen_socks[MAX_LISTEN_SOCKS];
સ્થિર પૂર્ણાંક અંક_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
સંરચના {
	સંરચના sshkey	**host_ચાવીઓ;		/* all private host keys */
	સંરચના sshkey	**host_pubkeys;		/* all public host keys */
	સંરચના sshkey	**host_certificates;	/* all public host certificates */
	પૂર્ણાંક		have_ssh2_ચાવી;
} sensitive_data;

/* This is set to true when a signal is received. */
સ્થિર અસ્થિર sig_atomic_t received_siginfo = 0;
સ્થિર અસ્થિર sig_atomic_t received_sigchld = 0;
સ્થિર અસ્થિર sig_atomic_t received_sighup = 0;
સ્થિર અસ્થિર sig_atomic_t received_sigterm = 0;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/*
 * The early_child/children array below is used for tracking children of the
 * listening sshd process early in their lifespans, before they have
 * completed authentication. This tracking is needed for four things:
 *
 * 1) Implementing the MaxStartups limit of concurrent unauthenticated
 *    connections.
 * 2) Avoiding a race condition for SIGHUP processing, where child processes
 *    may have listen_socks open that could collide with main listener process
 *    after it restarts.
 * 3) Ensuring that rexec'd sshd processes have received their initial state
 *    from the parent listen process before handling SIGHUP.
 * 4) Tracking and logging unsuccessful exits from the preauth sshd monitor,
 *    including and especially those for LoginGraceTime timeouts.
 *
 * Child processes signal that they have completed closure of the listen_socks
 * and (if applicable) received their rexec state by sending a char over their
 * sock.
 *
 * Child processes signal that authentication has completed by sending a
 * second char over the socket before closing it, otherwise the listener will
 * continue tracking the child (and using up a MaxStartups slot) until the
 * preauth subprocess exits, whereupon the listener will log its exit status.
 * preauth processes will exit with a status of EXIT_LOGIN_GRACE to indicate
 * they did not authenticate before the LoginGraceTime alarm fired.
 */
સંરચના early_child {
	પૂર્ણાંક pipefd;
	પૂર્ણાંક early;		/* Indicates child closed listener */
	અક્ષર *id;		/* human readable connection identifier */
	pid_t pid;
	સંરચના xaddr addr;
	પૂર્ણાંક have_addr;
	પૂર્ણાંક status, have_status;
	સંરચના sshbuf *config;
	સંરચના sshbuf *ચાવીઓ;
};
સ્થિર સંરચના early_child *children;
સ્થિર પૂર્ણાંક children_active;

/* sshd_config buffer */
સંરચના sshbuf *cfg;
સંરચના sshbuf *config;	/* packed */

/* Included files from the configuration file */
સંરચના include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
સંરચના sshbuf *loginmsg;

/* Unprivileged user */
સંરચના passwd *privsep_pw = ખાલી;

સ્થિર અક્ષર *listener_proctitle;

/*
 * Close all listening sockets
 */
સ્થિર શૂન્ય
close_listen_socks(શૂન્ય)
{
	પૂર્ણાંક i;

	માટે (i = 0; i < અંક_listen_socks; i++)
		close(listen_socks[i]);
	અંક_listen_socks = 0;
}

/* Allocate and initialise the children array */
સ્થિર શૂન્ય
child_alloc(શૂન્ય)
{
	પૂર્ણાંક i;

	children = xcalloc(options.max_startups, કદ(*children));
	માટે (i = 0; i < options.max_startups; i++) {
		children[i].pipefd = -1;
		children[i].pid = -1;
	}
}

/* Register a new connection in the children array; child pid comes later */
સ્થિર સંરચના early_child *
child_register(પૂર્ણાંક pipefd, પૂર્ણાંક sockfd)
{
	પૂર્ણાંક i, lport, rport;
	અક્ષર *laddr = ખાલી, *raddr = ખાલી;
	સંરચના early_child *child = ખાલી;
	સંરચના sockaddr_storage addr;
	socklen_t addrlen = કદ(addr);
	સંરચના sockaddr *sa = (સંરચના sockaddr *)&addr;

	માટે (i = 0; i < options.max_startups; i++) {
		જો (children[i].pipefd != -1 ||
		    children[i].config != ખાલી ||
		    children[i].ચાવીઓ != ખાલી ||
		    children[i].pid > 0)
			ચાલુ;
		child = &(children[i]);
		તોડો;
	}
	જો (child == ખાલી) {
		fatal_f("error: accepted connection when all %d child "
		    " slots full", options.max_startups);
	}
	child->pipefd = pipefd;
	child->early = 1;
	જો ((child->config = sshbuf_fromb(config)) == ખાલી)
		fatal_f("sshbuf_fromb failed");
	/* record peer address, if available */
	જો (getpeername(sockfd, sa, &addrlen) == 0 &&
	   addr_sa_to_xaddr(sa, addrlen, &child->addr) == 0)
		child->have_addr = 1;
	/* format peer address string for logs */
	જો ((lport = get_local_port(sockfd)) == 0 ||
	    (rport = get_peer_port(sockfd)) == 0) {
		/* Not a TCP socket */
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s", raddr);
	} નહીંતર {
		laddr = get_local_ipaddr(sockfd);
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s to %s", raddr, laddr);
	}
	મુક્ત(laddr);
	મુક્ત(raddr);
	જો (++children_active > options.max_startups)
		fatal_f("internal error: more children than max_startups");

	પાછા child;
}

/*
 * Finally free a child entry. Don't call this directly.
 */
સ્થિર શૂન્ય
child_finish(સંરચના early_child *child)
{
	જો (children_active == 0)
		fatal_f("internal error: children_active underflow");
	જો (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
	}
	sshbuf_free(child->config);
	sshbuf_free(child->ચાવીઓ);
	મુક્ત(child->id);
	memset(child, '\0', કદ(*child));
	child->pipefd = -1;
	child->pid = -1;
	children_active--;
}

/*
 * Close a child's pipe. This will not stop tracking the child immediately
 * (it will still be tracked for waitpid()) unless force_final is set, or
 * child has already exited.
 */
સ્થિર શૂન્ય
child_close(સંરચના early_child *child, પૂર્ણાંક force_final, પૂર્ણાંક quiet)
{
	જો (!quiet)
		debug_f("enter%s", force_final ? " (forcing)" : "");
	જો (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
		child->pipefd = -1;
	}
	જો (child->pid == -1 || force_final)
		child_finish(child);
}

/* Record a child exit. Safe to call from signal handlers */
સ્થિર શૂન્ય
child_exit(pid_t pid, પૂર્ણાંક status)
{
	પૂર્ણાંક i;

	જો (children == ખાલી || pid <= 0)
		પાછા;
	માટે (i = 0; i < options.max_startups; i++) {
		જો (children[i].pid == pid) {
			children[i].have_status = 1;
			children[i].status = status;
			તોડો;
		}
	}
}

/*
 * Reap a child entry that has exited, as previously flagged
 * using child_exit().
 * Handles logging of exit condition and will finalise the child if its pipe
 * had already been closed.
 */
સ્થિર શૂન્ય
child_reap(સંરચના early_child *child)
{
	LogLevel level = SYSLOG_LEVEL_DEBUG1;
	પૂર્ણાંક was_crash, penalty_type = SRCLIMIT_PENALTY_NONE;
	અચલ અક્ષર *child_status;

	જો (child->config)
		child_status = " (sending config)";
	નહીંતર જો (child->ચાવીઓ)
		child_status = " (sending keys)";
	નહીંતર જો (child->early)
		child_status = " (early)";
	નહીંતર
		child_status = "";

	/* Log exit information */
	જો (WIFSIGNALED(child->status)) {
		/*
		 * Increase logging for signals potentially associated
		 * with serious conditions.
		 */
		જો ((was_crash = signal_is_crash(WTERMSIG(child->status))))
			level = SYSLOG_LEVEL_ERROR;
		do_log2(level, "session process %ld for %s killed by "
		    "signal %d%s", (long)child->pid, child->id,
		    WTERMSIG(child->status), child_status);
		જો (was_crash)
			penalty_type = SRCLIMIT_PENALTY_CRASH;
	} નહીંતર જો (!WIFEXITED(child->status)) {
		penalty_type = SRCLIMIT_PENALTY_CRASH;
		error("session process %ld for %s terminated abnormally, "
		    "status=0x%x%s", (long)child->pid, child->id, child->status,
		    child_status);
	} નહીંતર {
		/* Normal exit. We care about the status */
		પસંદગી (WEXITSTATUS(child->status)) {
		સ્થિતિ 0:
			debug3_f("preauth child %ld for %s completed "
			    "normally%s", (long)child->pid, child->id,
			    child_status);
			તોડો;
		સ્થિતિ EXIT_LOGIN_GRACE:
			penalty_type = SRCLIMIT_PENALTY_GRACE_EXCEEDED;
			logit("Timeout before authentication for %s, "
			    "pid = %ld%s", child->id, (long)child->pid,
			    child_status);
			તોડો;
		સ્થિતિ EXIT_CHILD_CRASH:
			penalty_type = SRCLIMIT_PENALTY_CRASH;
			logit("Session process %ld unpriv child crash for %s%s",
			    (long)child->pid, child->id, child_status);
			તોડો;
		સ્થિતિ EXIT_AUTH_ATTEMPTED:
			penalty_type = SRCLIMIT_PENALTY_AUTHFAIL;
			debug_f("preauth child %ld for %s exited "
			    "after unsuccessful auth attempt%s",
			    (long)child->pid, child->id, child_status);
			તોડો;
		સ્થિતિ EXIT_INVALID_USER:
			penalty_type = SRCLIMIT_PENALTY_INVALIDUSER;
			debug_f("preauth child %ld for %s exited "
			    "after auth attempt by invalid user%s",
			    (long)child->pid, child->id, child_status);
			તોડો;
		સ્થિતિ EXIT_CONFIG_REFUSED:
			penalty_type = SRCLIMIT_PENALTY_REFUSECONNECTION;
			debug_f("preauth child %ld for %s prohibited by"
			    "RefuseConnection%s",
			    (long)child->pid, child->id, child_status);
			તોડો;
		મૂળભૂત:
			penalty_type = SRCLIMIT_PENALTY_NOAUTH;
			debug_f("preauth child %ld for %s exited "
			    "with status %d%s", (long)child->pid, child->id,
			    WEXITSTATUS(child->status), child_status);
			તોડો;
		}
	}

	જો (child->have_addr)
		srclimit_penalise(&child->addr, penalty_type);

	child->pid = -1;
	child->have_status = 0;
	જો (child->pipefd == -1)
		child_finish(child);
}

/* Reap all children that have exited; called after SIGCHLD */
સ્થિર શૂન્ય
child_reap_all_exited(શૂન્ય)
{
	પૂર્ણાંક i;
	pid_t pid;
	પૂર્ણાંક status;

	જો (children == ખાલી)
		પાછા;

	માટે (;;) {
		જો ((pid = waitpid(-1, &status, WNOHANG)) == 0)
			તોડો;
		નહીંતર જો (pid == -1) {
			જો (errno == EINTR || errno == EAGAIN)
				ચાલુ;
			જો (errno != ECHILD)
				error_f("waitpid: %s", strerror(errno));
			તોડો;
		}
		child_exit(pid, status);
	}

	માટે (i = 0; i < options.max_startups; i++) {
		જો (!children[i].have_status)
			ચાલુ;
		child_reap(&(children[i]));
	}
}

સ્થિર શૂન્ય
close_startup_pipes(શૂન્ય)
{
	પૂર્ણાંક i;

	જો (children == ખાલી)
		પાછા;
	માટે (i = 0; i < options.max_startups; i++) {
		જો (children[i].pipefd != -1)
			child_close(&(children[i]), 1, 1);
	}
}

/* Called after SIGINFO */
સ્થિર શૂન્ય
show_info(શૂન્ય)
{
	પૂર્ણાંક i;
	અચલ અક્ષર *child_status;

	/* XXX print listening sockets here too */
	જો (children == ખાલી)
		પાછા;
	logit("%d active startups", children_active);
	માટે (i = 0; i < options.max_startups; i++) {
		જો (children[i].pipefd == -1 && children[i].pid <= 0)
			ચાલુ;
		જો (children[i].config)
			child_status = " (sending config)";
		નહીંતર જો (children[i].ચાવીઓ)
			child_status = " (sending keys)";
		નહીંતર જો (children[i].early)
			child_status = " (early)";
		નહીંતર
			child_status = "";
		logit("child %d: fd=%d pid=%ld %s%s", i, children[i].pipefd,
		    (long)children[i].pid, children[i].id, child_status);
	}
	srclimit_penalty_info();
}

/*
 * Signal handler for SIGHUP.  Sshd execs itself when it receives SIGHUP;
 * the effect is to reread the configuration file (and to regenerate
 * the server key).
 */

સ્થિર શૂન્ય
sighup_handler(પૂર્ણાંક sig)
{
	received_sighup = 1;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
સ્થિર શૂન્ય
sighup_restart(શૂન્ય)
{
	logit("Received SIGHUP; restarting.");
	જો (options.pid_file != ખાલી)
		unlink(options.pid_file);
	platform_pre_restart();
	close_listen_socks();
	close_startup_pipes();
	ssh_signal(SIGHUP, SIG_IGN); /* will be restored after exec */
	execv(execpath, saved_argv);
	logit("RESTART FAILED: execpath='%.100s', error: %.100s.", execpath,
	    strerror(errno));
	exit(1);
}

/*
 * Generic signal handler for terminating signals in the master daemon.
 */
સ્થિર શૂન્ય
sigterm_handler(પૂર્ણાંક sig)
{
	received_sigterm = sig;
}

#ifdef SIGINFO
સ્થિર શૂન્ય
siginfo_handler(પૂર્ણાંક sig)
{
	received_siginfo = 1;
}
#endif

સ્થિર શૂન્ય
main_sigchld_handler(પૂર્ણાંક sig)
{
	received_sigchld = 1;
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
સ્થિર પૂર્ણાંક
should_drop_connection(પૂર્ણાંક startups)
{
	પૂર્ણાંક p, r;

	જો (startups < options.max_startups_begin)
		પાછા 0;
	જો (startups >= options.max_startups)
		પાછા 1;
	જો (options.max_startups_rate == 100)
		પાછા 1;

	p  = 100 - options.max_startups_rate;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_rate;
	r = arc4random_uniform(100);

	debug_f("p %d, r %d", p, r);
	પાછા (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups or for penalty.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
સ્થિર પૂર્ણાંક
drop_connection(પૂર્ણાંક sock, પૂર્ણાંક startups, પૂર્ણાંક notify_pipe)
{
	સ્થિર સંરચના log_ratelimit_ctx ratelimit_maxstartups;
	સ્થિર સંરચના log_ratelimit_ctx ratelimit_penalty;
	સ્થિર પૂર્ણાંક init_done;
	અક્ષર *laddr, *raddr;
	અચલ અક્ષર *reason = ખાલી, *subreason = ખાલી;
	અચલ અક્ષર સંદેશ[] = "Not allowed at this time\r\n";
	સંરચના log_ratelimit_ctx *rl = ખાલી;
	પૂર્ણાંક ratelimited;
	u_int ndropped;

	જો (!init_done) {
		init_done = 1;
		log_ratelimit_init(&ratelimit_maxstartups, 4, 60, 20, 5*60);
		log_ratelimit_init(&ratelimit_penalty, 8, 60, 30, 2*60);
	}

	/* PerSourcePenalties */
	જો (!srclimit_penalty_check_allow(sock, &subreason)) {
		reason = "PerSourcePenalties";
		rl = &ratelimit_penalty;
	} નહીંતર {
		/* MaxStartups */
		જો (!should_drop_connection(startups) &&
		    srclimit_check_allow(sock, notify_pipe) == 1)
			પાછા 0;
		reason = "MaxStartups";
		rl = &ratelimit_maxstartups;
	}

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	ratelimited = log_ratelimit(rl, time(ખાલી), ખાલી, &ndropped);
	do_log2(ratelimited ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    "drop connection #%d from [%s]:%d on [%s]:%d %s",
	    startups,
	    raddr, get_peer_port(sock),
	    laddr, get_local_port(sock),
	    subreason != ખાલી ? subreason : reason);
	મુક્ત(laddr);
	મુક્ત(raddr);
	જો (ndropped != 0) {
		logit("%s logging rate-limited: additional %u connections "
		    "dropped", reason, ndropped);
	}

	/* best-effort notification to client */
	(શૂન્ય)લિખ(sock, સંદેશ, કદ(સંદેશ) - 1);
	પાછા 1;
}

સ્થિર શૂન્ય
usage(શૂન્ય)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

સ્થિર સંરચના sshbuf *
pack_hostkeys(શૂન્ય)
{
	સંરચના sshbuf *m = ખાલી, *keybuf = ખાલી, *hostkeys = ખાલી;
	પૂર્ણાંક r;
	u_int i;
	size_t len;

	જો ((m = sshbuf_new()) == ખાલી ||
	    (keybuf = sshbuf_new()) == ખાલી ||
	    (hostkeys = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	માટે (i = 0; i < options.અંક_host_ચાવી_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		જો (sensitive_data.host_ચાવીઓ[i] != ખાલી &&
		    (r = sshkey_private_serialize(sensitive_data.host_ચાવીઓ[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		જો ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		જો (sensitive_data.host_pubkeys[i] != ખાલી) {
			જો ((r = sshkey_puts(sensitive_data.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} નહીંતર {
			જો ((r = sshbuf_put_string(hostkeys, ખાલી, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		જો (sensitive_data.host_certificates[i] != ખાલી) {
			જો ((r = sshkey_puts(
			    sensitive_data.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} નહીંતર {
			જો ((r = sshbuf_put_string(hostkeys, ખાલી, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	જો ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0)
		fatal_fr(r, "compose message");
	જો ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(keybuf);
	sshbuf_free(hostkeys);
	પાછા m;
}

સ્થિર સંરચના sshbuf *
pack_config(સંરચના sshbuf *conf)
{
	સંરચના sshbuf *m = ખાલી, *inc = ખાલી;
	સંરચના include_item *item = ખાલી;
	size_t len;
	પૂર્ણાંક r;

	debug3_f("d config len %zu", sshbuf_len(conf));

	જો ((m = sshbuf_new()) == ખાલી ||
	    (inc = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(item, &includes, entry) {
		જો ((r = sshbuf_put_cstring(inc, item->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, item->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	જો ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	જો ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(inc);

	debug3_f("done");
	પાછા m;
}

/*
 * Protocol from reexec master to child:
 *	uint32  size
 *	uint8   type (ignored)
 *	string	configuration
 *	uint64	timing_secret
 *	string	included_files[] {
 *		string	selector
 *		string	filename
 *		string	contents
 *	}
 * Second message
 *	uint32  size
 *	uint8   type (ignored)
 *	string	host_keys[] {
 *		string private_key
 *		string public_key
 *		string certificate
 *	}
 */
/*
 * This function is used only if inet_flag or debug_flag is set,
 * otherwise the data is sent from the main poll loop.
 * It sends the config from a child process back to the parent.
 * The parent will read the config after exec.
 */
સ્થિર શૂન્ય
send_rexec_state(પૂર્ણાંક fd)
{
	સંરચના sshbuf *ચાવીઓ;
	u_int mlen;
	pid_t pid;

	જો ((pid = fork()) == -1)
		fatal_f("fork failed: %s", strerror(errno));
	જો (pid != 0)
		પાછા;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(config));

	mlen = sshbuf_len(config);
	જો (atomicio(vwrite, fd, sshbuf_mutable_ptr(config), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	ચાવીઓ = pack_hostkeys();
	mlen = sshbuf_len(ચાવીઓ);
	જો (atomicio(vwrite, fd, sshbuf_mutable_ptr(ચાવીઓ), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	sshbuf_free(ચાવીઓ);
	debug3_f("done");
	exit(0);
}

/*
 * Listen for TCP connections
 */
સ્થિર શૂન્ય
listen_on_addrs(સંરચના listenaddr *la)
{
	પૂર્ણાંક ret, listen_sock;
	સંરચના addrinfo *ai;
	અક્ષર ntop[NI_MAXHOST], strport[NI_MAXSERV];

	માટે (ai = la->addrs; ai; ai = ai->ai_next) {
		જો (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			ચાલુ;
		જો (અંક_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		જો ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, કદ(ntop), strport, કદ(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			ચાલુ;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		જો (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			ચાલુ;
		}
		જો (set_nonblock(listen_sock) == -1) {
			close(listen_sock);
			ચાલુ;
		}
		જો (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			ચાલુ;
		}
		/* Socket options */
		set_reuseaddr(listen_sock);
		જો (la->rdomain != ખાલી &&
		    set_rdomain(listen_sock, la->rdomain) == -1) {
			close(listen_sock);
			ચાલુ;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		જો (ai->ai_family == AF_INET6)
			sock_set_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		જો (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, strerror(errno));
			close(listen_sock);
			ચાલુ;
		}
		listen_socks[અંક_listen_socks] = listen_sock;
		અંક_listen_socks++;

		/* Start listening on the port. */
		જો (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, strerror(errno));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == ખાલી ? "" : " rdomain ",
		    la->rdomain == ખાલી ? "" : la->rdomain);
	}
}

સ્થિર શૂન્ય
server_listen(શૂન્ય)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups,
	    options.per_source_max_startups,
	    options.per_source_masklen_ipv4,
	    options.per_source_masklen_ipv6,
	    &options.per_source_penalty,
	    options.per_source_penalty_exempt);

	માટે (i = 0; i < options.અંક_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		મુક્ત(options.listen_addrs[i].rdomain);
		memset(&options.listen_addrs[i], 0,
		    કદ(options.listen_addrs[i]));
	}
	મુક્ત(options.listen_addrs);
	options.listen_addrs = ખાલી;
	options.અંક_listen_addrs = 0;

	જો (!અંક_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
સ્થિર શૂન્ય
server_accept_loop(પૂર્ણાંક *sock_in, પૂર્ણાંક *sock_out, પૂર્ણાંક *newsock, પૂર્ણાંક *config_s,
    પૂર્ણાંક log_stderr)
{
	સંરચના pollfd *pfd = ખાલી;
	પૂર્ણાંક i, ret, npfd, r;
	પૂર્ણાંક oactive = -1, listening = 0, lameduck = 0;
	પૂર્ણાંક *startup_pollfd;
	ssize_t len;
	અચલ u_char *ptr;
	અક્ષર c = 0;
	સંરચના sockaddr_storage from;
	સંરચના early_child *child;
	સંરચના sshbuf *buf;
	socklen_t fromlen;
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	child_alloc();
	startup_pollfd = xcalloc(options.max_startups, કદ(પૂર્ણાંક));

	/*
	 * Prepare signal mask that we use to block signals that might set
	 * received_sigterm/hup/chld/info, so that we are guaranteed
	 * to immediately wake up the ppoll if a signal is received after
	 * the flag is checked.
	 */
	sigemptyset(&nsigset);
	sigaddset(&nsigset, SIGHUP);
	sigaddset(&nsigset, SIGCHLD);
#ifdef SIGINFO
	sigaddset(&nsigset, SIGINFO);
#endif
	sigaddset(&nsigset, SIGTERM);
	sigaddset(&nsigset, SIGQUIT);

	/* sized for worst-case */
	pfd = xcalloc(અંક_listen_socks + options.max_startups,
	    કદ(સંરચના pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	માટે (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		જો (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (પૂર્ણાંક) received_sigterm);
			close_listen_socks();
			જો (options.pid_file != ખાલી)
				unlink(options.pid_file);
			exit(received_sigterm == SIGTERM ? 0 : 255);
		}
		જો (received_sigchld) {
			child_reap_all_exited();
			received_sigchld = 0;
		}
		જો (received_siginfo) {
			show_info();
			received_siginfo = 0;
		}
		જો (oactive != children_active) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, children_active,
			    options.max_startups_begin, options.max_startups);
			oactive = children_active;
		}
		જો (received_sighup) {
			જો (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			જો (listening <= 0) {
				/*
				 * Leave termination signals blocked, so
				 * they don't get lost across a restart.
				 */
				sigaddset(&osigset, SIGTERM);
				sigaddset(&osigset, SIGQUIT);
				sigprocmask(SIG_SETMASK, &osigset, ખાલી);
				sighup_restart();
			}
		}

		માટે (i = 0; i < અંક_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = અંક_listen_socks;
		માટે (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			જો (children[i].pipefd != -1) {
				pfd[npfd].fd = children[i].pipefd;
				pfd[npfd].events = POLLIN;
				જો (children[i].config != ખાલી ||
				    children[i].ચાવીઓ != ખાલી)
					pfd[npfd].events |= POLLOUT;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, ખાલી, &osigset);
		જો (ret == -1 && errno != EINTR) {
			error("ppoll: %.100s", strerror(errno));
			જો (errno == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, ખાલી);
		જો (ret == -1)
			ચાલુ;

		માટે (i = 0; i < options.max_startups; i++) {
			જો (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & POLLOUT))
				ચાલુ;
			જો (children[i].config)
				buf = children[i].config;
			નહીંતર જો (children[i].ચાવીઓ)
				buf = children[i].ચાવીઓ;
			નહીંતર {
				error_f("no buffer to send");
				ચાલુ;
			}
			ptr = sshbuf_ptr(buf);
			len = sshbuf_len(buf);
			ret = લિખ(children[i].pipefd, ptr, len);
			જો (ret == -1 && (errno == EINTR || errno == EAGAIN))
				ચાલુ;
			જો (ret <= 0) {
				જો (children[i].early)
					listening--;
				child_close(&(children[i]), 0, 0);
				ચાલુ;
			}
			જો (ret == len) {
				/* finished sending buffer */
				sshbuf_free(buf);
				જો (children[i].config == buf) {
					/* sent config, now send keys */
					children[i].config = ખાલી;
					children[i].ચાવીઓ = pack_hostkeys();
				} નહીંતર જો (children[i].ચાવીઓ == buf) {
					/* sent both config and keys */
					children[i].ચાવીઓ = ખાલી;
				} નહીંતર {
					fatal("config buf not set");
				}

			} નહીંતર {
				જો ((r = sshbuf_consume(buf, ret)) != 0)
					fatal_fr(r, "config buf inconsistent");
			}
		}
		માટે (i = 0; i < options.max_startups; i++) {
			જો (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				ચાલુ;
			પસંદગી (પઠ(children[i].pipefd, &c, કદ(c))) {
			સ્થિતિ -1:
				જો (errno == EINTR || errno == EAGAIN)
					ચાલુ;
				જો (errno != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, children[i].pipefd,
					    strerror(errno));
				}
				/* FALLTHROUGH */
			સ્થિતિ 0:
				/* child closed pipe */
				જો (children[i].early)
					listening--;
				debug3_f("child %lu for %s closed pipe",
				    (long)children[i].pid, children[i].id);
				child_close(&(children[i]), 0, 0);
				તોડો;
			સ્થિતિ 1:
				જો (children[i].config) {
					error_f("startup pipe %d (fd=%d)"
					    " early read",
					    i, children[i].pipefd);
					જાઓ problem_child;
				}
				જો (children[i].early && c == '\0') {
					/* child has finished preliminaries */
					listening--;
					children[i].early = 0;
					debug2_f("child %lu for %s received "
					    "config", (long)children[i].pid,
					    children[i].id);
				} નહીંતર જો (!children[i].early && c == '\001') {
					/* child has completed auth */
					debug2_f("child %lu for %s auth done",
					    (long)children[i].pid,
					    children[i].id);
					child_close(&(children[i]), 1, 0);
				} નહીંતર {
					error_f("unexpected message 0x%02x "
					    "child %ld for %s in state %d",
					    (પૂર્ણાંક)c, (long)children[i].pid,
					    children[i].id, children[i].early);
 problem_child:
					જો (children[i].early)
						listening--;
					જો (children[i].pid > 0)
						kill(children[i].pid, SIGTERM);
					child_close(&(children[i]), 0, 0);
				}
				તોડો;
			}
		}
		માટે (i = 0; i < અંક_listen_socks; i++) {
			જો (!(pfd[i].revents & POLLIN))
				ચાલુ;
			fromlen = કદ(from);
			*newsock = accept(listen_socks[i],
			    (સંરચના sockaddr *)&from, &fromlen);
			જો (*newsock == -1) {
				જો (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED && errno != EAGAIN)
					error("accept: %.100s",
					    strerror(errno));
				જો (errno == EMFILE || errno == ENFILE)
					usleep(100 * 1000);
				ચાલુ;
			}
			જો (unset_nonblock(*newsock) == -1) {
				close(*newsock);
				ચાલુ;
			}
			જો (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    strerror(errno));
				close(*newsock);
				ચાલુ;
			}
			જો (drop_connection(*newsock,
			    children_active, config_s[0])) {
				close(*newsock);
				close(config_s[0]);
				close(config_s[1]);
				ચાલુ;
			}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			જો (debug_flag) {
				/*
				 * In debugging mode.  Close the listening
				 * socket, and start processing the
				 * connection without forking.
				 */
				debug("Server will not fork when running in debugging mode.");
				close_listen_socks();
				*sock_in = *newsock;
				*sock_out = *newsock;
				send_rexec_state(config_s[0]);
				close(config_s[0]);
				મુક્ત(pfd);
				મુક્ત(startup_pollfd);
				પાછા;
			}

			/*
			 * Normal production daemon.  Fork, and have
			 * the child process the connection. The
			 * parent continues listening.
			 */
			platform_pre_fork();
			set_nonblock(config_s[0]);
			listening++;
			child = child_register(config_s[0], *newsock);
			જો ((child->pid = fork()) == 0) {
				/*
				 * Child.  Close the listening and
				 * max_startup sockets.  Start using
				 * the accepted socket. Reinitialize
				 * logging (since our pid has changed).
				 * We return from this function to handle
				 * the connection.
				 */
				platform_post_fork_child();
				close_startup_pipes();
				close_listen_socks();
				*sock_in = *newsock;
				*sock_out = *newsock;
				log_init(__progname,
				    options.log_level,
				    options.log_facility,
				    log_stderr);
				close(config_s[0]);
				મુક્ત(pfd);
				મુક્ત(startup_pollfd);
				પાછા;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_parent(child->pid);
			જો (child->pid == -1)
				error("fork: %.100s", strerror(errno));
			નહીંતર
				debug("Forked child %ld.", (long)child->pid);

			close(config_s[1]);
			close(*newsock);

			/*
			 * Ensure that our random state differs
			 * from that of the child
			 */
			reseed_prngs();
		}
	}
}

સ્થિર શૂન્ય
accumulate_host_timing_secret(સંરચના sshbuf *server_cfg,
    સંરચના sshkey *ચાવી)
{
	સ્થિર સંરચના ssh_digest_ctx *ctx;
	u_char *hash;
	size_t len;
	સંરચના sshbuf *buf;
	પૂર્ણાંક r;

	જો (ctx == ખાલી && (ctx = ssh_digest_start(SSH_DIGEST_SHA512)) == ખાલી)
		fatal_f("ssh_digest_start");
	જો (ચાવી == ખાલી) { /* finalize */
		/* add server config in case we are using agent for host keys */
		જો (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_bytes(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		જો (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = ખાલી;
		પાછા;
	}
	જો ((buf = sshbuf_new()) == ખાલી)
		fatal_f("could not allocate buffer");
	જો ((r = sshkey_private_serialize(ચાવી, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(ચાવી));
	જો (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

સ્થિર અક્ષર *
prepare_proctitle(પૂર્ણાંક ac, અક્ષર **av)
{
	અક્ષર *ret = ખાલી;
	પૂર્ણાંક i;

	માટે (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	પાછા ret;
}

/* Disconnect from the controlling tty. */
સ્થિર શૂન્ય
disconnect_controlling_tty(શૂન્ય)
{
#ifdef TIOCNOTTY
# ifndef O_NOCTTY
#  define O_NOCTTY 0
# endif
	પૂર્ણાંક fd;

	જો ((fd = open(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(શૂન્ય) ioctl(fd, TIOCNOTTY, ખાલી);
		close(fd);
	}
#endif /* TIOCNOTTY */
}

સ્થિર શૂન્ય
print_config(સંરચના connection_info *connection_info)
{
	connection_info->test = 1;
	parse_server_match_config(&options, &includes, connection_info);
	dump_config(&options);
	exit(0);
}

/*
 * Main program for the daemon.
 */
પૂર્ણાંક
મુખ્ય(પૂર્ણાંક ac, અક્ષર **av)
{
	બાહ્ય અક્ષર *optarg;
	બાહ્ય પૂર્ણાંક optind;
	પૂર્ણાંક log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	અક્ષર *config_file_name = _PATH_SERVER_CONFIG_FILE;
	પૂર્ણાંક r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	પૂર્ણાંક sock_in = -1, sock_out = -1, newsock = -1, rexec_argc = 0;
	પૂર્ણાંક devnull, config_s[2] = { -1 , -1 }, have_connection_info = 0;
	પૂર્ણાંક need_chroot = 1;
	અક્ષર *args, *fp, *લીટી, *logfile = ખાલી, **rexec_argv = ખાલી;
	સંરચના stat sb;
	u_int i, j;
	mode_t new_umask;
	સંરચના sshkey *ચાવી;
	સંરચના sshkey *pubkey;
	સંરચના connection_info connection_info;
	સંરચના utsname utsname;
	sigset_t sigmask;

	memset(&connection_info, 0, કદ(connection_info));
#ifdef HAVE_SECUREWARE
	(શૂન્ય)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ખાલી);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, કદ(*saved_argv));
	માટે (i = 0; (પૂર્ણાંક)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ખાલી;

#ifndef HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#endif

	જો (geteuid() == 0 && setgroups(0, ખાલી) == -1)
		debug("setgroups(): %.200s", strerror(errno));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	જ્યારે ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		પસંદગી (opt) {
		સ્થિતિ '4':
			options.address_family = AF_INET;
			તોડો;
		સ્થિતિ '6':
			options.address_family = AF_INET6;
			તોડો;
		સ્થિતિ 'f':
			config_file_name = optarg;
			તોડો;
		સ્થિતિ 'c':
			servconf_add_hostcert("[command-line]", 0,
			    &options, optarg);
			તોડો;
		સ્થિતિ 'd':
			જો (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} નહીંતર જો (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			તોડો;
		સ્થિતિ 'D':
			no_daemon_flag = 1;
			તોડો;
		સ્થિતિ 'G':
			do_dump_cfg = 1;
			તોડો;
		સ્થિતિ 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		સ્થિતિ 'e':
			log_stderr = 1;
			તોડો;
		સ્થિતિ 'i':
			inetd_flag = 1;
			તોડો;
		સ્થિતિ 'r':
			logit("-r option is deprecated");
			તોડો;
		સ્થિતિ 'R':
			fatal("-R not supported here");
			તોડો;
		સ્થિતિ 'Q':
			/* ignored */
			તોડો;
		સ્થિતિ 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			તોડો;
		સ્થિતિ 'b':
			/* protocol 1, ignored */
			તોડો;
		સ્થિતિ 'p':
			options.ports_from_cmdline = 1;
			જો (options.અંક_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				exit(1);
			}
			options.ports[options.અંક_ports++] = a2port(optarg);
			જો (options.ports[options.અંક_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				exit(1);
			}
			તોડો;
		સ્થિતિ 'g':
			જો ((options.login_grace_time = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				exit(1);
			}
			તોડો;
		સ્થિતિ 'k':
			/* protocol 1, ignored */
			તોડો;
		સ્થિતિ 'h':
			servconf_add_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			તોડો;
		સ્થિતિ 't':
			test_flag = 1;
			તોડો;
		સ્થિતિ 'T':
			test_flag = 2;
			તોડો;
		સ્થિતિ 'C':
			જો (parse_server_match_testspec(&connection_info,
			    optarg) == -1)
				exit(1);
			have_connection_info = 1;
			તોડો;
		સ્થિતિ 'u':
			utmp_len = (u_int)strtonum(optarg, 0,
			    HOST_NAME_MAX+1+1, ખાલી);
			જો (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			તોડો;
		સ્થિતિ 'o':
			લીટી = xstrdup(optarg);
			જો (process_server_config_લીટી(&options, લીટી,
			    "command-line", 0, ખાલી, ખાલી, &includes) != 0)
				exit(1);
			મુક્ત(લીટી);
			તોડો;
		સ્થિતિ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
		મૂળભૂત:
			usage();
			તોડો;
		}
	}

	જો (getexecpath(execpath, કદ execpath) != 0) {
		જો (strlcpy(execpath, av[0], કદ execpath) >=
		    કદ execpath) {
			fprintf(stderr, "execution path is too long\n");
			exit(1);
		}
	}
	જો (!test_flag && !inetd_flag && !do_dump_cfg && !path_absolute(execpath))
		fatal("sshd requires execution with an absolute path");

	closefrom(STDERR_FILENO + 1);

	/* Reserve fds we'll need later for reexec things */
	જો ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	જ્યારે (devnull < REEXEC_MIN_FREE_FD) {
		જો ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	seed_rng();

	/* If requested, redirect the logs to the specified logfile. */
	જો (logfile != ખાલી) {
		અક્ષર *cp, pid_s[32];

		snprintf(pid_s, કદ(pid_s), "%ld", (unsigned long)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (અક્ષર *)ખાલી);
		log_redirect_stderr_to(cp);
		મુક્ત(cp);
	}

	/*
	 * Force logging to stderr until we have loaded the private host
	 * key (unless started from inetd)
	 */
	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_AUTH : options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	/*
	 * Unset KRB5CCNAME, otherwise the user's session may inherit it from
	 * root's environment
	 */
	જો (getenv("KRB5CCNAME") != ખાલી)
		(શૂન્ય) unsetenv("KRB5CCNAME");

	sensitive_data.have_ssh2_ચાવી = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	જો (test_flag < 2 && have_connection_info)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	debug("sshd version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);
	જો (uname(&utsname) != 0) {
		memset(&utsname, 0, કદ(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", કદ(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	મુક્ત(args);

	/* Fetch our configuration */
	જો ((cfg = sshbuf_new()) == ખાલી)
		fatal("sshbuf_new config failed");
	જો (strcasecmp(config_file_name, "none") != 0)
		load_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, ખાલી, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	જો (options.authorized_ચાવીઓ_command_user == ખાલી &&
	    (options.authorized_ચાવીઓ_command != ખાલી &&
	    strcasecmp(options.authorized_ચાવીઓ_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	જો (options.authorized_principals_command_user == ખાલી &&
	    (options.authorized_principals_command != ખાલી &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match blocks, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	જો (options.અંક_auth_methods != 0) {
		માટે (i = 0; i < options.અંક_auth_methods; i++) {
			જો (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				તોડો;
		}
		જો (i >= options.અંક_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	જો (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	જો (do_dump_cfg)
		print_config(&connection_info);

	/* load host keys */
	sensitive_data.host_ચાવીઓ = xcalloc(options.અંક_host_ચાવી_files,
	    કદ(સંરચના sshkey *));
	sensitive_data.host_pubkeys = xcalloc(options.અંક_host_ચાવી_files,
	    કદ(સંરચના sshkey *));

	જો (options.host_ચાવી_agent) {
		જો (strcmp(options.host_ચાવી_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_ચાવી_agent, 1);
		જો ((r = ssh_get_authentication_socket(ખાલી)) == 0)
			have_agent = 1;
		નહીંતર
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_ચાવી_agent);
	}

	માટે (i = 0; i < options.અંક_host_ચાવી_files; i++) {
		પૂર્ણાંક ll = options.host_ચાવી_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		જો (options.host_ચાવી_files[i] == ખાલી)
			ચાલુ;
		જો ((r = sshkey_load_private(options.host_ચાવી_files[i], "",
		    &ચાવી, ખાલી)) != 0 &&
		    r != SSH_ERR_SYSTEM_ERROR && !have_agent)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_ચાવી_files[i]);
		જો (sshkey_is_sk(ચાવી) &&
		    ચાવી->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_ચાવી_files[i]);
			ચાવી->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		જો (r == 0 && ચાવી != ખાલી &&
		    (r = sshkey_shield_private(ચાવી)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_ચાવી_files[i]);
			sshkey_free(ચાવી);
			ચાવી = ખાલી;
		}
		જો ((r = sshkey_load_public(options.host_ચાવી_files[i],
		    &pubkey, ખાલી)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_ચાવી_files[i]);
		જો (pubkey != ખાલી && ચાવી != ખાલી) {
			જો (!sshkey_equal(pubkey, ચાવી)) {
				error("Public key for %s does not match "
				    "private key", options.host_ચાવી_files[i]);
				sshkey_free(pubkey);
				pubkey = ખાલી;
			}
		}
		જો (pubkey == ખાલી && ચાવી != ખાલી) {
			જો ((r = sshkey_from_private(ચાવી, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_ચાવી_files[i]);
		}
		જો (pubkey != ખાલી && (r = sshkey_check_rsa_length(pubkey,
		    options.required_rsa_size)) != 0) {
			error_fr(r, "Host key %s", options.host_ચાવી_files[i]);
			sshkey_free(pubkey);
			sshkey_free(ચાવી);
			ચાલુ;
		}
		sensitive_data.host_ચાવીઓ[i] = ચાવી;
		sensitive_data.host_pubkeys[i] = pubkey;

		જો (ચાવી == ખાલી && pubkey != ખાલી && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_ચાવી_files[i]);
			keytype = pubkey->type;
		} નહીંતર જો (ચાવી != ખાલી) {
			keytype = ચાવી->type;
			accumulate_host_timing_secret(cfg, ચાવી);
		} નહીંતર {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_ચાવી_files[i]);
			sensitive_data.host_ચાવીઓ[i] = ખાલી;
			sensitive_data.host_pubkeys[i] = ખાલી;
			ચાલુ;
		}

		પસંદગી (keytype) {
		સ્થિતિ ચાવી_RSA:
		સ્થિતિ ચાવી_ECDSA:
		સ્થિતિ ચાવી_ED25519:
		સ્થિતિ ચાવી_MLDSA44_ED25519:
		સ્થિતિ ચાવી_ECDSA_SK:
		સ્થિતિ ચાવી_ED25519_SK:
			જો (have_agent || ચાવી != ખાલી)
				sensitive_data.have_ssh2_ચાવી = 1;
			તોડો;
		}
		જો ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == ખાલી)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    ચાવી ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		મુક્ત(fp);
	}
	accumulate_host_timing_secret(cfg, ખાલી);
	જો (!sensitive_data.have_ssh2_ચાવી) {
		logit("sshd: no hostkeys available -- exiting.");
		exit(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_data.host_certificates = xcalloc(options.અંક_host_ચાવી_files,
	    કદ(સંરચના sshkey *));
	માટે (i = 0; i < options.અંક_host_ચાવી_files; i++)
		sensitive_data.host_certificates[i] = ખાલી;

	માટે (i = 0; i < options.અંક_host_cert_files; i++) {
		જો (options.host_cert_files[i] == ખાલી)
			ચાલુ;
		જો ((r = sshkey_load_public(options.host_cert_files[i],
		    &ચાવી, ખાલી)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			ચાલુ;
		}
		જો (!sshkey_is_cert(ચાવી)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(ચાવી);
			ચાલુ;
		}
		/* Find matching private key */
		માટે (j = 0; j < options.અંક_host_ચાવી_files; j++) {
			જો (sshkey_equal_public(ચાવી,
			    sensitive_data.host_pubkeys[j])) {
				sensitive_data.host_certificates[j] = ચાવી;
				તોડો;
			}
		}
		જો (j >= options.અંક_host_ચાવી_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(ચાવી);
			ચાલુ;
		}
		sensitive_data.host_certificates[j] = ચાવી;
		debug("host certificate: #%u type %d %s", j, ચાવી->type,
		    sshkey_type(ચાવી));
	}

	/* Ensure privsep directory is correctly configured. */
	need_chroot = ((getuid() == 0 || geteuid() == 0) ||
	    options.kerberos_authentication);
	જો ((getpwnam(SSH_PRIVSEP_USER)) == ખાલી && need_chroot) {
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	}
	endpwent();

	જો (need_chroot) {
		જો ((stat(_PATH_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
		    (S_ISDIR(sb.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    _PATH_PRIVSEP_CHROOT_DIR);
#ifdef HAVE_CYGWIN
		જો (check_ntsec(_PATH_PRIVSEP_CHROOT_DIR) &&
		    (sb.st_uid != getuid () ||
		    (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#નહીંતર
		જો (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#endif
			fatal("%s must be owned by root and not group or "
			    "world-writable.", _PATH_PRIVSEP_CHROOT_DIR);
	}

	જો (test_flag > 1)
		print_config(&connection_info);

	config = pack_config(cfg);
	જો (sshbuf_len(config) > MONITOR_MAX_CFGLEN) {
		fatal("Configuration file is too large (have %zu, max %d)",
		    sshbuf_len(config), MONITOR_MAX_CFGLEN);
	}

	/* Configuration looks good, so exit if in test mode. */
	જો (test_flag)
		exit(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	જો (setgroups(0, ખાલી) < 0)
		debug("setgroups() failed: %.200s", strerror(errno));

	/* Prepare arguments for sshd-session */
	જો (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, કદ(અક્ષર *));
	/* Point to the sshd-session binary instead of sshd */
	rexec_argv[0] = options.sshd_session_path;
	માટે (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = ખાલી;
	જો (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	જો (stat(options.sshd_auth_path, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_auth_path);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(શૂન્ય) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	જો (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	માટે (i = 0; i < options.અંક_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	જો (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		જો (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", strerror(errno));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	જો (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or a listening TCP socket */
	જો (inetd_flag) {
		/* Send configuration to ancestor sshd-session process */
		જો (socketpair(AF_UNIX, SOCK_STREAM, 0, config_s) == -1)
			fatal("socketpair: %s", strerror(errno));
		send_rexec_state(config_s[0]);
		close(config_s[0]);
	} નહીંતર {
		platform_pre_listen();
		server_listen();

		ssh_signal(SIGHUP, sighup_handler);
		ssh_signal(SIGCHLD, main_sigchld_handler);
		ssh_signal(SIGTERM, sigterm_handler);
		ssh_signal(SIGQUIT, sigterm_handler);
#ifdef SIGINFO
		ssh_signal(SIGINFO, siginfo_handler);
#endif

		platform_post_listen();

		/*
		 * Write out the pid file after the sigterm handler
		 * is setup and the listen sockets are bound
		 */
		જો (options.pid_file != ખાલી && !debug_flag) {
			FILE *f = fopen(options.pid_file, "w");

			જો (f == ખાલી) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, strerror(errno));
			} નહીંતર {
				fprintf(f, "%ld\n", (long) getpid());
				fclose(f);
			}
		}

		/* Accept a connection and return in a forked child */
		server_accept_loop(&sock_in, &sock_out,
		    &newsock, config_s, log_stderr);
	}

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/*
	 * Create a new session and process group since the 4.4BSD
	 * setlogin() affects the entire process group.  We don't
	 * want the child to be able to affect the parent.
	 */
	જો (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	debug("rexec start in %d out %d newsock %d config_s %d/%d",
	    sock_in, sock_out, newsock, config_s[0], config_s[1]);
	જો (!inetd_flag) {
		જો (dup2(newsock, STDIN_FILENO) == -1)
			fatal("dup2 stdin: %s", strerror(errno));
		જો (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			fatal("dup2 stdout: %s", strerror(errno));
		જો (newsock > STDOUT_FILENO)
			close(newsock);
	}
	જો (config_s[1] != REEXEC_CONFIG_PASS_FD) {
		જો (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			fatal("dup2 config_s: %s", strerror(errno));
		close(config_s[1]);
	}
	log_redirect_stderr_to(ખાલી);
	closefrom(REEXEC_MIN_FREE_FD);

	ssh_signal(SIGHUP, SIG_IGN); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], strerror(errno));
}

/* server specific fatal cleanup */
શૂન્ય
cleanup_exit(પૂર્ણાંક i)
{
	_exit(i);
}
