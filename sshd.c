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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/ioctl.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/time.h>
#அந்தர்பாவ <sys/queue.h>
#அந்தர்பாவ <sys/wait.h>
#அந்தர்பாவ <sys/utsname.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <grp.h>
#அந்தர்பாவ <poll.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>

#ifdef HAVE_SECUREWARE
#அந்தர்பாவ <sys/security.h>
#அந்தர்பாவ <prot.h>
#endif

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "sshpty.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "msg.h"
#அந்தர்பாவ "version.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sk-api.h"
#அந்தர்பாவ "addr.h"
#அந்தர்பாவ "srclimit.h"
#அந்தர்பாவ "atomicio.h"
#ifdef GSSAPI
#அந்தர்பாவ "ssh-gss.h"
#endif
#அந்தர்பாவ "monitor_wrap.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

வெளி எழுத்து *__progname;

/* Server configuration options. */
ServerOptions options;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
முழு debug_flag = 0;

/* Saved arguments to main(). */
நிலையான எழுத்து execpath[PATH_MAX];
நிலையான எழுத்து **saved_argv;
நிலையான முழு saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#define	MAX_LISTEN_SOCKS	16
நிலையான முழு listen_socks[MAX_LISTEN_SOCKS];
நிலையான முழு இலக்கம்_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
கட்டமைப்பு {
	கட்டமைப்பு sshkey	**host_சாவிகள்;		/* all private host keys */
	கட்டமைப்பு sshkey	**host_pubkeys;		/* all public host keys */
	கட்டமைப்பு sshkey	**host_certificates;	/* all public host certificates */
	முழு		have_ssh2_சாவி;
} sensitive_data;

/* This is set to true when a signal is received. */
நிலையான நிலையற்ற sig_atomic_t received_siginfo = 0;
நிலையான நிலையற்ற sig_atomic_t received_sigchld = 0;
நிலையான நிலையற்ற sig_atomic_t received_sighup = 0;
நிலையான நிலையற்ற sig_atomic_t received_sigterm = 0;

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
கட்டமைப்பு early_child {
	முழு pipefd;
	முழு early;		/* Indicates child closed listener */
	எழுத்து *id;		/* human readable connection identifier */
	pid_t pid;
	கட்டமைப்பு xaddr addr;
	முழு have_addr;
	முழு status, have_status;
	கட்டமைப்பு sshbuf *config;
	கட்டமைப்பு sshbuf *சாவிகள்;
};
நிலையான கட்டமைப்பு early_child *children;
நிலையான முழு children_active;

/* sshd_config buffer */
கட்டமைப்பு sshbuf *cfg;
கட்டமைப்பு sshbuf *config;	/* packed */

/* Included files from the configuration file */
கட்டமைப்பு include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
கட்டமைப்பு sshbuf *loginmsg;

/* Unprivileged user */
கட்டமைப்பு passwd *privsep_pw = வெற்று;

நிலையான எழுத்து *listener_proctitle;

/*
 * Close all listening sockets
 */
நிலையான வெறுமை
close_listen_socks(வெறுமை)
{
	முழு i;

	க்கு (i = 0; i < இலக்கம்_listen_socks; i++)
		close(listen_socks[i]);
	இலக்கம்_listen_socks = 0;
}

/* Allocate and initialise the children array */
நிலையான வெறுமை
child_alloc(வெறுமை)
{
	முழு i;

	children = xcalloc(options.max_startups, அளவு(*children));
	க்கு (i = 0; i < options.max_startups; i++) {
		children[i].pipefd = -1;
		children[i].pid = -1;
	}
}

/* Register a new connection in the children array; child pid comes later */
நிலையான கட்டமைப்பு early_child *
child_register(முழு pipefd, முழு sockfd)
{
	முழு i, lport, rport;
	எழுத்து *laddr = வெற்று, *raddr = வெற்று;
	கட்டமைப்பு early_child *child = வெற்று;
	கட்டமைப்பு sockaddr_storage addr;
	socklen_t addrlen = அளவு(addr);
	கட்டமைப்பு sockaddr *sa = (கட்டமைப்பு sockaddr *)&addr;

	க்கு (i = 0; i < options.max_startups; i++) {
		எனில் (children[i].pipefd != -1 ||
		    children[i].config != வெற்று ||
		    children[i].சாவிகள் != வெற்று ||
		    children[i].pid > 0)
			தொடர்;
		child = &(children[i]);
		நிறுத்து;
	}
	எனில் (child == வெற்று) {
		fatal_f("error: accepted connection when all %d child "
		    " slots full", options.max_startups);
	}
	child->pipefd = pipefd;
	child->early = 1;
	எனில் ((child->config = sshbuf_fromb(config)) == வெற்று)
		fatal_f("sshbuf_fromb failed");
	/* record peer address, if available */
	எனில் (getpeername(sockfd, sa, &addrlen) == 0 &&
	   addr_sa_to_xaddr(sa, addrlen, &child->addr) == 0)
		child->have_addr = 1;
	/* format peer address string for logs */
	எனில் ((lport = get_local_port(sockfd)) == 0 ||
	    (rport = get_peer_port(sockfd)) == 0) {
		/* Not a TCP socket */
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s", raddr);
	} இல்லையெனில் {
		laddr = get_local_ipaddr(sockfd);
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s to %s", raddr, laddr);
	}
	விடுவி(laddr);
	விடுவி(raddr);
	எனில் (++children_active > options.max_startups)
		fatal_f("internal error: more children than max_startups");

	திரும்பு child;
}

/*
 * Finally free a child entry. Don't call this directly.
 */
நிலையான வெறுமை
child_finish(கட்டமைப்பு early_child *child)
{
	எனில் (children_active == 0)
		fatal_f("internal error: children_active underflow");
	எனில் (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
	}
	sshbuf_free(child->config);
	sshbuf_free(child->சாவிகள்);
	விடுவி(child->id);
	memset(child, '\0', அளவு(*child));
	child->pipefd = -1;
	child->pid = -1;
	children_active--;
}

/*
 * Close a child's pipe. This will not stop tracking the child immediately
 * (it will still be tracked for waitpid()) unless force_final is set, or
 * child has already exited.
 */
நிலையான வெறுமை
child_close(கட்டமைப்பு early_child *child, முழு force_final, முழு quiet)
{
	எனில் (!quiet)
		debug_f("enter%s", force_final ? " (forcing)" : "");
	எனில் (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
		child->pipefd = -1;
	}
	எனில் (child->pid == -1 || force_final)
		child_finish(child);
}

/* Record a child exit. Safe to call from signal handlers */
நிலையான வெறுமை
child_exit(pid_t pid, முழு status)
{
	முழு i;

	எனில் (children == வெற்று || pid <= 0)
		திரும்பு;
	க்கு (i = 0; i < options.max_startups; i++) {
		எனில் (children[i].pid == pid) {
			children[i].have_status = 1;
			children[i].status = status;
			நிறுத்து;
		}
	}
}

/*
 * Reap a child entry that has exited, as previously flagged
 * using child_exit().
 * Handles logging of exit condition and will finalise the child if its pipe
 * had already been closed.
 */
நிலையான வெறுமை
child_reap(கட்டமைப்பு early_child *child)
{
	LogLevel level = SYSLOG_LEVEL_DEBUG1;
	முழு was_crash, penalty_type = SRCLIMIT_PENALTY_NONE;
	மாறிலி எழுத்து *child_status;

	எனில் (child->config)
		child_status = " (sending config)";
	இல்லையெனில் எனில் (child->சாவிகள்)
		child_status = " (sending keys)";
	இல்லையெனில் எனில் (child->early)
		child_status = " (early)";
	இல்லையெனில்
		child_status = "";

	/* Log exit information */
	எனில் (WIFSIGNALED(child->status)) {
		/*
		 * Increase logging for signals potentially associated
		 * with serious conditions.
		 */
		எனில் ((was_crash = signal_is_crash(WTERMSIG(child->status))))
			level = SYSLOG_LEVEL_ERROR;
		do_log2(level, "session process %ld for %s killed by "
		    "signal %d%s", (long)child->pid, child->id,
		    WTERMSIG(child->status), child_status);
		எனில் (was_crash)
			penalty_type = SRCLIMIT_PENALTY_CRASH;
	} இல்லையெனில் எனில் (!WIFEXITED(child->status)) {
		penalty_type = SRCLIMIT_PENALTY_CRASH;
		error("session process %ld for %s terminated abnormally, "
		    "status=0x%x%s", (long)child->pid, child->id, child->status,
		    child_status);
	} இல்லையெனில் {
		/* Normal exit. We care about the status */
		தேர்வு (WEXITSTATUS(child->status)) {
		நிலை 0:
			debug3_f("preauth child %ld for %s completed "
			    "normally%s", (long)child->pid, child->id,
			    child_status);
			நிறுத்து;
		நிலை EXIT_LOGIN_GRACE:
			penalty_type = SRCLIMIT_PENALTY_GRACE_EXCEEDED;
			logit("Timeout before authentication for %s, "
			    "pid = %ld%s", child->id, (long)child->pid,
			    child_status);
			நிறுத்து;
		நிலை EXIT_CHILD_CRASH:
			penalty_type = SRCLIMIT_PENALTY_CRASH;
			logit("Session process %ld unpriv child crash for %s%s",
			    (long)child->pid, child->id, child_status);
			நிறுத்து;
		நிலை EXIT_AUTH_ATTEMPTED:
			penalty_type = SRCLIMIT_PENALTY_AUTHFAIL;
			debug_f("preauth child %ld for %s exited "
			    "after unsuccessful auth attempt%s",
			    (long)child->pid, child->id, child_status);
			நிறுத்து;
		நிலை EXIT_INVALID_USER:
			penalty_type = SRCLIMIT_PENALTY_INVALIDUSER;
			debug_f("preauth child %ld for %s exited "
			    "after auth attempt by invalid user%s",
			    (long)child->pid, child->id, child_status);
			நிறுத்து;
		நிலை EXIT_CONFIG_REFUSED:
			penalty_type = SRCLIMIT_PENALTY_REFUSECONNECTION;
			debug_f("preauth child %ld for %s prohibited by"
			    "RefuseConnection%s",
			    (long)child->pid, child->id, child_status);
			நிறுத்து;
		இயல்பு:
			penalty_type = SRCLIMIT_PENALTY_NOAUTH;
			debug_f("preauth child %ld for %s exited "
			    "with status %d%s", (long)child->pid, child->id,
			    WEXITSTATUS(child->status), child_status);
			நிறுத்து;
		}
	}

	எனில் (child->have_addr)
		srclimit_penalise(&child->addr, penalty_type);

	child->pid = -1;
	child->have_status = 0;
	எனில் (child->pipefd == -1)
		child_finish(child);
}

/* Reap all children that have exited; called after SIGCHLD */
நிலையான வெறுமை
child_reap_all_exited(வெறுமை)
{
	முழு i;
	pid_t pid;
	முழு status;

	எனில் (children == வெற்று)
		திரும்பு;

	க்கு (;;) {
		எனில் ((pid = waitpid(-1, &status, WNOHANG)) == 0)
			நிறுத்து;
		இல்லையெனில் எனில் (pid == -1) {
			எனில் (errno == EINTR || errno == EAGAIN)
				தொடர்;
			எனில் (errno != ECHILD)
				error_f("waitpid: %s", strerror(errno));
			நிறுத்து;
		}
		child_exit(pid, status);
	}

	க்கு (i = 0; i < options.max_startups; i++) {
		எனில் (!children[i].have_status)
			தொடர்;
		child_reap(&(children[i]));
	}
}

நிலையான வெறுமை
close_startup_pipes(வெறுமை)
{
	முழு i;

	எனில் (children == வெற்று)
		திரும்பு;
	க்கு (i = 0; i < options.max_startups; i++) {
		எனில் (children[i].pipefd != -1)
			child_close(&(children[i]), 1, 1);
	}
}

/* Called after SIGINFO */
நிலையான வெறுமை
show_info(வெறுமை)
{
	முழு i;
	மாறிலி எழுத்து *child_status;

	/* XXX print listening sockets here too */
	எனில் (children == வெற்று)
		திரும்பு;
	logit("%d active startups", children_active);
	க்கு (i = 0; i < options.max_startups; i++) {
		எனில் (children[i].pipefd == -1 && children[i].pid <= 0)
			தொடர்;
		எனில் (children[i].config)
			child_status = " (sending config)";
		இல்லையெனில் எனில் (children[i].சாவிகள்)
			child_status = " (sending keys)";
		இல்லையெனில் எனில் (children[i].early)
			child_status = " (early)";
		இல்லையெனில்
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

நிலையான வெறுமை
sighup_handler(முழு sig)
{
	received_sighup = 1;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
நிலையான வெறுமை
sighup_restart(வெறுமை)
{
	logit("Received SIGHUP; restarting.");
	எனில் (options.pid_file != வெற்று)
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
நிலையான வெறுமை
sigterm_handler(முழு sig)
{
	received_sigterm = sig;
}

#ifdef SIGINFO
நிலையான வெறுமை
siginfo_handler(முழு sig)
{
	received_siginfo = 1;
}
#endif

நிலையான வெறுமை
main_sigchld_handler(முழு sig)
{
	received_sigchld = 1;
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
நிலையான முழு
should_drop_connection(முழு startups)
{
	முழு p, r;

	எனில் (startups < options.max_startups_begin)
		திரும்பு 0;
	எனில் (startups >= options.max_startups)
		திரும்பு 1;
	எனில் (options.max_startups_rate == 100)
		திரும்பு 1;

	p  = 100 - options.max_startups_rate;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_rate;
	r = arc4random_uniform(100);

	debug_f("p %d, r %d", p, r);
	திரும்பு (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups or for penalty.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
நிலையான முழு
drop_connection(முழு sock, முழு startups, முழு notify_pipe)
{
	நிலையான கட்டமைப்பு log_ratelimit_ctx ratelimit_maxstartups;
	நிலையான கட்டமைப்பு log_ratelimit_ctx ratelimit_penalty;
	நிலையான முழு init_done;
	எழுத்து *laddr, *raddr;
	மாறிலி எழுத்து *reason = வெற்று, *subreason = வெற்று;
	மாறிலி எழுத்து செய்தி[] = "Not allowed at this time\r\n";
	கட்டமைப்பு log_ratelimit_ctx *rl = வெற்று;
	முழு ratelimited;
	u_int ndropped;

	எனில் (!init_done) {
		init_done = 1;
		log_ratelimit_init(&ratelimit_maxstartups, 4, 60, 20, 5*60);
		log_ratelimit_init(&ratelimit_penalty, 8, 60, 30, 2*60);
	}

	/* PerSourcePenalties */
	எனில் (!srclimit_penalty_check_allow(sock, &subreason)) {
		reason = "PerSourcePenalties";
		rl = &ratelimit_penalty;
	} இல்லையெனில் {
		/* MaxStartups */
		எனில் (!should_drop_connection(startups) &&
		    srclimit_check_allow(sock, notify_pipe) == 1)
			திரும்பு 0;
		reason = "MaxStartups";
		rl = &ratelimit_maxstartups;
	}

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	ratelimited = log_ratelimit(rl, time(வெற்று), வெற்று, &ndropped);
	do_log2(ratelimited ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    "drop connection #%d from [%s]:%d on [%s]:%d %s",
	    startups,
	    raddr, get_peer_port(sock),
	    laddr, get_local_port(sock),
	    subreason != வெற்று ? subreason : reason);
	விடுவி(laddr);
	விடுவி(raddr);
	எனில் (ndropped != 0) {
		logit("%s logging rate-limited: additional %u connections "
		    "dropped", reason, ndropped);
	}

	/* best-effort notification to client */
	(வெறுமை)லிக(sock, செய்தி, அளவு(செய்தி) - 1);
	திரும்பு 1;
}

நிலையான வெறுமை
usage(வெறுமை)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

நிலையான கட்டமைப்பு sshbuf *
pack_hostkeys(வெறுமை)
{
	கட்டமைப்பு sshbuf *m = வெற்று, *keybuf = வெற்று, *hostkeys = வெற்று;
	முழு r;
	u_int i;
	size_t len;

	எனில் ((m = sshbuf_new()) == வெற்று ||
	    (keybuf = sshbuf_new()) == வெற்று ||
	    (hostkeys = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	க்கு (i = 0; i < options.இலக்கம்_host_சாவி_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		எனில் (sensitive_data.host_சாவிகள்[i] != வெற்று &&
		    (r = sshkey_private_serialize(sensitive_data.host_சாவிகள்[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		எனில் ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		எனில் (sensitive_data.host_pubkeys[i] != வெற்று) {
			எனில் ((r = sshkey_puts(sensitive_data.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} இல்லையெனில் {
			எனில் ((r = sshbuf_put_string(hostkeys, வெற்று, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		எனில் (sensitive_data.host_certificates[i] != வெற்று) {
			எனில் ((r = sshkey_puts(
			    sensitive_data.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} இல்லையெனில் {
			எனில் ((r = sshbuf_put_string(hostkeys, வெற்று, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	எனில் ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0)
		fatal_fr(r, "compose message");
	எனில் ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(keybuf);
	sshbuf_free(hostkeys);
	திரும்பு m;
}

நிலையான கட்டமைப்பு sshbuf *
pack_config(கட்டமைப்பு sshbuf *conf)
{
	கட்டமைப்பு sshbuf *m = வெற்று, *inc = வெற்று;
	கட்டமைப்பு include_item *item = வெற்று;
	size_t len;
	முழு r;

	debug3_f("d config len %zu", sshbuf_len(conf));

	எனில் ((m = sshbuf_new()) == வெற்று ||
	    (inc = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(item, &includes, entry) {
		எனில் ((r = sshbuf_put_cstring(inc, item->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, item->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	எனில் ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	எனில் ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(inc);

	debug3_f("done");
	திரும்பு m;
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
நிலையான வெறுமை
send_rexec_state(முழு fd)
{
	கட்டமைப்பு sshbuf *சாவிகள்;
	u_int mlen;
	pid_t pid;

	எனில் ((pid = fork()) == -1)
		fatal_f("fork failed: %s", strerror(errno));
	எனில் (pid != 0)
		திரும்பு;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(config));

	mlen = sshbuf_len(config);
	எனில் (atomicio(vwrite, fd, sshbuf_mutable_ptr(config), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	சாவிகள் = pack_hostkeys();
	mlen = sshbuf_len(சாவிகள்);
	எனில் (atomicio(vwrite, fd, sshbuf_mutable_ptr(சாவிகள்), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	sshbuf_free(சாவிகள்);
	debug3_f("done");
	exit(0);
}

/*
 * Listen for TCP connections
 */
நிலையான வெறுமை
listen_on_addrs(கட்டமைப்பு listenaddr *la)
{
	முழு ret, listen_sock;
	கட்டமைப்பு addrinfo *ai;
	எழுத்து ntop[NI_MAXHOST], strport[NI_MAXSERV];

	க்கு (ai = la->addrs; ai; ai = ai->ai_next) {
		எனில் (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			தொடர்;
		எனில் (இலக்கம்_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		எனில் ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, அளவு(ntop), strport, அளவு(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			தொடர்;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		எனில் (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			தொடர்;
		}
		எனில் (set_nonblock(listen_sock) == -1) {
			close(listen_sock);
			தொடர்;
		}
		எனில் (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			தொடர்;
		}
		/* Socket options */
		set_reuseaddr(listen_sock);
		எனில் (la->rdomain != வெற்று &&
		    set_rdomain(listen_sock, la->rdomain) == -1) {
			close(listen_sock);
			தொடர்;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		எனில் (ai->ai_family == AF_INET6)
			sock_set_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		எனில் (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, strerror(errno));
			close(listen_sock);
			தொடர்;
		}
		listen_socks[இலக்கம்_listen_socks] = listen_sock;
		இலக்கம்_listen_socks++;

		/* Start listening on the port. */
		எனில் (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, strerror(errno));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == வெற்று ? "" : " rdomain ",
		    la->rdomain == வெற்று ? "" : la->rdomain);
	}
}

நிலையான வெறுமை
server_listen(வெறுமை)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups,
	    options.per_source_max_startups,
	    options.per_source_masklen_ipv4,
	    options.per_source_masklen_ipv6,
	    &options.per_source_penalty,
	    options.per_source_penalty_exempt);

	க்கு (i = 0; i < options.இலக்கம்_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		விடுவி(options.listen_addrs[i].rdomain);
		memset(&options.listen_addrs[i], 0,
		    அளவு(options.listen_addrs[i]));
	}
	விடுவி(options.listen_addrs);
	options.listen_addrs = வெற்று;
	options.இலக்கம்_listen_addrs = 0;

	எனில் (!இலக்கம்_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
நிலையான வெறுமை
server_accept_loop(முழு *sock_in, முழு *sock_out, முழு *newsock, முழு *config_s,
    முழு log_stderr)
{
	கட்டமைப்பு pollfd *pfd = வெற்று;
	முழு i, ret, npfd, r;
	முழு oactive = -1, listening = 0, lameduck = 0;
	முழு *startup_pollfd;
	ssize_t len;
	மாறிலி u_char *ptr;
	எழுத்து c = 0;
	கட்டமைப்பு sockaddr_storage from;
	கட்டமைப்பு early_child *child;
	கட்டமைப்பு sshbuf *buf;
	socklen_t fromlen;
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	child_alloc();
	startup_pollfd = xcalloc(options.max_startups, அளவு(முழு));

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
	pfd = xcalloc(இலக்கம்_listen_socks + options.max_startups,
	    அளவு(கட்டமைப்பு pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	க்கு (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		எனில் (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (முழு) received_sigterm);
			close_listen_socks();
			எனில் (options.pid_file != வெற்று)
				unlink(options.pid_file);
			exit(received_sigterm == SIGTERM ? 0 : 255);
		}
		எனில் (received_sigchld) {
			child_reap_all_exited();
			received_sigchld = 0;
		}
		எனில் (received_siginfo) {
			show_info();
			received_siginfo = 0;
		}
		எனில் (oactive != children_active) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, children_active,
			    options.max_startups_begin, options.max_startups);
			oactive = children_active;
		}
		எனில் (received_sighup) {
			எனில் (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			எனில் (listening <= 0) {
				/*
				 * Leave termination signals blocked, so
				 * they don't get lost across a restart.
				 */
				sigaddset(&osigset, SIGTERM);
				sigaddset(&osigset, SIGQUIT);
				sigprocmask(SIG_SETMASK, &osigset, வெற்று);
				sighup_restart();
			}
		}

		க்கு (i = 0; i < இலக்கம்_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = இலக்கம்_listen_socks;
		க்கு (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			எனில் (children[i].pipefd != -1) {
				pfd[npfd].fd = children[i].pipefd;
				pfd[npfd].events = POLLIN;
				எனில் (children[i].config != வெற்று ||
				    children[i].சாவிகள் != வெற்று)
					pfd[npfd].events |= POLLOUT;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, வெற்று, &osigset);
		எனில் (ret == -1 && errno != EINTR) {
			error("ppoll: %.100s", strerror(errno));
			எனில் (errno == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, வெற்று);
		எனில் (ret == -1)
			தொடர்;

		க்கு (i = 0; i < options.max_startups; i++) {
			எனில் (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & POLLOUT))
				தொடர்;
			எனில் (children[i].config)
				buf = children[i].config;
			இல்லையெனில் எனில் (children[i].சாவிகள்)
				buf = children[i].சாவிகள்;
			இல்லையெனில் {
				error_f("no buffer to send");
				தொடர்;
			}
			ptr = sshbuf_ptr(buf);
			len = sshbuf_len(buf);
			ret = லிக(children[i].pipefd, ptr, len);
			எனில் (ret == -1 && (errno == EINTR || errno == EAGAIN))
				தொடர்;
			எனில் (ret <= 0) {
				எனில் (children[i].early)
					listening--;
				child_close(&(children[i]), 0, 0);
				தொடர்;
			}
			எனில் (ret == len) {
				/* finished sending buffer */
				sshbuf_free(buf);
				எனில் (children[i].config == buf) {
					/* sent config, now send keys */
					children[i].config = வெற்று;
					children[i].சாவிகள் = pack_hostkeys();
				} இல்லையெனில் எனில் (children[i].சாவிகள் == buf) {
					/* sent both config and keys */
					children[i].சாவிகள் = வெற்று;
				} இல்லையெனில் {
					fatal("config buf not set");
				}

			} இல்லையெனில் {
				எனில் ((r = sshbuf_consume(buf, ret)) != 0)
					fatal_fr(r, "config buf inconsistent");
			}
		}
		க்கு (i = 0; i < options.max_startups; i++) {
			எனில் (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				தொடர்;
			தேர்வு (பட(children[i].pipefd, &c, அளவு(c))) {
			நிலை -1:
				எனில் (errno == EINTR || errno == EAGAIN)
					தொடர்;
				எனில் (errno != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, children[i].pipefd,
					    strerror(errno));
				}
				/* FALLTHROUGH */
			நிலை 0:
				/* child closed pipe */
				எனில் (children[i].early)
					listening--;
				debug3_f("child %lu for %s closed pipe",
				    (long)children[i].pid, children[i].id);
				child_close(&(children[i]), 0, 0);
				நிறுத்து;
			நிலை 1:
				எனில் (children[i].config) {
					error_f("startup pipe %d (fd=%d)"
					    " early read",
					    i, children[i].pipefd);
					செல் problem_child;
				}
				எனில் (children[i].early && c == '\0') {
					/* child has finished preliminaries */
					listening--;
					children[i].early = 0;
					debug2_f("child %lu for %s received "
					    "config", (long)children[i].pid,
					    children[i].id);
				} இல்லையெனில் எனில் (!children[i].early && c == '\001') {
					/* child has completed auth */
					debug2_f("child %lu for %s auth done",
					    (long)children[i].pid,
					    children[i].id);
					child_close(&(children[i]), 1, 0);
				} இல்லையெனில் {
					error_f("unexpected message 0x%02x "
					    "child %ld for %s in state %d",
					    (முழு)c, (long)children[i].pid,
					    children[i].id, children[i].early);
 problem_child:
					எனில் (children[i].early)
						listening--;
					எனில் (children[i].pid > 0)
						kill(children[i].pid, SIGTERM);
					child_close(&(children[i]), 0, 0);
				}
				நிறுத்து;
			}
		}
		க்கு (i = 0; i < இலக்கம்_listen_socks; i++) {
			எனில் (!(pfd[i].revents & POLLIN))
				தொடர்;
			fromlen = அளவு(from);
			*newsock = accept(listen_socks[i],
			    (கட்டமைப்பு sockaddr *)&from, &fromlen);
			எனில் (*newsock == -1) {
				எனில் (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED && errno != EAGAIN)
					error("accept: %.100s",
					    strerror(errno));
				எனில் (errno == EMFILE || errno == ENFILE)
					usleep(100 * 1000);
				தொடர்;
			}
			எனில் (unset_nonblock(*newsock) == -1) {
				close(*newsock);
				தொடர்;
			}
			எனில் (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    strerror(errno));
				close(*newsock);
				தொடர்;
			}
			எனில் (drop_connection(*newsock,
			    children_active, config_s[0])) {
				close(*newsock);
				close(config_s[0]);
				close(config_s[1]);
				தொடர்;
			}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			எனில் (debug_flag) {
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
				விடுவி(pfd);
				விடுவி(startup_pollfd);
				திரும்பு;
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
			எனில் ((child->pid = fork()) == 0) {
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
				விடுவி(pfd);
				விடுவி(startup_pollfd);
				திரும்பு;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_parent(child->pid);
			எனில் (child->pid == -1)
				error("fork: %.100s", strerror(errno));
			இல்லையெனில்
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

நிலையான வெறுமை
accumulate_host_timing_secret(கட்டமைப்பு sshbuf *server_cfg,
    கட்டமைப்பு sshkey *சாவி)
{
	நிலையான கட்டமைப்பு ssh_digest_ctx *ctx;
	u_char *hash;
	size_t len;
	கட்டமைப்பு sshbuf *buf;
	முழு r;

	எனில் (ctx == வெற்று && (ctx = ssh_digest_start(SSH_DIGEST_SHA512)) == வெற்று)
		fatal_f("ssh_digest_start");
	எனில் (சாவி == வெற்று) { /* finalize */
		/* add server config in case we are using agent for host keys */
		எனில் (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_bytes(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		எனில் (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = வெற்று;
		திரும்பு;
	}
	எனில் ((buf = sshbuf_new()) == வெற்று)
		fatal_f("could not allocate buffer");
	எனில் ((r = sshkey_private_serialize(சாவி, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(சாவி));
	எனில் (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

நிலையான எழுத்து *
prepare_proctitle(முழு ac, எழுத்து **av)
{
	எழுத்து *ret = வெற்று;
	முழு i;

	க்கு (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	திரும்பு ret;
}

/* Disconnect from the controlling tty. */
நிலையான வெறுமை
disconnect_controlling_tty(வெறுமை)
{
#ifdef TIOCNOTTY
# ifndef O_NOCTTY
#  define O_NOCTTY 0
# endif
	முழு fd;

	எனில் ((fd = open(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(வெறுமை) ioctl(fd, TIOCNOTTY, வெற்று);
		close(fd);
	}
#endif /* TIOCNOTTY */
}

நிலையான வெறுமை
print_config(கட்டமைப்பு connection_info *connection_info)
{
	connection_info->test = 1;
	parse_server_match_config(&options, &includes, connection_info);
	dump_config(&options);
	exit(0);
}

/*
 * Main program for the daemon.
 */
முழு
முதன்மை(முழு ac, எழுத்து **av)
{
	வெளி எழுத்து *optarg;
	வெளி முழு optind;
	முழு log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	எழுத்து *config_file_name = _PATH_SERVER_CONFIG_FILE;
	முழு r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	முழு sock_in = -1, sock_out = -1, newsock = -1, rexec_argc = 0;
	முழு devnull, config_s[2] = { -1 , -1 }, have_connection_info = 0;
	முழு need_chroot = 1;
	எழுத்து *args, *fp, *வரி, *logfile = வெற்று, **rexec_argv = வெற்று;
	கட்டமைப்பு stat sb;
	u_int i, j;
	mode_t new_umask;
	கட்டமைப்பு sshkey *சாவி;
	கட்டமைப்பு sshkey *pubkey;
	கட்டமைப்பு connection_info connection_info;
	கட்டமைப்பு utsname utsname;
	sigset_t sigmask;

	memset(&connection_info, 0, அளவு(connection_info));
#ifdef HAVE_SECUREWARE
	(வெறுமை)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, வெற்று);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, அளவு(*saved_argv));
	க்கு (i = 0; (முழு)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = வெற்று;

#ifndef HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#endif

	எனில் (geteuid() == 0 && setgroups(0, வெற்று) == -1)
		debug("setgroups(): %.200s", strerror(errno));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	போது ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		தேர்வு (opt) {
		நிலை '4':
			options.address_family = AF_INET;
			நிறுத்து;
		நிலை '6':
			options.address_family = AF_INET6;
			நிறுத்து;
		நிலை 'f':
			config_file_name = optarg;
			நிறுத்து;
		நிலை 'c':
			servconf_add_hostcert("[command-line]", 0,
			    &options, optarg);
			நிறுத்து;
		நிலை 'd':
			எனில் (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} இல்லையெனில் எனில் (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			நிறுத்து;
		நிலை 'D':
			no_daemon_flag = 1;
			நிறுத்து;
		நிலை 'G':
			do_dump_cfg = 1;
			நிறுத்து;
		நிலை 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		நிலை 'e':
			log_stderr = 1;
			நிறுத்து;
		நிலை 'i':
			inetd_flag = 1;
			நிறுத்து;
		நிலை 'r':
			logit("-r option is deprecated");
			நிறுத்து;
		நிலை 'R':
			fatal("-R not supported here");
			நிறுத்து;
		நிலை 'Q':
			/* ignored */
			நிறுத்து;
		நிலை 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			நிறுத்து;
		நிலை 'b':
			/* protocol 1, ignored */
			நிறுத்து;
		நிலை 'p':
			options.ports_from_cmdline = 1;
			எனில் (options.இலக்கம்_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				exit(1);
			}
			options.ports[options.இலக்கம்_ports++] = a2port(optarg);
			எனில் (options.ports[options.இலக்கம்_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				exit(1);
			}
			நிறுத்து;
		நிலை 'g':
			எனில் ((options.login_grace_time = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				exit(1);
			}
			நிறுத்து;
		நிலை 'k':
			/* protocol 1, ignored */
			நிறுத்து;
		நிலை 'h':
			servconf_add_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			நிறுத்து;
		நிலை 't':
			test_flag = 1;
			நிறுத்து;
		நிலை 'T':
			test_flag = 2;
			நிறுத்து;
		நிலை 'C':
			எனில் (parse_server_match_testspec(&connection_info,
			    optarg) == -1)
				exit(1);
			have_connection_info = 1;
			நிறுத்து;
		நிலை 'u':
			utmp_len = (u_int)strtonum(optarg, 0,
			    HOST_NAME_MAX+1+1, வெற்று);
			எனில் (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			நிறுத்து;
		நிலை 'o':
			வரி = xstrdup(optarg);
			எனில் (process_server_config_வரி(&options, வரி,
			    "command-line", 0, வெற்று, வெற்று, &includes) != 0)
				exit(1);
			விடுவி(வரி);
			நிறுத்து;
		நிலை 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
		இயல்பு:
			usage();
			நிறுத்து;
		}
	}

	எனில் (getexecpath(execpath, அளவு execpath) != 0) {
		எனில் (strlcpy(execpath, av[0], அளவு execpath) >=
		    அளவு execpath) {
			fprintf(stderr, "execution path is too long\n");
			exit(1);
		}
	}
	எனில் (!test_flag && !inetd_flag && !do_dump_cfg && !path_absolute(execpath))
		fatal("sshd requires execution with an absolute path");

	closefrom(STDERR_FILENO + 1);

	/* Reserve fds we'll need later for reexec things */
	எனில் ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	போது (devnull < REEXEC_MIN_FREE_FD) {
		எனில் ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	seed_rng();

	/* If requested, redirect the logs to the specified logfile. */
	எனில் (logfile != வெற்று) {
		எழுத்து *cp, pid_s[32];

		snprintf(pid_s, அளவு(pid_s), "%ld", (unsigned long)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (எழுத்து *)வெற்று);
		log_redirect_stderr_to(cp);
		விடுவி(cp);
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
	எனில் (getenv("KRB5CCNAME") != வெற்று)
		(வெறுமை) unsetenv("KRB5CCNAME");

	sensitive_data.have_ssh2_சாவி = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	எனில் (test_flag < 2 && have_connection_info)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	debug("sshd version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);
	எனில் (uname(&utsname) != 0) {
		memset(&utsname, 0, அளவு(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", அளவு(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	விடுவி(args);

	/* Fetch our configuration */
	எனில் ((cfg = sshbuf_new()) == வெற்று)
		fatal("sshbuf_new config failed");
	எனில் (strcasecmp(config_file_name, "none") != 0)
		load_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, வெற்று, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	எனில் (options.authorized_சாவிகள்_command_user == வெற்று &&
	    (options.authorized_சாவிகள்_command != வெற்று &&
	    strcasecmp(options.authorized_சாவிகள்_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	எனில் (options.authorized_principals_command_user == வெற்று &&
	    (options.authorized_principals_command != வெற்று &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match blocks, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	எனில் (options.இலக்கம்_auth_methods != 0) {
		க்கு (i = 0; i < options.இலக்கம்_auth_methods; i++) {
			எனில் (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				நிறுத்து;
		}
		எனில் (i >= options.இலக்கம்_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	எனில் (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	எனில் (do_dump_cfg)
		print_config(&connection_info);

	/* load host keys */
	sensitive_data.host_சாவிகள் = xcalloc(options.இலக்கம்_host_சாவி_files,
	    அளவு(கட்டமைப்பு sshkey *));
	sensitive_data.host_pubkeys = xcalloc(options.இலக்கம்_host_சாவி_files,
	    அளவு(கட்டமைப்பு sshkey *));

	எனில் (options.host_சாவி_agent) {
		எனில் (strcmp(options.host_சாவி_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_சாவி_agent, 1);
		எனில் ((r = ssh_get_authentication_socket(வெற்று)) == 0)
			have_agent = 1;
		இல்லையெனில்
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_சாவி_agent);
	}

	க்கு (i = 0; i < options.இலக்கம்_host_சாவி_files; i++) {
		முழு ll = options.host_சாவி_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		எனில் (options.host_சாவி_files[i] == வெற்று)
			தொடர்;
		எனில் ((r = sshkey_load_private(options.host_சாவி_files[i], "",
		    &சாவி, வெற்று)) != 0 &&
		    r != SSH_ERR_SYSTEM_ERROR && !have_agent)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_சாவி_files[i]);
		எனில் (sshkey_is_sk(சாவி) &&
		    சாவி->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_சாவி_files[i]);
			சாவி->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		எனில் (r == 0 && சாவி != வெற்று &&
		    (r = sshkey_shield_private(சாவி)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_சாவி_files[i]);
			sshkey_free(சாவி);
			சாவி = வெற்று;
		}
		எனில் ((r = sshkey_load_public(options.host_சாவி_files[i],
		    &pubkey, வெற்று)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_சாவி_files[i]);
		எனில் (pubkey != வெற்று && சாவி != வெற்று) {
			எனில் (!sshkey_equal(pubkey, சாவி)) {
				error("Public key for %s does not match "
				    "private key", options.host_சாவி_files[i]);
				sshkey_free(pubkey);
				pubkey = வெற்று;
			}
		}
		எனில் (pubkey == வெற்று && சாவி != வெற்று) {
			எனில் ((r = sshkey_from_private(சாவி, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_சாவி_files[i]);
		}
		எனில் (pubkey != வெற்று && (r = sshkey_check_rsa_length(pubkey,
		    options.required_rsa_size)) != 0) {
			error_fr(r, "Host key %s", options.host_சாவி_files[i]);
			sshkey_free(pubkey);
			sshkey_free(சாவி);
			தொடர்;
		}
		sensitive_data.host_சாவிகள்[i] = சாவி;
		sensitive_data.host_pubkeys[i] = pubkey;

		எனில் (சாவி == வெற்று && pubkey != வெற்று && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_சாவி_files[i]);
			keytype = pubkey->type;
		} இல்லையெனில் எனில் (சாவி != வெற்று) {
			keytype = சாவி->type;
			accumulate_host_timing_secret(cfg, சாவி);
		} இல்லையெனில் {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_சாவி_files[i]);
			sensitive_data.host_சாவிகள்[i] = வெற்று;
			sensitive_data.host_pubkeys[i] = வெற்று;
			தொடர்;
		}

		தேர்வு (keytype) {
		நிலை சாவி_RSA:
		நிலை சாவி_ECDSA:
		நிலை சாவி_ED25519:
		நிலை சாவி_MLDSA44_ED25519:
		நிலை சாவி_ECDSA_SK:
		நிலை சாவி_ED25519_SK:
			எனில் (have_agent || சாவி != வெற்று)
				sensitive_data.have_ssh2_சாவி = 1;
			நிறுத்து;
		}
		எனில் ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == வெற்று)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    சாவி ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		விடுவி(fp);
	}
	accumulate_host_timing_secret(cfg, வெற்று);
	எனில் (!sensitive_data.have_ssh2_சாவி) {
		logit("sshd: no hostkeys available -- exiting.");
		exit(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_data.host_certificates = xcalloc(options.இலக்கம்_host_சாவி_files,
	    அளவு(கட்டமைப்பு sshkey *));
	க்கு (i = 0; i < options.இலக்கம்_host_சாவி_files; i++)
		sensitive_data.host_certificates[i] = வெற்று;

	க்கு (i = 0; i < options.இலக்கம்_host_cert_files; i++) {
		எனில் (options.host_cert_files[i] == வெற்று)
			தொடர்;
		எனில் ((r = sshkey_load_public(options.host_cert_files[i],
		    &சாவி, வெற்று)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			தொடர்;
		}
		எனில் (!sshkey_is_cert(சாவி)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(சாவி);
			தொடர்;
		}
		/* Find matching private key */
		க்கு (j = 0; j < options.இலக்கம்_host_சாவி_files; j++) {
			எனில் (sshkey_equal_public(சாவி,
			    sensitive_data.host_pubkeys[j])) {
				sensitive_data.host_certificates[j] = சாவி;
				நிறுத்து;
			}
		}
		எனில் (j >= options.இலக்கம்_host_சாவி_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(சாவி);
			தொடர்;
		}
		sensitive_data.host_certificates[j] = சாவி;
		debug("host certificate: #%u type %d %s", j, சாவி->type,
		    sshkey_type(சாவி));
	}

	/* Ensure privsep directory is correctly configured. */
	need_chroot = ((getuid() == 0 || geteuid() == 0) ||
	    options.kerberos_authentication);
	எனில் ((getpwnam(SSH_PRIVSEP_USER)) == வெற்று && need_chroot) {
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	}
	endpwent();

	எனில் (need_chroot) {
		எனில் ((stat(_PATH_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
		    (S_ISDIR(sb.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    _PATH_PRIVSEP_CHROOT_DIR);
#ifdef HAVE_CYGWIN
		எனில் (check_ntsec(_PATH_PRIVSEP_CHROOT_DIR) &&
		    (sb.st_uid != getuid () ||
		    (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#இல்லையெனில்
		எனில் (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#endif
			fatal("%s must be owned by root and not group or "
			    "world-writable.", _PATH_PRIVSEP_CHROOT_DIR);
	}

	எனில் (test_flag > 1)
		print_config(&connection_info);

	config = pack_config(cfg);
	எனில் (sshbuf_len(config) > MONITOR_MAX_CFGLEN) {
		fatal("Configuration file is too large (have %zu, max %d)",
		    sshbuf_len(config), MONITOR_MAX_CFGLEN);
	}

	/* Configuration looks good, so exit if in test mode. */
	எனில் (test_flag)
		exit(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	எனில் (setgroups(0, வெற்று) < 0)
		debug("setgroups() failed: %.200s", strerror(errno));

	/* Prepare arguments for sshd-session */
	எனில் (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, அளவு(எழுத்து *));
	/* Point to the sshd-session binary instead of sshd */
	rexec_argv[0] = options.sshd_session_path;
	க்கு (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = வெற்று;
	எனில் (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	எனில் (stat(options.sshd_auth_path, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_auth_path);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(வெறுமை) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	எனில் (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	க்கு (i = 0; i < options.இலக்கம்_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	எனில் (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		எனில் (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", strerror(errno));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	எனில் (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or a listening TCP socket */
	எனில் (inetd_flag) {
		/* Send configuration to ancestor sshd-session process */
		எனில் (socketpair(AF_UNIX, SOCK_STREAM, 0, config_s) == -1)
			fatal("socketpair: %s", strerror(errno));
		send_rexec_state(config_s[0]);
		close(config_s[0]);
	} இல்லையெனில் {
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
		எனில் (options.pid_file != வெற்று && !debug_flag) {
			FILE *f = fopen(options.pid_file, "w");

			எனில் (f == வெற்று) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, strerror(errno));
			} இல்லையெனில் {
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
	எனில் (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	debug("rexec start in %d out %d newsock %d config_s %d/%d",
	    sock_in, sock_out, newsock, config_s[0], config_s[1]);
	எனில் (!inetd_flag) {
		எனில் (dup2(newsock, STDIN_FILENO) == -1)
			fatal("dup2 stdin: %s", strerror(errno));
		எனில் (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			fatal("dup2 stdout: %s", strerror(errno));
		எனில் (newsock > STDOUT_FILENO)
			close(newsock);
	}
	எனில் (config_s[1] != REEXEC_CONFIG_PASS_FD) {
		எனில் (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			fatal("dup2 config_s: %s", strerror(errno));
		close(config_s[1]);
	}
	log_redirect_stderr_to(வெற்று);
	closefrom(REEXEC_MIN_FREE_FD);

	ssh_signal(SIGHUP, SIG_IGN); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], strerror(errno));
}

/* server specific fatal cleanup */
வெறுமை
cleanup_exit(முழு i)
{
	_exit(i);
}
