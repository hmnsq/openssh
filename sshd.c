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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/ioctl.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ <sys/utsname.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <grp.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ifdef HAVE_SECUREWARE
#ಅನ್ತರ್ಭಾವ <sys/security.h>
#ಅನ್ತರ್ಭಾವ <prot.h>
#endif

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "sshpty.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "msg.h"
#ಅನ್ತರ್ಭಾವ "version.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sk-api.h"
#ಅನ್ತರ್ಭಾವ "addr.h"
#ಅನ್ತರ್ಭಾವ "srclimit.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ifdef GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#endif
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

ಬಾಹ್ಯ ವರ್ಣ *__progname;

/* Server configuration options. */
ServerOptions options;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
ಪೂರ್ಣಾಙ್ಕ debug_flag = 0;

/* Saved arguments to main(). */
ಸ್ಥಿರ ವರ್ಣ execpath[PATH_MAX];
ಸ್ಥಿರ ವರ್ಣ **saved_argv;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#define	MAX_LISTEN_SOCKS	16
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ listen_socks[MAX_LISTEN_SOCKS];
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಅಂಕೆ_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
ಸಂರಚನಾ {
	ಸಂರಚನಾ sshkey	**host_ಕೀಲಿಗಳು;		/* all private host keys */
	ಸಂರಚನಾ sshkey	**host_pubkeys;		/* all public host keys */
	ಸಂರಚನಾ sshkey	**host_certificates;	/* all public host certificates */
	ಪೂರ್ಣಾಙ್ಕ		have_ssh2_ಕೀಲಿ;
} sensitive_data;

/* This is set to true when a signal is received. */
ಸ್ಥಿರ ಚಞ್ಚಲ sig_atomic_t received_siginfo = 0;
ಸ್ಥಿರ ಚಞ್ಚಲ sig_atomic_t received_sigchld = 0;
ಸ್ಥಿರ ಚಞ್ಚಲ sig_atomic_t received_sighup = 0;
ಸ್ಥಿರ ಚಞ್ಚಲ sig_atomic_t received_sigterm = 0;

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
ಸಂರಚನಾ early_child {
	ಪೂರ್ಣಾಙ್ಕ pipefd;
	ಪೂರ್ಣಾಙ್ಕ early;		/* Indicates child closed listener */
	ವರ್ಣ *id;		/* human readable connection identifier */
	pid_t pid;
	ಸಂರಚನಾ xaddr addr;
	ಪೂರ್ಣಾಙ್ಕ have_addr;
	ಪೂರ್ಣಾಙ್ಕ status, have_status;
	ಸಂರಚನಾ sshbuf *config;
	ಸಂರಚನಾ sshbuf *ಕೀಲಿಗಳು;
};
ಸ್ಥಿರ ಸಂರಚನಾ early_child *children;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ children_active;

/* sshd_config buffer */
ಸಂರಚನಾ sshbuf *cfg;
ಸಂರಚನಾ sshbuf *config;	/* packed */

/* Included files from the configuration file */
ಸಂರಚನಾ include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ಸಂರಚನಾ sshbuf *loginmsg;

/* Unprivileged user */
ಸಂರಚನಾ passwd *privsep_pw = ರಿಕ್ತ;

ಸ್ಥಿರ ವರ್ಣ *listener_proctitle;

/*
 * Close all listening sockets
 */
ಸ್ಥಿರ ಶೂನ್ಯ
close_listen_socks(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_listen_socks; i++)
		close(listen_socks[i]);
	ಅಂಕೆ_listen_socks = 0;
}

/* Allocate and initialise the children array */
ಸ್ಥಿರ ಶೂನ್ಯ
child_alloc(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	children = xcalloc(options.max_startups, ಪರಿಮಾಣ(*children));
	ಪ್ರತಿ (i = 0; i < options.max_startups; i++) {
		children[i].pipefd = -1;
		children[i].pid = -1;
	}
}

/* Register a new connection in the children array; child pid comes later */
ಸ್ಥಿರ ಸಂರಚನಾ early_child *
child_register(ಪೂರ್ಣಾಙ್ಕ pipefd, ಪೂರ್ಣಾಙ್ಕ sockfd)
{
	ಪೂರ್ಣಾಙ್ಕ i, lport, rport;
	ವರ್ಣ *laddr = ರಿಕ್ತ, *raddr = ರಿಕ್ತ;
	ಸಂರಚನಾ early_child *child = ರಿಕ್ತ;
	ಸಂರಚನಾ sockaddr_storage addr;
	socklen_t addrlen = ಪರಿಮಾಣ(addr);
	ಸಂರಚನಾ sockaddr *sa = (ಸಂರಚನಾ sockaddr *)&addr;

	ಪ್ರತಿ (i = 0; i < options.max_startups; i++) {
		ಯದಿ (children[i].pipefd != -1 ||
		    children[i].config != ರಿಕ್ತ ||
		    children[i].ಕೀಲಿಗಳು != ರಿಕ್ತ ||
		    children[i].pid > 0)
			ಅನುವರ್ತ;
		child = &(children[i]);
		ಭಙ್ಗ;
	}
	ಯದಿ (child == ರಿಕ್ತ) {
		fatal_f("error: accepted connection when all %d child "
		    " slots full", options.max_startups);
	}
	child->pipefd = pipefd;
	child->early = 1;
	ಯದಿ ((child->config = sshbuf_fromb(config)) == ರಿಕ್ತ)
		fatal_f("sshbuf_fromb failed");
	/* record peer address, if available */
	ಯದಿ (getpeername(sockfd, sa, &addrlen) == 0 &&
	   addr_sa_to_xaddr(sa, addrlen, &child->addr) == 0)
		child->have_addr = 1;
	/* format peer address string for logs */
	ಯದಿ ((lport = get_local_port(sockfd)) == 0 ||
	    (rport = get_peer_port(sockfd)) == 0) {
		/* Not a TCP socket */
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s", raddr);
	} ಅನ್ಯಥಾ {
		laddr = get_local_ipaddr(sockfd);
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s to %s", raddr, laddr);
	}
	ಮುಕ್ತ(laddr);
	ಮುಕ್ತ(raddr);
	ಯದಿ (++children_active > options.max_startups)
		fatal_f("internal error: more children than max_startups");

	ಪ್ರತ್ಯಾಗಮ child;
}

/*
 * Finally free a child entry. Don't call this directly.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
child_finish(ಸಂರಚನಾ early_child *child)
{
	ಯದಿ (children_active == 0)
		fatal_f("internal error: children_active underflow");
	ಯದಿ (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
	}
	sshbuf_free(child->config);
	sshbuf_free(child->ಕೀಲಿಗಳು);
	ಮುಕ್ತ(child->id);
	memset(child, '\0', ಪರಿಮಾಣ(*child));
	child->pipefd = -1;
	child->pid = -1;
	children_active--;
}

/*
 * Close a child's pipe. This will not stop tracking the child immediately
 * (it will still be tracked for waitpid()) unless force_final is set, or
 * child has already exited.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
child_close(ಸಂರಚನಾ early_child *child, ಪೂರ್ಣಾಙ್ಕ force_final, ಪೂರ್ಣಾಙ್ಕ quiet)
{
	ಯದಿ (!quiet)
		debug_f("enter%s", force_final ? " (forcing)" : "");
	ಯದಿ (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
		child->pipefd = -1;
	}
	ಯದಿ (child->pid == -1 || force_final)
		child_finish(child);
}

/* Record a child exit. Safe to call from signal handlers */
ಸ್ಥಿರ ಶೂನ್ಯ
child_exit(pid_t pid, ಪೂರ್ಣಾಙ್ಕ status)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (children == ರಿಕ್ತ || pid <= 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; i < options.max_startups; i++) {
		ಯದಿ (children[i].pid == pid) {
			children[i].have_status = 1;
			children[i].status = status;
			ಭಙ್ಗ;
		}
	}
}

/*
 * Reap a child entry that has exited, as previously flagged
 * using child_exit().
 * Handles logging of exit condition and will finalise the child if its pipe
 * had already been closed.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
child_reap(ಸಂರಚನಾ early_child *child)
{
	LogLevel level = SYSLOG_LEVEL_DEBUG1;
	ಪೂರ್ಣಾಙ್ಕ was_crash, penalty_type = SRCLIMIT_PENALTY_NONE;
	ಧ್ರುವ ವರ್ಣ *child_status;

	ಯದಿ (child->config)
		child_status = " (sending config)";
	ಅನ್ಯಥಾ ಯದಿ (child->ಕೀಲಿಗಳು)
		child_status = " (sending keys)";
	ಅನ್ಯಥಾ ಯದಿ (child->early)
		child_status = " (early)";
	ಅನ್ಯಥಾ
		child_status = "";

	/* Log exit information */
	ಯದಿ (WIFSIGNALED(child->status)) {
		/*
		 * Increase logging for signals potentially associated
		 * with serious conditions.
		 */
		ಯದಿ ((was_crash = signal_is_crash(WTERMSIG(child->status))))
			level = SYSLOG_LEVEL_ERROR;
		do_log2(level, "session process %ld for %s killed by "
		    "signal %d%s", (long)child->pid, child->id,
		    WTERMSIG(child->status), child_status);
		ಯದಿ (was_crash)
			penalty_type = SRCLIMIT_PENALTY_CRASH;
	} ಅನ್ಯಥಾ ಯದಿ (!WIFEXITED(child->status)) {
		penalty_type = SRCLIMIT_PENALTY_CRASH;
		error("session process %ld for %s terminated abnormally, "
		    "status=0x%x%s", (long)child->pid, child->id, child->status,
		    child_status);
	} ಅನ್ಯಥಾ {
		/* Normal exit. We care about the status */
		ವಿಕಲ್ಪ (WEXITSTATUS(child->status)) {
		ಪಕ್ಷ 0:
			debug3_f("preauth child %ld for %s completed "
			    "normally%s", (long)child->pid, child->id,
			    child_status);
			ಭಙ್ಗ;
		ಪಕ್ಷ EXIT_LOGIN_GRACE:
			penalty_type = SRCLIMIT_PENALTY_GRACE_EXCEEDED;
			logit("Timeout before authentication for %s, "
			    "pid = %ld%s", child->id, (long)child->pid,
			    child_status);
			ಭಙ್ಗ;
		ಪಕ್ಷ EXIT_CHILD_CRASH:
			penalty_type = SRCLIMIT_PENALTY_CRASH;
			logit("Session process %ld unpriv child crash for %s%s",
			    (long)child->pid, child->id, child_status);
			ಭಙ್ಗ;
		ಪಕ್ಷ EXIT_AUTH_ATTEMPTED:
			penalty_type = SRCLIMIT_PENALTY_AUTHFAIL;
			debug_f("preauth child %ld for %s exited "
			    "after unsuccessful auth attempt%s",
			    (long)child->pid, child->id, child_status);
			ಭಙ್ಗ;
		ಪಕ್ಷ EXIT_INVALID_USER:
			penalty_type = SRCLIMIT_PENALTY_INVALIDUSER;
			debug_f("preauth child %ld for %s exited "
			    "after auth attempt by invalid user%s",
			    (long)child->pid, child->id, child_status);
			ಭಙ್ಗ;
		ಪಕ್ಷ EXIT_CONFIG_REFUSED:
			penalty_type = SRCLIMIT_PENALTY_REFUSECONNECTION;
			debug_f("preauth child %ld for %s prohibited by"
			    "RefuseConnection%s",
			    (long)child->pid, child->id, child_status);
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			penalty_type = SRCLIMIT_PENALTY_NOAUTH;
			debug_f("preauth child %ld for %s exited "
			    "with status %d%s", (long)child->pid, child->id,
			    WEXITSTATUS(child->status), child_status);
			ಭಙ್ಗ;
		}
	}

	ಯದಿ (child->have_addr)
		srclimit_penalise(&child->addr, penalty_type);

	child->pid = -1;
	child->have_status = 0;
	ಯದಿ (child->pipefd == -1)
		child_finish(child);
}

/* Reap all children that have exited; called after SIGCHLD */
ಸ್ಥಿರ ಶೂನ್ಯ
child_reap_all_exited(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	pid_t pid;
	ಪೂರ್ಣಾಙ್ಕ status;

	ಯದಿ (children == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	ಪ್ರತಿ (;;) {
		ಯದಿ ((pid = waitpid(-1, &status, WNOHANG)) == 0)
			ಭಙ್ಗ;
		ಅನ್ಯಥಾ ಯದಿ (pid == -1) {
			ಯದಿ (errno == EINTR || errno == EAGAIN)
				ಅನುವರ್ತ;
			ಯದಿ (errno != ECHILD)
				error_f("waitpid: %s", strerror(errno));
			ಭಙ್ಗ;
		}
		child_exit(pid, status);
	}

	ಪ್ರತಿ (i = 0; i < options.max_startups; i++) {
		ಯದಿ (!children[i].have_status)
			ಅನುವರ್ತ;
		child_reap(&(children[i]));
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
close_startup_pipes(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (children == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; i < options.max_startups; i++) {
		ಯದಿ (children[i].pipefd != -1)
			child_close(&(children[i]), 1, 1);
	}
}

/* Called after SIGINFO */
ಸ್ಥಿರ ಶೂನ್ಯ
show_info(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	ಧ್ರುವ ವರ್ಣ *child_status;

	/* XXX print listening sockets here too */
	ಯದಿ (children == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	logit("%d active startups", children_active);
	ಪ್ರತಿ (i = 0; i < options.max_startups; i++) {
		ಯದಿ (children[i].pipefd == -1 && children[i].pid <= 0)
			ಅನುವರ್ತ;
		ಯದಿ (children[i].config)
			child_status = " (sending config)";
		ಅನ್ಯಥಾ ಯದಿ (children[i].ಕೀಲಿಗಳು)
			child_status = " (sending keys)";
		ಅನ್ಯಥಾ ಯದಿ (children[i].early)
			child_status = " (early)";
		ಅನ್ಯಥಾ
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

ಸ್ಥಿರ ಶೂನ್ಯ
sighup_handler(ಪೂರ್ಣಾಙ್ಕ sig)
{
	received_sighup = 1;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
sighup_restart(ಶೂನ್ಯ)
{
	logit("Received SIGHUP; restarting.");
	ಯದಿ (options.pid_file != ರಿಕ್ತ)
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
ಸ್ಥಿರ ಶೂನ್ಯ
sigterm_handler(ಪೂರ್ಣಾಙ್ಕ sig)
{
	received_sigterm = sig;
}

#ifdef SIGINFO
ಸ್ಥಿರ ಶೂನ್ಯ
siginfo_handler(ಪೂರ್ಣಾಙ್ಕ sig)
{
	received_siginfo = 1;
}
#endif

ಸ್ಥಿರ ಶೂನ್ಯ
main_sigchld_handler(ಪೂರ್ಣಾಙ್ಕ sig)
{
	received_sigchld = 1;
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
should_drop_connection(ಪೂರ್ಣಾಙ್ಕ startups)
{
	ಪೂರ್ಣಾಙ್ಕ p, r;

	ಯದಿ (startups < options.max_startups_begin)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (startups >= options.max_startups)
		ಪ್ರತ್ಯಾಗಮ 1;
	ಯದಿ (options.max_startups_rate == 100)
		ಪ್ರತ್ಯಾಗಮ 1;

	p  = 100 - options.max_startups_rate;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_rate;
	r = arc4random_uniform(100);

	debug_f("p %d, r %d", p, r);
	ಪ್ರತ್ಯಾಗಮ (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups or for penalty.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
drop_connection(ಪೂರ್ಣಾಙ್ಕ sock, ಪೂರ್ಣಾಙ್ಕ startups, ಪೂರ್ಣಾಙ್ಕ notify_pipe)
{
	ಸ್ಥಿರ ಸಂರಚನಾ log_ratelimit_ctx ratelimit_maxstartups;
	ಸ್ಥಿರ ಸಂರಚನಾ log_ratelimit_ctx ratelimit_penalty;
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ init_done;
	ವರ್ಣ *laddr, *raddr;
	ಧ್ರುವ ವರ್ಣ *reason = ರಿಕ್ತ, *subreason = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ ಸಂದೇಶ[] = "Not allowed at this time\r\n";
	ಸಂರಚನಾ log_ratelimit_ctx *rl = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ratelimited;
	u_int ndropped;

	ಯದಿ (!init_done) {
		init_done = 1;
		log_ratelimit_init(&ratelimit_maxstartups, 4, 60, 20, 5*60);
		log_ratelimit_init(&ratelimit_penalty, 8, 60, 30, 2*60);
	}

	/* PerSourcePenalties */
	ಯದಿ (!srclimit_penalty_check_allow(sock, &subreason)) {
		reason = "PerSourcePenalties";
		rl = &ratelimit_penalty;
	} ಅನ್ಯಥಾ {
		/* MaxStartups */
		ಯದಿ (!should_drop_connection(startups) &&
		    srclimit_check_allow(sock, notify_pipe) == 1)
			ಪ್ರತ್ಯಾಗಮ 0;
		reason = "MaxStartups";
		rl = &ratelimit_maxstartups;
	}

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	ratelimited = log_ratelimit(rl, time(ರಿಕ್ತ), ರಿಕ್ತ, &ndropped);
	do_log2(ratelimited ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    "drop connection #%d from [%s]:%d on [%s]:%d %s",
	    startups,
	    raddr, get_peer_port(sock),
	    laddr, get_local_port(sock),
	    subreason != ರಿಕ್ತ ? subreason : reason);
	ಮುಕ್ತ(laddr);
	ಮುಕ್ತ(raddr);
	ಯದಿ (ndropped != 0) {
		logit("%s logging rate-limited: additional %u connections "
		    "dropped", reason, ndropped);
	}

	/* best-effort notification to client */
	(ಶೂನ್ಯ)ಲಿಖ(sock, ಸಂದೇಶ, ಪರಿಮಾಣ(ಸಂದೇಶ) - 1);
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

ಸ್ಥಿರ ಸಂರಚನಾ sshbuf *
pack_hostkeys(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *m = ರಿಕ್ತ, *keybuf = ರಿಕ್ತ, *hostkeys = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i;
	size_t len;

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ ||
	    (keybuf = sshbuf_new()) == ರಿಕ್ತ ||
	    (hostkeys = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		ಯದಿ (sensitive_data.host_ಕೀಲಿಗಳು[i] != ರಿಕ್ತ &&
		    (r = sshkey_private_serialize(sensitive_data.host_ಕೀಲಿಗಳು[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		ಯದಿ ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		ಯದಿ (sensitive_data.host_pubkeys[i] != ರಿಕ್ತ) {
			ಯದಿ ((r = sshkey_puts(sensitive_data.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} ಅನ್ಯಥಾ {
			ಯದಿ ((r = sshbuf_put_string(hostkeys, ರಿಕ್ತ, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		ಯದಿ (sensitive_data.host_certificates[i] != ರಿಕ್ತ) {
			ಯದಿ ((r = sshkey_puts(
			    sensitive_data.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} ಅನ್ಯಥಾ {
			ಯದಿ ((r = sshbuf_put_string(hostkeys, ರಿಕ್ತ, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	ಯದಿ ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0)
		fatal_fr(r, "compose message");
	ಯದಿ ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(keybuf);
	sshbuf_free(hostkeys);
	ಪ್ರತ್ಯಾಗಮ m;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshbuf *
pack_config(ಸಂರಚನಾ sshbuf *conf)
{
	ಸಂರಚನಾ sshbuf *m = ರಿಕ್ತ, *inc = ರಿಕ್ತ;
	ಸಂರಚನಾ include_item *item = ರಿಕ್ತ;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("d config len %zu", sshbuf_len(conf));

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ ||
	    (inc = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(item, &includes, entry) {
		ಯದಿ ((r = sshbuf_put_cstring(inc, item->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, item->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	ಯದಿ ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	ಯದಿ ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(inc);

	debug3_f("done");
	ಪ್ರತ್ಯಾಗಮ m;
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
ಸ್ಥಿರ ಶೂನ್ಯ
send_rexec_state(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಸಂರಚನಾ sshbuf *ಕೀಲಿಗಳು;
	u_int mlen;
	pid_t pid;

	ಯದಿ ((pid = fork()) == -1)
		fatal_f("fork failed: %s", strerror(errno));
	ಯದಿ (pid != 0)
		ಪ್ರತ್ಯಾಗಮ;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(config));

	mlen = sshbuf_len(config);
	ಯದಿ (atomicio(vwrite, fd, sshbuf_mutable_ptr(config), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	ಕೀಲಿಗಳು = pack_hostkeys();
	mlen = sshbuf_len(ಕೀಲಿಗಳು);
	ಯದಿ (atomicio(vwrite, fd, sshbuf_mutable_ptr(ಕೀಲಿಗಳು), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	sshbuf_free(ಕೀಲಿಗಳು);
	debug3_f("done");
	exit(0);
}

/*
 * Listen for TCP connections
 */
ಸ್ಥಿರ ಶೂನ್ಯ
listen_on_addrs(ಸಂರಚನಾ listenaddr *la)
{
	ಪೂರ್ಣಾಙ್ಕ ret, listen_sock;
	ಸಂರಚನಾ addrinfo *ai;
	ವರ್ಣ ntop[NI_MAXHOST], strport[NI_MAXSERV];

	ಪ್ರತಿ (ai = la->addrs; ai; ai = ai->ai_next) {
		ಯದಿ (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			ಅನುವರ್ತ;
		ಯದಿ (ಅಂಕೆ_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		ಯದಿ ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, ಪರಿಮಾಣ(ntop), strport, ಪರಿಮಾಣ(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			ಅನುವರ್ತ;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		ಯದಿ (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			ಅನುವರ್ತ;
		}
		ಯದಿ (set_nonblock(listen_sock) == -1) {
			close(listen_sock);
			ಅನುವರ್ತ;
		}
		ಯದಿ (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			ಅನುವರ್ತ;
		}
		/* Socket options */
		set_reuseaddr(listen_sock);
		ಯದಿ (la->rdomain != ರಿಕ್ತ &&
		    set_rdomain(listen_sock, la->rdomain) == -1) {
			close(listen_sock);
			ಅನುವರ್ತ;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		ಯದಿ (ai->ai_family == AF_INET6)
			sock_set_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		ಯದಿ (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, strerror(errno));
			close(listen_sock);
			ಅನುವರ್ತ;
		}
		listen_socks[ಅಂಕೆ_listen_socks] = listen_sock;
		ಅಂಕೆ_listen_socks++;

		/* Start listening on the port. */
		ಯದಿ (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, strerror(errno));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == ರಿಕ್ತ ? "" : " rdomain ",
		    la->rdomain == ರಿಕ್ತ ? "" : la->rdomain);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
server_listen(ಶೂನ್ಯ)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups,
	    options.per_source_max_startups,
	    options.per_source_masklen_ipv4,
	    options.per_source_masklen_ipv6,
	    &options.per_source_penalty,
	    options.per_source_penalty_exempt);

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		ಮುಕ್ತ(options.listen_addrs[i].rdomain);
		memset(&options.listen_addrs[i], 0,
		    ಪರಿಮಾಣ(options.listen_addrs[i]));
	}
	ಮುಕ್ತ(options.listen_addrs);
	options.listen_addrs = ರಿಕ್ತ;
	options.ಅಂಕೆ_listen_addrs = 0;

	ಯದಿ (!ಅಂಕೆ_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
server_accept_loop(ಪೂರ್ಣಾಙ್ಕ *sock_in, ಪೂರ್ಣಾಙ್ಕ *sock_out, ಪೂರ್ಣಾಙ್ಕ *newsock, ಪೂರ್ಣಾಙ್ಕ *config_s,
    ಪೂರ್ಣಾಙ್ಕ log_stderr)
{
	ಸಂರಚನಾ pollfd *pfd = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ i, ret, npfd, r;
	ಪೂರ್ಣಾಙ್ಕ oactive = -1, listening = 0, lameduck = 0;
	ಪೂರ್ಣಾಙ್ಕ *startup_pollfd;
	ssize_t len;
	ಧ್ರುವ u_char *ptr;
	ವರ್ಣ c = 0;
	ಸಂರಚನಾ sockaddr_storage from;
	ಸಂರಚನಾ early_child *child;
	ಸಂರಚನಾ sshbuf *buf;
	socklen_t fromlen;
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	child_alloc();
	startup_pollfd = xcalloc(options.max_startups, ಪರಿಮಾಣ(ಪೂರ್ಣಾಙ್ಕ));

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
	pfd = xcalloc(ಅಂಕೆ_listen_socks + options.max_startups,
	    ಪರಿಮಾಣ(ಸಂರಚನಾ pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	ಪ್ರತಿ (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		ಯದಿ (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (ಪೂರ್ಣಾಙ್ಕ) received_sigterm);
			close_listen_socks();
			ಯದಿ (options.pid_file != ರಿಕ್ತ)
				unlink(options.pid_file);
			exit(received_sigterm == SIGTERM ? 0 : 255);
		}
		ಯದಿ (received_sigchld) {
			child_reap_all_exited();
			received_sigchld = 0;
		}
		ಯದಿ (received_siginfo) {
			show_info();
			received_siginfo = 0;
		}
		ಯದಿ (oactive != children_active) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, children_active,
			    options.max_startups_begin, options.max_startups);
			oactive = children_active;
		}
		ಯದಿ (received_sighup) {
			ಯದಿ (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			ಯದಿ (listening <= 0) {
				/*
				 * Leave termination signals blocked, so
				 * they don't get lost across a restart.
				 */
				sigaddset(&osigset, SIGTERM);
				sigaddset(&osigset, SIGQUIT);
				sigprocmask(SIG_SETMASK, &osigset, ರಿಕ್ತ);
				sighup_restart();
			}
		}

		ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = ಅಂಕೆ_listen_socks;
		ಪ್ರತಿ (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			ಯದಿ (children[i].pipefd != -1) {
				pfd[npfd].fd = children[i].pipefd;
				pfd[npfd].events = POLLIN;
				ಯದಿ (children[i].config != ರಿಕ್ತ ||
				    children[i].ಕೀಲಿಗಳು != ರಿಕ್ತ)
					pfd[npfd].events |= POLLOUT;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, ರಿಕ್ತ, &osigset);
		ಯದಿ (ret == -1 && errno != EINTR) {
			error("ppoll: %.100s", strerror(errno));
			ಯದಿ (errno == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, ರಿಕ್ತ);
		ಯದಿ (ret == -1)
			ಅನುವರ್ತ;

		ಪ್ರತಿ (i = 0; i < options.max_startups; i++) {
			ಯದಿ (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & POLLOUT))
				ಅನುವರ್ತ;
			ಯದಿ (children[i].config)
				buf = children[i].config;
			ಅನ್ಯಥಾ ಯದಿ (children[i].ಕೀಲಿಗಳು)
				buf = children[i].ಕೀಲಿಗಳು;
			ಅನ್ಯಥಾ {
				error_f("no buffer to send");
				ಅನುವರ್ತ;
			}
			ptr = sshbuf_ptr(buf);
			len = sshbuf_len(buf);
			ret = ಲಿಖ(children[i].pipefd, ptr, len);
			ಯದಿ (ret == -1 && (errno == EINTR || errno == EAGAIN))
				ಅನುವರ್ತ;
			ಯದಿ (ret <= 0) {
				ಯದಿ (children[i].early)
					listening--;
				child_close(&(children[i]), 0, 0);
				ಅನುವರ್ತ;
			}
			ಯದಿ (ret == len) {
				/* finished sending buffer */
				sshbuf_free(buf);
				ಯದಿ (children[i].config == buf) {
					/* sent config, now send keys */
					children[i].config = ರಿಕ್ತ;
					children[i].ಕೀಲಿಗಳು = pack_hostkeys();
				} ಅನ್ಯಥಾ ಯದಿ (children[i].ಕೀಲಿಗಳು == buf) {
					/* sent both config and keys */
					children[i].ಕೀಲಿಗಳು = ರಿಕ್ತ;
				} ಅನ್ಯಥಾ {
					fatal("config buf not set");
				}

			} ಅನ್ಯಥಾ {
				ಯದಿ ((r = sshbuf_consume(buf, ret)) != 0)
					fatal_fr(r, "config buf inconsistent");
			}
		}
		ಪ್ರತಿ (i = 0; i < options.max_startups; i++) {
			ಯದಿ (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				ಅನುವರ್ತ;
			ವಿಕಲ್ಪ (ಪಠ(children[i].pipefd, &c, ಪರಿಮಾಣ(c))) {
			ಪಕ್ಷ -1:
				ಯದಿ (errno == EINTR || errno == EAGAIN)
					ಅನುವರ್ತ;
				ಯದಿ (errno != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, children[i].pipefd,
					    strerror(errno));
				}
				/* FALLTHROUGH */
			ಪಕ್ಷ 0:
				/* child closed pipe */
				ಯದಿ (children[i].early)
					listening--;
				debug3_f("child %lu for %s closed pipe",
				    (long)children[i].pid, children[i].id);
				child_close(&(children[i]), 0, 0);
				ಭಙ್ಗ;
			ಪಕ್ಷ 1:
				ಯದಿ (children[i].config) {
					error_f("startup pipe %d (fd=%d)"
					    " early read",
					    i, children[i].pipefd);
					ಗಚ್ಛ problem_child;
				}
				ಯದಿ (children[i].early && c == '\0') {
					/* child has finished preliminaries */
					listening--;
					children[i].early = 0;
					debug2_f("child %lu for %s received "
					    "config", (long)children[i].pid,
					    children[i].id);
				} ಅನ್ಯಥಾ ಯದಿ (!children[i].early && c == '\001') {
					/* child has completed auth */
					debug2_f("child %lu for %s auth done",
					    (long)children[i].pid,
					    children[i].id);
					child_close(&(children[i]), 1, 0);
				} ಅನ್ಯಥಾ {
					error_f("unexpected message 0x%02x "
					    "child %ld for %s in state %d",
					    (ಪೂರ್ಣಾಙ್ಕ)c, (long)children[i].pid,
					    children[i].id, children[i].early);
 problem_child:
					ಯದಿ (children[i].early)
						listening--;
					ಯದಿ (children[i].pid > 0)
						kill(children[i].pid, SIGTERM);
					child_close(&(children[i]), 0, 0);
				}
				ಭಙ್ಗ;
			}
		}
		ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_listen_socks; i++) {
			ಯದಿ (!(pfd[i].revents & POLLIN))
				ಅನುವರ್ತ;
			fromlen = ಪರಿಮಾಣ(from);
			*newsock = accept(listen_socks[i],
			    (ಸಂರಚನಾ sockaddr *)&from, &fromlen);
			ಯದಿ (*newsock == -1) {
				ಯದಿ (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED && errno != EAGAIN)
					error("accept: %.100s",
					    strerror(errno));
				ಯದಿ (errno == EMFILE || errno == ENFILE)
					usleep(100 * 1000);
				ಅನುವರ್ತ;
			}
			ಯದಿ (unset_nonblock(*newsock) == -1) {
				close(*newsock);
				ಅನುವರ್ತ;
			}
			ಯದಿ (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    strerror(errno));
				close(*newsock);
				ಅನುವರ್ತ;
			}
			ಯದಿ (drop_connection(*newsock,
			    children_active, config_s[0])) {
				close(*newsock);
				close(config_s[0]);
				close(config_s[1]);
				ಅನುವರ್ತ;
			}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			ಯದಿ (debug_flag) {
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
				ಮುಕ್ತ(pfd);
				ಮುಕ್ತ(startup_pollfd);
				ಪ್ರತ್ಯಾಗಮ;
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
			ಯದಿ ((child->pid = fork()) == 0) {
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
				ಮುಕ್ತ(pfd);
				ಮುಕ್ತ(startup_pollfd);
				ಪ್ರತ್ಯಾಗಮ;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_parent(child->pid);
			ಯದಿ (child->pid == -1)
				error("fork: %.100s", strerror(errno));
			ಅನ್ಯಥಾ
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

ಸ್ಥಿರ ಶೂನ್ಯ
accumulate_host_timing_secret(ಸಂರಚನಾ sshbuf *server_cfg,
    ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಸ್ಥಿರ ಸಂರಚನಾ ssh_digest_ctx *ctx;
	u_char *hash;
	size_t len;
	ಸಂರಚನಾ sshbuf *buf;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (ctx == ರಿಕ್ತ && (ctx = ssh_digest_start(SSH_DIGEST_SHA512)) == ರಿಕ್ತ)
		fatal_f("ssh_digest_start");
	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ) { /* finalize */
		/* add server config in case we are using agent for host keys */
		ಯದಿ (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_bytes(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		ಯದಿ (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = ರಿಕ್ತ;
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("could not allocate buffer");
	ಯದಿ ((r = sshkey_private_serialize(ಕೀಲಿ, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(ಕೀಲಿ));
	ಯದಿ (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

ಸ್ಥಿರ ವರ್ಣ *
prepare_proctitle(ಪೂರ್ಣಾಙ್ಕ ac, ವರ್ಣ **av)
{
	ವರ್ಣ *ret = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ i;

	ಪ್ರತಿ (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/* Disconnect from the controlling tty. */
ಸ್ಥಿರ ಶೂನ್ಯ
disconnect_controlling_tty(ಶೂನ್ಯ)
{
#ifdef TIOCNOTTY
# ifndef O_NOCTTY
#  define O_NOCTTY 0
# endif
	ಪೂರ್ಣಾಙ್ಕ fd;

	ಯದಿ ((fd = open(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(ಶೂನ್ಯ) ioctl(fd, TIOCNOTTY, ರಿಕ್ತ);
		close(fd);
	}
#endif /* TIOCNOTTY */
}

ಸ್ಥಿರ ಶೂನ್ಯ
print_config(ಸಂರಚನಾ connection_info *connection_info)
{
	connection_info->test = 1;
	parse_server_match_config(&options, &includes, connection_info);
	dump_config(&options);
	exit(0);
}

/*
 * Main program for the daemon.
 */
ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ ac, ವರ್ಣ **av)
{
	ಬಾಹ್ಯ ವರ್ಣ *optarg;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ optind;
	ಪೂರ್ಣಾಙ್ಕ log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	ವರ್ಣ *config_file_name = _PATH_SERVER_CONFIG_FILE;
	ಪೂರ್ಣಾಙ್ಕ r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	ಪೂರ್ಣಾಙ್ಕ sock_in = -1, sock_out = -1, newsock = -1, rexec_argc = 0;
	ಪೂರ್ಣಾಙ್ಕ devnull, config_s[2] = { -1 , -1 }, have_connection_info = 0;
	ಪೂರ್ಣಾಙ್ಕ need_chroot = 1;
	ವರ್ಣ *args, *fp, *ಸಾಲು, *logfile = ರಿಕ್ತ, **rexec_argv = ರಿಕ್ತ;
	ಸಂರಚನಾ stat sb;
	u_int i, j;
	mode_t new_umask;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ;
	ಸಂರಚನಾ sshkey *pubkey;
	ಸಂರಚನಾ connection_info connection_info;
	ಸಂರಚನಾ utsname utsname;
	sigset_t sigmask;

	memset(&connection_info, 0, ಪರಿಮಾಣ(connection_info));
#ifdef HAVE_SECUREWARE
	(ಶೂನ್ಯ)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ರಿಕ್ತ);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, ಪರಿಮಾಣ(*saved_argv));
	ಪ್ರತಿ (i = 0; (ಪೂರ್ಣಾಙ್ಕ)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ರಿಕ್ತ;

#ifndef HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#endif

	ಯದಿ (geteuid() == 0 && setgroups(0, ರಿಕ್ತ) == -1)
		debug("setgroups(): %.200s", strerror(errno));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	ಯಾವತ್ ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		ವಿಕಲ್ಪ (opt) {
		ಪಕ್ಷ '4':
			options.address_family = AF_INET;
			ಭಙ್ಗ;
		ಪಕ್ಷ '6':
			options.address_family = AF_INET6;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'f':
			config_file_name = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'c':
			servconf_add_hostcert("[command-line]", 0,
			    &options, optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'd':
			ಯದಿ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ಅನ್ಯಥಾ ಯದಿ (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'D':
			no_daemon_flag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'G':
			do_dump_cfg = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		ಪಕ್ಷ 'e':
			log_stderr = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'i':
			inetd_flag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'r':
			logit("-r option is deprecated");
			ಭಙ್ಗ;
		ಪಕ್ಷ 'R':
			fatal("-R not supported here");
			ಭಙ್ಗ;
		ಪಕ್ಷ 'Q':
			/* ignored */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'b':
			/* protocol 1, ignored */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'p':
			options.ports_from_cmdline = 1;
			ಯದಿ (options.ಅಂಕೆ_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				exit(1);
			}
			options.ports[options.ಅಂಕೆ_ports++] = a2port(optarg);
			ಯದಿ (options.ports[options.ಅಂಕೆ_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				exit(1);
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ 'g':
			ಯದಿ ((options.login_grace_time = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				exit(1);
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ 'k':
			/* protocol 1, ignored */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'h':
			servconf_add_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			ಭಙ್ಗ;
		ಪಕ್ಷ 't':
			test_flag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'T':
			test_flag = 2;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'C':
			ಯದಿ (parse_server_match_testspec(&connection_info,
			    optarg) == -1)
				exit(1);
			have_connection_info = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'u':
			utmp_len = (u_int)strtonum(optarg, 0,
			    HOST_NAME_MAX+1+1, ರಿಕ್ತ);
			ಯದಿ (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ 'o':
			ಸಾಲು = xstrdup(optarg);
			ಯದಿ (process_server_config_ಸಾಲು(&options, ಸಾಲು,
			    "command-line", 0, ರಿಕ್ತ, ರಿಕ್ತ, &includes) != 0)
				exit(1);
			ಮುಕ್ತ(ಸಾಲು);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
		ಸ್ವಭಾವ:
			usage();
			ಭಙ್ಗ;
		}
	}

	ಯದಿ (getexecpath(execpath, ಪರಿಮಾಣ execpath) != 0) {
		ಯದಿ (strlcpy(execpath, av[0], ಪರಿಮಾಣ execpath) >=
		    ಪರಿಮಾಣ execpath) {
			fprintf(stderr, "execution path is too long\n");
			exit(1);
		}
	}
	ಯದಿ (!test_flag && !inetd_flag && !do_dump_cfg && !path_absolute(execpath))
		fatal("sshd requires execution with an absolute path");

	closefrom(STDERR_FILENO + 1);

	/* Reserve fds we'll need later for reexec things */
	ಯದಿ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	ಯಾವತ್ (devnull < REEXEC_MIN_FREE_FD) {
		ಯದಿ ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	seed_rng();

	/* If requested, redirect the logs to the specified logfile. */
	ಯದಿ (logfile != ರಿಕ್ತ) {
		ವರ್ಣ *cp, pid_s[32];

		snprintf(pid_s, ಪರಿಮಾಣ(pid_s), "%ld", (unsigned long)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (ವರ್ಣ *)ರಿಕ್ತ);
		log_redirect_stderr_to(cp);
		ಮುಕ್ತ(cp);
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
	ಯದಿ (getenv("KRB5CCNAME") != ರಿಕ್ತ)
		(ಶೂನ್ಯ) unsetenv("KRB5CCNAME");

	sensitive_data.have_ssh2_ಕೀಲಿ = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	ಯದಿ (test_flag < 2 && have_connection_info)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	debug("sshd version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);
	ಯದಿ (uname(&utsname) != 0) {
		memset(&utsname, 0, ಪರಿಮಾಣ(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", ಪರಿಮಾಣ(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	ಮುಕ್ತ(args);

	/* Fetch our configuration */
	ಯದಿ ((cfg = sshbuf_new()) == ರಿಕ್ತ)
		fatal("sshbuf_new config failed");
	ಯದಿ (strcasecmp(config_file_name, "none") != 0)
		load_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, ರಿಕ್ತ, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	ಯದಿ (options.authorized_ಕೀಲಿಗಳು_command_user == ರಿಕ್ತ &&
	    (options.authorized_ಕೀಲಿಗಳು_command != ರಿಕ್ತ &&
	    strcasecmp(options.authorized_ಕೀಲಿಗಳು_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	ಯದಿ (options.authorized_principals_command_user == ರಿಕ್ತ &&
	    (options.authorized_principals_command != ರಿಕ್ತ &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match blocks, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	ಯದಿ (options.ಅಂಕೆ_auth_methods != 0) {
		ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_auth_methods; i++) {
			ಯದಿ (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				ಭಙ್ಗ;
		}
		ಯದಿ (i >= options.ಅಂಕೆ_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	ಯದಿ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	ಯದಿ (do_dump_cfg)
		print_config(&connection_info);

	/* load host keys */
	sensitive_data.host_ಕೀಲಿಗಳು = xcalloc(options.ಅಂಕೆ_host_ಕೀಲಿ_files,
	    ಪರಿಮಾಣ(ಸಂರಚನಾ sshkey *));
	sensitive_data.host_pubkeys = xcalloc(options.ಅಂಕೆ_host_ಕೀಲಿ_files,
	    ಪರಿಮಾಣ(ಸಂರಚನಾ sshkey *));

	ಯದಿ (options.host_ಕೀಲಿ_agent) {
		ಯದಿ (strcmp(options.host_ಕೀಲಿ_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_ಕೀಲಿ_agent, 1);
		ಯದಿ ((r = ssh_get_authentication_socket(ರಿಕ್ತ)) == 0)
			have_agent = 1;
		ಅನ್ಯಥಾ
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_ಕೀಲಿ_agent);
	}

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಪೂರ್ಣಾಙ್ಕ ll = options.host_ಕೀಲಿ_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		ಯದಿ (options.host_ಕೀಲಿ_files[i] == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ಯದಿ ((r = sshkey_load_private(options.host_ಕೀಲಿ_files[i], "",
		    &ಕೀಲಿ, ರಿಕ್ತ)) != 0 &&
		    r != SSH_ERR_SYSTEM_ERROR && !have_agent)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_ಕೀಲಿ_files[i]);
		ಯದಿ (sshkey_is_sk(ಕೀಲಿ) &&
		    ಕೀಲಿ->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_ಕೀಲಿ_files[i]);
			ಕೀಲಿ->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		ಯದಿ (r == 0 && ಕೀಲಿ != ರಿಕ್ತ &&
		    (r = sshkey_shield_private(ಕೀಲಿ)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_ಕೀಲಿ_files[i]);
			sshkey_free(ಕೀಲಿ);
			ಕೀಲಿ = ರಿಕ್ತ;
		}
		ಯದಿ ((r = sshkey_load_public(options.host_ಕೀಲಿ_files[i],
		    &pubkey, ರಿಕ್ತ)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_ಕೀಲಿ_files[i]);
		ಯದಿ (pubkey != ರಿಕ್ತ && ಕೀಲಿ != ರಿಕ್ತ) {
			ಯದಿ (!sshkey_equal(pubkey, ಕೀಲಿ)) {
				error("Public key for %s does not match "
				    "private key", options.host_ಕೀಲಿ_files[i]);
				sshkey_free(pubkey);
				pubkey = ರಿಕ್ತ;
			}
		}
		ಯದಿ (pubkey == ರಿಕ್ತ && ಕೀಲಿ != ರಿಕ್ತ) {
			ಯದಿ ((r = sshkey_from_private(ಕೀಲಿ, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_ಕೀಲಿ_files[i]);
		}
		ಯದಿ (pubkey != ರಿಕ್ತ && (r = sshkey_check_rsa_length(pubkey,
		    options.required_rsa_size)) != 0) {
			error_fr(r, "Host key %s", options.host_ಕೀಲಿ_files[i]);
			sshkey_free(pubkey);
			sshkey_free(ಕೀಲಿ);
			ಅನುವರ್ತ;
		}
		sensitive_data.host_ಕೀಲಿಗಳು[i] = ಕೀಲಿ;
		sensitive_data.host_pubkeys[i] = pubkey;

		ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ && pubkey != ರಿಕ್ತ && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_ಕೀಲಿ_files[i]);
			keytype = pubkey->type;
		} ಅನ್ಯಥಾ ಯದಿ (ಕೀಲಿ != ರಿಕ್ತ) {
			keytype = ಕೀಲಿ->type;
			accumulate_host_timing_secret(cfg, ಕೀಲಿ);
		} ಅನ್ಯಥಾ {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_ಕೀಲಿ_files[i]);
			sensitive_data.host_ಕೀಲಿಗಳು[i] = ರಿಕ್ತ;
			sensitive_data.host_pubkeys[i] = ರಿಕ್ತ;
			ಅನುವರ್ತ;
		}

		ವಿಕಲ್ಪ (keytype) {
		ಪಕ್ಷ ಕೀಲಿ_RSA:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA:
		ಪಕ್ಷ ಕೀಲಿ_ED25519:
		ಪಕ್ಷ ಕೀಲಿ_MLDSA44_ED25519:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
		ಪಕ್ಷ ಕೀಲಿ_ED25519_SK:
			ಯದಿ (have_agent || ಕೀಲಿ != ರಿಕ್ತ)
				sensitive_data.have_ssh2_ಕೀಲಿ = 1;
			ಭಙ್ಗ;
		}
		ಯದಿ ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    ಕೀಲಿ ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		ಮುಕ್ತ(fp);
	}
	accumulate_host_timing_secret(cfg, ರಿಕ್ತ);
	ಯದಿ (!sensitive_data.have_ssh2_ಕೀಲಿ) {
		logit("sshd: no hostkeys available -- exiting.");
		exit(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_data.host_certificates = xcalloc(options.ಅಂಕೆ_host_ಕೀಲಿ_files,
	    ಪರಿಮಾಣ(ಸಂರಚನಾ sshkey *));
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++)
		sensitive_data.host_certificates[i] = ರಿಕ್ತ;

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_host_cert_files; i++) {
		ಯದಿ (options.host_cert_files[i] == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ಯದಿ ((r = sshkey_load_public(options.host_cert_files[i],
		    &ಕೀಲಿ, ರಿಕ್ತ)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			ಅನುವರ್ತ;
		}
		ಯದಿ (!sshkey_is_cert(ಕೀಲಿ)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(ಕೀಲಿ);
			ಅನುವರ್ತ;
		}
		/* Find matching private key */
		ಪ್ರತಿ (j = 0; j < options.ಅಂಕೆ_host_ಕೀಲಿ_files; j++) {
			ಯದಿ (sshkey_equal_public(ಕೀಲಿ,
			    sensitive_data.host_pubkeys[j])) {
				sensitive_data.host_certificates[j] = ಕೀಲಿ;
				ಭಙ್ಗ;
			}
		}
		ಯದಿ (j >= options.ಅಂಕೆ_host_ಕೀಲಿ_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(ಕೀಲಿ);
			ಅನುವರ್ತ;
		}
		sensitive_data.host_certificates[j] = ಕೀಲಿ;
		debug("host certificate: #%u type %d %s", j, ಕೀಲಿ->type,
		    sshkey_type(ಕೀಲಿ));
	}

	/* Ensure privsep directory is correctly configured. */
	need_chroot = ((getuid() == 0 || geteuid() == 0) ||
	    options.kerberos_authentication);
	ಯದಿ ((getpwnam(SSH_PRIVSEP_USER)) == ರಿಕ್ತ && need_chroot) {
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	}
	endpwent();

	ಯದಿ (need_chroot) {
		ಯದಿ ((stat(_PATH_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
		    (S_ISDIR(sb.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    _PATH_PRIVSEP_CHROOT_DIR);
#ifdef HAVE_CYGWIN
		ಯದಿ (check_ntsec(_PATH_PRIVSEP_CHROOT_DIR) &&
		    (sb.st_uid != getuid () ||
		    (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#ಅನ್ಯಥಾ
		ಯದಿ (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#endif
			fatal("%s must be owned by root and not group or "
			    "world-writable.", _PATH_PRIVSEP_CHROOT_DIR);
	}

	ಯದಿ (test_flag > 1)
		print_config(&connection_info);

	config = pack_config(cfg);
	ಯದಿ (sshbuf_len(config) > MONITOR_MAX_CFGLEN) {
		fatal("Configuration file is too large (have %zu, max %d)",
		    sshbuf_len(config), MONITOR_MAX_CFGLEN);
	}

	/* Configuration looks good, so exit if in test mode. */
	ಯದಿ (test_flag)
		exit(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	ಯದಿ (setgroups(0, ರಿಕ್ತ) < 0)
		debug("setgroups() failed: %.200s", strerror(errno));

	/* Prepare arguments for sshd-session */
	ಯದಿ (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, ಪರಿಮಾಣ(ವರ್ಣ *));
	/* Point to the sshd-session binary instead of sshd */
	rexec_argv[0] = options.sshd_session_path;
	ಪ್ರತಿ (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = ರಿಕ್ತ;
	ಯದಿ (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	ಯದಿ (stat(options.sshd_auth_path, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_auth_path);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(ಶೂನ್ಯ) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	ಯದಿ (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	ಯದಿ (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		ಯದಿ (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", strerror(errno));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	ಯದಿ (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or a listening TCP socket */
	ಯದಿ (inetd_flag) {
		/* Send configuration to ancestor sshd-session process */
		ಯದಿ (socketpair(AF_UNIX, SOCK_STREAM, 0, config_s) == -1)
			fatal("socketpair: %s", strerror(errno));
		send_rexec_state(config_s[0]);
		close(config_s[0]);
	} ಅನ್ಯಥಾ {
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
		ಯದಿ (options.pid_file != ರಿಕ್ತ && !debug_flag) {
			FILE *f = fopen(options.pid_file, "w");

			ಯದಿ (f == ರಿಕ್ತ) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, strerror(errno));
			} ಅನ್ಯಥಾ {
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
	ಯದಿ (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	debug("rexec start in %d out %d newsock %d config_s %d/%d",
	    sock_in, sock_out, newsock, config_s[0], config_s[1]);
	ಯದಿ (!inetd_flag) {
		ಯದಿ (dup2(newsock, STDIN_FILENO) == -1)
			fatal("dup2 stdin: %s", strerror(errno));
		ಯದಿ (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			fatal("dup2 stdout: %s", strerror(errno));
		ಯದಿ (newsock > STDOUT_FILENO)
			close(newsock);
	}
	ಯದಿ (config_s[1] != REEXEC_CONFIG_PASS_FD) {
		ಯದಿ (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			fatal("dup2 config_s: %s", strerror(errno));
		close(config_s[1]);
	}
	log_redirect_stderr_to(ರಿಕ್ತ);
	closefrom(REEXEC_MIN_FREE_FD);

	ssh_signal(SIGHUP, SIG_IGN); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], strerror(errno));
}

/* server specific fatal cleanup */
ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಙ್ಕ i)
{
	_exit(i);
}
