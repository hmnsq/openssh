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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SECUREWARE
#ಅನ್ತರ್ಭಾವ <sys/security.h>
#ಅನ್ತರ್ಭಾವ <prot.h>
#ಆದರೆ_ಅಂತ್ಯ

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
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"

/* Re-exec fds */
#ವ್ಯಾಖ್ಯಾನಿಸು REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#ವ್ಯಾಖ್ಯಾನಿಸು REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#ವ್ಯಾಖ್ಯಾನಿಸು REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

/* Server configuration options. */
ServerOptions options;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
ಪೂರ್ಣಾಂಕ debug_flag = 0;

/* Saved arguments to main(). */
ಸ್ಥಿರ ಅಕ್ಷರ execpath[PATH_MAX];
ಸ್ಥಿರ ಅಕ್ಷರ **saved_argv;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	MAX_LISTEN_SOCKS	16
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ listen_socks[MAX_LISTEN_SOCKS];
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಅಂಕೆ_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
ರಚನೆ {
	ರಚನೆ sshkey	**host_ಕೀಲಿಗಳು;		/* all private host keys */
	ರಚನೆ sshkey	**host_pubkeys;		/* all public host keys */
	ರಚನೆ sshkey	**host_certificates;	/* all public host certificates */
	ಪೂರ್ಣಾಂಕ		have_ssh2_ಕೀಲಿ;
} sensitive_ದತ್ತಾಂಶ;

/* This is set to true when a signal is received. */
ಸ್ಥಿರ ಅಸ್ಥಿರ sig_atomic_t received_siginfo = 0;
ಸ್ಥಿರ ಅಸ್ಥಿರ sig_atomic_t received_sigchld = 0;
ಸ್ಥಿರ ಅಸ್ಥಿರ sig_atomic_t received_sighup = 0;
ಸ್ಥಿರ ಅಸ್ಥಿರ sig_atomic_t received_sigterm = 0;

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
ರಚನೆ early_ಮಗು {
	ಪೂರ್ಣಾಂಕ pipefd;
	ಪೂರ್ಣಾಂಕ early;		/* Indicates child closed listener */
	ಅಕ್ಷರ *id;		/* human readable connection identifier */
	pid_t pid;
	ರಚನೆ xaddr addr;
	ಪೂರ್ಣಾಂಕ have_addr;
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2, have_ಸ್ಥಿತಿ;
	ರಚನೆ sshbuf *config;
	ರಚನೆ sshbuf *ಕೀಲಿಗಳು;
};
ಸ್ಥಿರ ರಚನೆ early_ಮಗು *children;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ children_ಸಕ್ರಿಯ;

/* sshd_config buffer */
ರಚನೆ sshbuf *cfg;
ರಚನೆ sshbuf *config;	/* packed */

/* Included files from the configuration file */
ರಚನೆ include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ರಚನೆ sshbuf *loginmsg;

/* Unprivileged user */
ರಚನೆ passwd *privsep_pw = ಖಾಲಿ;

ಸ್ಥಿರ ಅಕ್ಷರ *listener_proctitle;

/*
 * Close all listening sockets
 */
ಸ್ಥಿರ ಶೂನ್ಯ
close_listen_socks(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ i;

	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_listen_socks; i++)
		close(listen_socks[i]);
	ಅಂಕೆ_listen_socks = 0;
}

/* Allocate and initialise the children array */
ಸ್ಥಿರ ಶೂನ್ಯ
ಮಗು_alloc(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ i;

	children = xcalloc(options.max_startups, ಗಾತ್ರ(*children));
	ಗಾಗಿ (i = 0; i < options.max_startups; i++) {
		children[i].pipefd = -1;
		children[i].pid = -1;
	}
}

/* Register a new connection in the children array; child pid comes later */
ಸ್ಥಿರ ರಚನೆ early_ಮಗು *
ಮಗು_ರಿಜಿಸ್ಟರ್(ಪೂರ್ಣಾಂಕ pipefd, ಪೂರ್ಣಾಂಕ sockfd)
{
	ಪೂರ್ಣಾಂಕ i, lport, rport;
	ಅಕ್ಷರ *laddr = ಖಾಲಿ, *raddr = ಖಾಲಿ;
	ರಚನೆ early_ಮಗು *ಮಗು = ಖಾಲಿ;
	ರಚನೆ sockaddr_storage addr;
	socklen_t addrlen = ಗಾತ್ರ(addr);
	ರಚನೆ sockaddr *sa = (ರಚನೆ sockaddr *)&addr;

	ಗಾಗಿ (i = 0; i < options.max_startups; i++) {
		ಆದರೆ (children[i].pipefd != -1 ||
		    children[i].config != ಖಾಲಿ ||
		    children[i].ಕೀಲಿಗಳು != ಖಾಲಿ ||
		    children[i].pid > 0)
			ಮುಂದುವರಿ;
		ಮಗು = &(children[i]);
		ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (ಮಗು == ಖಾಲಿ) {
		fatal_f("error: accepted connection when all %d child "
		    " slots full", options.max_startups);
	}
	ಮಗು->pipefd = pipefd;
	ಮಗು->early = 1;
	ಆದರೆ ((ಮಗು->config = sshbuf_fromb(config)) == ಖಾಲಿ)
		fatal_f("sshbuf_fromb failed");
	/* record peer address, if available */
	ಆದರೆ (getpeername(sockfd, sa, &addrlen) == 0 &&
	   addr_sa_ಗಮ್ಯ_xaddr(sa, addrlen, &ಮಗು->addr) == 0)
		ಮಗು->have_addr = 1;
	/* format peer address string for logs */
	ಆದರೆ ((lport = get_local_ಪೋರ್ಟ್(sockfd)) == 0 ||
	    (rport = get_peer_ಪೋರ್ಟ್(sockfd)) == 0) {
		/* Not a TCP socket */
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&ಮಗು->id, "connection from %s", raddr);
	} ಇಲ್ಲದಿದ್ದರೆ {
		laddr = get_local_ipaddr(sockfd);
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&ಮಗು->id, "connection from %s to %s", raddr, laddr);
	}
	ಬಿಡುಗಡೆ(laddr);
	ಬಿಡುಗಡೆ(raddr);
	ಆದರೆ (++children_ಸಕ್ರಿಯ > options.max_startups)
		fatal_f("internal error: more children than max_startups");

	ಹಿಂತಿರುಗಿ ಮಗು;
}

/*
 * Finally free a child entry. Don't call this directly.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
ಮಗು_ಮುಕ್ತಾಯ(ರಚನೆ early_ಮಗು *ಮಗು)
{
	ಆದರೆ (children_ಸಕ್ರಿಯ == 0)
		fatal_f("internal error: children_active underflow");
	ಆದರೆ (ಮಗು->pipefd != -1) {
		srclimit_ಮುಗಿದ(ಮಗು->pipefd);
		close(ಮಗು->pipefd);
	}
	sshbuf_free(ಮಗು->config);
	sshbuf_free(ಮಗು->ಕೀಲಿಗಳು);
	ಬಿಡುಗಡೆ(ಮಗು->id);
	memset(ಮಗು, '\0', ಗಾತ್ರ(*ಮಗು));
	ಮಗು->pipefd = -1;
	ಮಗು->pid = -1;
	children_ಸಕ್ರಿಯ--;
}

/*
 * Close a child's pipe. This will not stop tracking the child immediately
 * (it will still be tracked for waitpid()) unless force_final is set, or
 * child has already exited.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
ಮಗು_close(ರಚನೆ early_ಮಗು *ಮಗು, ಪೂರ್ಣಾಂಕ force_final, ಪೂರ್ಣಾಂಕ quiet)
{
	ಆದರೆ (!quiet)
		debug_f("enter%s", force_final ? " (forcing)" : "");
	ಆದರೆ (ಮಗು->pipefd != -1) {
		srclimit_ಮುಗಿದ(ಮಗು->pipefd);
		close(ಮಗು->pipefd);
		ಮಗು->pipefd = -1;
	}
	ಆದರೆ (ಮಗು->pid == -1 || force_final)
		ಮಗು_ಮುಕ್ತಾಯ(ಮಗು);
}

/* Record a child exit. Safe to call from signal handlers */
ಸ್ಥಿರ ಶೂನ್ಯ
ಮಗು_exit(pid_t pid, ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (children == ಖಾಲಿ || pid <= 0)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; i < options.max_startups; i++) {
		ಆದರೆ (children[i].pid == pid) {
			children[i].have_ಸ್ಥಿತಿ = 1;
			children[i].ಸ್ಥಿತಿ_2 = ಸ್ಥಿತಿ_2;
			ನಿಲ್ಲಿಸು;
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
ಮಗು_reap(ರಚನೆ early_ಮಗು *ಮಗು)
{
	LogLevel level = SYSLOG_LEVEL_DEBUG1;
	ಪೂರ್ಣಾಂಕ was_crash, penalty_type = SRCLIMIT_PENALTY_NONE;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಗು_ಸ್ಥಿತಿ;

	ಆದರೆ (ಮಗು->config)
		ಮಗು_ಸ್ಥಿತಿ = " (sending config)";
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಮಗು->ಕೀಲಿಗಳು)
		ಮಗು_ಸ್ಥಿತಿ = " (sending keys)";
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಮಗು->early)
		ಮಗು_ಸ್ಥಿತಿ = " (early)";
	ಇಲ್ಲದಿದ್ದರೆ
		ಮಗು_ಸ್ಥಿತಿ = "";

	/* Log exit information */
	ಆದರೆ (WIFSIGNALED(ಮಗು->ಸ್ಥಿತಿ_2)) {
		/*
		 * Increase logging for signals potentially associated
		 * with serious conditions.
		 */
		ಆದರೆ ((was_crash = signal_is_crash(WTERMSIG(ಮಗು->ಸ್ಥಿತಿ_2))))
			level = SYSLOG_LEVEL_ERROR;
		do_log2(level, "session process %ld for %s killed by "
		    "signal %d%s", (ದೀರ್ಘ)ಮಗು->pid, ಮಗು->id,
		    WTERMSIG(ಮಗು->ಸ್ಥಿತಿ_2), ಮಗು_ಸ್ಥಿತಿ);
		ಆದರೆ (was_crash)
			penalty_type = SRCLIMIT_PENALTY_CRASH;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!WIFEXITED(ಮಗು->ಸ್ಥಿತಿ_2)) {
		penalty_type = SRCLIMIT_PENALTY_CRASH;
		error("session process %ld for %s terminated abnormally, "
		    "status=0x%x%s", (ದೀರ್ಘ)ಮಗು->pid, ಮಗು->id, ಮಗು->ಸ್ಥಿತಿ_2,
		    ಮಗು_ಸ್ಥಿತಿ);
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Normal exit. We care about the status */
		ಆಯ್ಕೆ (WEXITSTATUS(ಮಗು->ಸ್ಥಿತಿ_2)) {
		ಸ್ಥಿತಿ 0:
			debug3_f("preauth child %ld for %s completed "
			    "normally%s", (ದೀರ್ಘ)ಮಗು->pid, ಮಗು->id,
			    ಮಗು_ಸ್ಥಿತಿ);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ EXIT_LOGIN_GRACE:
			penalty_type = SRCLIMIT_PENALTY_GRACE_EXCEEDED;
			logit("Timeout before authentication for %s, "
			    "pid = %ld%s", ಮಗು->id, (ದೀರ್ಘ)ಮಗು->pid,
			    ಮಗು_ಸ್ಥಿತಿ);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ EXIT_ಮಗು_CRASH:
			penalty_type = SRCLIMIT_PENALTY_CRASH;
			logit("Session process %ld unpriv child crash for %s%s",
			    (ದೀರ್ಘ)ಮಗು->pid, ಮಗು->id, ಮಗು_ಸ್ಥಿತಿ);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ EXIT_AUTH_ATTEMPTED:
			penalty_type = SRCLIMIT_PENALTY_AUTHFAIL;
			debug_f("preauth child %ld for %s exited "
			    "after unsuccessful auth attempt%s",
			    (ದೀರ್ಘ)ಮಗು->pid, ಮಗು->id, ಮಗು_ಸ್ಥಿತಿ);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ EXIT_INVALID_USER:
			penalty_type = SRCLIMIT_PENALTY_INVALIDUSER;
			debug_f("preauth child %ld for %s exited "
			    "after auth attempt by invalid user%s",
			    (ದೀರ್ಘ)ಮಗು->pid, ಮಗು->id, ಮಗು_ಸ್ಥಿತಿ);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ EXIT_CONFIG_REFUSED:
			penalty_type = SRCLIMIT_PENALTY_REFUSECONNECTION;
			debug_f("preauth child %ld for %s prohibited by"
			    "RefuseConnection%s",
			    (ದೀರ್ಘ)ಮಗು->pid, ಮಗು->id, ಮಗು_ಸ್ಥಿತಿ);
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			penalty_type = SRCLIMIT_PENALTY_NOAUTH;
			debug_f("preauth child %ld for %s exited "
			    "with status %d%s", (ದೀರ್ಘ)ಮಗು->pid, ಮಗು->id,
			    WEXITSTATUS(ಮಗು->ಸ್ಥಿತಿ_2), ಮಗು_ಸ್ಥಿತಿ);
			ನಿಲ್ಲಿಸು;
		}
	}

	ಆದರೆ (ಮಗು->have_addr)
		srclimit_penalise(&ಮಗು->addr, penalty_type);

	ಮಗು->pid = -1;
	ಮಗು->have_ಸ್ಥಿತಿ = 0;
	ಆದರೆ (ಮಗು->pipefd == -1)
		ಮಗು_ಮುಕ್ತಾಯ(ಮಗು);
}

/* Reap all children that have exited; called after SIGCHLD */
ಸ್ಥಿರ ಶೂನ್ಯ
ಮಗು_reap_all_exited(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ i;
	pid_t pid;
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2;

	ಆದರೆ (children == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	ಗಾಗಿ (;;) {
		ಆದರೆ ((pid = waitpid(-1, &ಸ್ಥಿತಿ_2, WNOHANG)) == 0)
			ನಿಲ್ಲಿಸು;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (pid == -1) {
			ಆದರೆ (errno == EINTR || errno == EAGAIN)
				ಮುಂದುವರಿ;
			ಆದರೆ (errno != ECHILD)
				error_f("waitpid: %s", strerror(errno));
			ನಿಲ್ಲಿಸು;
		}
		ಮಗು_exit(pid, ಸ್ಥಿತಿ_2);
	}

	ಗಾಗಿ (i = 0; i < options.max_startups; i++) {
		ಆದರೆ (!children[i].have_ಸ್ಥಿತಿ)
			ಮುಂದುವರಿ;
		ಮಗು_reap(&(children[i]));
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
close_startup_pipes(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (children == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; i < options.max_startups; i++) {
		ಆದರೆ (children[i].pipefd != -1)
			ಮಗು_close(&(children[i]), 1, 1);
	}
}

/* Called after SIGINFO */
ಸ್ಥಿರ ಶೂನ್ಯ
show_info(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ i;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಗು_ಸ್ಥಿತಿ;

	/* XXX print listening sockets here too */
	ಆದರೆ (children == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	logit("%d active startups", children_ಸಕ್ರಿಯ);
	ಗಾಗಿ (i = 0; i < options.max_startups; i++) {
		ಆದರೆ (children[i].pipefd == -1 && children[i].pid <= 0)
			ಮುಂದುವರಿ;
		ಆದರೆ (children[i].config)
			ಮಗು_ಸ್ಥಿತಿ = " (sending config)";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (children[i].ಕೀಲಿಗಳು)
			ಮಗು_ಸ್ಥಿತಿ = " (sending keys)";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (children[i].early)
			ಮಗು_ಸ್ಥಿತಿ = " (early)";
		ಇಲ್ಲದಿದ್ದರೆ
			ಮಗು_ಸ್ಥಿತಿ = "";
		logit("child %d: fd=%d pid=%ld %s%s", i, children[i].pipefd,
		    (ದೀರ್ಘ)children[i].pid, children[i].id, ಮಗು_ಸ್ಥಿತಿ);
	}
	srclimit_penalty_info();
}

/*
 * Signal handler for SIGHUP.  Sshd execs itself when it receives SIGHUP;
 * the effect is to reread the configuration file (and to regenerate
 * the server key).
 */

ಸ್ಥಿರ ಶೂನ್ಯ
sighup_handler(ಪೂರ್ಣಾಂಕ sig)
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
	ಆದರೆ (options.pid_file != ಖಾಲಿ)
		unlink(options.pid_file);
	platform_pre_restart();
	close_listen_socks();
	close_startup_pipes();
	ssh_signal(SIGHUP, SIG_IGN); /* will be restored after exec */
	execv(execpath, saved_argv);
	logit("RESTART FAILED: execpath='%.100s', error: %.100s.", execpath,
	    strerror(errno));
	ನಿರ್ಗಮಿಸು(1);
}

/*
 * Generic signal handler for terminating signals in the master daemon.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
sigterm_handler(ಪೂರ್ಣಾಂಕ sig)
{
	received_sigterm = sig;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SIGINFO
ಸ್ಥಿರ ಶೂನ್ಯ
siginfo_handler(ಪೂರ್ಣಾಂಕ sig)
{
	received_siginfo = 1;
}
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ ಶೂನ್ಯ
main_sigchld_handler(ಪೂರ್ಣಾಂಕ sig)
{
	received_sigchld = 1;
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
should_drop_connection(ಪೂರ್ಣಾಂಕ startups)
{
	ಪೂರ್ಣಾಂಕ p, r;

	ಆದರೆ (startups < options.max_startups_begin)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (startups >= options.max_startups)
		ಹಿಂತಿರುಗಿ 1;
	ಆದರೆ (options.max_startups_ದರ == 100)
		ಹಿಂತಿರುಗಿ 1;

	p  = 100 - options.max_startups_ದರ;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_ದರ;
	r = arc4random_ಏಕರೂಪ(100);

	debug_f("p %d, r %d", p, r);
	ಹಿಂತಿರುಗಿ (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups or for penalty.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
drop_connection(ಪೂರ್ಣಾಂಕ sock, ಪೂರ್ಣಾಂಕ startups, ಪೂರ್ಣಾಂಕ notify_pipe)
{
	ಸ್ಥಿರ ರಚನೆ log_ratelimit_ctx ratelimit_maxstartups;
	ಸ್ಥಿರ ರಚನೆ log_ratelimit_ctx ratelimit_penalty;
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ init_ಮುಗಿದ;
	ಅಕ್ಷರ *laddr, *raddr;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *reason = ಖಾಲಿ, *subreason = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ ಸಂದೇಶ[] = "Not allowed at this time\r\n";
	ರಚನೆ log_ratelimit_ctx *rl = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ratelimited;
	u_int ndropped;

	ಆದರೆ (!init_ಮುಗಿದ) {
		init_ಮುಗಿದ = 1;
		log_ratelimit_init(&ratelimit_maxstartups, 4, 60, 20, 5*60);
		log_ratelimit_init(&ratelimit_penalty, 8, 60, 30, 2*60);
	}

	/* PerSourcePenalties */
	ಆದರೆ (!srclimit_penalty_check_allow(sock, &subreason)) {
		reason = "PerSourcePenalties";
		rl = &ratelimit_penalty;
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* MaxStartups */
		ಆದರೆ (!should_drop_connection(startups) &&
		    srclimit_check_allow(sock, notify_pipe) == 1)
			ಹಿಂತಿರುಗಿ 0;
		reason = "MaxStartups";
		rl = &ratelimit_maxstartups;
	}

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	ratelimited = log_ratelimit(rl, time(ಖಾಲಿ), ಖಾಲಿ, &ndropped);
	do_log2(ratelimited ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    "drop connection #%d from [%s]:%d on [%s]:%d %s",
	    startups,
	    raddr, get_peer_ಪೋರ್ಟ್(sock),
	    laddr, get_local_ಪೋರ್ಟ್(sock),
	    subreason != ಖಾಲಿ ? subreason : reason);
	ಬಿಡುಗಡೆ(laddr);
	ಬಿಡುಗಡೆ(raddr);
	ಆದರೆ (ndropped != 0) {
		logit("%s logging rate-limited: additional %u connections "
		    "dropped", reason, ndropped);
	}

	/* best-effort notification to client */
	(ಶೂನ್ಯ)ಲಿಖ(sock, ಸಂದೇಶ, ಗಾತ್ರ(ಸಂದೇಶ) - 1);
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_ಆವೃತ್ತಿ);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	ನಿರ್ಗಮಿಸು(1);
}

ಸ್ಥಿರ ರಚನೆ sshbuf *
pack_hostkeys(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *m = ಖಾಲಿ, *keybuf = ಖಾಲಿ, *hostkeys = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;
	u_int i;
	ಗಾತ್ರ_t len;

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ ||
	    (keybuf = sshbuf_new()) == ಖಾಲಿ ||
	    (hostkeys = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		ಆದರೆ (sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i] != ಖಾಲಿ &&
		    (r = sshkey_ಖಾಸಗಿ_serialize(sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		ಆದರೆ ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		ಆದರೆ (sensitive_ದತ್ತಾಂಶ.host_pubkeys[i] != ಖಾಲಿ) {
			ಆದರೆ ((r = sshkey_puts(sensitive_ದತ್ತಾಂಶ.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ ((r = sshbuf_put_string(hostkeys, ಖಾಲಿ, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		ಆದರೆ (sensitive_ದತ್ತಾಂಶ.host_certificates[i] != ಖಾಲಿ) {
			ಆದರೆ ((r = sshkey_puts(
			    sensitive_ದತ್ತಾಂಶ.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ ((r = sshbuf_put_string(hostkeys, ಖಾಲಿ, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	ಆದರೆ ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0)
		fatal_fr(r, "compose message");
	ಆದರೆ ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(keybuf);
	sshbuf_free(hostkeys);
	ಹಿಂತಿರುಗಿ m;
}

ಸ್ಥಿರ ರಚನೆ sshbuf *
pack_config(ರಚನೆ sshbuf *conf)
{
	ರಚನೆ sshbuf *m = ಖಾಲಿ, *inc = ಖಾಲಿ;
	ರಚನೆ include_ಅಂಶ *ಅಂಶ = ಖಾಲಿ;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("d config len %zu", sshbuf_len(conf));

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ ||
	    (inc = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(ಅಂಶ, &includes, ನಮೂದು) {
		ಆದರೆ ((r = sshbuf_put_cstring(inc, ಅಂಶ->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, ಅಂಶ->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, ಅಂಶ->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	ಆದರೆ ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	ಆದರೆ ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(inc);

	debug3_f("done");
	ಹಿಂತಿರುಗಿ m;
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
send_rexec_state(ಪೂರ್ಣಾಂಕ fd)
{
	ರಚನೆ sshbuf *ಕೀಲಿಗಳು;
	u_int mlen;
	pid_t pid;

	ಆದರೆ ((pid = fork()) == -1)
		fatal_f("fork failed: %s", strerror(errno));
	ಆದರೆ (pid != 0)
		ಹಿಂತಿರುಗಿ;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(config));

	mlen = sshbuf_len(config);
	ಆದರೆ (atomicio(vwrite, fd, sshbuf_mutable_ptr(config), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	ಕೀಲಿಗಳು = pack_hostkeys();
	mlen = sshbuf_len(ಕೀಲಿಗಳು);
	ಆದರೆ (atomicio(vwrite, fd, sshbuf_mutable_ptr(ಕೀಲಿಗಳು), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	sshbuf_free(ಕೀಲಿಗಳು);
	debug3_f("done");
	ನಿರ್ಗಮಿಸು(0);
}

/*
 * Listen for TCP connections
 */
ಸ್ಥಿರ ಶೂನ್ಯ
listen_on_addrs(ರಚನೆ listenaddr *la)
{
	ಪೂರ್ಣಾಂಕ ret, listen_sock;
	ರಚನೆ addrinfo *ai;
	ಅಕ್ಷರ ntop[NI_MAXHOST], strport[NI_MAXSERV];

	ಗಾಗಿ (ai = la->addrs; ai; ai = ai->ai_next) {
		ಆದರೆ (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			ಮುಂದುವರಿ;
		ಆದರೆ (ಅಂಕೆ_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		ಆದರೆ ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, ಗಾತ್ರ(ntop), strport, ಗಾತ್ರ(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			ಮುಂದುವರಿ;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		ಆದರೆ (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (ಗಣ_nonblock(listen_sock) == -1) {
			close(listen_sock);
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			ಮುಂದುವರಿ;
		}
		/* Socket options */
		ಗಣ_reuseaddr(listen_sock);
		ಆದರೆ (la->rdomain != ಖಾಲಿ &&
		    ಗಣ_rdomain(listen_sock, la->rdomain) == -1) {
			close(listen_sock);
			ಮುಂದುವರಿ;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		ಆದರೆ (ai->ai_family == AF_INET6)
			sock_ಗಣ_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		ಆದರೆ (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, strerror(errno));
			close(listen_sock);
			ಮುಂದುವರಿ;
		}
		listen_socks[ಅಂಕೆ_listen_socks] = listen_sock;
		ಅಂಕೆ_listen_socks++;

		/* Start listening on the port. */
		ಆದರೆ (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, strerror(errno));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == ಖಾಲಿ ? "" : " rdomain ",
		    la->rdomain == ಖಾಲಿ ? "" : la->rdomain);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
server_listen(ಶೂನ್ಯ)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups,
	    options.ಪ್ರತಿ_ಮೂಲ_max_startups,
	    options.ಪ್ರತಿ_ಮೂಲ_masklen_ipv4,
	    options.ಪ್ರತಿ_ಮೂಲ_masklen_ipv6,
	    &options.ಪ್ರತಿ_ಮೂಲ_penalty,
	    options.ಪ್ರತಿ_ಮೂಲ_penalty_exempt);

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		ಬಿಡುಗಡೆ(options.listen_addrs[i].rdomain);
		memset(&options.listen_addrs[i], 0,
		    ಗಾತ್ರ(options.listen_addrs[i]));
	}
	ಬಿಡುಗಡೆ(options.listen_addrs);
	options.listen_addrs = ಖಾಲಿ;
	options.ಅಂಕೆ_listen_addrs = 0;

	ಆದರೆ (!ಅಂಕೆ_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
server_accept_loop(ಪೂರ್ಣಾಂಕ *sock_ಒಳ, ಪೂರ್ಣಾಂಕ *sock_ಹೊರಹೋಗು, ಪೂರ್ಣಾಂಕ *newsock, ಪೂರ್ಣಾಂಕ *config_s,
    ಪೂರ್ಣಾಂಕ log_stderr)
{
	ರಚನೆ pollfd *pfd = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ i, ret, npfd, r;
	ಪೂರ್ಣಾಂಕ oactive = -1, listening = 0, lameduck = 0;
	ಪೂರ್ಣಾಂಕ *startup_pollfd;
	ssize_t len;
	ಸ್ಥಿರಾಂಕ u_char *ptr;
	ಅಕ್ಷರ c = 0;
	ರಚನೆ sockaddr_storage from;
	ರಚನೆ early_ಮಗು *ಮಗು;
	ರಚನೆ sshbuf *buf;
	socklen_t fromlen;
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	ಮಗು_alloc();
	startup_pollfd = xcalloc(options.max_startups, ಗಾತ್ರ(ಪೂರ್ಣಾಂಕ));

	/*
	 * Prepare signal mask that we use to block signals that might set
	 * received_sigterm/hup/chld/info, so that we are guaranteed
	 * to immediately wake up the ppoll if a signal is received after
	 * the flag is checked.
	 */
	sigemptyset(&nsigset);
	sigaddset(&nsigset, SIGHUP);
	sigaddset(&nsigset, SIGCHLD);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SIGINFO
	sigaddset(&nsigset, SIGINFO);
#ಆದರೆ_ಅಂತ್ಯ
	sigaddset(&nsigset, SIGTERM);
	sigaddset(&nsigset, SIGQUIT);

	/* sized for worst-case */
	pfd = xcalloc(ಅಂಕೆ_listen_socks + options.max_startups,
	    ಗಾತ್ರ(ರಚನೆ pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	ಗಾಗಿ (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		ಆದರೆ (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (ಪೂರ್ಣಾಂಕ) received_sigterm);
			close_listen_socks();
			ಆದರೆ (options.pid_file != ಖಾಲಿ)
				unlink(options.pid_file);
			ನಿರ್ಗಮಿಸು(received_sigterm == SIGTERM ? 0 : 255);
		}
		ಆದರೆ (received_sigchld) {
			ಮಗು_reap_all_exited();
			received_sigchld = 0;
		}
		ಆದರೆ (received_siginfo) {
			show_info();
			received_siginfo = 0;
		}
		ಆದರೆ (oactive != children_ಸಕ್ರಿಯ) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, children_ಸಕ್ರಿಯ,
			    options.max_startups_begin, options.max_startups);
			oactive = children_ಸಕ್ರಿಯ;
		}
		ಆದರೆ (received_sighup) {
			ಆದರೆ (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			ಆದರೆ (listening <= 0) {
				/*
				 * Leave termination signals blocked, so
				 * they don't get lost across a restart.
				 */
				sigaddset(&osigset, SIGTERM);
				sigaddset(&osigset, SIGQUIT);
				sigprocmask(SIG_SETMASK, &osigset, ಖಾಲಿ);
				sighup_restart();
			}
		}

		ಗಾಗಿ (i = 0; i < ಅಂಕೆ_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = ಅಂಕೆ_listen_socks;
		ಗಾಗಿ (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			ಆದರೆ (children[i].pipefd != -1) {
				pfd[npfd].fd = children[i].pipefd;
				pfd[npfd].events = POLLIN;
				ಆದರೆ (children[i].config != ಖಾಲಿ ||
				    children[i].ಕೀಲಿಗಳು != ಖಾಲಿ)
					pfd[npfd].events |= POLLOUT;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, ಖಾಲಿ, &osigset);
		ಆದರೆ (ret == -1 && errno != EINTR) {
			error("ppoll: %.100s", strerror(errno));
			ಆದರೆ (errno == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, ಖಾಲಿ);
		ಆದರೆ (ret == -1)
			ಮುಂದುವರಿ;

		ಗಾಗಿ (i = 0; i < options.max_startups; i++) {
			ಆದರೆ (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & POLLOUT))
				ಮುಂದುವರಿ;
			ಆದರೆ (children[i].config)
				buf = children[i].config;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (children[i].ಕೀಲಿಗಳು)
				buf = children[i].ಕೀಲಿಗಳು;
			ಇಲ್ಲದಿದ್ದರೆ {
				error_f("no buffer to send");
				ಮುಂದುವರಿ;
			}
			ptr = sshbuf_ptr(buf);
			len = sshbuf_len(buf);
			ret = ಲಿಖ(children[i].pipefd, ptr, len);
			ಆದರೆ (ret == -1 && (errno == EINTR || errno == EAGAIN))
				ಮುಂದುವರಿ;
			ಆದರೆ (ret <= 0) {
				ಆದರೆ (children[i].early)
					listening--;
				ಮಗು_close(&(children[i]), 0, 0);
				ಮುಂದುವರಿ;
			}
			ಆದರೆ (ret == len) {
				/* finished sending buffer */
				sshbuf_free(buf);
				ಆದರೆ (children[i].config == buf) {
					/* sent config, now send keys */
					children[i].config = ಖಾಲಿ;
					children[i].ಕೀಲಿಗಳು = pack_hostkeys();
				} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (children[i].ಕೀಲಿಗಳು == buf) {
					/* sent both config and keys */
					children[i].ಕೀಲಿಗಳು = ಖಾಲಿ;
				} ಇಲ್ಲದಿದ್ದರೆ {
					fatal("config buf not set");
				}

			} ಇಲ್ಲದಿದ್ದರೆ {
				ಆದರೆ ((r = sshbuf_consume(buf, ret)) != 0)
					fatal_fr(r, "config buf inconsistent");
			}
		}
		ಗಾಗಿ (i = 0; i < options.max_startups; i++) {
			ಆದರೆ (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				ಮುಂದುವರಿ;
			ಆಯ್ಕೆ (ಪಠ(children[i].pipefd, &c, ಗಾತ್ರ(c))) {
			ಸ್ಥಿತಿ -1:
				ಆದರೆ (errno == EINTR || errno == EAGAIN)
					ಮುಂದುವರಿ;
				ಆದರೆ (errno != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, children[i].pipefd,
					    strerror(errno));
				}
				/* FALLTHROUGH */
			ಸ್ಥಿತಿ 0:
				/* child closed pipe */
				ಆದರೆ (children[i].early)
					listening--;
				debug3_f("child %lu for %s closed pipe",
				    (ದೀರ್ಘ)children[i].pid, children[i].id);
				ಮಗು_close(&(children[i]), 0, 0);
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ 1:
				ಆದರೆ (children[i].config) {
					error_f("startup pipe %d (fd=%d)"
					    " early read",
					    i, children[i].pipefd);
					ಹೋಗು problem_ಮಗು;
				}
				ಆದರೆ (children[i].early && c == '\0') {
					/* child has finished preliminaries */
					listening--;
					children[i].early = 0;
					debug2_f("child %lu for %s received "
					    "config", (ದೀರ್ಘ)children[i].pid,
					    children[i].id);
				} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!children[i].early && c == '\001') {
					/* child has completed auth */
					debug2_f("child %lu for %s auth done",
					    (ದೀರ್ಘ)children[i].pid,
					    children[i].id);
					ಮಗು_close(&(children[i]), 1, 0);
				} ಇಲ್ಲದಿದ್ದರೆ {
					error_f("unexpected message 0x%02x "
					    "child %ld for %s in state %d",
					    (ಪೂರ್ಣಾಂಕ)c, (ದೀರ್ಘ)children[i].pid,
					    children[i].id, children[i].early);
 problem_ಮಗು:
					ಆದರೆ (children[i].early)
						listening--;
					ಆದರೆ (children[i].pid > 0)
						kill(children[i].pid, SIGTERM);
					ಮಗು_close(&(children[i]), 0, 0);
				}
				ನಿಲ್ಲಿಸು;
			}
		}
		ಗಾಗಿ (i = 0; i < ಅಂಕೆ_listen_socks; i++) {
			ಆದರೆ (!(pfd[i].revents & POLLIN))
				ಮುಂದುವರಿ;
			fromlen = ಗಾತ್ರ(from);
			*newsock = accept(listen_socks[i],
			    (ರಚನೆ sockaddr *)&from, &fromlen);
			ಆದರೆ (*newsock == -1) {
				ಆದರೆ (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED && errno != EAGAIN)
					error("accept: %.100s",
					    strerror(errno));
				ಆದರೆ (errno == EMFILE || errno == ENFILE)
					usleep(100 * 1000);
				ಮುಂದುವರಿ;
			}
			ಆದರೆ (unset_nonblock(*newsock) == -1) {
				close(*newsock);
				ಮುಂದುವರಿ;
			}
			ಆದರೆ (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    strerror(errno));
				close(*newsock);
				ಮುಂದುವರಿ;
			}
			ಆದರೆ (drop_connection(*newsock,
			    children_ಸಕ್ರಿಯ, config_s[0])) {
				close(*newsock);
				close(config_s[0]);
				close(config_s[1]);
				ಮುಂದುವರಿ;
			}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			ಆದರೆ (debug_flag) {
				/*
				 * In debugging mode.  Close the listening
				 * socket, and start processing the
				 * connection without forking.
				 */
				debug("Server will not fork when running in debugging mode.");
				close_listen_socks();
				*sock_ಒಳ = *newsock;
				*sock_ಹೊರಹೋಗು = *newsock;
				send_rexec_state(config_s[0]);
				close(config_s[0]);
				ಬಿಡುಗಡೆ(pfd);
				ಬಿಡುಗಡೆ(startup_pollfd);
				ಹಿಂತಿರುಗಿ;
			}

			/*
			 * Normal production daemon.  Fork, and have
			 * the child process the connection. The
			 * parent continues listening.
			 */
			platform_pre_fork();
			ಗಣ_nonblock(config_s[0]);
			listening++;
			ಮಗು = ಮಗು_ರಿಜಿಸ್ಟರ್(config_s[0], *newsock);
			ಆದರೆ ((ಮಗು->pid = fork()) == 0) {
				/*
				 * Child.  Close the listening and
				 * max_startup sockets.  Start using
				 * the accepted socket. Reinitialize
				 * logging (since our pid has changed).
				 * We return from this function to handle
				 * the connection.
				 */
				platform_post_fork_ಮಗು();
				close_startup_pipes();
				close_listen_socks();
				*sock_ಒಳ = *newsock;
				*sock_ಹೊರಹೋಗು = *newsock;
				log_init(__progname,
				    options.log_level,
				    options.log_facility,
				    log_stderr);
				close(config_s[0]);
				ಬಿಡುಗಡೆ(pfd);
				ಬಿಡುಗಡೆ(startup_pollfd);
				ಹಿಂತಿರುಗಿ;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_ಪೋಷಕ(ಮಗು->pid);
			ಆದರೆ (ಮಗು->pid == -1)
				error("fork: %.100s", strerror(errno));
			ಇಲ್ಲದಿದ್ದರೆ
				debug("Forked child %ld.", (ದೀರ್ಘ)ಮಗು->pid);

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
accumulate_host_timing_secret(ರಚನೆ sshbuf *server_cfg,
    ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಸ್ಥಿರ ರಚನೆ ssh_digest_ctx *ctx;
	u_char *hash;
	ಗಾತ್ರ_t len;
	ರಚನೆ sshbuf *buf;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ctx == ಖಾಲಿ && (ctx = ssh_digest_ಆರಂಭ(SSH_DIGEST_SHA512)) == ಖಾಲಿ)
		fatal_f("ssh_digest_start");
	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ) { /* finalize */
		/* add server config in case we are using agent for host keys */
		ಆದರೆ (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_ಬೈಟುಗಳು(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		ಆದರೆ (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = ಖಾಲಿ;
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("could not allocate buffer");
	ಆದರೆ ((r = sshkey_ಖಾಸಗಿ_serialize(ಕೀಲಿ, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(ಕೀಲಿ));
	ಆದರೆ (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

ಸ್ಥಿರ ಅಕ್ಷರ *
prepare_proctitle(ಪೂರ್ಣಾಂಕ ac, ಅಕ್ಷರ **av)
{
	ಅಕ್ಷರ *ret = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ i;

	ಗಾಗಿ (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	ಹಿಂತಿರುಗಿ ret;
}

/* Disconnect from the controlling tty. */
ಸ್ಥಿರ ಶೂನ್ಯ
disconnect_controlling_tty(ಶೂನ್ಯ)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ TIOCNOTTY
# ifndef O_NOCTTY
#  define O_NOCTTY 0
# endif
	ಪೂರ್ಣಾಂಕ fd;

	ಆದರೆ ((fd = open(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(ಶೂನ್ಯ) ioctl(fd, TIOCNOTTY, ಖಾಲಿ);
		close(fd);
	}
#ಆದರೆ_ಅಂತ್ಯ /* TIOCNOTTY */
}

ಸ್ಥಿರ ಶೂನ್ಯ
print_config(ರಚನೆ connection_info *connection_info)
{
	connection_info->test = 1;
	parse_server_ಹೊಂದಿಕೆ_config(&options, &includes, connection_info);
	dump_config(&options);
	ನಿರ್ಗಮಿಸು(0);
}

/*
 * Main program for the daemon.
 */
ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ ac, ಅಕ್ಷರ **av)
{
	ಬಾಹ್ಯ ಅಕ್ಷರ *optarg;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ optind;
	ಪೂರ್ಣಾಂಕ log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	ಅಕ್ಷರ *config_file_name = ಮಾರ್ಗ_SERVER_CONFIG_FILE;
	ಪೂರ್ಣಾಂಕ r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	ಪೂರ್ಣಾಂಕ sock_ಒಳ = -1, sock_ಹೊರಹೋಗು = -1, newsock = -1, rexec_argc = 0;
	ಪೂರ್ಣಾಂಕ devnull, config_s[2] = { -1 , -1 }, have_connection_info = 0;
	ಪೂರ್ಣಾಂಕ need_chroot = 1;
	ಅಕ್ಷರ *ವಾದಗಳು, *fp, *ಸಾಲು, *logfile = ಖಾಲಿ, **rexec_argv = ಖಾಲಿ;
	ರಚನೆ stat sb;
	u_int i, j;
	ಬಹುಲಕ_t new_umask;
	ರಚನೆ sshkey *ಕೀಲಿ;
	ರಚನೆ sshkey *pubkey;
	ರಚನೆ connection_info connection_info;
	ರಚನೆ utsname utsname;
	sigset_t sigmask;

	memset(&connection_info, 0, ಗಾತ್ರ(connection_info));
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SECUREWARE
	(ಶೂನ್ಯ)ಗಣ_auth_parameters(ac, av);
#ಆದರೆ_ಅಂತ್ಯ
	__progname = ssh_get_progname(av[0]);

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ಖಾಲಿ);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, ಗಾತ್ರ(*saved_argv));
	ಗಾಗಿ (i = 0; (ಪೂರ್ಣಾಂಕ)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ಖಾಲಿ;

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (geteuid() == 0 && setgroups(0, ಖಾಲಿ) == -1)
		debug("setgroups(): %.200s", strerror(errno));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	ವಾದಗಳು = argv_assemble(ac, av); /* logged later */
	ಆಗ ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		ಆಯ್ಕೆ (opt) {
		ಸ್ಥಿತಿ '4':
			options.ವಿಳಾಸ_family = AF_INET;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '6':
			options.ವಿಳಾಸ_family = AF_INET6;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'f':
			config_file_name = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'c':
			servconf_ಕೂಡಿಸು_hostcert("[command-line]", 0,
			    &options, optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'd':
			ಆದರೆ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'D':
			no_daemon_flag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'G':
			do_dump_cfg = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		ಸ್ಥಿತಿ 'e':
			log_stderr = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'i':
			inetd_flag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'r':
			logit("-r option is deprecated");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'R':
			fatal("-R not supported here");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'Q':
			/* ignored */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'b':
			/* protocol 1, ignored */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'p':
			options.ports_from_cmdline = 1;
			ಆದರೆ (options.ಅಂಕೆ_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				ನಿರ್ಗಮಿಸು(1);
			}
			options.ports[options.ಅಂಕೆ_ports++] = a2port(optarg);
			ಆದರೆ (options.ports[options.ಅಂಕೆ_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				ನಿರ್ಗಮಿಸು(1);
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'g':
			ಆದರೆ ((options.login_grace_ಸಮಯ = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				ನಿರ್ಗಮಿಸು(1);
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'k':
			/* protocol 1, ignored */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'h':
			servconf_ಕೂಡಿಸು_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 't':
			test_flag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'T':
			test_flag = 2;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'C':
			ಆದರೆ (parse_server_ಹೊಂದಿಕೆ_testspec(&connection_info,
			    optarg) == -1)
				ನಿರ್ಗಮಿಸು(1);
			have_connection_info = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'u':
			utmp_len = (u_int)strtonum(optarg, 0,
			    HOST_NAME_MAX+1+1, ಖಾಲಿ);
			ಆದರೆ (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				ನಿರ್ಗಮಿಸು(1);
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'o':
			ಸಾಲು = xstrdup(optarg);
			ಆದರೆ (process_server_config_ಸಾಲು(&options, ಸಾಲು,
			    "command-line", 0, ಖಾಲಿ, ಖಾಲಿ, &includes) != 0)
				ನಿರ್ಗಮಿಸು(1);
			ಬಿಡುಗಡೆ(ಸಾಲು);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_ಆವೃತ್ತಿ);
			ನಿರ್ಗಮಿಸು(0);
		ಪೂರ್ವನಿಯೋಜಿತ:
			usage();
			ನಿಲ್ಲಿಸು;
		}
	}

	ಆದರೆ (getexecpath(execpath, ಗಾತ್ರ execpath) != 0) {
		ಆದರೆ (strlcpy(execpath, av[0], ಗಾತ್ರ execpath) >=
		    ಗಾತ್ರ execpath) {
			fprintf(stderr, "execution path is too long\n");
			ನಿರ್ಗಮಿಸು(1);
		}
	}
	ಆದರೆ (!test_flag && !inetd_flag && !do_dump_cfg && !ಮಾರ್ಗ_absolute(execpath))
		fatal("sshd requires execution with an absolute path");

	closefrom(STDERR_FILENO + 1);

	/* Reserve fds we'll need later for reexec things */
	ಆದರೆ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	ಆಗ (devnull < REEXEC_MIN_FREE_FD) {
		ಆದರೆ ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	ಬೀಜ_rng();

	/* If requested, redirect the logs to the specified logfile. */
	ಆದರೆ (logfile != ಖಾಲಿ) {
		ಅಕ್ಷರ *cp, pid_s[32];

		snprintf(pid_s, ಗಾತ್ರ(pid_s), "%ld", (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (ಅಕ್ಷರ *)ಖಾಲಿ);
		log_redirect_stderr_ಗಮ್ಯ(cp);
		ಬಿಡುಗಡೆ(cp);
	}

	/*
	 * Force logging to stderr until we have loaded the private host
	 * key (unless started from inetd)
	 */
	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_ಗಣ ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_ಗಣ ?
	    SYSLOG_FACILITY_AUTH : options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	/*
	 * Unset KRB5CCNAME, otherwise the user's session may inherit it from
	 * root's environment
	 */
	ಆದರೆ (getenv("KRB5CCNAME") != ಖಾಲಿ)
		(ಶೂನ್ಯ) unsetenv("KRB5CCNAME");

	sensitive_ದತ್ತಾಂಶ.have_ssh2_ಕೀಲಿ = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	ಆದರೆ (test_flag < 2 && have_connection_info)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	debug("sshd version %s, %s", SSH_ಆವೃತ್ತಿ, SSH_OPENSSL_ಆವೃತ್ತಿ);
	ಆದರೆ (uname(&utsname) != 0) {
		memset(&utsname, 0, ಗಾತ್ರ(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", ಗಾತ್ರ(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.ಆವೃತ್ತಿ, utsname.machine);
	debug3("Started with: %s", ವಾದಗಳು);
	ಬಿಡುಗಡೆ(ವಾದಗಳು);

	/* Fetch our configuration */
	ಆದರೆ ((cfg = sshbuf_new()) == ಖಾಲಿ)
		fatal("sshbuf_new config failed");
	ಆದರೆ (strcasecmp(config_file_name, "none") != 0)
		ತುಂಬು_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, ಖಾಲಿ, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	ಆದರೆ (options.authorized_ಕೀಲಿಗಳು_command_user == ಖಾಲಿ &&
	    (options.authorized_ಕೀಲಿಗಳು_command != ಖಾಲಿ &&
	    strcasecmp(options.authorized_ಕೀಲಿಗಳು_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	ಆದರೆ (options.authorized_principals_command_user == ಖಾಲಿ &&
	    (options.authorized_principals_command != ಖಾಲಿ &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match blocks, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	ಆದರೆ (options.ಅಂಕೆ_auth_methods != 0) {
		ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_auth_methods; i++) {
			ಆದರೆ (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (i >= options.ಅಂಕೆ_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	ಆದರೆ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		ನಿರ್ಗಮಿಸು(1);
	}

	ಆದರೆ (do_dump_cfg)
		print_config(&connection_info);

	/* load host keys */
	sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು = xcalloc(options.ಅಂಕೆ_host_ಕೀಲಿ_files,
	    ಗಾತ್ರ(ರಚನೆ sshkey *));
	sensitive_ದತ್ತಾಂಶ.host_pubkeys = xcalloc(options.ಅಂಕೆ_host_ಕೀಲಿ_files,
	    ಗಾತ್ರ(ರಚನೆ sshkey *));

	ಆದರೆ (options.host_ಕೀಲಿ_agent) {
		ಆದರೆ (strcmp(options.host_ಕೀಲಿ_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_ಕೀಲಿ_agent, 1);
		ಆದರೆ ((r = ssh_get_authentication_socket(ಖಾಲಿ)) == 0)
			have_agent = 1;
		ಇಲ್ಲದಿದ್ದರೆ
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_ಕೀಲಿ_agent);
	}

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಪೂರ್ಣಾಂಕ ll = options.host_ಕೀಲಿ_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		ಆದರೆ (options.host_ಕೀಲಿ_files[i] == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆದರೆ ((r = sshkey_ತುಂಬು_ಖಾಸಗಿ(options.host_ಕೀಲಿ_files[i], "",
		    &ಕೀಲಿ, ಖಾಲಿ)) != 0 &&
		    r != SSH_ERR_SYSTEM_ERROR && !have_agent)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_ಕೀಲಿ_files[i]);
		ಆದರೆ (sshkey_is_sk(ಕೀಲಿ) &&
		    ಕೀಲಿ->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_ಕೀಲಿ_files[i]);
			ಕೀಲಿ->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		ಆದರೆ (r == 0 && ಕೀಲಿ != ಖಾಲಿ &&
		    (r = sshkey_shield_ಖಾಸಗಿ(ಕೀಲಿ)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_ಕೀಲಿ_files[i]);
			sshkey_free(ಕೀಲಿ);
			ಕೀಲಿ = ಖಾಲಿ;
		}
		ಆದರೆ ((r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(options.host_ಕೀಲಿ_files[i],
		    &pubkey, ಖಾಲಿ)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_ಕೀಲಿ_files[i]);
		ಆದರೆ (pubkey != ಖಾಲಿ && ಕೀಲಿ != ಖಾಲಿ) {
			ಆದರೆ (!sshkey_equal(pubkey, ಕೀಲಿ)) {
				error("Public key for %s does not match "
				    "private key", options.host_ಕೀಲಿ_files[i]);
				sshkey_free(pubkey);
				pubkey = ಖಾಲಿ;
			}
		}
		ಆದರೆ (pubkey == ಖಾಲಿ && ಕೀಲಿ != ಖಾಲಿ) {
			ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(ಕೀಲಿ, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_ಕೀಲಿ_files[i]);
		}
		ಆದರೆ (pubkey != ಖಾಲಿ && (r = sshkey_check_rsa_ಉದ್ದಳತೆ(pubkey,
		    options.required_rsa_ಗಾತ್ರ)) != 0) {
			error_fr(r, "Host key %s", options.host_ಕೀಲಿ_files[i]);
			sshkey_free(pubkey);
			sshkey_free(ಕೀಲಿ);
			ಮುಂದುವರಿ;
		}
		sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i] = ಕೀಲಿ;
		sensitive_ದತ್ತಾಂಶ.host_pubkeys[i] = pubkey;

		ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ && pubkey != ಖಾಲಿ && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_ಕೀಲಿ_files[i]);
			keytype = pubkey->type;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಕೀಲಿ != ಖಾಲಿ) {
			keytype = ಕೀಲಿ->type;
			accumulate_host_timing_secret(cfg, ಕೀಲಿ);
		} ಇಲ್ಲದಿದ್ದರೆ {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_ಕೀಲಿ_files[i]);
			sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i] = ಖಾಲಿ;
			sensitive_ದತ್ತಾಂಶ.host_pubkeys[i] = ಖಾಲಿ;
			ಮುಂದುವರಿ;
		}

		ಆಯ್ಕೆ (keytype) {
		ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
		ಸ್ಥಿತಿ ಕೀಲಿ_ED25519:
		ಸ್ಥಿತಿ ಕೀಲಿ_MLDSA44_ED25519:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
		ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK:
			ಆದರೆ (have_agent || ಕೀಲಿ != ಖಾಲಿ)
				sensitive_ದತ್ತಾಂಶ.have_ssh2_ಕೀಲಿ = 1;
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == ಖಾಲಿ)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    ಕೀಲಿ ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		ಬಿಡುಗಡೆ(fp);
	}
	accumulate_host_timing_secret(cfg, ಖಾಲಿ);
	ಆದರೆ (!sensitive_ದತ್ತಾಂಶ.have_ssh2_ಕೀಲಿ) {
		logit("sshd: no hostkeys available -- exiting.");
		ನಿರ್ಗಮಿಸು(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_ದತ್ತಾಂಶ.host_certificates = xcalloc(options.ಅಂಕೆ_host_ಕೀಲಿ_files,
	    ಗಾತ್ರ(ರಚನೆ sshkey *));
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++)
		sensitive_ದತ್ತಾಂಶ.host_certificates[i] = ಖಾಲಿ;

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_host_cert_files; i++) {
		ಆದರೆ (options.host_cert_files[i] == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆದರೆ ((r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(options.host_cert_files[i],
		    &ಕೀಲಿ, ಖಾಲಿ)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (!sshkey_is_cert(ಕೀಲಿ)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(ಕೀಲಿ);
			ಮುಂದುವರಿ;
		}
		/* Find matching private key */
		ಗಾಗಿ (j = 0; j < options.ಅಂಕೆ_host_ಕೀಲಿ_files; j++) {
			ಆದರೆ (sshkey_equal_ಬಹಿರಂಗ(ಕೀಲಿ,
			    sensitive_ದತ್ತಾಂಶ.host_pubkeys[j])) {
				sensitive_ದತ್ತಾಂಶ.host_certificates[j] = ಕೀಲಿ;
				ನಿಲ್ಲಿಸು;
			}
		}
		ಆದರೆ (j >= options.ಅಂಕೆ_host_ಕೀಲಿ_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(ಕೀಲಿ);
			ಮುಂದುವರಿ;
		}
		sensitive_ದತ್ತಾಂಶ.host_certificates[j] = ಕೀಲಿ;
		debug("host certificate: #%u type %d %s", j, ಕೀಲಿ->type,
		    sshkey_type(ಕೀಲಿ));
	}

	/* Ensure privsep directory is correctly configured. */
	need_chroot = ((getuid() == 0 || geteuid() == 0) ||
	    options.kerberos_authentication);
	ಆದರೆ ((getpwnam(SSH_PRIVSEP_USER)) == ಖಾಲಿ && need_chroot) {
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	}
	endpwent();

	ಆದರೆ (need_chroot) {
		ಆದರೆ ((stat(ಮಾರ್ಗ_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
		    (S_ISDIR(sb.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    ಮಾರ್ಗ_PRIVSEP_CHROOT_DIR);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CYGWIN
		ಆದರೆ (check_ntsec(ಮಾರ್ಗ_PRIVSEP_CHROOT_DIR) &&
		    (sb.st_uid != getuid () ||
		    (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#ಇಲ್ಲದಿದ್ದರೆ
		ಆದರೆ (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#ಆದರೆ_ಅಂತ್ಯ
			fatal("%s must be owned by root and not group or "
			    "world-writable.", ಮಾರ್ಗ_PRIVSEP_CHROOT_DIR);
	}

	ಆದರೆ (test_flag > 1)
		print_config(&connection_info);

	config = pack_config(cfg);
	ಆದರೆ (sshbuf_len(config) > MONITOR_MAX_CFGLEN) {
		fatal("Configuration file is too large (have %zu, max %d)",
		    sshbuf_len(config), MONITOR_MAX_CFGLEN);
	}

	/* Configuration looks good, so exit if in test mode. */
	ಆದರೆ (test_flag)
		ನಿರ್ಗಮಿಸು(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	ಆದರೆ (setgroups(0, ಖಾಲಿ) < 0)
		debug("setgroups() failed: %.200s", strerror(errno));

	/* Prepare arguments for sshd-session */
	ಆದರೆ (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, ಗಾತ್ರ(ಅಕ್ಷರ *));
	/* Point to the sshd-session binary instead of sshd */
	rexec_argv[0] = options.sshd_session_ಮಾರ್ಗ;
	ಗಾಗಿ (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = ಖಾಲಿ;
	ಆದರೆ (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	ಆದರೆ (stat(options.sshd_auth_ಮಾರ್ಗ, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_auth_ಮಾರ್ಗ);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(ಶೂನ್ಯ) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	ಆದರೆ (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_log_verbose; i++)
		log_verbose_ಕೂಡಿಸು(options.log_verbose[i]);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	ಆದರೆ (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		ಆದರೆ (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", strerror(errno));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	ಆದರೆ (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or a listening TCP socket */
	ಆದರೆ (inetd_flag) {
		/* Send configuration to ancestor sshd-session process */
		ಆದರೆ (socketpair(AF_UNIX, SOCK_STREAM, 0, config_s) == -1)
			fatal("socketpair: %s", strerror(errno));
		send_rexec_state(config_s[0]);
		close(config_s[0]);
	} ಇಲ್ಲದಿದ್ದರೆ {
		platform_pre_listen();
		server_listen();

		ssh_signal(SIGHUP, sighup_handler);
		ssh_signal(SIGCHLD, main_sigchld_handler);
		ssh_signal(SIGTERM, sigterm_handler);
		ssh_signal(SIGQUIT, sigterm_handler);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SIGINFO
		ssh_signal(SIGINFO, siginfo_handler);
#ಆದರೆ_ಅಂತ್ಯ

		platform_post_listen();

		/*
		 * Write out the pid file after the sigterm handler
		 * is setup and the listen sockets are bound
		 */
		ಆದರೆ (options.pid_file != ಖಾಲಿ && !debug_flag) {
			FILE *f = fopen(options.pid_file, "w");

			ಆದರೆ (f == ಖಾಲಿ) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, strerror(errno));
			} ಇಲ್ಲದಿದ್ದರೆ {
				fprintf(f, "%ld\n", (ದೀರ್ಘ) getpid());
				fclose(f);
			}
		}

		/* Accept a connection and return in a forked child */
		server_accept_loop(&sock_ಒಳ, &sock_ಹೊರಹೋಗು,
		    &newsock, config_s, log_stderr);
	}

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/*
	 * Create a new session and process group since the 4.4BSD
	 * setlogin() affects the entire process group.  We don't
	 * want the child to be able to affect the parent.
	 */
	ಆದರೆ (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	debug("rexec start in %d out %d newsock %d config_s %d/%d",
	    sock_ಒಳ, sock_ಹೊರಹೋಗು, newsock, config_s[0], config_s[1]);
	ಆದರೆ (!inetd_flag) {
		ಆದರೆ (dup2(newsock, STDIN_FILENO) == -1)
			fatal("dup2 stdin: %s", strerror(errno));
		ಆದರೆ (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			fatal("dup2 stdout: %s", strerror(errno));
		ಆದರೆ (newsock > STDOUT_FILENO)
			close(newsock);
	}
	ಆದರೆ (config_s[1] != REEXEC_CONFIG_PASS_FD) {
		ಆದರೆ (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			fatal("dup2 config_s: %s", strerror(errno));
		close(config_s[1]);
	}
	log_redirect_stderr_ಗಮ್ಯ(ಖಾಲಿ);
	closefrom(REEXEC_MIN_FREE_FD);

	ssh_signal(SIGHUP, SIG_IGN); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], strerror(errno));
}

/* server specific fatal cleanup */
ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಂಕ i)
{
	_exit(i);
}
