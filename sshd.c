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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/ioctl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/utsname.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <grp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SECUREWARE
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/security.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <prot.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshpty.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "msg.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "version.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sk-api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "addr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "srclimit.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_wrap.h"

/* Re-exec fds */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

ਬਾਹਰੀ ਅੱਖਰ *__progname;

/* Server configuration options. */
ServerOptions options;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
ਪੂਰਨ debug_flag = 0;

/* Saved arguments to main(). */
ਸਥਿਰ ਅੱਖਰ execpath[PATH_MAX];
ਸਥਿਰ ਅੱਖਰ **saved_argv;
ਸਥਿਰ ਪੂਰਨ saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	MAX_LISTEN_SOCKS	16
ਸਥਿਰ ਪੂਰਨ listen_socks[MAX_LISTEN_SOCKS];
ਸਥਿਰ ਪੂਰਨ ਅੰਕ_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
ਬਣਤਰ {
	ਬਣਤਰ sshkey	**host_ਕੁੰਜੀਆਂ;		/* all private host keys */
	ਬਣਤਰ sshkey	**host_pubkeys;		/* all public host keys */
	ਬਣਤਰ sshkey	**host_certificates;	/* all public host certificates */
	ਪੂਰਨ		have_ssh2_ਕੁੰਜੀ;
} sensitive_ਅੰਕੜੇ;

/* This is set to true when a signal is received. */
ਸਥਿਰ ਅਸਥਿਰ sig_atomic_t received_siginfo = 0;
ਸਥਿਰ ਅਸਥਿਰ sig_atomic_t received_sigchld = 0;
ਸਥਿਰ ਅਸਥਿਰ sig_atomic_t received_sighup = 0;
ਸਥਿਰ ਅਸਥਿਰ sig_atomic_t received_sigterm = 0;

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
ਬਣਤਰ early_ਬੱਚਾ {
	ਪੂਰਨ pipefd;
	ਪੂਰਨ early;		/* Indicates child closed listener */
	ਅੱਖਰ *id;		/* human readable connection identifier */
	pid_t pid;
	ਬਣਤਰ xaddr addr;
	ਪੂਰਨ have_addr;
	ਪੂਰਨ ਸਥਿਤੀ, have_ਸਥਿਤੀ;
	ਬਣਤਰ sshbuf *config;
	ਬਣਤਰ sshbuf *ਕੁੰਜੀਆਂ;
};
ਸਥਿਰ ਬਣਤਰ early_ਬੱਚਾ *children;
ਸਥਿਰ ਪੂਰਨ children_ਸਰਗਰਮ;

/* sshd_config buffer */
ਬਣਤਰ sshbuf *cfg;
ਬਣਤਰ sshbuf *config;	/* packed */

/* Included files from the configuration file */
ਬਣਤਰ include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ਬਣਤਰ sshbuf *loginmsg;

/* Unprivileged user */
ਬਣਤਰ passwd *privsep_pw = ਨਿਰਾ;

ਸਥਿਰ ਅੱਖਰ *listener_proctitle;

/*
 * Close all listening sockets
 */
ਸਥਿਰ ਖਾਲੀ
close_listen_socks(ਖਾਲੀ)
{
	ਪੂਰਨ i;

	ਲਈ (i = 0; i < ਅੰਕ_listen_socks; i++)
		close(listen_socks[i]);
	ਅੰਕ_listen_socks = 0;
}

/* Allocate and initialise the children array */
ਸਥਿਰ ਖਾਲੀ
ਬੱਚਾ_alloc(ਖਾਲੀ)
{
	ਪੂਰਨ i;

	children = xcalloc(options.max_startups, ਆਕਾਰ(*children));
	ਲਈ (i = 0; i < options.max_startups; i++) {
		children[i].pipefd = -1;
		children[i].pid = -1;
	}
}

/* Register a new connection in the children array; child pid comes later */
ਸਥਿਰ ਬਣਤਰ early_ਬੱਚਾ *
ਬੱਚਾ_ਰਜਿਸਟਰ(ਪੂਰਨ pipefd, ਪੂਰਨ sockfd)
{
	ਪੂਰਨ i, lport, rport;
	ਅੱਖਰ *laddr = ਨਿਰਾ, *raddr = ਨਿਰਾ;
	ਬਣਤਰ early_ਬੱਚਾ *ਬੱਚਾ = ਨਿਰਾ;
	ਬਣਤਰ sockaddr_storage addr;
	socklen_t addrlen = ਆਕਾਰ(addr);
	ਬਣਤਰ sockaddr *sa = (ਬਣਤਰ sockaddr *)&addr;

	ਲਈ (i = 0; i < options.max_startups; i++) {
		ਜੇ (children[i].pipefd != -1 ||
		    children[i].config != ਨਿਰਾ ||
		    children[i].ਕੁੰਜੀਆਂ != ਨਿਰਾ ||
		    children[i].pid > 0)
			ਜਾਰੀ;
		ਬੱਚਾ = &(children[i]);
		ਰੋਕੋ;
	}
	ਜੇ (ਬੱਚਾ == ਨਿਰਾ) {
		fatal_f("error: accepted connection when all %d child "
		    " slots full", options.max_startups);
	}
	ਬੱਚਾ->pipefd = pipefd;
	ਬੱਚਾ->early = 1;
	ਜੇ ((ਬੱਚਾ->config = sshbuf_fromb(config)) == ਨਿਰਾ)
		fatal_f("sshbuf_fromb failed");
	/* record peer address, if available */
	ਜੇ (getpeername(sockfd, sa, &addrlen) == 0 &&
	   addr_sa_ਮੰਜ਼ਿਲ_xaddr(sa, addrlen, &ਬੱਚਾ->addr) == 0)
		ਬੱਚਾ->have_addr = 1;
	/* format peer address string for logs */
	ਜੇ ((lport = get_local_ਪੋਰਟ(sockfd)) == 0 ||
	    (rport = get_peer_ਪੋਰਟ(sockfd)) == 0) {
		/* Not a TCP socket */
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&ਬੱਚਾ->id, "connection from %s", raddr);
	} ਨਹੀਂਤਾਂ {
		laddr = get_local_ipaddr(sockfd);
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&ਬੱਚਾ->id, "connection from %s to %s", raddr, laddr);
	}
	ਮੁਕਤ(laddr);
	ਮੁਕਤ(raddr);
	ਜੇ (++children_ਸਰਗਰਮ > options.max_startups)
		fatal_f("internal error: more children than max_startups");

	ਵਾਪਸ ਬੱਚਾ;
}

/*
 * Finally free a child entry. Don't call this directly.
 */
ਸਥਿਰ ਖਾਲੀ
ਬੱਚਾ_ਅੰਤ(ਬਣਤਰ early_ਬੱਚਾ *ਬੱਚਾ)
{
	ਜੇ (children_ਸਰਗਰਮ == 0)
		fatal_f("internal error: children_active underflow");
	ਜੇ (ਬੱਚਾ->pipefd != -1) {
		srclimit_ਪੂਰਾ(ਬੱਚਾ->pipefd);
		close(ਬੱਚਾ->pipefd);
	}
	sshbuf_free(ਬੱਚਾ->config);
	sshbuf_free(ਬੱਚਾ->ਕੁੰਜੀਆਂ);
	ਮੁਕਤ(ਬੱਚਾ->id);
	memset(ਬੱਚਾ, '\0', ਆਕਾਰ(*ਬੱਚਾ));
	ਬੱਚਾ->pipefd = -1;
	ਬੱਚਾ->pid = -1;
	children_ਸਰਗਰਮ--;
}

/*
 * Close a child's pipe. This will not stop tracking the child immediately
 * (it will still be tracked for waitpid()) unless force_final is set, or
 * child has already exited.
 */
ਸਥਿਰ ਖਾਲੀ
ਬੱਚਾ_close(ਬਣਤਰ early_ਬੱਚਾ *ਬੱਚਾ, ਪੂਰਨ force_final, ਪੂਰਨ quiet)
{
	ਜੇ (!quiet)
		debug_f("enter%s", force_final ? " (forcing)" : "");
	ਜੇ (ਬੱਚਾ->pipefd != -1) {
		srclimit_ਪੂਰਾ(ਬੱਚਾ->pipefd);
		close(ਬੱਚਾ->pipefd);
		ਬੱਚਾ->pipefd = -1;
	}
	ਜੇ (ਬੱਚਾ->pid == -1 || force_final)
		ਬੱਚਾ_ਅੰਤ(ਬੱਚਾ);
}

/* Record a child exit. Safe to call from signal handlers */
ਸਥਿਰ ਖਾਲੀ
ਬੱਚਾ_exit(pid_t pid, ਪੂਰਨ ਸਥਿਤੀ)
{
	ਪੂਰਨ i;

	ਜੇ (children == ਨਿਰਾ || pid <= 0)
		ਵਾਪਸ;
	ਲਈ (i = 0; i < options.max_startups; i++) {
		ਜੇ (children[i].pid == pid) {
			children[i].have_ਸਥਿਤੀ = 1;
			children[i].ਸਥਿਤੀ = ਸਥਿਤੀ;
			ਰੋਕੋ;
		}
	}
}

/*
 * Reap a child entry that has exited, as previously flagged
 * using child_exit().
 * Handles logging of exit condition and will finalise the child if its pipe
 * had already been closed.
 */
ਸਥਿਰ ਖਾਲੀ
ਬੱਚਾ_reap(ਬਣਤਰ early_ਬੱਚਾ *ਬੱਚਾ)
{
	LogLevel level = SYSLOG_LEVEL_DEBUG1;
	ਪੂਰਨ was_crash, penalty_type = SRCLIMIT_PENALTY_NONE;
	ਅਚਲ ਅੱਖਰ *ਬੱਚਾ_ਸਥਿਤੀ;

	ਜੇ (ਬੱਚਾ->config)
		ਬੱਚਾ_ਸਥਿਤੀ = " (sending config)";
	ਨਹੀਂਤਾਂ ਜੇ (ਬੱਚਾ->ਕੁੰਜੀਆਂ)
		ਬੱਚਾ_ਸਥਿਤੀ = " (sending keys)";
	ਨਹੀਂਤਾਂ ਜੇ (ਬੱਚਾ->early)
		ਬੱਚਾ_ਸਥਿਤੀ = " (early)";
	ਨਹੀਂਤਾਂ
		ਬੱਚਾ_ਸਥਿਤੀ = "";

	/* Log exit information */
	ਜੇ (WIFSIGNALED(ਬੱਚਾ->ਸਥਿਤੀ)) {
		/*
		 * Increase logging for signals potentially associated
		 * with serious conditions.
		 */
		ਜੇ ((was_crash = signal_is_crash(WTERMSIG(ਬੱਚਾ->ਸਥਿਤੀ))))
			level = SYSLOG_LEVEL_ERROR;
		do_log2(level, "session process %ld for %s killed by "
		    "signal %d%s", (ਲੰਮਾ)ਬੱਚਾ->pid, ਬੱਚਾ->id,
		    WTERMSIG(ਬੱਚਾ->ਸਥਿਤੀ), ਬੱਚਾ_ਸਥਿਤੀ);
		ਜੇ (was_crash)
			penalty_type = SRCLIMIT_PENALTY_CRASH;
	} ਨਹੀਂਤਾਂ ਜੇ (!WIFEXITED(ਬੱਚਾ->ਸਥਿਤੀ)) {
		penalty_type = SRCLIMIT_PENALTY_CRASH;
		error("session process %ld for %s terminated abnormally, "
		    "status=0x%x%s", (ਲੰਮਾ)ਬੱਚਾ->pid, ਬੱਚਾ->id, ਬੱਚਾ->ਸਥਿਤੀ,
		    ਬੱਚਾ_ਸਥਿਤੀ);
	} ਨਹੀਂਤਾਂ {
		/* Normal exit. We care about the status */
		ਚੋਣ (WEXITSTATUS(ਬੱਚਾ->ਸਥਿਤੀ)) {
		ਹਾਲਤ 0:
			debug3_f("preauth child %ld for %s completed "
			    "normally%s", (ਲੰਮਾ)ਬੱਚਾ->pid, ਬੱਚਾ->id,
			    ਬੱਚਾ_ਸਥਿਤੀ);
			ਰੋਕੋ;
		ਹਾਲਤ EXIT_LOGIN_GRACE:
			penalty_type = SRCLIMIT_PENALTY_GRACE_EXCEEDED;
			logit("Timeout before authentication for %s, "
			    "pid = %ld%s", ਬੱਚਾ->id, (ਲੰਮਾ)ਬੱਚਾ->pid,
			    ਬੱਚਾ_ਸਥਿਤੀ);
			ਰੋਕੋ;
		ਹਾਲਤ EXIT_ਬੱਚਾ_CRASH:
			penalty_type = SRCLIMIT_PENALTY_CRASH;
			logit("Session process %ld unpriv child crash for %s%s",
			    (ਲੰਮਾ)ਬੱਚਾ->pid, ਬੱਚਾ->id, ਬੱਚਾ_ਸਥਿਤੀ);
			ਰੋਕੋ;
		ਹਾਲਤ EXIT_AUTH_ATTEMPTED:
			penalty_type = SRCLIMIT_PENALTY_AUTHFAIL;
			debug_f("preauth child %ld for %s exited "
			    "after unsuccessful auth attempt%s",
			    (ਲੰਮਾ)ਬੱਚਾ->pid, ਬੱਚਾ->id, ਬੱਚਾ_ਸਥਿਤੀ);
			ਰੋਕੋ;
		ਹਾਲਤ EXIT_INVALID_USER:
			penalty_type = SRCLIMIT_PENALTY_INVALIDUSER;
			debug_f("preauth child %ld for %s exited "
			    "after auth attempt by invalid user%s",
			    (ਲੰਮਾ)ਬੱਚਾ->pid, ਬੱਚਾ->id, ਬੱਚਾ_ਸਥਿਤੀ);
			ਰੋਕੋ;
		ਹਾਲਤ EXIT_CONFIG_REFUSED:
			penalty_type = SRCLIMIT_PENALTY_REFUSECONNECTION;
			debug_f("preauth child %ld for %s prohibited by"
			    "RefuseConnection%s",
			    (ਲੰਮਾ)ਬੱਚਾ->pid, ਬੱਚਾ->id, ਬੱਚਾ_ਸਥਿਤੀ);
			ਰੋਕੋ;
		ਮੂਲ:
			penalty_type = SRCLIMIT_PENALTY_NOAUTH;
			debug_f("preauth child %ld for %s exited "
			    "with status %d%s", (ਲੰਮਾ)ਬੱਚਾ->pid, ਬੱਚਾ->id,
			    WEXITSTATUS(ਬੱਚਾ->ਸਥਿਤੀ), ਬੱਚਾ_ਸਥਿਤੀ);
			ਰੋਕੋ;
		}
	}

	ਜੇ (ਬੱਚਾ->have_addr)
		srclimit_penalise(&ਬੱਚਾ->addr, penalty_type);

	ਬੱਚਾ->pid = -1;
	ਬੱਚਾ->have_ਸਥਿਤੀ = 0;
	ਜੇ (ਬੱਚਾ->pipefd == -1)
		ਬੱਚਾ_ਅੰਤ(ਬੱਚਾ);
}

/* Reap all children that have exited; called after SIGCHLD */
ਸਥਿਰ ਖਾਲੀ
ਬੱਚਾ_reap_all_exited(ਖਾਲੀ)
{
	ਪੂਰਨ i;
	pid_t pid;
	ਪੂਰਨ ਸਥਿਤੀ;

	ਜੇ (children == ਨਿਰਾ)
		ਵਾਪਸ;

	ਲਈ (;;) {
		ਜੇ ((pid = waitpid(-1, &ਸਥਿਤੀ, WNOHANG)) == 0)
			ਰੋਕੋ;
		ਨਹੀਂਤਾਂ ਜੇ (pid == -1) {
			ਜੇ (errno == EINTR || errno == EAGAIN)
				ਜਾਰੀ;
			ਜੇ (errno != ECHILD)
				error_f("waitpid: %s", strerror(errno));
			ਰੋਕੋ;
		}
		ਬੱਚਾ_exit(pid, ਸਥਿਤੀ);
	}

	ਲਈ (i = 0; i < options.max_startups; i++) {
		ਜੇ (!children[i].have_ਸਥਿਤੀ)
			ਜਾਰੀ;
		ਬੱਚਾ_reap(&(children[i]));
	}
}

ਸਥਿਰ ਖਾਲੀ
close_startup_pipes(ਖਾਲੀ)
{
	ਪੂਰਨ i;

	ਜੇ (children == ਨਿਰਾ)
		ਵਾਪਸ;
	ਲਈ (i = 0; i < options.max_startups; i++) {
		ਜੇ (children[i].pipefd != -1)
			ਬੱਚਾ_close(&(children[i]), 1, 1);
	}
}

/* Called after SIGINFO */
ਸਥਿਰ ਖਾਲੀ
show_info(ਖਾਲੀ)
{
	ਪੂਰਨ i;
	ਅਚਲ ਅੱਖਰ *ਬੱਚਾ_ਸਥਿਤੀ;

	/* XXX print listening sockets here too */
	ਜੇ (children == ਨਿਰਾ)
		ਵਾਪਸ;
	logit("%d active startups", children_ਸਰਗਰਮ);
	ਲਈ (i = 0; i < options.max_startups; i++) {
		ਜੇ (children[i].pipefd == -1 && children[i].pid <= 0)
			ਜਾਰੀ;
		ਜੇ (children[i].config)
			ਬੱਚਾ_ਸਥਿਤੀ = " (sending config)";
		ਨਹੀਂਤਾਂ ਜੇ (children[i].ਕੁੰਜੀਆਂ)
			ਬੱਚਾ_ਸਥਿਤੀ = " (sending keys)";
		ਨਹੀਂਤਾਂ ਜੇ (children[i].early)
			ਬੱਚਾ_ਸਥਿਤੀ = " (early)";
		ਨਹੀਂਤਾਂ
			ਬੱਚਾ_ਸਥਿਤੀ = "";
		logit("child %d: fd=%d pid=%ld %s%s", i, children[i].pipefd,
		    (ਲੰਮਾ)children[i].pid, children[i].id, ਬੱਚਾ_ਸਥਿਤੀ);
	}
	srclimit_penalty_info();
}

/*
 * Signal handler for SIGHUP.  Sshd execs itself when it receives SIGHUP;
 * the effect is to reread the configuration file (and to regenerate
 * the server key).
 */

ਸਥਿਰ ਖਾਲੀ
sighup_handler(ਪੂਰਨ sig)
{
	received_sighup = 1;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
ਸਥਿਰ ਖਾਲੀ
sighup_restart(ਖਾਲੀ)
{
	logit("Received SIGHUP; restarting.");
	ਜੇ (options.pid_file != ਨਿਰਾ)
		unlink(options.pid_file);
	platform_pre_restart();
	close_listen_socks();
	close_startup_pipes();
	ssh_signal(SIGHUP, SIG_IGN); /* will be restored after exec */
	execv(execpath, saved_argv);
	logit("RESTART FAILED: execpath='%.100s', error: %.100s.", execpath,
	    strerror(errno));
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

/*
 * Generic signal handler for terminating signals in the master daemon.
 */
ਸਥਿਰ ਖਾਲੀ
sigterm_handler(ਪੂਰਨ sig)
{
	received_sigterm = sig;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SIGINFO
ਸਥਿਰ ਖਾਲੀ
siginfo_handler(ਪੂਰਨ sig)
{
	received_siginfo = 1;
}
#ਜੇ_ਅੰਤ

ਸਥਿਰ ਖਾਲੀ
main_sigchld_handler(ਪੂਰਨ sig)
{
	received_sigchld = 1;
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
ਸਥਿਰ ਪੂਰਨ
should_drop_connection(ਪੂਰਨ startups)
{
	ਪੂਰਨ p, r;

	ਜੇ (startups < options.max_startups_begin)
		ਵਾਪਸ 0;
	ਜੇ (startups >= options.max_startups)
		ਵਾਪਸ 1;
	ਜੇ (options.max_startups_ਦਰ == 100)
		ਵਾਪਸ 1;

	p  = 100 - options.max_startups_ਦਰ;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_ਦਰ;
	r = arc4random_ਇਕਸਾਰ(100);

	debug_f("p %d, r %d", p, r);
	ਵਾਪਸ (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups or for penalty.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
ਸਥਿਰ ਪੂਰਨ
drop_connection(ਪੂਰਨ sock, ਪੂਰਨ startups, ਪੂਰਨ notify_pipe)
{
	ਸਥਿਰ ਬਣਤਰ log_ratelimit_ctx ratelimit_maxstartups;
	ਸਥਿਰ ਬਣਤਰ log_ratelimit_ctx ratelimit_penalty;
	ਸਥਿਰ ਪੂਰਨ init_ਪੂਰਾ;
	ਅੱਖਰ *laddr, *raddr;
	ਅਚਲ ਅੱਖਰ *reason = ਨਿਰਾ, *subreason = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ ਸੁਨੇਹਾ[] = "Not allowed at this time\r\n";
	ਬਣਤਰ log_ratelimit_ctx *rl = ਨਿਰਾ;
	ਪੂਰਨ ratelimited;
	u_int ndropped;

	ਜੇ (!init_ਪੂਰਾ) {
		init_ਪੂਰਾ = 1;
		log_ratelimit_init(&ratelimit_maxstartups, 4, 60, 20, 5*60);
		log_ratelimit_init(&ratelimit_penalty, 8, 60, 30, 2*60);
	}

	/* PerSourcePenalties */
	ਜੇ (!srclimit_penalty_check_allow(sock, &subreason)) {
		reason = "PerSourcePenalties";
		rl = &ratelimit_penalty;
	} ਨਹੀਂਤਾਂ {
		/* MaxStartups */
		ਜੇ (!should_drop_connection(startups) &&
		    srclimit_check_allow(sock, notify_pipe) == 1)
			ਵਾਪਸ 0;
		reason = "MaxStartups";
		rl = &ratelimit_maxstartups;
	}

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	ratelimited = log_ratelimit(rl, time(ਨਿਰਾ), ਨਿਰਾ, &ndropped);
	do_log2(ratelimited ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    "drop connection #%d from [%s]:%d on [%s]:%d %s",
	    startups,
	    raddr, get_peer_ਪੋਰਟ(sock),
	    laddr, get_local_ਪੋਰਟ(sock),
	    subreason != ਨਿਰਾ ? subreason : reason);
	ਮੁਕਤ(laddr);
	ਮੁਕਤ(raddr);
	ਜੇ (ndropped != 0) {
		logit("%s logging rate-limited: additional %u connections "
		    "dropped", reason, ndropped);
	}

	/* best-effort notification to client */
	(ਖਾਲੀ)ਲਿਖ(sock, ਸੁਨੇਹਾ, ਆਕਾਰ(ਸੁਨੇਹਾ) - 1);
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਖਾਲੀ
usage(ਖਾਲੀ)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_ਸੰਸਕਰਣ);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਸਥਿਰ ਬਣਤਰ sshbuf *
pack_hostkeys(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *m = ਨਿਰਾ, *keybuf = ਨਿਰਾ, *hostkeys = ਨਿਰਾ;
	ਪੂਰਨ r;
	u_int i;
	ਮਾਪ_t len;

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ ||
	    (keybuf = sshbuf_new()) == ਨਿਰਾ ||
	    (hostkeys = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	ਲਈ (i = 0; i < options.ਅੰਕ_host_ਕੁੰਜੀ_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		ਜੇ (sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i] != ਨਿਰਾ &&
		    (r = sshkey_ਨਿੱਜੀ_serialize(sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		ਜੇ ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		ਜੇ (sensitive_ਅੰਕੜੇ.host_pubkeys[i] != ਨਿਰਾ) {
			ਜੇ ((r = sshkey_puts(sensitive_ਅੰਕੜੇ.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} ਨਹੀਂਤਾਂ {
			ਜੇ ((r = sshbuf_put_string(hostkeys, ਨਿਰਾ, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		ਜੇ (sensitive_ਅੰਕੜੇ.host_certificates[i] != ਨਿਰਾ) {
			ਜੇ ((r = sshkey_puts(
			    sensitive_ਅੰਕੜੇ.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} ਨਹੀਂਤਾਂ {
			ਜੇ ((r = sshbuf_put_string(hostkeys, ਨਿਰਾ, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	ਜੇ ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0)
		fatal_fr(r, "compose message");
	ਜੇ ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(keybuf);
	sshbuf_free(hostkeys);
	ਵਾਪਸ m;
}

ਸਥਿਰ ਬਣਤਰ sshbuf *
pack_config(ਬਣਤਰ sshbuf *conf)
{
	ਬਣਤਰ sshbuf *m = ਨਿਰਾ, *inc = ਨਿਰਾ;
	ਬਣਤਰ include_ਵਸਤੂ *ਵਸਤੂ = ਨਿਰਾ;
	ਮਾਪ_t len;
	ਪੂਰਨ r;

	debug3_f("d config len %zu", sshbuf_len(conf));

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ ||
	    (inc = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(ਵਸਤੂ, &includes, ਇੰਦਰਾਜ) {
		ਜੇ ((r = sshbuf_put_cstring(inc, ਵਸਤੂ->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, ਵਸਤੂ->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, ਵਸਤੂ->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	ਜੇ ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	ਜੇ ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(inc);

	debug3_f("done");
	ਵਾਪਸ m;
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
ਸਥਿਰ ਖਾਲੀ
send_rexec_state(ਪੂਰਨ fd)
{
	ਬਣਤਰ sshbuf *ਕੁੰਜੀਆਂ;
	u_int mlen;
	pid_t pid;

	ਜੇ ((pid = fork()) == -1)
		fatal_f("fork failed: %s", strerror(errno));
	ਜੇ (pid != 0)
		ਵਾਪਸ;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(config));

	mlen = sshbuf_len(config);
	ਜੇ (atomicio(vwrite, fd, sshbuf_mutable_ptr(config), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	ਕੁੰਜੀਆਂ = pack_hostkeys();
	mlen = sshbuf_len(ਕੁੰਜੀਆਂ);
	ਜੇ (atomicio(vwrite, fd, sshbuf_mutable_ptr(ਕੁੰਜੀਆਂ), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	sshbuf_free(ਕੁੰਜੀਆਂ);
	debug3_f("done");
	ਬਾਹਰ_ਨਿਕਲੋ(0);
}

/*
 * Listen for TCP connections
 */
ਸਥਿਰ ਖਾਲੀ
listen_on_addrs(ਬਣਤਰ listenaddr *la)
{
	ਪੂਰਨ ret, listen_sock;
	ਬਣਤਰ addrinfo *ai;
	ਅੱਖਰ ntop[NI_MAXHOST], strport[NI_MAXSERV];

	ਲਈ (ai = la->addrs; ai; ai = ai->ai_next) {
		ਜੇ (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			ਜਾਰੀ;
		ਜੇ (ਅੰਕ_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		ਜੇ ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, ਆਕਾਰ(ntop), strport, ਆਕਾਰ(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			ਜਾਰੀ;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		ਜੇ (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			ਜਾਰੀ;
		}
		ਜੇ (ਸੈੱਟ_nonblock(listen_sock) == -1) {
			close(listen_sock);
			ਜਾਰੀ;
		}
		ਜੇ (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			ਜਾਰੀ;
		}
		/* Socket options */
		ਸੈੱਟ_reuseaddr(listen_sock);
		ਜੇ (la->rdomain != ਨਿਰਾ &&
		    ਸੈੱਟ_rdomain(listen_sock, la->rdomain) == -1) {
			close(listen_sock);
			ਜਾਰੀ;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		ਜੇ (ai->ai_family == AF_INET6)
			sock_ਸੈੱਟ_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		ਜੇ (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, strerror(errno));
			close(listen_sock);
			ਜਾਰੀ;
		}
		listen_socks[ਅੰਕ_listen_socks] = listen_sock;
		ਅੰਕ_listen_socks++;

		/* Start listening on the port. */
		ਜੇ (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, strerror(errno));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == ਨਿਰਾ ? "" : " rdomain ",
		    la->rdomain == ਨਿਰਾ ? "" : la->rdomain);
	}
}

ਸਥਿਰ ਖਾਲੀ
server_listen(ਖਾਲੀ)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups,
	    options.ਪ੍ਰਤੀ_ਸਰੋਤ_max_startups,
	    options.ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv4,
	    options.ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv6,
	    &options.ਪ੍ਰਤੀ_ਸਰੋਤ_penalty,
	    options.ਪ੍ਰਤੀ_ਸਰੋਤ_penalty_exempt);

	ਲਈ (i = 0; i < options.ਅੰਕ_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		ਮੁਕਤ(options.listen_addrs[i].rdomain);
		memset(&options.listen_addrs[i], 0,
		    ਆਕਾਰ(options.listen_addrs[i]));
	}
	ਮੁਕਤ(options.listen_addrs);
	options.listen_addrs = ਨਿਰਾ;
	options.ਅੰਕ_listen_addrs = 0;

	ਜੇ (!ਅੰਕ_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
ਸਥਿਰ ਖਾਲੀ
server_accept_loop(ਪੂਰਨ *sock_ਵਿੱਚ, ਪੂਰਨ *sock_ਬਾਹਰਲਾ, ਪੂਰਨ *newsock, ਪੂਰਨ *config_s,
    ਪੂਰਨ log_stderr)
{
	ਬਣਤਰ pollfd *pfd = ਨਿਰਾ;
	ਪੂਰਨ i, ret, npfd, r;
	ਪੂਰਨ oactive = -1, listening = 0, lameduck = 0;
	ਪੂਰਨ *startup_pollfd;
	ssize_t len;
	ਅਚਲ u_char *ptr;
	ਅੱਖਰ c = 0;
	ਬਣਤਰ sockaddr_storage from;
	ਬਣਤਰ early_ਬੱਚਾ *ਬੱਚਾ;
	ਬਣਤਰ sshbuf *buf;
	socklen_t fromlen;
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	ਬੱਚਾ_alloc();
	startup_pollfd = xcalloc(options.max_startups, ਆਕਾਰ(ਪੂਰਨ));

	/*
	 * Prepare signal mask that we use to block signals that might set
	 * received_sigterm/hup/chld/info, so that we are guaranteed
	 * to immediately wake up the ppoll if a signal is received after
	 * the flag is checked.
	 */
	sigemptyset(&nsigset);
	sigaddset(&nsigset, SIGHUP);
	sigaddset(&nsigset, SIGCHLD);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SIGINFO
	sigaddset(&nsigset, SIGINFO);
#ਜੇ_ਅੰਤ
	sigaddset(&nsigset, SIGTERM);
	sigaddset(&nsigset, SIGQUIT);

	/* sized for worst-case */
	pfd = xcalloc(ਅੰਕ_listen_socks + options.max_startups,
	    ਆਕਾਰ(ਬਣਤਰ pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	ਲਈ (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		ਜੇ (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (ਪੂਰਨ) received_sigterm);
			close_listen_socks();
			ਜੇ (options.pid_file != ਨਿਰਾ)
				unlink(options.pid_file);
			ਬਾਹਰ_ਨਿਕਲੋ(received_sigterm == SIGTERM ? 0 : 255);
		}
		ਜੇ (received_sigchld) {
			ਬੱਚਾ_reap_all_exited();
			received_sigchld = 0;
		}
		ਜੇ (received_siginfo) {
			show_info();
			received_siginfo = 0;
		}
		ਜੇ (oactive != children_ਸਰਗਰਮ) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, children_ਸਰਗਰਮ,
			    options.max_startups_begin, options.max_startups);
			oactive = children_ਸਰਗਰਮ;
		}
		ਜੇ (received_sighup) {
			ਜੇ (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			ਜੇ (listening <= 0) {
				/*
				 * Leave termination signals blocked, so
				 * they don't get lost across a restart.
				 */
				sigaddset(&osigset, SIGTERM);
				sigaddset(&osigset, SIGQUIT);
				sigprocmask(SIG_SETMASK, &osigset, ਨਿਰਾ);
				sighup_restart();
			}
		}

		ਲਈ (i = 0; i < ਅੰਕ_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = ਅੰਕ_listen_socks;
		ਲਈ (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			ਜੇ (children[i].pipefd != -1) {
				pfd[npfd].fd = children[i].pipefd;
				pfd[npfd].events = POLLIN;
				ਜੇ (children[i].config != ਨਿਰਾ ||
				    children[i].ਕੁੰਜੀਆਂ != ਨਿਰਾ)
					pfd[npfd].events |= POLLOUT;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, ਨਿਰਾ, &osigset);
		ਜੇ (ret == -1 && errno != EINTR) {
			error("ppoll: %.100s", strerror(errno));
			ਜੇ (errno == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, ਨਿਰਾ);
		ਜੇ (ret == -1)
			ਜਾਰੀ;

		ਲਈ (i = 0; i < options.max_startups; i++) {
			ਜੇ (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & POLLOUT))
				ਜਾਰੀ;
			ਜੇ (children[i].config)
				buf = children[i].config;
			ਨਹੀਂਤਾਂ ਜੇ (children[i].ਕੁੰਜੀਆਂ)
				buf = children[i].ਕੁੰਜੀਆਂ;
			ਨਹੀਂਤਾਂ {
				error_f("no buffer to send");
				ਜਾਰੀ;
			}
			ptr = sshbuf_ptr(buf);
			len = sshbuf_len(buf);
			ret = ਲਿਖ(children[i].pipefd, ptr, len);
			ਜੇ (ret == -1 && (errno == EINTR || errno == EAGAIN))
				ਜਾਰੀ;
			ਜੇ (ret <= 0) {
				ਜੇ (children[i].early)
					listening--;
				ਬੱਚਾ_close(&(children[i]), 0, 0);
				ਜਾਰੀ;
			}
			ਜੇ (ret == len) {
				/* finished sending buffer */
				sshbuf_free(buf);
				ਜੇ (children[i].config == buf) {
					/* sent config, now send keys */
					children[i].config = ਨਿਰਾ;
					children[i].ਕੁੰਜੀਆਂ = pack_hostkeys();
				} ਨਹੀਂਤਾਂ ਜੇ (children[i].ਕੁੰਜੀਆਂ == buf) {
					/* sent both config and keys */
					children[i].ਕੁੰਜੀਆਂ = ਨਿਰਾ;
				} ਨਹੀਂਤਾਂ {
					fatal("config buf not set");
				}

			} ਨਹੀਂਤਾਂ {
				ਜੇ ((r = sshbuf_consume(buf, ret)) != 0)
					fatal_fr(r, "config buf inconsistent");
			}
		}
		ਲਈ (i = 0; i < options.max_startups; i++) {
			ਜੇ (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				ਜਾਰੀ;
			ਚੋਣ (ਪਠ(children[i].pipefd, &c, ਆਕਾਰ(c))) {
			ਹਾਲਤ -1:
				ਜੇ (errno == EINTR || errno == EAGAIN)
					ਜਾਰੀ;
				ਜੇ (errno != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, children[i].pipefd,
					    strerror(errno));
				}
				/* FALLTHROUGH */
			ਹਾਲਤ 0:
				/* child closed pipe */
				ਜੇ (children[i].early)
					listening--;
				debug3_f("child %lu for %s closed pipe",
				    (ਲੰਮਾ)children[i].pid, children[i].id);
				ਬੱਚਾ_close(&(children[i]), 0, 0);
				ਰੋਕੋ;
			ਹਾਲਤ 1:
				ਜੇ (children[i].config) {
					error_f("startup pipe %d (fd=%d)"
					    " early read",
					    i, children[i].pipefd);
					ਜਾਓ problem_ਬੱਚਾ;
				}
				ਜੇ (children[i].early && c == '\0') {
					/* child has finished preliminaries */
					listening--;
					children[i].early = 0;
					debug2_f("child %lu for %s received "
					    "config", (ਲੰਮਾ)children[i].pid,
					    children[i].id);
				} ਨਹੀਂਤਾਂ ਜੇ (!children[i].early && c == '\001') {
					/* child has completed auth */
					debug2_f("child %lu for %s auth done",
					    (ਲੰਮਾ)children[i].pid,
					    children[i].id);
					ਬੱਚਾ_close(&(children[i]), 1, 0);
				} ਨਹੀਂਤਾਂ {
					error_f("unexpected message 0x%02x "
					    "child %ld for %s in state %d",
					    (ਪੂਰਨ)c, (ਲੰਮਾ)children[i].pid,
					    children[i].id, children[i].early);
 problem_ਬੱਚਾ:
					ਜੇ (children[i].early)
						listening--;
					ਜੇ (children[i].pid > 0)
						kill(children[i].pid, SIGTERM);
					ਬੱਚਾ_close(&(children[i]), 0, 0);
				}
				ਰੋਕੋ;
			}
		}
		ਲਈ (i = 0; i < ਅੰਕ_listen_socks; i++) {
			ਜੇ (!(pfd[i].revents & POLLIN))
				ਜਾਰੀ;
			fromlen = ਆਕਾਰ(from);
			*newsock = accept(listen_socks[i],
			    (ਬਣਤਰ sockaddr *)&from, &fromlen);
			ਜੇ (*newsock == -1) {
				ਜੇ (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED && errno != EAGAIN)
					error("accept: %.100s",
					    strerror(errno));
				ਜੇ (errno == EMFILE || errno == ENFILE)
					usleep(100 * 1000);
				ਜਾਰੀ;
			}
			ਜੇ (unset_nonblock(*newsock) == -1) {
				close(*newsock);
				ਜਾਰੀ;
			}
			ਜੇ (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    strerror(errno));
				close(*newsock);
				ਜਾਰੀ;
			}
			ਜੇ (drop_connection(*newsock,
			    children_ਸਰਗਰਮ, config_s[0])) {
				close(*newsock);
				close(config_s[0]);
				close(config_s[1]);
				ਜਾਰੀ;
			}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			ਜੇ (debug_flag) {
				/*
				 * In debugging mode.  Close the listening
				 * socket, and start processing the
				 * connection without forking.
				 */
				debug("Server will not fork when running in debugging mode.");
				close_listen_socks();
				*sock_ਵਿੱਚ = *newsock;
				*sock_ਬਾਹਰਲਾ = *newsock;
				send_rexec_state(config_s[0]);
				close(config_s[0]);
				ਮੁਕਤ(pfd);
				ਮੁਕਤ(startup_pollfd);
				ਵਾਪਸ;
			}

			/*
			 * Normal production daemon.  Fork, and have
			 * the child process the connection. The
			 * parent continues listening.
			 */
			platform_pre_fork();
			ਸੈੱਟ_nonblock(config_s[0]);
			listening++;
			ਬੱਚਾ = ਬੱਚਾ_ਰਜਿਸਟਰ(config_s[0], *newsock);
			ਜੇ ((ਬੱਚਾ->pid = fork()) == 0) {
				/*
				 * Child.  Close the listening and
				 * max_startup sockets.  Start using
				 * the accepted socket. Reinitialize
				 * logging (since our pid has changed).
				 * We return from this function to handle
				 * the connection.
				 */
				platform_post_fork_ਬੱਚਾ();
				close_startup_pipes();
				close_listen_socks();
				*sock_ਵਿੱਚ = *newsock;
				*sock_ਬਾਹਰਲਾ = *newsock;
				log_init(__progname,
				    options.log_level,
				    options.log_facility,
				    log_stderr);
				close(config_s[0]);
				ਮੁਕਤ(pfd);
				ਮੁਕਤ(startup_pollfd);
				ਵਾਪਸ;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_ਮਾਪਾ(ਬੱਚਾ->pid);
			ਜੇ (ਬੱਚਾ->pid == -1)
				error("fork: %.100s", strerror(errno));
			ਨਹੀਂਤਾਂ
				debug("Forked child %ld.", (ਲੰਮਾ)ਬੱਚਾ->pid);

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

ਸਥਿਰ ਖਾਲੀ
accumulate_host_timing_secret(ਬਣਤਰ sshbuf *server_cfg,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਸਥਿਰ ਬਣਤਰ ssh_digest_ctx *ctx;
	u_char *hash;
	ਮਾਪ_t len;
	ਬਣਤਰ sshbuf *buf;
	ਪੂਰਨ r;

	ਜੇ (ctx == ਨਿਰਾ && (ctx = ssh_digest_ਸ਼ੁਰੂ(SSH_DIGEST_SHA512)) == ਨਿਰਾ)
		fatal_f("ssh_digest_start");
	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ) { /* finalize */
		/* add server config in case we are using agent for host keys */
		ਜੇ (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_ਬਾਈਟਾਂ(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		ਜੇ (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = ਨਿਰਾ;
		ਵਾਪਸ;
	}
	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("could not allocate buffer");
	ਜੇ ((r = sshkey_ਨਿੱਜੀ_serialize(ਕੁੰਜੀ, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(ਕੁੰਜੀ));
	ਜੇ (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

ਸਥਿਰ ਅੱਖਰ *
prepare_proctitle(ਪੂਰਨ ac, ਅੱਖਰ **av)
{
	ਅੱਖਰ *ret = ਨਿਰਾ;
	ਪੂਰਨ i;

	ਲਈ (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	ਵਾਪਸ ret;
}

/* Disconnect from the controlling tty. */
ਸਥਿਰ ਖਾਲੀ
disconnect_controlling_tty(ਖਾਲੀ)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ TIOCNOTTY
# ifndef O_NOCTTY
#  define O_NOCTTY 0
# endif
	ਪੂਰਨ fd;

	ਜੇ ((fd = open(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(ਖਾਲੀ) ioctl(fd, TIOCNOTTY, ਨਿਰਾ);
		close(fd);
	}
#ਜੇ_ਅੰਤ /* TIOCNOTTY */
}

ਸਥਿਰ ਖਾਲੀ
print_config(ਬਣਤਰ connection_info *connection_info)
{
	connection_info->test = 1;
	parse_server_ਮੇਲ_config(&options, &includes, connection_info);
	dump_config(&options);
	ਬਾਹਰ_ਨਿਕਲੋ(0);
}

/*
 * Main program for the daemon.
 */
ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ ac, ਅੱਖਰ **av)
{
	ਬਾਹਰੀ ਅੱਖਰ *optarg;
	ਬਾਹਰੀ ਪੂਰਨ optind;
	ਪੂਰਨ log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	ਅੱਖਰ *config_file_name = ਰਸਤਾ_SERVER_CONFIG_FILE;
	ਪੂਰਨ r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	ਪੂਰਨ sock_ਵਿੱਚ = -1, sock_ਬਾਹਰਲਾ = -1, newsock = -1, rexec_argc = 0;
	ਪੂਰਨ devnull, config_s[2] = { -1 , -1 }, have_connection_info = 0;
	ਪੂਰਨ need_chroot = 1;
	ਅੱਖਰ *ਦਲੀਲਾਂ, *fp, *ਸਤਰ, *logfile = ਨਿਰਾ, **rexec_argv = ਨਿਰਾ;
	ਬਣਤਰ stat sb;
	u_int i, j;
	ਬਹੁਲਕ_t new_umask;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ;
	ਬਣਤਰ sshkey *pubkey;
	ਬਣਤਰ connection_info connection_info;
	ਬਣਤਰ utsname utsname;
	sigset_t sigmask;

	memset(&connection_info, 0, ਆਕਾਰ(connection_info));
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SECUREWARE
	(ਖਾਲੀ)ਸੈੱਟ_auth_parameters(ac, av);
#ਜੇ_ਅੰਤ
	__progname = ssh_get_progname(av[0]);

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ਨਿਰਾ);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, ਆਕਾਰ(*saved_argv));
	ਲਈ (i = 0; (ਪੂਰਨ)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ਨਿਰਾ;

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#ਜੇ_ਅੰਤ

	ਜੇ (geteuid() == 0 && setgroups(0, ਨਿਰਾ) == -1)
		debug("setgroups(): %.200s", strerror(errno));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	ਦਲੀਲਾਂ = argv_assemble(ac, av); /* logged later */
	ਜਦੋਂ ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		ਚੋਣ (opt) {
		ਹਾਲਤ '4':
			options.ਪਤਾ_family = AF_INET;
			ਰੋਕੋ;
		ਹਾਲਤ '6':
			options.ਪਤਾ_family = AF_INET6;
			ਰੋਕੋ;
		ਹਾਲਤ 'f':
			config_file_name = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'c':
			servconf_ਜੋੜੋ_hostcert("[command-line]", 0,
			    &options, optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'd':
			ਜੇ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ਨਹੀਂਤਾਂ ਜੇ (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			ਰੋਕੋ;
		ਹਾਲਤ 'D':
			no_daemon_flag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'G':
			do_dump_cfg = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		ਹਾਲਤ 'e':
			log_stderr = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'i':
			inetd_flag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'r':
			logit("-r option is deprecated");
			ਰੋਕੋ;
		ਹਾਲਤ 'R':
			fatal("-R not supported here");
			ਰੋਕੋ;
		ਹਾਲਤ 'Q':
			/* ignored */
			ਰੋਕੋ;
		ਹਾਲਤ 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			ਰੋਕੋ;
		ਹਾਲਤ 'b':
			/* protocol 1, ignored */
			ਰੋਕੋ;
		ਹਾਲਤ 'p':
			options.ports_from_cmdline = 1;
			ਜੇ (options.ਅੰਕ_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			options.ports[options.ਅੰਕ_ports++] = a2port(optarg);
			ਜੇ (options.ports[options.ਅੰਕ_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ਰੋਕੋ;
		ਹਾਲਤ 'g':
			ਜੇ ((options.login_grace_ਸਮਾਂ = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ਰੋਕੋ;
		ਹਾਲਤ 'k':
			/* protocol 1, ignored */
			ਰੋਕੋ;
		ਹਾਲਤ 'h':
			servconf_ਜੋੜੋ_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			ਰੋਕੋ;
		ਹਾਲਤ 't':
			test_flag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'T':
			test_flag = 2;
			ਰੋਕੋ;
		ਹਾਲਤ 'C':
			ਜੇ (parse_server_ਮੇਲ_testspec(&connection_info,
			    optarg) == -1)
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			have_connection_info = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'u':
			utmp_len = (u_int)strtonum(optarg, 0,
			    HOST_NAME_MAX+1+1, ਨਿਰਾ);
			ਜੇ (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ਰੋਕੋ;
		ਹਾਲਤ 'o':
			ਸਤਰ = xstrdup(optarg);
			ਜੇ (process_server_config_ਸਤਰ(&options, ਸਤਰ,
			    "command-line", 0, ਨਿਰਾ, ਨਿਰਾ, &includes) != 0)
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			ਮੁਕਤ(ਸਤਰ);
			ਰੋਕੋ;
		ਹਾਲਤ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_ਸੰਸਕਰਣ);
			ਬਾਹਰ_ਨਿਕਲੋ(0);
		ਮੂਲ:
			usage();
			ਰੋਕੋ;
		}
	}

	ਜੇ (getexecpath(execpath, ਆਕਾਰ execpath) != 0) {
		ਜੇ (strlcpy(execpath, av[0], ਆਕਾਰ execpath) >=
		    ਆਕਾਰ execpath) {
			fprintf(stderr, "execution path is too long\n");
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
	}
	ਜੇ (!test_flag && !inetd_flag && !do_dump_cfg && !ਰਸਤਾ_absolute(execpath))
		fatal("sshd requires execution with an absolute path");

	closefrom(STDERR_FILENO + 1);

	/* Reserve fds we'll need later for reexec things */
	ਜੇ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	ਜਦੋਂ (devnull < REEXEC_MIN_FREE_FD) {
		ਜੇ ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	ਬੀਜ_rng();

	/* If requested, redirect the logs to the specified logfile. */
	ਜੇ (logfile != ਨਿਰਾ) {
		ਅੱਖਰ *cp, pid_s[32];

		snprintf(pid_s, ਆਕਾਰ(pid_s), "%ld", (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (ਅੱਖਰ *)ਨਿਰਾ);
		log_redirect_stderr_ਮੰਜ਼ਿਲ(cp);
		ਮੁਕਤ(cp);
	}

	/*
	 * Force logging to stderr until we have loaded the private host
	 * key (unless started from inetd)
	 */
	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_ਸੈੱਟ ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_ਸੈੱਟ ?
	    SYSLOG_FACILITY_AUTH : options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	/*
	 * Unset KRB5CCNAME, otherwise the user's session may inherit it from
	 * root's environment
	 */
	ਜੇ (getenv("KRB5CCNAME") != ਨਿਰਾ)
		(ਖਾਲੀ) unsetenv("KRB5CCNAME");

	sensitive_ਅੰਕੜੇ.have_ssh2_ਕੁੰਜੀ = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	ਜੇ (test_flag < 2 && have_connection_info)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	debug("sshd version %s, %s", SSH_ਸੰਸਕਰਣ, SSH_OPENSSL_ਸੰਸਕਰਣ);
	ਜੇ (uname(&utsname) != 0) {
		memset(&utsname, 0, ਆਕਾਰ(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", ਆਕਾਰ(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.ਸੰਸਕਰਣ, utsname.machine);
	debug3("Started with: %s", ਦਲੀਲਾਂ);
	ਮੁਕਤ(ਦਲੀਲਾਂ);

	/* Fetch our configuration */
	ਜੇ ((cfg = sshbuf_new()) == ਨਿਰਾ)
		fatal("sshbuf_new config failed");
	ਜੇ (strcasecmp(config_file_name, "none") != 0)
		ਲੱਦੋ_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, ਨਿਰਾ, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	ਜੇ (options.authorized_ਕੁੰਜੀਆਂ_command_user == ਨਿਰਾ &&
	    (options.authorized_ਕੁੰਜੀਆਂ_command != ਨਿਰਾ &&
	    strcasecmp(options.authorized_ਕੁੰਜੀਆਂ_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	ਜੇ (options.authorized_principals_command_user == ਨਿਰਾ &&
	    (options.authorized_principals_command != ਨਿਰਾ &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match blocks, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	ਜੇ (options.ਅੰਕ_auth_methods != 0) {
		ਲਈ (i = 0; i < options.ਅੰਕ_auth_methods; i++) {
			ਜੇ (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				ਰੋਕੋ;
		}
		ਜੇ (i >= options.ਅੰਕ_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	ਜੇ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}

	ਜੇ (do_dump_cfg)
		print_config(&connection_info);

	/* load host keys */
	sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ = xcalloc(options.ਅੰਕ_host_ਕੁੰਜੀ_files,
	    ਆਕਾਰ(ਬਣਤਰ sshkey *));
	sensitive_ਅੰਕੜੇ.host_pubkeys = xcalloc(options.ਅੰਕ_host_ਕੁੰਜੀ_files,
	    ਆਕਾਰ(ਬਣਤਰ sshkey *));

	ਜੇ (options.host_ਕੁੰਜੀ_agent) {
		ਜੇ (strcmp(options.host_ਕੁੰਜੀ_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_ਕੁੰਜੀ_agent, 1);
		ਜੇ ((r = ssh_get_authentication_socket(ਨਿਰਾ)) == 0)
			have_agent = 1;
		ਨਹੀਂਤਾਂ
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_ਕੁੰਜੀ_agent);
	}

	ਲਈ (i = 0; i < options.ਅੰਕ_host_ਕੁੰਜੀ_files; i++) {
		ਪੂਰਨ ll = options.host_ਕੁੰਜੀ_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		ਜੇ (options.host_ਕੁੰਜੀ_files[i] == ਨਿਰਾ)
			ਜਾਰੀ;
		ਜੇ ((r = sshkey_ਲੱਦੋ_ਨਿੱਜੀ(options.host_ਕੁੰਜੀ_files[i], "",
		    &ਕੁੰਜੀ, ਨਿਰਾ)) != 0 &&
		    r != SSH_ERR_SYSTEM_ERROR && !have_agent)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_ਕੁੰਜੀ_files[i]);
		ਜੇ (sshkey_is_sk(ਕੁੰਜੀ) &&
		    ਕੁੰਜੀ->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_ਕੁੰਜੀ_files[i]);
			ਕੁੰਜੀ->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		ਜੇ (r == 0 && ਕੁੰਜੀ != ਨਿਰਾ &&
		    (r = sshkey_shield_ਨਿੱਜੀ(ਕੁੰਜੀ)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_ਕੁੰਜੀ_files[i]);
			sshkey_free(ਕੁੰਜੀ);
			ਕੁੰਜੀ = ਨਿਰਾ;
		}
		ਜੇ ((r = sshkey_ਲੱਦੋ_ਜਨਤਕ(options.host_ਕੁੰਜੀ_files[i],
		    &pubkey, ਨਿਰਾ)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_ਕੁੰਜੀ_files[i]);
		ਜੇ (pubkey != ਨਿਰਾ && ਕੁੰਜੀ != ਨਿਰਾ) {
			ਜੇ (!sshkey_equal(pubkey, ਕੁੰਜੀ)) {
				error("Public key for %s does not match "
				    "private key", options.host_ਕੁੰਜੀ_files[i]);
				sshkey_free(pubkey);
				pubkey = ਨਿਰਾ;
			}
		}
		ਜੇ (pubkey == ਨਿਰਾ && ਕੁੰਜੀ != ਨਿਰਾ) {
			ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(ਕੁੰਜੀ, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_ਕੁੰਜੀ_files[i]);
		}
		ਜੇ (pubkey != ਨਿਰਾ && (r = sshkey_check_rsa_ਲੰਮਾਈ(pubkey,
		    options.required_rsa_ਮਾਪ)) != 0) {
			error_fr(r, "Host key %s", options.host_ਕੁੰਜੀ_files[i]);
			sshkey_free(pubkey);
			sshkey_free(ਕੁੰਜੀ);
			ਜਾਰੀ;
		}
		sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i] = ਕੁੰਜੀ;
		sensitive_ਅੰਕੜੇ.host_pubkeys[i] = pubkey;

		ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ && pubkey != ਨਿਰਾ && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_ਕੁੰਜੀ_files[i]);
			keytype = pubkey->type;
		} ਨਹੀਂਤਾਂ ਜੇ (ਕੁੰਜੀ != ਨਿਰਾ) {
			keytype = ਕੁੰਜੀ->type;
			accumulate_host_timing_secret(cfg, ਕੁੰਜੀ);
		} ਨਹੀਂਤਾਂ {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_ਕੁੰਜੀ_files[i]);
			sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i] = ਨਿਰਾ;
			sensitive_ਅੰਕੜੇ.host_pubkeys[i] = ਨਿਰਾ;
			ਜਾਰੀ;
		}

		ਚੋਣ (keytype) {
		ਹਾਲਤ ਕੁੰਜੀ_RSA:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
		ਹਾਲਤ ਕੁੰਜੀ_ED25519:
		ਹਾਲਤ ਕੁੰਜੀ_MLDSA44_ED25519:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
		ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK:
			ਜੇ (have_agent || ਕੁੰਜੀ != ਨਿਰਾ)
				sensitive_ਅੰਕੜੇ.have_ssh2_ਕੁੰਜੀ = 1;
			ਰੋਕੋ;
		}
		ਜੇ ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == ਨਿਰਾ)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    ਕੁੰਜੀ ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		ਮੁਕਤ(fp);
	}
	accumulate_host_timing_secret(cfg, ਨਿਰਾ);
	ਜੇ (!sensitive_ਅੰਕੜੇ.have_ssh2_ਕੁੰਜੀ) {
		logit("sshd: no hostkeys available -- exiting.");
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_ਅੰਕੜੇ.host_certificates = xcalloc(options.ਅੰਕ_host_ਕੁੰਜੀ_files,
	    ਆਕਾਰ(ਬਣਤਰ sshkey *));
	ਲਈ (i = 0; i < options.ਅੰਕ_host_ਕੁੰਜੀ_files; i++)
		sensitive_ਅੰਕੜੇ.host_certificates[i] = ਨਿਰਾ;

	ਲਈ (i = 0; i < options.ਅੰਕ_host_cert_files; i++) {
		ਜੇ (options.host_cert_files[i] == ਨਿਰਾ)
			ਜਾਰੀ;
		ਜੇ ((r = sshkey_ਲੱਦੋ_ਜਨਤਕ(options.host_cert_files[i],
		    &ਕੁੰਜੀ, ਨਿਰਾ)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			ਜਾਰੀ;
		}
		ਜੇ (!sshkey_is_cert(ਕੁੰਜੀ)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(ਕੁੰਜੀ);
			ਜਾਰੀ;
		}
		/* Find matching private key */
		ਲਈ (j = 0; j < options.ਅੰਕ_host_ਕੁੰਜੀ_files; j++) {
			ਜੇ (sshkey_equal_ਜਨਤਕ(ਕੁੰਜੀ,
			    sensitive_ਅੰਕੜੇ.host_pubkeys[j])) {
				sensitive_ਅੰਕੜੇ.host_certificates[j] = ਕੁੰਜੀ;
				ਰੋਕੋ;
			}
		}
		ਜੇ (j >= options.ਅੰਕ_host_ਕੁੰਜੀ_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(ਕੁੰਜੀ);
			ਜਾਰੀ;
		}
		sensitive_ਅੰਕੜੇ.host_certificates[j] = ਕੁੰਜੀ;
		debug("host certificate: #%u type %d %s", j, ਕੁੰਜੀ->type,
		    sshkey_type(ਕੁੰਜੀ));
	}

	/* Ensure privsep directory is correctly configured. */
	need_chroot = ((getuid() == 0 || geteuid() == 0) ||
	    options.kerberos_authentication);
	ਜੇ ((getpwnam(SSH_PRIVSEP_USER)) == ਨਿਰਾ && need_chroot) {
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	}
	endpwent();

	ਜੇ (need_chroot) {
		ਜੇ ((stat(ਰਸਤਾ_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
		    (S_ISDIR(sb.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    ਰਸਤਾ_PRIVSEP_CHROOT_DIR);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN
		ਜੇ (check_ntsec(ਰਸਤਾ_PRIVSEP_CHROOT_DIR) &&
		    (sb.st_uid != getuid () ||
		    (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#ਨਹੀਂਤਾਂ
		ਜੇ (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#ਜੇ_ਅੰਤ
			fatal("%s must be owned by root and not group or "
			    "world-writable.", ਰਸਤਾ_PRIVSEP_CHROOT_DIR);
	}

	ਜੇ (test_flag > 1)
		print_config(&connection_info);

	config = pack_config(cfg);
	ਜੇ (sshbuf_len(config) > MONITOR_MAX_CFGLEN) {
		fatal("Configuration file is too large (have %zu, max %d)",
		    sshbuf_len(config), MONITOR_MAX_CFGLEN);
	}

	/* Configuration looks good, so exit if in test mode. */
	ਜੇ (test_flag)
		ਬਾਹਰ_ਨਿਕਲੋ(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	ਜੇ (setgroups(0, ਨਿਰਾ) < 0)
		debug("setgroups() failed: %.200s", strerror(errno));

	/* Prepare arguments for sshd-session */
	ਜੇ (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, ਆਕਾਰ(ਅੱਖਰ *));
	/* Point to the sshd-session binary instead of sshd */
	rexec_argv[0] = options.sshd_session_ਰਸਤਾ;
	ਲਈ (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = ਨਿਰਾ;
	ਜੇ (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	ਜੇ (stat(options.sshd_auth_ਰਸਤਾ, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_auth_ਰਸਤਾ);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(ਖਾਲੀ) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	ਜੇ (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	ਲਈ (i = 0; i < options.ਅੰਕ_log_verbose; i++)
		log_verbose_ਜੋੜੋ(options.log_verbose[i]);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	ਜੇ (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		ਜੇ (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", strerror(errno));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	ਜੇ (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or a listening TCP socket */
	ਜੇ (inetd_flag) {
		/* Send configuration to ancestor sshd-session process */
		ਜੇ (socketpair(AF_UNIX, SOCK_STREAM, 0, config_s) == -1)
			fatal("socketpair: %s", strerror(errno));
		send_rexec_state(config_s[0]);
		close(config_s[0]);
	} ਨਹੀਂਤਾਂ {
		platform_pre_listen();
		server_listen();

		ssh_signal(SIGHUP, sighup_handler);
		ssh_signal(SIGCHLD, main_sigchld_handler);
		ssh_signal(SIGTERM, sigterm_handler);
		ssh_signal(SIGQUIT, sigterm_handler);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SIGINFO
		ssh_signal(SIGINFO, siginfo_handler);
#ਜੇ_ਅੰਤ

		platform_post_listen();

		/*
		 * Write out the pid file after the sigterm handler
		 * is setup and the listen sockets are bound
		 */
		ਜੇ (options.pid_file != ਨਿਰਾ && !debug_flag) {
			FILE *f = fopen(options.pid_file, "w");

			ਜੇ (f == ਨਿਰਾ) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, strerror(errno));
			} ਨਹੀਂਤਾਂ {
				fprintf(f, "%ld\n", (ਲੰਮਾ) getpid());
				fclose(f);
			}
		}

		/* Accept a connection and return in a forked child */
		server_accept_loop(&sock_ਵਿੱਚ, &sock_ਬਾਹਰਲਾ,
		    &newsock, config_s, log_stderr);
	}

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/*
	 * Create a new session and process group since the 4.4BSD
	 * setlogin() affects the entire process group.  We don't
	 * want the child to be able to affect the parent.
	 */
	ਜੇ (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	debug("rexec start in %d out %d newsock %d config_s %d/%d",
	    sock_ਵਿੱਚ, sock_ਬਾਹਰਲਾ, newsock, config_s[0], config_s[1]);
	ਜੇ (!inetd_flag) {
		ਜੇ (dup2(newsock, STDIN_FILENO) == -1)
			fatal("dup2 stdin: %s", strerror(errno));
		ਜੇ (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			fatal("dup2 stdout: %s", strerror(errno));
		ਜੇ (newsock > STDOUT_FILENO)
			close(newsock);
	}
	ਜੇ (config_s[1] != REEXEC_CONFIG_PASS_FD) {
		ਜੇ (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			fatal("dup2 config_s: %s", strerror(errno));
		close(config_s[1]);
	}
	log_redirect_stderr_ਮੰਜ਼ਿਲ(ਨਿਰਾ);
	closefrom(REEXEC_MIN_FREE_FD);

	ssh_signal(SIGHUP, SIG_IGN); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], strerror(errno));
}

/* server specific fatal cleanup */
ਖਾਲੀ
cleanup_exit(ਪੂਰਨ i)
{
	_exit(i);
}
