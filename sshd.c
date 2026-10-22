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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/ioctl.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>
#ଅନ୍ତର୍ଭାଵ <sys/queue.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>
#ଅନ୍ତର୍ଭାଵ <sys/utsname.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <paths.h>
#ଅନ୍ତର୍ଭାଵ <grp.h>
#ଅନ୍ତର୍ଭାଵ <poll.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>

#ifdef HAVE_SECUREWARE
#ଅନ୍ତର୍ଭାଵ <sys/security.h>
#ଅନ୍ତର୍ଭାଵ <prot.h>
#endif

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "sshpty.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "compat.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "authfd.h"
#ଅନ୍ତର୍ଭାଵ "msg.h"
#ଅନ୍ତର୍ଭାଵ "version.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sk-api.h"
#ଅନ୍ତର୍ଭାଵ "addr.h"
#ଅନ୍ତର୍ଭାଵ "srclimit.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ifdef GSSAPI
#ଅନ୍ତର୍ଭାଵ "ssh-gss.h"
#endif
#ଅନ୍ତର୍ଭାଵ "monitor_wrap.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

ବାହ୍ୟ ଅକ୍ଷର *__progname;

/* Server configuration options. */
ServerOptions options;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା debug_flag = 0;

/* Saved arguments to main(). */
ସ୍ଥିର ଅକ୍ଷର execpath[PATH_MAX];
ସ୍ଥିର ଅକ୍ଷର **saved_argv;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#define	MAX_LISTEN_SOCKS	16
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା listen_socks[MAX_LISTEN_SOCKS];
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଅଙ୍କ_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
ସଂରଚନା {
	ସଂରଚନା sshkey	**host_ଚାବିଗୁଡ଼ିକ;		/* all private host keys */
	ସଂରଚନା sshkey	**host_pubkeys;		/* all public host keys */
	ସଂରଚନା sshkey	**host_certificates;	/* all public host certificates */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		have_ssh2_ଚାବି;
} sensitive_data;

/* This is set to true when a signal is received. */
ସ୍ଥିର ଅସ୍ଥିର sig_atomic_t received_siginfo = 0;
ସ୍ଥିର ଅସ୍ଥିର sig_atomic_t received_sigchld = 0;
ସ୍ଥିର ଅସ୍ଥିର sig_atomic_t received_sighup = 0;
ସ୍ଥିର ଅସ୍ଥିର sig_atomic_t received_sigterm = 0;

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
ସଂରଚନା early_child {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା pipefd;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା early;		/* Indicates child closed listener */
	ଅକ୍ଷର *id;		/* human readable connection identifier */
	pid_t pid;
	ସଂରଚନା xaddr addr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା have_addr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status, have_status;
	ସଂରଚନା sshbuf *config;
	ସଂରଚନା sshbuf *ଚାବିଗୁଡ଼ିକ;
};
ସ୍ଥିର ସଂରଚନା early_child *children;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା children_active;

/* sshd_config buffer */
ସଂରଚନା sshbuf *cfg;
ସଂରଚନା sshbuf *config;	/* packed */

/* Included files from the configuration file */
ସଂରଚନା include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ସଂରଚନା sshbuf *loginmsg;

/* Unprivileged user */
ସଂରଚନା passwd *privsep_pw = ଖାଲି;

ସ୍ଥିର ଅକ୍ଷର *listener_proctitle;

/*
 * Close all listening sockets
 */
ସ୍ଥିର ଶୂନ୍ୟ
close_listen_socks(ଶୂନ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ପାଇଁ (i = 0; i < ଅଙ୍କ_listen_socks; i++)
		close(listen_socks[i]);
	ଅଙ୍କ_listen_socks = 0;
}

/* Allocate and initialise the children array */
ସ୍ଥିର ଶୂନ୍ୟ
child_alloc(ଶୂନ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	children = xcalloc(options.max_startups, ଆକାର(*children));
	ପାଇଁ (i = 0; i < options.max_startups; i++) {
		children[i].pipefd = -1;
		children[i].pid = -1;
	}
}

/* Register a new connection in the children array; child pid comes later */
ସ୍ଥିର ସଂରଚନା early_child *
child_register(ପୂର୍ଣ୍ଣସଂଖ୍ୟା pipefd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sockfd)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, lport, rport;
	ଅକ୍ଷର *laddr = ଖାଲି, *raddr = ଖାଲି;
	ସଂରଚନା early_child *child = ଖାଲି;
	ସଂରଚନା sockaddr_storage addr;
	socklen_t addrlen = ଆକାର(addr);
	ସଂରଚନା sockaddr *sa = (ସଂରଚନା sockaddr *)&addr;

	ପାଇଁ (i = 0; i < options.max_startups; i++) {
		ଯଦି (children[i].pipefd != -1 ||
		    children[i].config != ଖାଲି ||
		    children[i].ଚାବିଗୁଡ଼ିକ != ଖାଲି ||
		    children[i].pid > 0)
			ଜାରି;
		child = &(children[i]);
		ଭାଙ୍ଗ;
	}
	ଯଦି (child == ଖାଲି) {
		fatal_f("error: accepted connection when all %d child "
		    " slots full", options.max_startups);
	}
	child->pipefd = pipefd;
	child->early = 1;
	ଯଦି ((child->config = sshbuf_fromb(config)) == ଖାଲି)
		fatal_f("sshbuf_fromb failed");
	/* record peer address, if available */
	ଯଦି (getpeername(sockfd, sa, &addrlen) == 0 &&
	   addr_sa_to_xaddr(sa, addrlen, &child->addr) == 0)
		child->have_addr = 1;
	/* format peer address string for logs */
	ଯଦି ((lport = get_local_port(sockfd)) == 0 ||
	    (rport = get_peer_port(sockfd)) == 0) {
		/* Not a TCP socket */
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s", raddr);
	} ଅନ୍ୟଥା {
		laddr = get_local_ipaddr(sockfd);
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s to %s", raddr, laddr);
	}
	ମୁକ୍ତ(laddr);
	ମୁକ୍ତ(raddr);
	ଯଦି (++children_active > options.max_startups)
		fatal_f("internal error: more children than max_startups");

	ଫେରନ୍ତୁ child;
}

/*
 * Finally free a child entry. Don't call this directly.
 */
ସ୍ଥିର ଶୂନ୍ୟ
child_finish(ସଂରଚନା early_child *child)
{
	ଯଦି (children_active == 0)
		fatal_f("internal error: children_active underflow");
	ଯଦି (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
	}
	sshbuf_free(child->config);
	sshbuf_free(child->ଚାବିଗୁଡ଼ିକ);
	ମୁକ୍ତ(child->id);
	memset(child, '\0', ଆକାର(*child));
	child->pipefd = -1;
	child->pid = -1;
	children_active--;
}

/*
 * Close a child's pipe. This will not stop tracking the child immediately
 * (it will still be tracked for waitpid()) unless force_final is set, or
 * child has already exited.
 */
ସ୍ଥିର ଶୂନ୍ୟ
child_close(ସଂରଚନା early_child *child, ପୂର୍ଣ୍ଣସଂଖ୍ୟା force_final, ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet)
{
	ଯଦି (!quiet)
		debug_f("enter%s", force_final ? " (forcing)" : "");
	ଯଦି (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
		child->pipefd = -1;
	}
	ଯଦି (child->pid == -1 || force_final)
		child_finish(child);
}

/* Record a child exit. Safe to call from signal handlers */
ସ୍ଥିର ଶୂନ୍ୟ
child_exit(pid_t pid, ପୂର୍ଣ୍ଣସଂଖ୍ୟା status)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (children == ଖାଲି || pid <= 0)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; i < options.max_startups; i++) {
		ଯଦି (children[i].pid == pid) {
			children[i].have_status = 1;
			children[i].status = status;
			ଭାଙ୍ଗ;
		}
	}
}

/*
 * Reap a child entry that has exited, as previously flagged
 * using child_exit().
 * Handles logging of exit condition and will finalise the child if its pipe
 * had already been closed.
 */
ସ୍ଥିର ଶୂନ୍ୟ
child_reap(ସଂରଚନା early_child *child)
{
	LogLevel level = SYSLOG_LEVEL_DEBUG1;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା was_crash, penalty_type = SRCLIMIT_PENALTY_NONE;
	ଅଚଳ ଅକ୍ଷର *child_status;

	ଯଦି (child->config)
		child_status = " (sending config)";
	ଅନ୍ୟଥା ଯଦି (child->ଚାବିଗୁଡ଼ିକ)
		child_status = " (sending keys)";
	ଅନ୍ୟଥା ଯଦି (child->early)
		child_status = " (early)";
	ଅନ୍ୟଥା
		child_status = "";

	/* Log exit information */
	ଯଦି (WIFSIGNALED(child->status)) {
		/*
		 * Increase logging for signals potentially associated
		 * with serious conditions.
		 */
		ଯଦି ((was_crash = signal_is_crash(WTERMSIG(child->status))))
			level = SYSLOG_LEVEL_ERROR;
		do_log2(level, "session process %ld for %s killed by "
		    "signal %d%s", (long)child->pid, child->id,
		    WTERMSIG(child->status), child_status);
		ଯଦି (was_crash)
			penalty_type = SRCLIMIT_PENALTY_CRASH;
	} ଅନ୍ୟଥା ଯଦି (!WIFEXITED(child->status)) {
		penalty_type = SRCLIMIT_PENALTY_CRASH;
		error("session process %ld for %s terminated abnormally, "
		    "status=0x%x%s", (long)child->pid, child->id, child->status,
		    child_status);
	} ଅନ୍ୟଥା {
		/* Normal exit. We care about the status */
		ବାଛ (WEXITSTATUS(child->status)) {
		ସ୍ଥିତି 0:
			debug3_f("preauth child %ld for %s completed "
			    "normally%s", (long)child->pid, child->id,
			    child_status);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି EXIT_LOGIN_GRACE:
			penalty_type = SRCLIMIT_PENALTY_GRACE_EXCEEDED;
			logit("Timeout before authentication for %s, "
			    "pid = %ld%s", child->id, (long)child->pid,
			    child_status);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି EXIT_CHILD_CRASH:
			penalty_type = SRCLIMIT_PENALTY_CRASH;
			logit("Session process %ld unpriv child crash for %s%s",
			    (long)child->pid, child->id, child_status);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି EXIT_AUTH_ATTEMPTED:
			penalty_type = SRCLIMIT_PENALTY_AUTHFAIL;
			debug_f("preauth child %ld for %s exited "
			    "after unsuccessful auth attempt%s",
			    (long)child->pid, child->id, child_status);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି EXIT_INVALID_USER:
			penalty_type = SRCLIMIT_PENALTY_INVALIDUSER;
			debug_f("preauth child %ld for %s exited "
			    "after auth attempt by invalid user%s",
			    (long)child->pid, child->id, child_status);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି EXIT_CONFIG_REFUSED:
			penalty_type = SRCLIMIT_PENALTY_REFUSECONNECTION;
			debug_f("preauth child %ld for %s prohibited by"
			    "RefuseConnection%s",
			    (long)child->pid, child->id, child_status);
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			penalty_type = SRCLIMIT_PENALTY_NOAUTH;
			debug_f("preauth child %ld for %s exited "
			    "with status %d%s", (long)child->pid, child->id,
			    WEXITSTATUS(child->status), child_status);
			ଭାଙ୍ଗ;
		}
	}

	ଯଦି (child->have_addr)
		srclimit_penalise(&child->addr, penalty_type);

	child->pid = -1;
	child->have_status = 0;
	ଯଦି (child->pipefd == -1)
		child_finish(child);
}

/* Reap all children that have exited; called after SIGCHLD */
ସ୍ଥିର ଶୂନ୍ୟ
child_reap_all_exited(ଶୂନ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	pid_t pid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status;

	ଯଦି (children == ଖାଲି)
		ଫେରନ୍ତୁ;

	ପାଇଁ (;;) {
		ଯଦି ((pid = waitpid(-1, &status, WNOHANG)) == 0)
			ଭାଙ୍ଗ;
		ଅନ୍ୟଥା ଯଦି (pid == -1) {
			ଯଦି (errno == EINTR || errno == EAGAIN)
				ଜାରି;
			ଯଦି (errno != ECHILD)
				error_f("waitpid: %s", strerror(errno));
			ଭାଙ୍ଗ;
		}
		child_exit(pid, status);
	}

	ପାଇଁ (i = 0; i < options.max_startups; i++) {
		ଯଦି (!children[i].have_status)
			ଜାରି;
		child_reap(&(children[i]));
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
close_startup_pipes(ଶୂନ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (children == ଖାଲି)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; i < options.max_startups; i++) {
		ଯଦି (children[i].pipefd != -1)
			child_close(&(children[i]), 1, 1);
	}
}

/* Called after SIGINFO */
ସ୍ଥିର ଶୂନ୍ୟ
show_info(ଶୂନ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ଅଚଳ ଅକ୍ଷର *child_status;

	/* XXX print listening sockets here too */
	ଯଦି (children == ଖାଲି)
		ଫେରନ୍ତୁ;
	logit("%d active startups", children_active);
	ପାଇଁ (i = 0; i < options.max_startups; i++) {
		ଯଦି (children[i].pipefd == -1 && children[i].pid <= 0)
			ଜାରି;
		ଯଦି (children[i].config)
			child_status = " (sending config)";
		ଅନ୍ୟଥା ଯଦି (children[i].ଚାବିଗୁଡ଼ିକ)
			child_status = " (sending keys)";
		ଅନ୍ୟଥା ଯଦି (children[i].early)
			child_status = " (early)";
		ଅନ୍ୟଥା
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

ସ୍ଥିର ଶୂନ୍ୟ
sighup_handler(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	received_sighup = 1;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
ସ୍ଥିର ଶୂନ୍ୟ
sighup_restart(ଶୂନ୍ୟ)
{
	logit("Received SIGHUP; restarting.");
	ଯଦି (options.pid_file != ଖାଲି)
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
ସ୍ଥିର ଶୂନ୍ୟ
sigterm_handler(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	received_sigterm = sig;
}

#ifdef SIGINFO
ସ୍ଥିର ଶୂନ୍ୟ
siginfo_handler(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	received_siginfo = 1;
}
#endif

ସ୍ଥିର ଶୂନ୍ୟ
main_sigchld_handler(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	received_sigchld = 1;
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
should_drop_connection(ପୂର୍ଣ୍ଣସଂଖ୍ୟା startups)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା p, r;

	ଯଦି (startups < options.max_startups_begin)
		ଫେରନ୍ତୁ 0;
	ଯଦି (startups >= options.max_startups)
		ଫେରନ୍ତୁ 1;
	ଯଦି (options.max_startups_rate == 100)
		ଫେରନ୍ତୁ 1;

	p  = 100 - options.max_startups_rate;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_rate;
	r = arc4random_uniform(100);

	debug_f("p %d, r %d", p, r);
	ଫେରନ୍ତୁ (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups or for penalty.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
drop_connection(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ପୂର୍ଣ୍ଣସଂଖ୍ୟା startups, ପୂର୍ଣ୍ଣସଂଖ୍ୟା notify_pipe)
{
	ସ୍ଥିର ସଂରଚନା log_ratelimit_ctx ratelimit_maxstartups;
	ସ୍ଥିର ସଂରଚନା log_ratelimit_ctx ratelimit_penalty;
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା init_done;
	ଅକ୍ଷର *laddr, *raddr;
	ଅଚଳ ଅକ୍ଷର *reason = ଖାଲି, *subreason = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର ସନ୍ଦେଶ[] = "Not allowed at this time\r\n";
	ସଂରଚନା log_ratelimit_ctx *rl = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ratelimited;
	u_int ndropped;

	ଯଦି (!init_done) {
		init_done = 1;
		log_ratelimit_init(&ratelimit_maxstartups, 4, 60, 20, 5*60);
		log_ratelimit_init(&ratelimit_penalty, 8, 60, 30, 2*60);
	}

	/* PerSourcePenalties */
	ଯଦି (!srclimit_penalty_check_allow(sock, &subreason)) {
		reason = "PerSourcePenalties";
		rl = &ratelimit_penalty;
	} ଅନ୍ୟଥା {
		/* MaxStartups */
		ଯଦି (!should_drop_connection(startups) &&
		    srclimit_check_allow(sock, notify_pipe) == 1)
			ଫେରନ୍ତୁ 0;
		reason = "MaxStartups";
		rl = &ratelimit_maxstartups;
	}

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	ratelimited = log_ratelimit(rl, time(ଖାଲି), ଖାଲି, &ndropped);
	do_log2(ratelimited ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    "drop connection #%d from [%s]:%d on [%s]:%d %s",
	    startups,
	    raddr, get_peer_port(sock),
	    laddr, get_local_port(sock),
	    subreason != ଖାଲି ? subreason : reason);
	ମୁକ୍ତ(laddr);
	ମୁକ୍ତ(raddr);
	ଯଦି (ndropped != 0) {
		logit("%s logging rate-limited: additional %u connections "
		    "dropped", reason, ndropped);
	}

	/* best-effort notification to client */
	(ଶୂନ୍ୟ)ଲିଖ(sock, ସନ୍ଦେଶ, ଆକାର(ସନ୍ଦେଶ) - 1);
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ଶୂନ୍ୟ
usage(ଶୂନ୍ୟ)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

ସ୍ଥିର ସଂରଚନା sshbuf *
pack_hostkeys(ଶୂନ୍ୟ)
{
	ସଂରଚନା sshbuf *m = ଖାଲି, *keybuf = ଖାଲି, *hostkeys = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i;
	size_t len;

	ଯଦି ((m = sshbuf_new()) == ଖାଲି ||
	    (keybuf = sshbuf_new()) == ଖାଲି ||
	    (hostkeys = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_host_ଚାବି_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		ଯଦି (sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i] != ଖାଲି &&
		    (r = sshkey_private_serialize(sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		ଯଦି ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		ଯଦି (sensitive_data.host_pubkeys[i] != ଖାଲି) {
			ଯଦି ((r = sshkey_puts(sensitive_data.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} ଅନ୍ୟଥା {
			ଯଦି ((r = sshbuf_put_string(hostkeys, ଖାଲି, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		ଯଦି (sensitive_data.host_certificates[i] != ଖାଲି) {
			ଯଦି ((r = sshkey_puts(
			    sensitive_data.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} ଅନ୍ୟଥା {
			ଯଦି ((r = sshbuf_put_string(hostkeys, ଖାଲି, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	ଯଦି ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0)
		fatal_fr(r, "compose message");
	ଯଦି ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(keybuf);
	sshbuf_free(hostkeys);
	ଫେରନ୍ତୁ m;
}

ସ୍ଥିର ସଂରଚନା sshbuf *
pack_config(ସଂରଚନା sshbuf *conf)
{
	ସଂରଚନା sshbuf *m = ଖାଲି, *inc = ଖାଲି;
	ସଂରଚନା include_item *item = ଖାଲି;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("d config len %zu", sshbuf_len(conf));

	ଯଦି ((m = sshbuf_new()) == ଖାଲି ||
	    (inc = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(item, &includes, entry) {
		ଯଦି ((r = sshbuf_put_cstring(inc, item->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, item->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	ଯଦି ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	ଯଦି ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(inc);

	debug3_f("done");
	ଫେରନ୍ତୁ m;
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
ସ୍ଥିର ଶୂନ୍ୟ
send_rexec_state(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ସଂରଚନା sshbuf *ଚାବିଗୁଡ଼ିକ;
	u_int mlen;
	pid_t pid;

	ଯଦି ((pid = fork()) == -1)
		fatal_f("fork failed: %s", strerror(errno));
	ଯଦି (pid != 0)
		ଫେରନ୍ତୁ;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(config));

	mlen = sshbuf_len(config);
	ଯଦି (atomicio(vwrite, fd, sshbuf_mutable_ptr(config), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	ଚାବିଗୁଡ଼ିକ = pack_hostkeys();
	mlen = sshbuf_len(ଚାବିଗୁଡ଼ିକ);
	ଯଦି (atomicio(vwrite, fd, sshbuf_mutable_ptr(ଚାବିଗୁଡ଼ିକ), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	sshbuf_free(ଚାବିଗୁଡ଼ିକ);
	debug3_f("done");
	exit(0);
}

/*
 * Listen for TCP connections
 */
ସ୍ଥିର ଶୂନ୍ୟ
listen_on_addrs(ସଂରଚନା listenaddr *la)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret, listen_sock;
	ସଂରଚନା addrinfo *ai;
	ଅକ୍ଷର ntop[NI_MAXHOST], strport[NI_MAXSERV];

	ପାଇଁ (ai = la->addrs; ai; ai = ai->ai_next) {
		ଯଦି (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			ଜାରି;
		ଯଦି (ଅଙ୍କ_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		ଯଦି ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, ଆକାର(ntop), strport, ଆକାର(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			ଜାରି;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		ଯଦି (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			ଜାରି;
		}
		ଯଦି (set_nonblock(listen_sock) == -1) {
			close(listen_sock);
			ଜାରି;
		}
		ଯଦି (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			ଜାରି;
		}
		/* Socket options */
		set_reuseaddr(listen_sock);
		ଯଦି (la->rdomain != ଖାଲି &&
		    set_rdomain(listen_sock, la->rdomain) == -1) {
			close(listen_sock);
			ଜାରି;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		ଯଦି (ai->ai_family == AF_INET6)
			sock_set_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		ଯଦି (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, strerror(errno));
			close(listen_sock);
			ଜାରି;
		}
		listen_socks[ଅଙ୍କ_listen_socks] = listen_sock;
		ଅଙ୍କ_listen_socks++;

		/* Start listening on the port. */
		ଯଦି (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, strerror(errno));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == ଖାଲି ? "" : " rdomain ",
		    la->rdomain == ଖାଲି ? "" : la->rdomain);
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
server_listen(ଶୂନ୍ୟ)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups,
	    options.per_source_max_startups,
	    options.per_source_masklen_ipv4,
	    options.per_source_masklen_ipv6,
	    &options.per_source_penalty,
	    options.per_source_penalty_exempt);

	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		ମୁକ୍ତ(options.listen_addrs[i].rdomain);
		memset(&options.listen_addrs[i], 0,
		    ଆକାର(options.listen_addrs[i]));
	}
	ମୁକ୍ତ(options.listen_addrs);
	options.listen_addrs = ଖାଲି;
	options.ଅଙ୍କ_listen_addrs = 0;

	ଯଦି (!ଅଙ୍କ_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
ସ୍ଥିର ଶୂନ୍ୟ
server_accept_loop(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *sock_in, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *sock_out, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *newsock, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *config_s,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା log_stderr)
{
	ସଂରଚନା pollfd *pfd = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, ret, npfd, r;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା oactive = -1, listening = 0, lameduck = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା *startup_pollfd;
	ssize_t len;
	ଅଚଳ u_char *ptr;
	ଅକ୍ଷର c = 0;
	ସଂରଚନା sockaddr_storage from;
	ସଂରଚନା early_child *child;
	ସଂରଚନା sshbuf *buf;
	socklen_t fromlen;
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	child_alloc();
	startup_pollfd = xcalloc(options.max_startups, ଆକାର(ପୂର୍ଣ୍ଣସଂଖ୍ୟା));

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
	pfd = xcalloc(ଅଙ୍କ_listen_socks + options.max_startups,
	    ଆକାର(ସଂରଚନା pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	ପାଇଁ (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		ଯଦି (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (ପୂର୍ଣ୍ଣସଂଖ୍ୟା) received_sigterm);
			close_listen_socks();
			ଯଦି (options.pid_file != ଖାଲି)
				unlink(options.pid_file);
			exit(received_sigterm == SIGTERM ? 0 : 255);
		}
		ଯଦି (received_sigchld) {
			child_reap_all_exited();
			received_sigchld = 0;
		}
		ଯଦି (received_siginfo) {
			show_info();
			received_siginfo = 0;
		}
		ଯଦି (oactive != children_active) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, children_active,
			    options.max_startups_begin, options.max_startups);
			oactive = children_active;
		}
		ଯଦି (received_sighup) {
			ଯଦି (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			ଯଦି (listening <= 0) {
				/*
				 * Leave termination signals blocked, so
				 * they don't get lost across a restart.
				 */
				sigaddset(&osigset, SIGTERM);
				sigaddset(&osigset, SIGQUIT);
				sigprocmask(SIG_SETMASK, &osigset, ଖାଲି);
				sighup_restart();
			}
		}

		ପାଇଁ (i = 0; i < ଅଙ୍କ_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = ଅଙ୍କ_listen_socks;
		ପାଇଁ (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			ଯଦି (children[i].pipefd != -1) {
				pfd[npfd].fd = children[i].pipefd;
				pfd[npfd].events = POLLIN;
				ଯଦି (children[i].config != ଖାଲି ||
				    children[i].ଚାବିଗୁଡ଼ିକ != ଖାଲି)
					pfd[npfd].events |= POLLOUT;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, ଖାଲି, &osigset);
		ଯଦି (ret == -1 && errno != EINTR) {
			error("ppoll: %.100s", strerror(errno));
			ଯଦି (errno == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, ଖାଲି);
		ଯଦି (ret == -1)
			ଜାରି;

		ପାଇଁ (i = 0; i < options.max_startups; i++) {
			ଯଦି (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & POLLOUT))
				ଜାରି;
			ଯଦି (children[i].config)
				buf = children[i].config;
			ଅନ୍ୟଥା ଯଦି (children[i].ଚାବିଗୁଡ଼ିକ)
				buf = children[i].ଚାବିଗୁଡ଼ିକ;
			ଅନ୍ୟଥା {
				error_f("no buffer to send");
				ଜାରି;
			}
			ptr = sshbuf_ptr(buf);
			len = sshbuf_len(buf);
			ret = ଲିଖ(children[i].pipefd, ptr, len);
			ଯଦି (ret == -1 && (errno == EINTR || errno == EAGAIN))
				ଜାରି;
			ଯଦି (ret <= 0) {
				ଯଦି (children[i].early)
					listening--;
				child_close(&(children[i]), 0, 0);
				ଜାରି;
			}
			ଯଦି (ret == len) {
				/* finished sending buffer */
				sshbuf_free(buf);
				ଯଦି (children[i].config == buf) {
					/* sent config, now send keys */
					children[i].config = ଖାଲି;
					children[i].ଚାବିଗୁଡ଼ିକ = pack_hostkeys();
				} ଅନ୍ୟଥା ଯଦି (children[i].ଚାବିଗୁଡ଼ିକ == buf) {
					/* sent both config and keys */
					children[i].ଚାବିଗୁଡ଼ିକ = ଖାଲି;
				} ଅନ୍ୟଥା {
					fatal("config buf not set");
				}

			} ଅନ୍ୟଥା {
				ଯଦି ((r = sshbuf_consume(buf, ret)) != 0)
					fatal_fr(r, "config buf inconsistent");
			}
		}
		ପାଇଁ (i = 0; i < options.max_startups; i++) {
			ଯଦି (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				ଜାରି;
			ବାଛ (ପଠ(children[i].pipefd, &c, ଆକାର(c))) {
			ସ୍ଥିତି -1:
				ଯଦି (errno == EINTR || errno == EAGAIN)
					ଜାରି;
				ଯଦି (errno != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, children[i].pipefd,
					    strerror(errno));
				}
				/* FALLTHROUGH */
			ସ୍ଥିତି 0:
				/* child closed pipe */
				ଯଦି (children[i].early)
					listening--;
				debug3_f("child %lu for %s closed pipe",
				    (long)children[i].pid, children[i].id);
				child_close(&(children[i]), 0, 0);
				ଭାଙ୍ଗ;
			ସ୍ଥିତି 1:
				ଯଦି (children[i].config) {
					error_f("startup pipe %d (fd=%d)"
					    " early read",
					    i, children[i].pipefd);
					ଯାଅ problem_child;
				}
				ଯଦି (children[i].early && c == '\0') {
					/* child has finished preliminaries */
					listening--;
					children[i].early = 0;
					debug2_f("child %lu for %s received "
					    "config", (long)children[i].pid,
					    children[i].id);
				} ଅନ୍ୟଥା ଯଦି (!children[i].early && c == '\001') {
					/* child has completed auth */
					debug2_f("child %lu for %s auth done",
					    (long)children[i].pid,
					    children[i].id);
					child_close(&(children[i]), 1, 0);
				} ଅନ୍ୟଥା {
					error_f("unexpected message 0x%02x "
					    "child %ld for %s in state %d",
					    (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)c, (long)children[i].pid,
					    children[i].id, children[i].early);
 problem_child:
					ଯଦି (children[i].early)
						listening--;
					ଯଦି (children[i].pid > 0)
						kill(children[i].pid, SIGTERM);
					child_close(&(children[i]), 0, 0);
				}
				ଭାଙ୍ଗ;
			}
		}
		ପାଇଁ (i = 0; i < ଅଙ୍କ_listen_socks; i++) {
			ଯଦି (!(pfd[i].revents & POLLIN))
				ଜାରି;
			fromlen = ଆକାର(from);
			*newsock = accept(listen_socks[i],
			    (ସଂରଚନା sockaddr *)&from, &fromlen);
			ଯଦି (*newsock == -1) {
				ଯଦି (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED && errno != EAGAIN)
					error("accept: %.100s",
					    strerror(errno));
				ଯଦି (errno == EMFILE || errno == ENFILE)
					usleep(100 * 1000);
				ଜାରି;
			}
			ଯଦି (unset_nonblock(*newsock) == -1) {
				close(*newsock);
				ଜାରି;
			}
			ଯଦି (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    strerror(errno));
				close(*newsock);
				ଜାରି;
			}
			ଯଦି (drop_connection(*newsock,
			    children_active, config_s[0])) {
				close(*newsock);
				close(config_s[0]);
				close(config_s[1]);
				ଜାରି;
			}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			ଯଦି (debug_flag) {
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
				ମୁକ୍ତ(pfd);
				ମୁକ୍ତ(startup_pollfd);
				ଫେରନ୍ତୁ;
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
			ଯଦି ((child->pid = fork()) == 0) {
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
				ମୁକ୍ତ(pfd);
				ମୁକ୍ତ(startup_pollfd);
				ଫେରନ୍ତୁ;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_parent(child->pid);
			ଯଦି (child->pid == -1)
				error("fork: %.100s", strerror(errno));
			ଅନ୍ୟଥା
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

ସ୍ଥିର ଶୂନ୍ୟ
accumulate_host_timing_secret(ସଂରଚନା sshbuf *server_cfg,
    ସଂରଚନା sshkey *ଚାବି)
{
	ସ୍ଥିର ସଂରଚନା ssh_digest_ctx *ctx;
	u_char *hash;
	size_t len;
	ସଂରଚନା sshbuf *buf;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (ctx == ଖାଲି && (ctx = ssh_digest_start(SSH_DIGEST_SHA512)) == ଖାଲି)
		fatal_f("ssh_digest_start");
	ଯଦି (ଚାବି == ଖାଲି) { /* finalize */
		/* add server config in case we are using agent for host keys */
		ଯଦି (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_bytes(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		ଯଦି (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = ଖାଲି;
		ଫେରନ୍ତୁ;
	}
	ଯଦି ((buf = sshbuf_new()) == ଖାଲି)
		fatal_f("could not allocate buffer");
	ଯଦି ((r = sshkey_private_serialize(ଚାବି, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(ଚାବି));
	ଯଦି (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

ସ୍ଥିର ଅକ୍ଷର *
prepare_proctitle(ପୂର୍ଣ୍ଣସଂଖ୍ୟା ac, ଅକ୍ଷର **av)
{
	ଅକ୍ଷର *ret = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ପାଇଁ (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	ଫେରନ୍ତୁ ret;
}

/* Disconnect from the controlling tty. */
ସ୍ଥିର ଶୂନ୍ୟ
disconnect_controlling_tty(ଶୂନ୍ୟ)
{
#ifdef TIOCNOTTY
# ifndef O_NOCTTY
#  define O_NOCTTY 0
# endif
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;

	ଯଦି ((fd = open(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(ଶୂନ୍ୟ) ioctl(fd, TIOCNOTTY, ଖାଲି);
		close(fd);
	}
#endif /* TIOCNOTTY */
}

ସ୍ଥିର ଶୂନ୍ୟ
print_config(ସଂରଚନା connection_info *connection_info)
{
	connection_info->test = 1;
	parse_server_match_config(&options, &includes, connection_info);
	dump_config(&options);
	exit(0);
}

/*
 * Main program for the daemon.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା ac, ଅକ୍ଷର **av)
{
	ବାହ୍ୟ ଅକ୍ଷର *optarg;
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା optind;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	ଅକ୍ଷର *config_file_name = _PATH_SERVER_CONFIG_FILE;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock_in = -1, sock_out = -1, newsock = -1, rexec_argc = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା devnull, config_s[2] = { -1 , -1 }, have_connection_info = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା need_chroot = 1;
	ଅକ୍ଷର *args, *fp, *ଧାଡ଼ି, *logfile = ଖାଲି, **rexec_argv = ଖାଲି;
	ସଂରଚନା stat sb;
	u_int i, j;
	mode_t new_umask;
	ସଂରଚନା sshkey *ଚାବି;
	ସଂରଚନା sshkey *pubkey;
	ସଂରଚନା connection_info connection_info;
	ସଂରଚନା utsname utsname;
	sigset_t sigmask;

	memset(&connection_info, 0, ଆକାର(connection_info));
#ifdef HAVE_SECUREWARE
	(ଶୂନ୍ୟ)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ଖାଲି);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, ଆକାର(*saved_argv));
	ପାଇଁ (i = 0; (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ଖାଲି;

#ifndef HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#endif

	ଯଦି (geteuid() == 0 && setgroups(0, ଖାଲି) == -1)
		debug("setgroups(): %.200s", strerror(errno));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	ଯେତେବେଳେ ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		ବାଛ (opt) {
		ସ୍ଥିତି '4':
			options.address_family = AF_INET;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '6':
			options.address_family = AF_INET6;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'f':
			config_file_name = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'c':
			servconf_add_hostcert("[command-line]", 0,
			    &options, optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'd':
			ଯଦି (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ଅନ୍ୟଥା ଯଦି (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'D':
			no_daemon_flag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'G':
			do_dump_cfg = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		ସ୍ଥିତି 'e':
			log_stderr = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'i':
			inetd_flag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'r':
			logit("-r option is deprecated");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'R':
			fatal("-R not supported here");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'Q':
			/* ignored */
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'b':
			/* protocol 1, ignored */
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'p':
			options.ports_from_cmdline = 1;
			ଯଦି (options.ଅଙ୍କ_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				exit(1);
			}
			options.ports[options.ଅଙ୍କ_ports++] = a2port(optarg);
			ଯଦି (options.ports[options.ଅଙ୍କ_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				exit(1);
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'g':
			ଯଦି ((options.login_grace_time = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				exit(1);
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'k':
			/* protocol 1, ignored */
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'h':
			servconf_add_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 't':
			test_flag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'T':
			test_flag = 2;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'C':
			ଯଦି (parse_server_match_testspec(&connection_info,
			    optarg) == -1)
				exit(1);
			have_connection_info = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'u':
			utmp_len = (u_int)strtonum(optarg, 0,
			    HOST_NAME_MAX+1+1, ଖାଲି);
			ଯଦି (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'o':
			ଧାଡ଼ି = xstrdup(optarg);
			ଯଦି (process_server_config_ଧାଡ଼ି(&options, ଧାଡ଼ି,
			    "command-line", 0, ଖାଲି, ଖାଲି, &includes) != 0)
				exit(1);
			ମୁକ୍ତ(ଧାଡ଼ି);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			usage();
			ଭାଙ୍ଗ;
		}
	}

	ଯଦି (getexecpath(execpath, ଆକାର execpath) != 0) {
		ଯଦି (strlcpy(execpath, av[0], ଆକାର execpath) >=
		    ଆକାର execpath) {
			fprintf(stderr, "execution path is too long\n");
			exit(1);
		}
	}
	ଯଦି (!test_flag && !inetd_flag && !do_dump_cfg && !path_absolute(execpath))
		fatal("sshd requires execution with an absolute path");

	closefrom(STDERR_FILENO + 1);

	/* Reserve fds we'll need later for reexec things */
	ଯଦି ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	ଯେତେବେଳେ (devnull < REEXEC_MIN_FREE_FD) {
		ଯଦି ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	seed_rng();

	/* If requested, redirect the logs to the specified logfile. */
	ଯଦି (logfile != ଖାଲି) {
		ଅକ୍ଷର *cp, pid_s[32];

		snprintf(pid_s, ଆକାର(pid_s), "%ld", (unsigned long)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (ଅକ୍ଷର *)ଖାଲି);
		log_redirect_stderr_to(cp);
		ମୁକ୍ତ(cp);
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
	ଯଦି (getenv("KRB5CCNAME") != ଖାଲି)
		(ଶୂନ୍ୟ) unsetenv("KRB5CCNAME");

	sensitive_data.have_ssh2_ଚାବି = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	ଯଦି (test_flag < 2 && have_connection_info)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	debug("sshd version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);
	ଯଦି (uname(&utsname) != 0) {
		memset(&utsname, 0, ଆକାର(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", ଆକାର(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	ମୁକ୍ତ(args);

	/* Fetch our configuration */
	ଯଦି ((cfg = sshbuf_new()) == ଖାଲି)
		fatal("sshbuf_new config failed");
	ଯଦି (strcasecmp(config_file_name, "none") != 0)
		load_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, ଖାଲି, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	ଯଦି (options.authorized_ଚାବିଗୁଡ଼ିକ_command_user == ଖାଲି &&
	    (options.authorized_ଚାବିଗୁଡ଼ିକ_command != ଖାଲି &&
	    strcasecmp(options.authorized_ଚାବିଗୁଡ଼ିକ_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	ଯଦି (options.authorized_principals_command_user == ଖାଲି &&
	    (options.authorized_principals_command != ଖାଲି &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match blocks, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	ଯଦି (options.ଅଙ୍କ_auth_methods != 0) {
		ପାଇଁ (i = 0; i < options.ଅଙ୍କ_auth_methods; i++) {
			ଯଦି (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				ଭାଙ୍ଗ;
		}
		ଯଦି (i >= options.ଅଙ୍କ_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	ଯଦି (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	ଯଦି (do_dump_cfg)
		print_config(&connection_info);

	/* load host keys */
	sensitive_data.host_ଚାବିଗୁଡ଼ିକ = xcalloc(options.ଅଙ୍କ_host_ଚାବି_files,
	    ଆକାର(ସଂରଚନା sshkey *));
	sensitive_data.host_pubkeys = xcalloc(options.ଅଙ୍କ_host_ଚାବି_files,
	    ଆକାର(ସଂରଚନା sshkey *));

	ଯଦି (options.host_ଚାବି_agent) {
		ଯଦି (strcmp(options.host_ଚାବି_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_ଚାବି_agent, 1);
		ଯଦି ((r = ssh_get_authentication_socket(ଖାଲି)) == 0)
			have_agent = 1;
		ଅନ୍ୟଥା
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_ଚାବି_agent);
	}

	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_host_ଚାବି_files; i++) {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା ll = options.host_ଚାବି_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		ଯଦି (options.host_ଚାବି_files[i] == ଖାଲି)
			ଜାରି;
		ଯଦି ((r = sshkey_load_private(options.host_ଚାବି_files[i], "",
		    &ଚାବି, ଖାଲି)) != 0 &&
		    r != SSH_ERR_SYSTEM_ERROR && !have_agent)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_ଚାବି_files[i]);
		ଯଦି (sshkey_is_sk(ଚାବି) &&
		    ଚାବି->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_ଚାବି_files[i]);
			ଚାବି->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		ଯଦି (r == 0 && ଚାବି != ଖାଲି &&
		    (r = sshkey_shield_private(ଚାବି)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_ଚାବି_files[i]);
			sshkey_free(ଚାବି);
			ଚାବି = ଖାଲି;
		}
		ଯଦି ((r = sshkey_load_public(options.host_ଚାବି_files[i],
		    &pubkey, ଖାଲି)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_ଚାବି_files[i]);
		ଯଦି (pubkey != ଖାଲି && ଚାବି != ଖାଲି) {
			ଯଦି (!sshkey_equal(pubkey, ଚାବି)) {
				error("Public key for %s does not match "
				    "private key", options.host_ଚାବି_files[i]);
				sshkey_free(pubkey);
				pubkey = ଖାଲି;
			}
		}
		ଯଦି (pubkey == ଖାଲି && ଚାବି != ଖାଲି) {
			ଯଦି ((r = sshkey_from_private(ଚାବି, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_ଚାବି_files[i]);
		}
		ଯଦି (pubkey != ଖାଲି && (r = sshkey_check_rsa_length(pubkey,
		    options.required_rsa_size)) != 0) {
			error_fr(r, "Host key %s", options.host_ଚାବି_files[i]);
			sshkey_free(pubkey);
			sshkey_free(ଚାବି);
			ଜାରି;
		}
		sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i] = ଚାବି;
		sensitive_data.host_pubkeys[i] = pubkey;

		ଯଦି (ଚାବି == ଖାଲି && pubkey != ଖାଲି && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_ଚାବି_files[i]);
			keytype = pubkey->type;
		} ଅନ୍ୟଥା ଯଦି (ଚାବି != ଖାଲି) {
			keytype = ଚାବି->type;
			accumulate_host_timing_secret(cfg, ଚାବି);
		} ଅନ୍ୟଥା {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_ଚାବି_files[i]);
			sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i] = ଖାଲି;
			sensitive_data.host_pubkeys[i] = ଖାଲି;
			ଜାରି;
		}

		ବାଛ (keytype) {
		ସ୍ଥିତି ଚାବି_RSA:
		ସ୍ଥିତି ଚାବି_ECDSA:
		ସ୍ଥିତି ଚାବି_ED25519:
		ସ୍ଥିତି ଚାବି_MLDSA44_ED25519:
		ସ୍ଥିତି ଚାବି_ECDSA_SK:
		ସ୍ଥିତି ଚାବି_ED25519_SK:
			ଯଦି (have_agent || ଚାବି != ଖାଲି)
				sensitive_data.have_ssh2_ଚାବି = 1;
			ଭାଙ୍ଗ;
		}
		ଯଦି ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == ଖାଲି)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    ଚାବି ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		ମୁକ୍ତ(fp);
	}
	accumulate_host_timing_secret(cfg, ଖାଲି);
	ଯଦି (!sensitive_data.have_ssh2_ଚାବି) {
		logit("sshd: no hostkeys available -- exiting.");
		exit(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_data.host_certificates = xcalloc(options.ଅଙ୍କ_host_ଚାବି_files,
	    ଆକାର(ସଂରଚନା sshkey *));
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_host_ଚାବି_files; i++)
		sensitive_data.host_certificates[i] = ଖାଲି;

	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_host_cert_files; i++) {
		ଯଦି (options.host_cert_files[i] == ଖାଲି)
			ଜାରି;
		ଯଦି ((r = sshkey_load_public(options.host_cert_files[i],
		    &ଚାବି, ଖାଲି)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			ଜାରି;
		}
		ଯଦି (!sshkey_is_cert(ଚାବି)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(ଚାବି);
			ଜାରି;
		}
		/* Find matching private key */
		ପାଇଁ (j = 0; j < options.ଅଙ୍କ_host_ଚାବି_files; j++) {
			ଯଦି (sshkey_equal_public(ଚାବି,
			    sensitive_data.host_pubkeys[j])) {
				sensitive_data.host_certificates[j] = ଚାବି;
				ଭାଙ୍ଗ;
			}
		}
		ଯଦି (j >= options.ଅଙ୍କ_host_ଚାବି_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(ଚାବି);
			ଜାରି;
		}
		sensitive_data.host_certificates[j] = ଚାବି;
		debug("host certificate: #%u type %d %s", j, ଚାବି->type,
		    sshkey_type(ଚାବି));
	}

	/* Ensure privsep directory is correctly configured. */
	need_chroot = ((getuid() == 0 || geteuid() == 0) ||
	    options.kerberos_authentication);
	ଯଦି ((getpwnam(SSH_PRIVSEP_USER)) == ଖାଲି && need_chroot) {
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	}
	endpwent();

	ଯଦି (need_chroot) {
		ଯଦି ((stat(_PATH_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
		    (S_ISDIR(sb.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    _PATH_PRIVSEP_CHROOT_DIR);
#ifdef HAVE_CYGWIN
		ଯଦି (check_ntsec(_PATH_PRIVSEP_CHROOT_DIR) &&
		    (sb.st_uid != getuid () ||
		    (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#ଅନ୍ୟଥା
		ଯଦି (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#endif
			fatal("%s must be owned by root and not group or "
			    "world-writable.", _PATH_PRIVSEP_CHROOT_DIR);
	}

	ଯଦି (test_flag > 1)
		print_config(&connection_info);

	config = pack_config(cfg);
	ଯଦି (sshbuf_len(config) > MONITOR_MAX_CFGLEN) {
		fatal("Configuration file is too large (have %zu, max %d)",
		    sshbuf_len(config), MONITOR_MAX_CFGLEN);
	}

	/* Configuration looks good, so exit if in test mode. */
	ଯଦି (test_flag)
		exit(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	ଯଦି (setgroups(0, ଖାଲି) < 0)
		debug("setgroups() failed: %.200s", strerror(errno));

	/* Prepare arguments for sshd-session */
	ଯଦି (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, ଆକାର(ଅକ୍ଷର *));
	/* Point to the sshd-session binary instead of sshd */
	rexec_argv[0] = options.sshd_session_path;
	ପାଇଁ (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = ଖାଲି;
	ଯଦି (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	ଯଦି (stat(options.sshd_auth_path, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_auth_path);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(ଶୂନ୍ୟ) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	ଯଦି (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	ଯଦି (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		ଯଦି (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", strerror(errno));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	ଯଦି (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or a listening TCP socket */
	ଯଦି (inetd_flag) {
		/* Send configuration to ancestor sshd-session process */
		ଯଦି (socketpair(AF_UNIX, SOCK_STREAM, 0, config_s) == -1)
			fatal("socketpair: %s", strerror(errno));
		send_rexec_state(config_s[0]);
		close(config_s[0]);
	} ଅନ୍ୟଥା {
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
		ଯଦି (options.pid_file != ଖାଲି && !debug_flag) {
			FILE *f = fopen(options.pid_file, "w");

			ଯଦି (f == ଖାଲି) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, strerror(errno));
			} ଅନ୍ୟଥା {
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
	ଯଦି (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	debug("rexec start in %d out %d newsock %d config_s %d/%d",
	    sock_in, sock_out, newsock, config_s[0], config_s[1]);
	ଯଦି (!inetd_flag) {
		ଯଦି (dup2(newsock, STDIN_FILENO) == -1)
			fatal("dup2 stdin: %s", strerror(errno));
		ଯଦି (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			fatal("dup2 stdout: %s", strerror(errno));
		ଯଦି (newsock > STDOUT_FILENO)
			close(newsock);
	}
	ଯଦି (config_s[1] != REEXEC_CONFIG_PASS_FD) {
		ଯଦି (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			fatal("dup2 config_s: %s", strerror(errno));
		close(config_s[1]);
	}
	log_redirect_stderr_to(ଖାଲି);
	closefrom(REEXEC_MIN_FREE_FD);

	ssh_signal(SIGHUP, SIG_IGN); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], strerror(errno));
}

/* server specific fatal cleanup */
ଶୂନ୍ୟ
cleanup_exit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା i)
{
	_exit(i);
}
