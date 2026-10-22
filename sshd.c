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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/ioctl.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/time.h>
#అన్తర్భావ <sys/queue.h>
#అన్తర్భావ <sys/wait.h>
#అన్తర్భావ <sys/utsname.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <grp.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>

#నిర్వచితమైతే HAVE_SECUREWARE
#అన్తర్భావ <sys/security.h>
#అన్తర్భావ <prot.h>
#అయితే_ముగింపు

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "sshpty.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "authfd.h"
#అన్తర్భావ "msg.h"
#అన్తర్భావ "version.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sk-api.h"
#అన్తర్భావ "addr.h"
#అన్తర్భావ "srclimit.h"
#అన్తర్భావ "atomicio.h"
#నిర్వచితమైతే GSSAPI
#అన్తర్భావ "ssh-gss.h"
#అయితే_ముగింపు
#అన్తర్భావ "monitor_wrap.h"

/* Re-exec fds */
#నిర్వచించు REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#నిర్వచించు REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#నిర్వచించు REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

బాహ్య అక్షరం *__progname;

/* Server configuration options. */
ServerOptions options;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
పూర్ణాంకం debug_flag = 0;

/* Saved arguments to main(). */
స్థిర అక్షరం execpath[PATH_MAX];
స్థిర అక్షరం **saved_argv;
స్థిర పూర్ణాంకం saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#నిర్వచించు	MAX_LISTEN_SOCKS	16
స్థిర పూర్ణాంకం listen_socks[MAX_LISTEN_SOCKS];
స్థిర పూర్ణాంకం అంకె_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
నిర్మాణం {
	నిర్మాణం sshkey	**host_కీలకాలు;		/* all private host keys */
	నిర్మాణం sshkey	**host_pubkeys;		/* all public host keys */
	నిర్మాణం sshkey	**host_certificates;	/* all public host certificates */
	పూర్ణాంకం		have_ssh2_కీలకం;
} sensitive_దత్తాంశం;

/* This is set to true when a signal is received. */
స్థిర అస్థిర sig_atomic_t received_siginfo = 0;
స్థిర అస్థిర sig_atomic_t received_sigchld = 0;
స్థిర అస్థిర sig_atomic_t received_sighup = 0;
స్థిర అస్థిర sig_atomic_t received_sigterm = 0;

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
నిర్మాణం early_బిడ్డ {
	పూర్ణాంకం pipefd;
	పూర్ణాంకం early;		/* Indicates child closed listener */
	అక్షరం *id;		/* human readable connection identifier */
	pid_t pid;
	నిర్మాణం xaddr addr;
	పూర్ణాంకం have_addr;
	పూర్ణాంకం స్థితి_2, have_స్థితి;
	నిర్మాణం sshbuf *config;
	నిర్మాణం sshbuf *కీలకాలు;
};
స్థిర నిర్మాణం early_బిడ్డ *children;
స్థిర పూర్ణాంకం children_చురుకైన;

/* sshd_config buffer */
నిర్మాణం sshbuf *cfg;
నిర్మాణం sshbuf *config;	/* packed */

/* Included files from the configuration file */
నిర్మాణం include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
నిర్మాణం sshbuf *loginmsg;

/* Unprivileged user */
నిర్మాణం passwd *privsep_pw = ఖాళీ;

స్థిర అక్షరం *listener_proctitle;

/*
 * Close all listening sockets
 */
స్థిర శూన్య
close_listen_socks(శూన్య)
{
	పూర్ణాంకం i;

	కొరకు (i = 0; i < అంకె_listen_socks; i++)
		close(listen_socks[i]);
	అంకె_listen_socks = 0;
}

/* Allocate and initialise the children array */
స్థిర శూన్య
బిడ్డ_alloc(శూన్య)
{
	పూర్ణాంకం i;

	children = xcalloc(options.max_startups, పరిమాణం(*children));
	కొరకు (i = 0; i < options.max_startups; i++) {
		children[i].pipefd = -1;
		children[i].pid = -1;
	}
}

/* Register a new connection in the children array; child pid comes later */
స్థిర నిర్మాణం early_బిడ్డ *
బిడ్డ_రిజిస్టరు(పూర్ణాంకం pipefd, పూర్ణాంకం sockfd)
{
	పూర్ణాంకం i, lport, rport;
	అక్షరం *laddr = ఖాళీ, *raddr = ఖాళీ;
	నిర్మాణం early_బిడ్డ *బిడ్డ = ఖాళీ;
	నిర్మాణం sockaddr_storage addr;
	socklen_t addrlen = పరిమాణం(addr);
	నిర్మాణం sockaddr *sa = (నిర్మాణం sockaddr *)&addr;

	కొరకు (i = 0; i < options.max_startups; i++) {
		ఒకవేళ (children[i].pipefd != -1 ||
		    children[i].config != ఖాళీ ||
		    children[i].కీలకాలు != ఖాళీ ||
		    children[i].pid > 0)
			కొనసాగు;
		బిడ్డ = &(children[i]);
		ఆపు;
	}
	ఒకవేళ (బిడ్డ == ఖాళీ) {
		fatal_f("error: accepted connection when all %d child "
		    " slots full", options.max_startups);
	}
	బిడ్డ->pipefd = pipefd;
	బిడ్డ->early = 1;
	ఒకవేళ ((బిడ్డ->config = sshbuf_fromb(config)) == ఖాళీ)
		fatal_f("sshbuf_fromb failed");
	/* record peer address, if available */
	ఒకవేళ (getpeername(sockfd, sa, &addrlen) == 0 &&
	   addr_sa_గమ్యం_xaddr(sa, addrlen, &బిడ్డ->addr) == 0)
		బిడ్డ->have_addr = 1;
	/* format peer address string for logs */
	ఒకవేళ ((lport = get_local_పోర్టు(sockfd)) == 0 ||
	    (rport = get_peer_పోర్టు(sockfd)) == 0) {
		/* Not a TCP socket */
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&బిడ్డ->id, "connection from %s", raddr);
	} లేకపోతే {
		laddr = get_local_ipaddr(sockfd);
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&బిడ్డ->id, "connection from %s to %s", raddr, laddr);
	}
	విడుదల(laddr);
	విడుదల(raddr);
	ఒకవేళ (++children_చురుకైన > options.max_startups)
		fatal_f("internal error: more children than max_startups");

	తిరిగి బిడ్డ;
}

/*
 * Finally free a child entry. Don't call this directly.
 */
స్థిర శూన్య
బిడ్డ_ముగింపు(నిర్మాణం early_బిడ్డ *బిడ్డ)
{
	ఒకవేళ (children_చురుకైన == 0)
		fatal_f("internal error: children_active underflow");
	ఒకవేళ (బిడ్డ->pipefd != -1) {
		srclimit_పూర్తి(బిడ్డ->pipefd);
		close(బిడ్డ->pipefd);
	}
	sshbuf_free(బిడ్డ->config);
	sshbuf_free(బిడ్డ->కీలకాలు);
	విడుదల(బిడ్డ->id);
	memset(బిడ్డ, '\0', పరిమాణం(*బిడ్డ));
	బిడ్డ->pipefd = -1;
	బిడ్డ->pid = -1;
	children_చురుకైన--;
}

/*
 * Close a child's pipe. This will not stop tracking the child immediately
 * (it will still be tracked for waitpid()) unless force_final is set, or
 * child has already exited.
 */
స్థిర శూన్య
బిడ్డ_close(నిర్మాణం early_బిడ్డ *బిడ్డ, పూర్ణాంకం force_final, పూర్ణాంకం quiet)
{
	ఒకవేళ (!quiet)
		debug_f("enter%s", force_final ? " (forcing)" : "");
	ఒకవేళ (బిడ్డ->pipefd != -1) {
		srclimit_పూర్తి(బిడ్డ->pipefd);
		close(బిడ్డ->pipefd);
		బిడ్డ->pipefd = -1;
	}
	ఒకవేళ (బిడ్డ->pid == -1 || force_final)
		బిడ్డ_ముగింపు(బిడ్డ);
}

/* Record a child exit. Safe to call from signal handlers */
స్థిర శూన్య
బిడ్డ_exit(pid_t pid, పూర్ణాంకం స్థితి_2)
{
	పూర్ణాంకం i;

	ఒకవేళ (children == ఖాళీ || pid <= 0)
		తిరిగి;
	కొరకు (i = 0; i < options.max_startups; i++) {
		ఒకవేళ (children[i].pid == pid) {
			children[i].have_స్థితి = 1;
			children[i].స్థితి_2 = స్థితి_2;
			ఆపు;
		}
	}
}

/*
 * Reap a child entry that has exited, as previously flagged
 * using child_exit().
 * Handles logging of exit condition and will finalise the child if its pipe
 * had already been closed.
 */
స్థిర శూన్య
బిడ్డ_reap(నిర్మాణం early_బిడ్డ *బిడ్డ)
{
	LogLevel level = SYSLOG_LEVEL_DEBUG1;
	పూర్ణాంకం was_crash, penalty_type = SRCLIMIT_PENALTY_NONE;
	స్థిరరాశి అక్షరం *బిడ్డ_స్థితి;

	ఒకవేళ (బిడ్డ->config)
		బిడ్డ_స్థితి = " (sending config)";
	లేకపోతే ఒకవేళ (బిడ్డ->కీలకాలు)
		బిడ్డ_స్థితి = " (sending keys)";
	లేకపోతే ఒకవేళ (బిడ్డ->early)
		బిడ్డ_స్థితి = " (early)";
	లేకపోతే
		బిడ్డ_స్థితి = "";

	/* Log exit information */
	ఒకవేళ (WIFSIGNALED(బిడ్డ->స్థితి_2)) {
		/*
		 * Increase logging for signals potentially associated
		 * with serious conditions.
		 */
		ఒకవేళ ((was_crash = signal_is_crash(WTERMSIG(బిడ్డ->స్థితి_2))))
			level = SYSLOG_LEVEL_ERROR;
		do_log2(level, "session process %ld for %s killed by "
		    "signal %d%s", (దీర్ఘ)బిడ్డ->pid, బిడ్డ->id,
		    WTERMSIG(బిడ్డ->స్థితి_2), బిడ్డ_స్థితి);
		ఒకవేళ (was_crash)
			penalty_type = SRCLIMIT_PENALTY_CRASH;
	} లేకపోతే ఒకవేళ (!WIFEXITED(బిడ్డ->స్థితి_2)) {
		penalty_type = SRCLIMIT_PENALTY_CRASH;
		error("session process %ld for %s terminated abnormally, "
		    "status=0x%x%s", (దీర్ఘ)బిడ్డ->pid, బిడ్డ->id, బిడ్డ->స్థితి_2,
		    బిడ్డ_స్థితి);
	} లేకపోతే {
		/* Normal exit. We care about the status */
		ఎంపిక (WEXITSTATUS(బిడ్డ->స్థితి_2)) {
		స్థితి 0:
			debug3_f("preauth child %ld for %s completed "
			    "normally%s", (దీర్ఘ)బిడ్డ->pid, బిడ్డ->id,
			    బిడ్డ_స్థితి);
			ఆపు;
		స్థితి EXIT_LOGIN_GRACE:
			penalty_type = SRCLIMIT_PENALTY_GRACE_EXCEEDED;
			logit("Timeout before authentication for %s, "
			    "pid = %ld%s", బిడ్డ->id, (దీర్ఘ)బిడ్డ->pid,
			    బిడ్డ_స్థితి);
			ఆపు;
		స్థితి EXIT_బిడ్డ_CRASH:
			penalty_type = SRCLIMIT_PENALTY_CRASH;
			logit("Session process %ld unpriv child crash for %s%s",
			    (దీర్ఘ)బిడ్డ->pid, బిడ్డ->id, బిడ్డ_స్థితి);
			ఆపు;
		స్థితి EXIT_AUTH_ATTEMPTED:
			penalty_type = SRCLIMIT_PENALTY_AUTHFAIL;
			debug_f("preauth child %ld for %s exited "
			    "after unsuccessful auth attempt%s",
			    (దీర్ఘ)బిడ్డ->pid, బిడ్డ->id, బిడ్డ_స్థితి);
			ఆపు;
		స్థితి EXIT_INVALID_USER:
			penalty_type = SRCLIMIT_PENALTY_INVALIDUSER;
			debug_f("preauth child %ld for %s exited "
			    "after auth attempt by invalid user%s",
			    (దీర్ఘ)బిడ్డ->pid, బిడ్డ->id, బిడ్డ_స్థితి);
			ఆపు;
		స్థితి EXIT_CONFIG_REFUSED:
			penalty_type = SRCLIMIT_PENALTY_REFUSECONNECTION;
			debug_f("preauth child %ld for %s prohibited by"
			    "RefuseConnection%s",
			    (దీర్ఘ)బిడ్డ->pid, బిడ్డ->id, బిడ్డ_స్థితి);
			ఆపు;
		అప్రమేయ:
			penalty_type = SRCLIMIT_PENALTY_NOAUTH;
			debug_f("preauth child %ld for %s exited "
			    "with status %d%s", (దీర్ఘ)బిడ్డ->pid, బిడ్డ->id,
			    WEXITSTATUS(బిడ్డ->స్థితి_2), బిడ్డ_స్థితి);
			ఆపు;
		}
	}

	ఒకవేళ (బిడ్డ->have_addr)
		srclimit_penalise(&బిడ్డ->addr, penalty_type);

	బిడ్డ->pid = -1;
	బిడ్డ->have_స్థితి = 0;
	ఒకవేళ (బిడ్డ->pipefd == -1)
		బిడ్డ_ముగింపు(బిడ్డ);
}

/* Reap all children that have exited; called after SIGCHLD */
స్థిర శూన్య
బిడ్డ_reap_all_exited(శూన్య)
{
	పూర్ణాంకం i;
	pid_t pid;
	పూర్ణాంకం స్థితి_2;

	ఒకవేళ (children == ఖాళీ)
		తిరిగి;

	కొరకు (;;) {
		ఒకవేళ ((pid = waitpid(-1, &స్థితి_2, WNOHANG)) == 0)
			ఆపు;
		లేకపోతే ఒకవేళ (pid == -1) {
			ఒకవేళ (errno == EINTR || errno == EAGAIN)
				కొనసాగు;
			ఒకవేళ (errno != ECHILD)
				error_f("waitpid: %s", strerror(errno));
			ఆపు;
		}
		బిడ్డ_exit(pid, స్థితి_2);
	}

	కొరకు (i = 0; i < options.max_startups; i++) {
		ఒకవేళ (!children[i].have_స్థితి)
			కొనసాగు;
		బిడ్డ_reap(&(children[i]));
	}
}

స్థిర శూన్య
close_startup_pipes(శూన్య)
{
	పూర్ణాంకం i;

	ఒకవేళ (children == ఖాళీ)
		తిరిగి;
	కొరకు (i = 0; i < options.max_startups; i++) {
		ఒకవేళ (children[i].pipefd != -1)
			బిడ్డ_close(&(children[i]), 1, 1);
	}
}

/* Called after SIGINFO */
స్థిర శూన్య
show_info(శూన్య)
{
	పూర్ణాంకం i;
	స్థిరరాశి అక్షరం *బిడ్డ_స్థితి;

	/* XXX print listening sockets here too */
	ఒకవేళ (children == ఖాళీ)
		తిరిగి;
	logit("%d active startups", children_చురుకైన);
	కొరకు (i = 0; i < options.max_startups; i++) {
		ఒకవేళ (children[i].pipefd == -1 && children[i].pid <= 0)
			కొనసాగు;
		ఒకవేళ (children[i].config)
			బిడ్డ_స్థితి = " (sending config)";
		లేకపోతే ఒకవేళ (children[i].కీలకాలు)
			బిడ్డ_స్థితి = " (sending keys)";
		లేకపోతే ఒకవేళ (children[i].early)
			బిడ్డ_స్థితి = " (early)";
		లేకపోతే
			బిడ్డ_స్థితి = "";
		logit("child %d: fd=%d pid=%ld %s%s", i, children[i].pipefd,
		    (దీర్ఘ)children[i].pid, children[i].id, బిడ్డ_స్థితి);
	}
	srclimit_penalty_info();
}

/*
 * Signal handler for SIGHUP.  Sshd execs itself when it receives SIGHUP;
 * the effect is to reread the configuration file (and to regenerate
 * the server key).
 */

స్థిర శూన్య
sighup_handler(పూర్ణాంకం sig)
{
	received_sighup = 1;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
స్థిర శూన్య
sighup_restart(శూన్య)
{
	logit("Received SIGHUP; restarting.");
	ఒకవేళ (options.pid_file != ఖాళీ)
		unlink(options.pid_file);
	platform_pre_restart();
	close_listen_socks();
	close_startup_pipes();
	ssh_signal(SIGHUP, SIG_IGN); /* will be restored after exec */
	execv(execpath, saved_argv);
	logit("RESTART FAILED: execpath='%.100s', error: %.100s.", execpath,
	    strerror(errno));
	నిష్క్రమించు(1);
}

/*
 * Generic signal handler for terminating signals in the master daemon.
 */
స్థిర శూన్య
sigterm_handler(పూర్ణాంకం sig)
{
	received_sigterm = sig;
}

#నిర్వచితమైతే SIGINFO
స్థిర శూన్య
siginfo_handler(పూర్ణాంకం sig)
{
	received_siginfo = 1;
}
#అయితే_ముగింపు

స్థిర శూన్య
main_sigchld_handler(పూర్ణాంకం sig)
{
	received_sigchld = 1;
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
స్థిర పూర్ణాంకం
should_drop_connection(పూర్ణాంకం startups)
{
	పూర్ణాంకం p, r;

	ఒకవేళ (startups < options.max_startups_begin)
		తిరిగి 0;
	ఒకవేళ (startups >= options.max_startups)
		తిరిగి 1;
	ఒకవేళ (options.max_startups_రేటు == 100)
		తిరిగి 1;

	p  = 100 - options.max_startups_రేటు;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_రేటు;
	r = arc4random_ఏకరీతి(100);

	debug_f("p %d, r %d", p, r);
	తిరిగి (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups or for penalty.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
స్థిర పూర్ణాంకం
drop_connection(పూర్ణాంకం sock, పూర్ణాంకం startups, పూర్ణాంకం notify_pipe)
{
	స్థిర నిర్మాణం log_ratelimit_ctx ratelimit_maxstartups;
	స్థిర నిర్మాణం log_ratelimit_ctx ratelimit_penalty;
	స్థిర పూర్ణాంకం init_పూర్తి;
	అక్షరం *laddr, *raddr;
	స్థిరరాశి అక్షరం *reason = ఖాళీ, *subreason = ఖాళీ;
	స్థిరరాశి అక్షరం సందేశం[] = "Not allowed at this time\r\n";
	నిర్మాణం log_ratelimit_ctx *rl = ఖాళీ;
	పూర్ణాంకం ratelimited;
	u_int ndropped;

	ఒకవేళ (!init_పూర్తి) {
		init_పూర్తి = 1;
		log_ratelimit_init(&ratelimit_maxstartups, 4, 60, 20, 5*60);
		log_ratelimit_init(&ratelimit_penalty, 8, 60, 30, 2*60);
	}

	/* PerSourcePenalties */
	ఒకవేళ (!srclimit_penalty_check_allow(sock, &subreason)) {
		reason = "PerSourcePenalties";
		rl = &ratelimit_penalty;
	} లేకపోతే {
		/* MaxStartups */
		ఒకవేళ (!should_drop_connection(startups) &&
		    srclimit_check_allow(sock, notify_pipe) == 1)
			తిరిగి 0;
		reason = "MaxStartups";
		rl = &ratelimit_maxstartups;
	}

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	ratelimited = log_ratelimit(rl, time(ఖాళీ), ఖాళీ, &ndropped);
	do_log2(ratelimited ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    "drop connection #%d from [%s]:%d on [%s]:%d %s",
	    startups,
	    raddr, get_peer_పోర్టు(sock),
	    laddr, get_local_పోర్టు(sock),
	    subreason != ఖాళీ ? subreason : reason);
	విడుదల(laddr);
	విడుదల(raddr);
	ఒకవేళ (ndropped != 0) {
		logit("%s logging rate-limited: additional %u connections "
		    "dropped", reason, ndropped);
	}

	/* best-effort notification to client */
	(శూన్య)లిఖ(sock, సందేశం, పరిమాణం(సందేశం) - 1);
	తిరిగి 1;
}

స్థిర శూన్య
usage(శూన్య)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_సంస్కరణ);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	నిష్క్రమించు(1);
}

స్థిర నిర్మాణం sshbuf *
pack_hostkeys(శూన్య)
{
	నిర్మాణం sshbuf *m = ఖాళీ, *keybuf = ఖాళీ, *hostkeys = ఖాళీ;
	పూర్ణాంకం r;
	u_int i;
	కొలత_t len;

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ ||
	    (keybuf = sshbuf_new()) == ఖాళీ ||
	    (hostkeys = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	కొరకు (i = 0; i < options.అంకె_host_కీలకం_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		ఒకవేళ (sensitive_దత్తాంశం.host_కీలకాలు[i] != ఖాళీ &&
		    (r = sshkey_వ్యక్తిగత_serialize(sensitive_దత్తాంశం.host_కీలకాలు[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		ఒకవేళ ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		ఒకవేళ (sensitive_దత్తాంశం.host_pubkeys[i] != ఖాళీ) {
			ఒకవేళ ((r = sshkey_puts(sensitive_దత్తాంశం.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} లేకపోతే {
			ఒకవేళ ((r = sshbuf_put_string(hostkeys, ఖాళీ, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		ఒకవేళ (sensitive_దత్తాంశం.host_certificates[i] != ఖాళీ) {
			ఒకవేళ ((r = sshkey_puts(
			    sensitive_దత్తాంశం.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} లేకపోతే {
			ఒకవేళ ((r = sshbuf_put_string(hostkeys, ఖాళీ, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	ఒకవేళ ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0)
		fatal_fr(r, "compose message");
	ఒకవేళ ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(keybuf);
	sshbuf_free(hostkeys);
	తిరిగి m;
}

స్థిర నిర్మాణం sshbuf *
pack_config(నిర్మాణం sshbuf *conf)
{
	నిర్మాణం sshbuf *m = ఖాళీ, *inc = ఖాళీ;
	నిర్మాణం include_అంశం *అంశం = ఖాళీ;
	కొలత_t len;
	పూర్ణాంకం r;

	debug3_f("d config len %zu", sshbuf_len(conf));

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ ||
	    (inc = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(అంశం, &includes, నమోదు_2) {
		ఒకవేళ ((r = sshbuf_put_cstring(inc, అంశం->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, అంశం->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, అంశం->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	ఒకవేళ ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	ఒకవేళ ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(inc);

	debug3_f("done");
	తిరిగి m;
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
స్థిర శూన్య
send_rexec_state(పూర్ణాంకం fd)
{
	నిర్మాణం sshbuf *కీలకాలు;
	u_int mlen;
	pid_t pid;

	ఒకవేళ ((pid = fork()) == -1)
		fatal_f("fork failed: %s", strerror(errno));
	ఒకవేళ (pid != 0)
		తిరిగి;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(config));

	mlen = sshbuf_len(config);
	ఒకవేళ (atomicio(vwrite, fd, sshbuf_mutable_ptr(config), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	కీలకాలు = pack_hostkeys();
	mlen = sshbuf_len(కీలకాలు);
	ఒకవేళ (atomicio(vwrite, fd, sshbuf_mutable_ptr(కీలకాలు), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	sshbuf_free(కీలకాలు);
	debug3_f("done");
	నిష్క్రమించు(0);
}

/*
 * Listen for TCP connections
 */
స్థిర శూన్య
listen_on_addrs(నిర్మాణం listenaddr *la)
{
	పూర్ణాంకం ret, listen_sock;
	నిర్మాణం addrinfo *ai;
	అక్షరం ntop[NI_MAXHOST], strport[NI_MAXSERV];

	కొరకు (ai = la->addrs; ai; ai = ai->ai_next) {
		ఒకవేళ (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			కొనసాగు;
		ఒకవేళ (అంకె_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		ఒకవేళ ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, పరిమాణం(ntop), strport, పరిమాణం(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			కొనసాగు;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		ఒకవేళ (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			కొనసాగు;
		}
		ఒకవేళ (సమితి_nonblock(listen_sock) == -1) {
			close(listen_sock);
			కొనసాగు;
		}
		ఒకవేళ (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			కొనసాగు;
		}
		/* Socket options */
		సమితి_reuseaddr(listen_sock);
		ఒకవేళ (la->rdomain != ఖాళీ &&
		    సమితి_rdomain(listen_sock, la->rdomain) == -1) {
			close(listen_sock);
			కొనసాగు;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		ఒకవేళ (ai->ai_family == AF_INET6)
			sock_సమితి_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		ఒకవేళ (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, strerror(errno));
			close(listen_sock);
			కొనసాగు;
		}
		listen_socks[అంకె_listen_socks] = listen_sock;
		అంకె_listen_socks++;

		/* Start listening on the port. */
		ఒకవేళ (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, strerror(errno));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == ఖాళీ ? "" : " rdomain ",
		    la->rdomain == ఖాళీ ? "" : la->rdomain);
	}
}

స్థిర శూన్య
server_listen(శూన్య)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups,
	    options.చొప్పున_ఆధారం_max_startups,
	    options.చొప్పున_ఆధారం_masklen_ipv4,
	    options.చొప్పున_ఆధారం_masklen_ipv6,
	    &options.చొప్పున_ఆధారం_penalty,
	    options.చొప్పున_ఆధారం_penalty_exempt);

	కొరకు (i = 0; i < options.అంకె_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		విడుదల(options.listen_addrs[i].rdomain);
		memset(&options.listen_addrs[i], 0,
		    పరిమాణం(options.listen_addrs[i]));
	}
	విడుదల(options.listen_addrs);
	options.listen_addrs = ఖాళీ;
	options.అంకె_listen_addrs = 0;

	ఒకవేళ (!అంకె_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
స్థిర శూన్య
server_accept_loop(పూర్ణాంకం *sock_లోపల, పూర్ణాంకం *sock_బహిర్గతం, పూర్ణాంకం *newsock, పూర్ణాంకం *config_s,
    పూర్ణాంకం log_stderr)
{
	నిర్మాణం pollfd *pfd = ఖాళీ;
	పూర్ణాంకం i, ret, npfd, r;
	పూర్ణాంకం oactive = -1, listening = 0, lameduck = 0;
	పూర్ణాంకం *startup_pollfd;
	ssize_t len;
	స్థిరరాశి u_char *ptr;
	అక్షరం c = 0;
	నిర్మాణం sockaddr_storage from;
	నిర్మాణం early_బిడ్డ *బిడ్డ;
	నిర్మాణం sshbuf *buf;
	socklen_t fromlen;
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	బిడ్డ_alloc();
	startup_pollfd = xcalloc(options.max_startups, పరిమాణం(పూర్ణాంకం));

	/*
	 * Prepare signal mask that we use to block signals that might set
	 * received_sigterm/hup/chld/info, so that we are guaranteed
	 * to immediately wake up the ppoll if a signal is received after
	 * the flag is checked.
	 */
	sigemptyset(&nsigset);
	sigaddset(&nsigset, SIGHUP);
	sigaddset(&nsigset, SIGCHLD);
#నిర్వచితమైతే SIGINFO
	sigaddset(&nsigset, SIGINFO);
#అయితే_ముగింపు
	sigaddset(&nsigset, SIGTERM);
	sigaddset(&nsigset, SIGQUIT);

	/* sized for worst-case */
	pfd = xcalloc(అంకె_listen_socks + options.max_startups,
	    పరిమాణం(నిర్మాణం pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	కొరకు (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		ఒకవేళ (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (పూర్ణాంకం) received_sigterm);
			close_listen_socks();
			ఒకవేళ (options.pid_file != ఖాళీ)
				unlink(options.pid_file);
			నిష్క్రమించు(received_sigterm == SIGTERM ? 0 : 255);
		}
		ఒకవేళ (received_sigchld) {
			బిడ్డ_reap_all_exited();
			received_sigchld = 0;
		}
		ఒకవేళ (received_siginfo) {
			show_info();
			received_siginfo = 0;
		}
		ఒకవేళ (oactive != children_చురుకైన) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, children_చురుకైన,
			    options.max_startups_begin, options.max_startups);
			oactive = children_చురుకైన;
		}
		ఒకవేళ (received_sighup) {
			ఒకవేళ (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			ఒకవేళ (listening <= 0) {
				/*
				 * Leave termination signals blocked, so
				 * they don't get lost across a restart.
				 */
				sigaddset(&osigset, SIGTERM);
				sigaddset(&osigset, SIGQUIT);
				sigprocmask(SIG_SETMASK, &osigset, ఖాళీ);
				sighup_restart();
			}
		}

		కొరకు (i = 0; i < అంకె_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = అంకె_listen_socks;
		కొరకు (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			ఒకవేళ (children[i].pipefd != -1) {
				pfd[npfd].fd = children[i].pipefd;
				pfd[npfd].events = POLLIN;
				ఒకవేళ (children[i].config != ఖాళీ ||
				    children[i].కీలకాలు != ఖాళీ)
					pfd[npfd].events |= POLLOUT;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, ఖాళీ, &osigset);
		ఒకవేళ (ret == -1 && errno != EINTR) {
			error("ppoll: %.100s", strerror(errno));
			ఒకవేళ (errno == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, ఖాళీ);
		ఒకవేళ (ret == -1)
			కొనసాగు;

		కొరకు (i = 0; i < options.max_startups; i++) {
			ఒకవేళ (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & POLLOUT))
				కొనసాగు;
			ఒకవేళ (children[i].config)
				buf = children[i].config;
			లేకపోతే ఒకవేళ (children[i].కీలకాలు)
				buf = children[i].కీలకాలు;
			లేకపోతే {
				error_f("no buffer to send");
				కొనసాగు;
			}
			ptr = sshbuf_ptr(buf);
			len = sshbuf_len(buf);
			ret = లిఖ(children[i].pipefd, ptr, len);
			ఒకవేళ (ret == -1 && (errno == EINTR || errno == EAGAIN))
				కొనసాగు;
			ఒకవేళ (ret <= 0) {
				ఒకవేళ (children[i].early)
					listening--;
				బిడ్డ_close(&(children[i]), 0, 0);
				కొనసాగు;
			}
			ఒకవేళ (ret == len) {
				/* finished sending buffer */
				sshbuf_free(buf);
				ఒకవేళ (children[i].config == buf) {
					/* sent config, now send keys */
					children[i].config = ఖాళీ;
					children[i].కీలకాలు = pack_hostkeys();
				} లేకపోతే ఒకవేళ (children[i].కీలకాలు == buf) {
					/* sent both config and keys */
					children[i].కీలకాలు = ఖాళీ;
				} లేకపోతే {
					fatal("config buf not set");
				}

			} లేకపోతే {
				ఒకవేళ ((r = sshbuf_consume(buf, ret)) != 0)
					fatal_fr(r, "config buf inconsistent");
			}
		}
		కొరకు (i = 0; i < options.max_startups; i++) {
			ఒకవేళ (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				కొనసాగు;
			ఎంపిక (పఠ(children[i].pipefd, &c, పరిమాణం(c))) {
			స్థితి -1:
				ఒకవేళ (errno == EINTR || errno == EAGAIN)
					కొనసాగు;
				ఒకవేళ (errno != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, children[i].pipefd,
					    strerror(errno));
				}
				/* FALLTHROUGH */
			స్థితి 0:
				/* child closed pipe */
				ఒకవేళ (children[i].early)
					listening--;
				debug3_f("child %lu for %s closed pipe",
				    (దీర్ఘ)children[i].pid, children[i].id);
				బిడ్డ_close(&(children[i]), 0, 0);
				ఆపు;
			స్థితి 1:
				ఒకవేళ (children[i].config) {
					error_f("startup pipe %d (fd=%d)"
					    " early read",
					    i, children[i].pipefd);
					వెళ్ళు problem_బిడ్డ;
				}
				ఒకవేళ (children[i].early && c == '\0') {
					/* child has finished preliminaries */
					listening--;
					children[i].early = 0;
					debug2_f("child %lu for %s received "
					    "config", (దీర్ఘ)children[i].pid,
					    children[i].id);
				} లేకపోతే ఒకవేళ (!children[i].early && c == '\001') {
					/* child has completed auth */
					debug2_f("child %lu for %s auth done",
					    (దీర్ఘ)children[i].pid,
					    children[i].id);
					బిడ్డ_close(&(children[i]), 1, 0);
				} లేకపోతే {
					error_f("unexpected message 0x%02x "
					    "child %ld for %s in state %d",
					    (పూర్ణాంకం)c, (దీర్ఘ)children[i].pid,
					    children[i].id, children[i].early);
 problem_బిడ్డ:
					ఒకవేళ (children[i].early)
						listening--;
					ఒకవేళ (children[i].pid > 0)
						kill(children[i].pid, SIGTERM);
					బిడ్డ_close(&(children[i]), 0, 0);
				}
				ఆపు;
			}
		}
		కొరకు (i = 0; i < అంకె_listen_socks; i++) {
			ఒకవేళ (!(pfd[i].revents & POLLIN))
				కొనసాగు;
			fromlen = పరిమాణం(from);
			*newsock = accept(listen_socks[i],
			    (నిర్మాణం sockaddr *)&from, &fromlen);
			ఒకవేళ (*newsock == -1) {
				ఒకవేళ (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED && errno != EAGAIN)
					error("accept: %.100s",
					    strerror(errno));
				ఒకవేళ (errno == EMFILE || errno == ENFILE)
					usleep(100 * 1000);
				కొనసాగు;
			}
			ఒకవేళ (unset_nonblock(*newsock) == -1) {
				close(*newsock);
				కొనసాగు;
			}
			ఒకవేళ (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    strerror(errno));
				close(*newsock);
				కొనసాగు;
			}
			ఒకవేళ (drop_connection(*newsock,
			    children_చురుకైన, config_s[0])) {
				close(*newsock);
				close(config_s[0]);
				close(config_s[1]);
				కొనసాగు;
			}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			ఒకవేళ (debug_flag) {
				/*
				 * In debugging mode.  Close the listening
				 * socket, and start processing the
				 * connection without forking.
				 */
				debug("Server will not fork when running in debugging mode.");
				close_listen_socks();
				*sock_లోపల = *newsock;
				*sock_బహిర్గతం = *newsock;
				send_rexec_state(config_s[0]);
				close(config_s[0]);
				విడుదల(pfd);
				విడుదల(startup_pollfd);
				తిరిగి;
			}

			/*
			 * Normal production daemon.  Fork, and have
			 * the child process the connection. The
			 * parent continues listening.
			 */
			platform_pre_fork();
			సమితి_nonblock(config_s[0]);
			listening++;
			బిడ్డ = బిడ్డ_రిజిస్టరు(config_s[0], *newsock);
			ఒకవేళ ((బిడ్డ->pid = fork()) == 0) {
				/*
				 * Child.  Close the listening and
				 * max_startup sockets.  Start using
				 * the accepted socket. Reinitialize
				 * logging (since our pid has changed).
				 * We return from this function to handle
				 * the connection.
				 */
				platform_post_fork_బిడ్డ();
				close_startup_pipes();
				close_listen_socks();
				*sock_లోపల = *newsock;
				*sock_బహిర్గతం = *newsock;
				log_init(__progname,
				    options.log_level,
				    options.log_facility,
				    log_stderr);
				close(config_s[0]);
				విడుదల(pfd);
				విడుదల(startup_pollfd);
				తిరిగి;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_మాతృ(బిడ్డ->pid);
			ఒకవేళ (బిడ్డ->pid == -1)
				error("fork: %.100s", strerror(errno));
			లేకపోతే
				debug("Forked child %ld.", (దీర్ఘ)బిడ్డ->pid);

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

స్థిర శూన్య
accumulate_host_timing_secret(నిర్మాణం sshbuf *server_cfg,
    నిర్మాణం sshkey *కీలకం)
{
	స్థిర నిర్మాణం ssh_digest_ctx *ctx;
	u_char *hash;
	కొలత_t len;
	నిర్మాణం sshbuf *buf;
	పూర్ణాంకం r;

	ఒకవేళ (ctx == ఖాళీ && (ctx = ssh_digest_ప్రారంభం(SSH_DIGEST_SHA512)) == ఖాళీ)
		fatal_f("ssh_digest_start");
	ఒకవేళ (కీలకం == ఖాళీ) { /* finalize */
		/* add server config in case we are using agent for host keys */
		ఒకవేళ (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_బైట్లు(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		ఒకవేళ (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = ఖాళీ;
		తిరిగి;
	}
	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ)
		fatal_f("could not allocate buffer");
	ఒకవేళ ((r = sshkey_వ్యక్తిగత_serialize(కీలకం, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(కీలకం));
	ఒకవేళ (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

స్థిర అక్షరం *
prepare_proctitle(పూర్ణాంకం ac, అక్షరం **av)
{
	అక్షరం *ret = ఖాళీ;
	పూర్ణాంకం i;

	కొరకు (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	తిరిగి ret;
}

/* Disconnect from the controlling tty. */
స్థిర శూన్య
disconnect_controlling_tty(శూన్య)
{
#నిర్వచితమైతే TIOCNOTTY
# ifndef O_NOCTTY
#  define O_NOCTTY 0
# endif
	పూర్ణాంకం fd;

	ఒకవేళ ((fd = open(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(శూన్య) ioctl(fd, TIOCNOTTY, ఖాళీ);
		close(fd);
	}
#అయితే_ముగింపు /* TIOCNOTTY */
}

స్థిర శూన్య
print_config(నిర్మాణం connection_info *connection_info)
{
	connection_info->test = 1;
	parse_server_సరిపోలిక_config(&options, &includes, connection_info);
	dump_config(&options);
	నిష్క్రమించు(0);
}

/*
 * Main program for the daemon.
 */
పూర్ణాంకం
ప్రధాన(పూర్ణాంకం ac, అక్షరం **av)
{
	బాహ్య అక్షరం *optarg;
	బాహ్య పూర్ణాంకం optind;
	పూర్ణాంకం log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	అక్షరం *config_file_name = మార్గం_SERVER_CONFIG_FILE;
	పూర్ణాంకం r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	పూర్ణాంకం sock_లోపల = -1, sock_బహిర్గతం = -1, newsock = -1, rexec_argc = 0;
	పూర్ణాంకం devnull, config_s[2] = { -1 , -1 }, have_connection_info = 0;
	పూర్ణాంకం need_chroot = 1;
	అక్షరం *వాదనలు, *fp, *పంక్తి, *logfile = ఖాళీ, **rexec_argv = ఖాళీ;
	నిర్మాణం stat sb;
	u_int i, j;
	బహుళకం_t new_umask;
	నిర్మాణం sshkey *కీలకం;
	నిర్మాణం sshkey *pubkey;
	నిర్మాణం connection_info connection_info;
	నిర్మాణం utsname utsname;
	sigset_t sigmask;

	memset(&connection_info, 0, పరిమాణం(connection_info));
#నిర్వచితమైతే HAVE_SECUREWARE
	(శూన్య)సమితి_auth_parameters(ac, av);
#అయితే_ముగింపు
	__progname = ssh_get_progname(av[0]);

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ఖాళీ);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, పరిమాణం(*saved_argv));
	కొరకు (i = 0; (పూర్ణాంకం)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ఖాళీ;

#నిర్వచితం_కాకపోతే HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#అయితే_ముగింపు

	ఒకవేళ (geteuid() == 0 && setgroups(0, ఖాళీ) == -1)
		debug("setgroups(): %.200s", strerror(errno));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	వాదనలు = argv_assemble(ac, av); /* logged later */
	అయితే ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		ఎంపిక (opt) {
		స్థితి '4':
			options.చిరునామా_family = AF_INET;
			ఆపు;
		స్థితి '6':
			options.చిరునామా_family = AF_INET6;
			ఆపు;
		స్థితి 'f':
			config_file_name = optarg;
			ఆపు;
		స్థితి 'c':
			servconf_కూడు_hostcert("[command-line]", 0,
			    &options, optarg);
			ఆపు;
		స్థితి 'd':
			ఒకవేళ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} లేకపోతే ఒకవేళ (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			ఆపు;
		స్థితి 'D':
			no_daemon_flag = 1;
			ఆపు;
		స్థితి 'G':
			do_dump_cfg = 1;
			ఆపు;
		స్థితి 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		స్థితి 'e':
			log_stderr = 1;
			ఆపు;
		స్థితి 'i':
			inetd_flag = 1;
			ఆపు;
		స్థితి 'r':
			logit("-r option is deprecated");
			ఆపు;
		స్థితి 'R':
			fatal("-R not supported here");
			ఆపు;
		స్థితి 'Q':
			/* ignored */
			ఆపు;
		స్థితి 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			ఆపు;
		స్థితి 'b':
			/* protocol 1, ignored */
			ఆపు;
		స్థితి 'p':
			options.ports_from_cmdline = 1;
			ఒకవేళ (options.అంకె_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				నిష్క్రమించు(1);
			}
			options.ports[options.అంకె_ports++] = a2port(optarg);
			ఒకవేళ (options.ports[options.అంకె_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				నిష్క్రమించు(1);
			}
			ఆపు;
		స్థితి 'g':
			ఒకవేళ ((options.login_grace_సమయం = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				నిష్క్రమించు(1);
			}
			ఆపు;
		స్థితి 'k':
			/* protocol 1, ignored */
			ఆపు;
		స్థితి 'h':
			servconf_కూడు_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			ఆపు;
		స్థితి 't':
			test_flag = 1;
			ఆపు;
		స్థితి 'T':
			test_flag = 2;
			ఆపు;
		స్థితి 'C':
			ఒకవేళ (parse_server_సరిపోలిక_testspec(&connection_info,
			    optarg) == -1)
				నిష్క్రమించు(1);
			have_connection_info = 1;
			ఆపు;
		స్థితి 'u':
			utmp_len = (u_int)strtonum(optarg, 0,
			    HOST_NAME_MAX+1+1, ఖాళీ);
			ఒకవేళ (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				నిష్క్రమించు(1);
			}
			ఆపు;
		స్థితి 'o':
			పంక్తి = xstrdup(optarg);
			ఒకవేళ (process_server_config_పంక్తి(&options, పంక్తి,
			    "command-line", 0, ఖాళీ, ఖాళీ, &includes) != 0)
				నిష్క్రమించు(1);
			విడుదల(పంక్తి);
			ఆపు;
		స్థితి 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_సంస్కరణ);
			నిష్క్రమించు(0);
		అప్రమేయ:
			usage();
			ఆపు;
		}
	}

	ఒకవేళ (getexecpath(execpath, పరిమాణం execpath) != 0) {
		ఒకవేళ (strlcpy(execpath, av[0], పరిమాణం execpath) >=
		    పరిమాణం execpath) {
			fprintf(stderr, "execution path is too long\n");
			నిష్క్రమించు(1);
		}
	}
	ఒకవేళ (!test_flag && !inetd_flag && !do_dump_cfg && !మార్గం_absolute(execpath))
		fatal("sshd requires execution with an absolute path");

	closefrom(STDERR_FILENO + 1);

	/* Reserve fds we'll need later for reexec things */
	ఒకవేళ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	అయితే (devnull < REEXEC_MIN_FREE_FD) {
		ఒకవేళ ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	విత్తనం_rng();

	/* If requested, redirect the logs to the specified logfile. */
	ఒకవేళ (logfile != ఖాళీ) {
		అక్షరం *cp, pid_s[32];

		snprintf(pid_s, పరిమాణం(pid_s), "%ld", (గుర్తులేని దీర్ఘ)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (అక్షరం *)ఖాళీ);
		log_redirect_stderr_గమ్యం(cp);
		విడుదల(cp);
	}

	/*
	 * Force logging to stderr until we have loaded the private host
	 * key (unless started from inetd)
	 */
	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_సమితి ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_సమితి ?
	    SYSLOG_FACILITY_AUTH : options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	/*
	 * Unset KRB5CCNAME, otherwise the user's session may inherit it from
	 * root's environment
	 */
	ఒకవేళ (getenv("KRB5CCNAME") != ఖాళీ)
		(శూన్య) unsetenv("KRB5CCNAME");

	sensitive_దత్తాంశం.have_ssh2_కీలకం = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	ఒకవేళ (test_flag < 2 && have_connection_info)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	debug("sshd version %s, %s", SSH_సంస్కరణ, SSH_OPENSSL_సంస్కరణ);
	ఒకవేళ (uname(&utsname) != 0) {
		memset(&utsname, 0, పరిమాణం(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", పరిమాణం(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.సంస్కరణ, utsname.machine);
	debug3("Started with: %s", వాదనలు);
	విడుదల(వాదనలు);

	/* Fetch our configuration */
	ఒకవేళ ((cfg = sshbuf_new()) == ఖాళీ)
		fatal("sshbuf_new config failed");
	ఒకవేళ (strcasecmp(config_file_name, "none") != 0)
		ఎక్కించు_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, ఖాళీ, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	ఒకవేళ (options.authorized_కీలకాలు_command_user == ఖాళీ &&
	    (options.authorized_కీలకాలు_command != ఖాళీ &&
	    strcasecmp(options.authorized_కీలకాలు_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	ఒకవేళ (options.authorized_principals_command_user == ఖాళీ &&
	    (options.authorized_principals_command != ఖాళీ &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match blocks, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	ఒకవేళ (options.అంకె_auth_methods != 0) {
		కొరకు (i = 0; i < options.అంకె_auth_methods; i++) {
			ఒకవేళ (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				ఆపు;
		}
		ఒకవేళ (i >= options.అంకె_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	ఒకవేళ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		నిష్క్రమించు(1);
	}

	ఒకవేళ (do_dump_cfg)
		print_config(&connection_info);

	/* load host keys */
	sensitive_దత్తాంశం.host_కీలకాలు = xcalloc(options.అంకె_host_కీలకం_files,
	    పరిమాణం(నిర్మాణం sshkey *));
	sensitive_దత్తాంశం.host_pubkeys = xcalloc(options.అంకె_host_కీలకం_files,
	    పరిమాణం(నిర్మాణం sshkey *));

	ఒకవేళ (options.host_కీలకం_agent) {
		ఒకవేళ (strcmp(options.host_కీలకం_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_కీలకం_agent, 1);
		ఒకవేళ ((r = ssh_get_authentication_socket(ఖాళీ)) == 0)
			have_agent = 1;
		లేకపోతే
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_కీలకం_agent);
	}

	కొరకు (i = 0; i < options.అంకె_host_కీలకం_files; i++) {
		పూర్ణాంకం ll = options.host_కీలకం_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		ఒకవేళ (options.host_కీలకం_files[i] == ఖాళీ)
			కొనసాగు;
		ఒకవేళ ((r = sshkey_ఎక్కించు_వ్యక్తిగత(options.host_కీలకం_files[i], "",
		    &కీలకం, ఖాళీ)) != 0 &&
		    r != SSH_ERR_SYSTEM_ERROR && !have_agent)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_కీలకం_files[i]);
		ఒకవేళ (sshkey_is_sk(కీలకం) &&
		    కీలకం->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_కీలకం_files[i]);
			కీలకం->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		ఒకవేళ (r == 0 && కీలకం != ఖాళీ &&
		    (r = sshkey_shield_వ్యక్తిగత(కీలకం)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_కీలకం_files[i]);
			sshkey_free(కీలకం);
			కీలకం = ఖాళీ;
		}
		ఒకవేళ ((r = sshkey_ఎక్కించు_ప్రజా(options.host_కీలకం_files[i],
		    &pubkey, ఖాళీ)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_కీలకం_files[i]);
		ఒకవేళ (pubkey != ఖాళీ && కీలకం != ఖాళీ) {
			ఒకవేళ (!sshkey_equal(pubkey, కీలకం)) {
				error("Public key for %s does not match "
				    "private key", options.host_కీలకం_files[i]);
				sshkey_free(pubkey);
				pubkey = ఖాళీ;
			}
		}
		ఒకవేళ (pubkey == ఖాళీ && కీలకం != ఖాళీ) {
			ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(కీలకం, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_కీలకం_files[i]);
		}
		ఒకవేళ (pubkey != ఖాళీ && (r = sshkey_check_rsa_నిడివి(pubkey,
		    options.required_rsa_కొలత)) != 0) {
			error_fr(r, "Host key %s", options.host_కీలకం_files[i]);
			sshkey_free(pubkey);
			sshkey_free(కీలకం);
			కొనసాగు;
		}
		sensitive_దత్తాంశం.host_కీలకాలు[i] = కీలకం;
		sensitive_దత్తాంశం.host_pubkeys[i] = pubkey;

		ఒకవేళ (కీలకం == ఖాళీ && pubkey != ఖాళీ && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_కీలకం_files[i]);
			keytype = pubkey->type;
		} లేకపోతే ఒకవేళ (కీలకం != ఖాళీ) {
			keytype = కీలకం->type;
			accumulate_host_timing_secret(cfg, కీలకం);
		} లేకపోతే {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_కీలకం_files[i]);
			sensitive_దత్తాంశం.host_కీలకాలు[i] = ఖాళీ;
			sensitive_దత్తాంశం.host_pubkeys[i] = ఖాళీ;
			కొనసాగు;
		}

		ఎంపిక (keytype) {
		స్థితి కీలకం_RSA:
		స్థితి కీలకం_ECDSA:
		స్థితి కీలకం_ED25519:
		స్థితి కీలకం_MLDSA44_ED25519:
		స్థితి కీలకం_ECDSA_SK:
		స్థితి కీలకం_ED25519_SK:
			ఒకవేళ (have_agent || కీలకం != ఖాళీ)
				sensitive_దత్తాంశం.have_ssh2_కీలకం = 1;
			ఆపు;
		}
		ఒకవేళ ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == ఖాళీ)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    కీలకం ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		విడుదల(fp);
	}
	accumulate_host_timing_secret(cfg, ఖాళీ);
	ఒకవేళ (!sensitive_దత్తాంశం.have_ssh2_కీలకం) {
		logit("sshd: no hostkeys available -- exiting.");
		నిష్క్రమించు(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_దత్తాంశం.host_certificates = xcalloc(options.అంకె_host_కీలకం_files,
	    పరిమాణం(నిర్మాణం sshkey *));
	కొరకు (i = 0; i < options.అంకె_host_కీలకం_files; i++)
		sensitive_దత్తాంశం.host_certificates[i] = ఖాళీ;

	కొరకు (i = 0; i < options.అంకె_host_cert_files; i++) {
		ఒకవేళ (options.host_cert_files[i] == ఖాళీ)
			కొనసాగు;
		ఒకవేళ ((r = sshkey_ఎక్కించు_ప్రజా(options.host_cert_files[i],
		    &కీలకం, ఖాళీ)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			కొనసాగు;
		}
		ఒకవేళ (!sshkey_is_cert(కీలకం)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(కీలకం);
			కొనసాగు;
		}
		/* Find matching private key */
		కొరకు (j = 0; j < options.అంకె_host_కీలకం_files; j++) {
			ఒకవేళ (sshkey_equal_ప్రజా(కీలకం,
			    sensitive_దత్తాంశం.host_pubkeys[j])) {
				sensitive_దత్తాంశం.host_certificates[j] = కీలకం;
				ఆపు;
			}
		}
		ఒకవేళ (j >= options.అంకె_host_కీలకం_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(కీలకం);
			కొనసాగు;
		}
		sensitive_దత్తాంశం.host_certificates[j] = కీలకం;
		debug("host certificate: #%u type %d %s", j, కీలకం->type,
		    sshkey_type(కీలకం));
	}

	/* Ensure privsep directory is correctly configured. */
	need_chroot = ((getuid() == 0 || geteuid() == 0) ||
	    options.kerberos_authentication);
	ఒకవేళ ((getpwnam(SSH_PRIVSEP_USER)) == ఖాళీ && need_chroot) {
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	}
	endpwent();

	ఒకవేళ (need_chroot) {
		ఒకవేళ ((stat(మార్గం_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
		    (S_ISDIR(sb.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    మార్గం_PRIVSEP_CHROOT_DIR);
#నిర్వచితమైతే HAVE_CYGWIN
		ఒకవేళ (check_ntsec(మార్గం_PRIVSEP_CHROOT_DIR) &&
		    (sb.st_uid != getuid () ||
		    (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#లేకపోతే
		ఒకవేళ (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#అయితే_ముగింపు
			fatal("%s must be owned by root and not group or "
			    "world-writable.", మార్గం_PRIVSEP_CHROOT_DIR);
	}

	ఒకవేళ (test_flag > 1)
		print_config(&connection_info);

	config = pack_config(cfg);
	ఒకవేళ (sshbuf_len(config) > MONITOR_MAX_CFGLEN) {
		fatal("Configuration file is too large (have %zu, max %d)",
		    sshbuf_len(config), MONITOR_MAX_CFGLEN);
	}

	/* Configuration looks good, so exit if in test mode. */
	ఒకవేళ (test_flag)
		నిష్క్రమించు(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	ఒకవేళ (setgroups(0, ఖాళీ) < 0)
		debug("setgroups() failed: %.200s", strerror(errno));

	/* Prepare arguments for sshd-session */
	ఒకవేళ (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, పరిమాణం(అక్షరం *));
	/* Point to the sshd-session binary instead of sshd */
	rexec_argv[0] = options.sshd_session_మార్గం;
	కొరకు (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = ఖాళీ;
	ఒకవేళ (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	ఒకవేళ (stat(options.sshd_auth_మార్గం, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_auth_మార్గం);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(శూన్య) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	ఒకవేళ (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	కొరకు (i = 0; i < options.అంకె_log_verbose; i++)
		log_verbose_కూడు(options.log_verbose[i]);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	ఒకవేళ (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		ఒకవేళ (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", strerror(errno));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	ఒకవేళ (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or a listening TCP socket */
	ఒకవేళ (inetd_flag) {
		/* Send configuration to ancestor sshd-session process */
		ఒకవేళ (socketpair(AF_UNIX, SOCK_STREAM, 0, config_s) == -1)
			fatal("socketpair: %s", strerror(errno));
		send_rexec_state(config_s[0]);
		close(config_s[0]);
	} లేకపోతే {
		platform_pre_listen();
		server_listen();

		ssh_signal(SIGHUP, sighup_handler);
		ssh_signal(SIGCHLD, main_sigchld_handler);
		ssh_signal(SIGTERM, sigterm_handler);
		ssh_signal(SIGQUIT, sigterm_handler);
#నిర్వచితమైతే SIGINFO
		ssh_signal(SIGINFO, siginfo_handler);
#అయితే_ముగింపు

		platform_post_listen();

		/*
		 * Write out the pid file after the sigterm handler
		 * is setup and the listen sockets are bound
		 */
		ఒకవేళ (options.pid_file != ఖాళీ && !debug_flag) {
			FILE *f = fopen(options.pid_file, "w");

			ఒకవేళ (f == ఖాళీ) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, strerror(errno));
			} లేకపోతే {
				fprintf(f, "%ld\n", (దీర్ఘ) getpid());
				fclose(f);
			}
		}

		/* Accept a connection and return in a forked child */
		server_accept_loop(&sock_లోపల, &sock_బహిర్గతం,
		    &newsock, config_s, log_stderr);
	}

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/*
	 * Create a new session and process group since the 4.4BSD
	 * setlogin() affects the entire process group.  We don't
	 * want the child to be able to affect the parent.
	 */
	ఒకవేళ (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	debug("rexec start in %d out %d newsock %d config_s %d/%d",
	    sock_లోపల, sock_బహిర్గతం, newsock, config_s[0], config_s[1]);
	ఒకవేళ (!inetd_flag) {
		ఒకవేళ (dup2(newsock, STDIN_FILENO) == -1)
			fatal("dup2 stdin: %s", strerror(errno));
		ఒకవేళ (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			fatal("dup2 stdout: %s", strerror(errno));
		ఒకవేళ (newsock > STDOUT_FILENO)
			close(newsock);
	}
	ఒకవేళ (config_s[1] != REEXEC_CONFIG_PASS_FD) {
		ఒకవేళ (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			fatal("dup2 config_s: %s", strerror(errno));
		close(config_s[1]);
	}
	log_redirect_stderr_గమ్యం(ఖాళీ);
	closefrom(REEXEC_MIN_FREE_FD);

	ssh_signal(SIGHUP, SIG_IGN); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], strerror(errno));
}

/* server specific fatal cleanup */
శూన్య
cleanup_exit(పూర్ణాంకం i)
{
	_exit(i);
}
