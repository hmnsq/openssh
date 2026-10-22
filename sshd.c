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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/ioctl.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/time.h>
#അന്തര്ഭാവ <sys/queue.h>
#അന്തര്ഭാവ <sys/wait.h>
#അന്തര്ഭാവ <sys/utsname.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <grp.h>
#അന്തര്ഭാവ <poll.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>

#ifdef HAVE_SECUREWARE
#അന്തര്ഭാവ <sys/security.h>
#അന്തര്ഭാവ <prot.h>
#endif

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "sshpty.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "compat.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "msg.h"
#അന്തര്ഭാവ "version.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sk-api.h"
#അന്തര്ഭാവ "addr.h"
#അന്തര്ഭാവ "srclimit.h"
#അന്തര്ഭാവ "atomicio.h"
#ifdef GSSAPI
#അന്തര്ഭാവ "ssh-gss.h"
#endif
#അന്തര്ഭാവ "monitor_wrap.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

ബാഹ്യ അക്ഷരം *__progname;

/* Server configuration options. */
ServerOptions options;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
പൂർണ്ണസംഖ്യ debug_flag = 0;

/* Saved arguments to main(). */
സ്ഥിതം അക്ഷരം execpath[PATH_MAX];
സ്ഥിതം അക്ഷരം **saved_argv;
സ്ഥിതം പൂർണ്ണസംഖ്യ saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#define	MAX_LISTEN_SOCKS	16
സ്ഥിതം പൂർണ്ണസംഖ്യ listen_socks[MAX_LISTEN_SOCKS];
സ്ഥിതം പൂർണ്ണസംഖ്യ അക്കം_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
ഘടന {
	ഘടന sshkey	**host_താക്കോലുകൾ;		/* all private host keys */
	ഘടന sshkey	**host_pubkeys;		/* all public host keys */
	ഘടന sshkey	**host_certificates;	/* all public host certificates */
	പൂർണ്ണസംഖ്യ		have_ssh2_താക്കോൽ;
} sensitive_data;

/* This is set to true when a signal is received. */
സ്ഥിതം അസ്ഥിര sig_atomic_t received_siginfo = 0;
സ്ഥിതം അസ്ഥിര sig_atomic_t received_sigchld = 0;
സ്ഥിതം അസ്ഥിര sig_atomic_t received_sighup = 0;
സ്ഥിതം അസ്ഥിര sig_atomic_t received_sigterm = 0;

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
ഘടന early_child {
	പൂർണ്ണസംഖ്യ pipefd;
	പൂർണ്ണസംഖ്യ early;		/* Indicates child closed listener */
	അക്ഷരം *id;		/* human readable connection identifier */
	pid_t pid;
	ഘടന xaddr addr;
	പൂർണ്ണസംഖ്യ have_addr;
	പൂർണ്ണസംഖ്യ status, have_status;
	ഘടന sshbuf *config;
	ഘടന sshbuf *താക്കോലുകൾ;
};
സ്ഥിതം ഘടന early_child *children;
സ്ഥിതം പൂർണ്ണസംഖ്യ children_active;

/* sshd_config buffer */
ഘടന sshbuf *cfg;
ഘടന sshbuf *config;	/* packed */

/* Included files from the configuration file */
ഘടന include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ഘടന sshbuf *loginmsg;

/* Unprivileged user */
ഘടന passwd *privsep_pw = ശൂന്യ;

സ്ഥിതം അക്ഷരം *listener_proctitle;

/*
 * Close all listening sockets
 */
സ്ഥിതം ശൂന്യം
close_listen_socks(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ i;

	വേണ്ടി (i = 0; i < അക്കം_listen_socks; i++)
		close(listen_socks[i]);
	അക്കം_listen_socks = 0;
}

/* Allocate and initialise the children array */
സ്ഥിതം ശൂന്യം
child_alloc(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ i;

	children = xcalloc(options.max_startups, വലുപ്പം(*children));
	വേണ്ടി (i = 0; i < options.max_startups; i++) {
		children[i].pipefd = -1;
		children[i].pid = -1;
	}
}

/* Register a new connection in the children array; child pid comes later */
സ്ഥിതം ഘടന early_child *
child_register(പൂർണ്ണസംഖ്യ pipefd, പൂർണ്ണസംഖ്യ sockfd)
{
	പൂർണ്ണസംഖ്യ i, lport, rport;
	അക്ഷരം *laddr = ശൂന്യ, *raddr = ശൂന്യ;
	ഘടന early_child *child = ശൂന്യ;
	ഘടന sockaddr_storage addr;
	socklen_t addrlen = വലുപ്പം(addr);
	ഘടന sockaddr *sa = (ഘടന sockaddr *)&addr;

	വേണ്ടി (i = 0; i < options.max_startups; i++) {
		എങ്കിൽ (children[i].pipefd != -1 ||
		    children[i].config != ശൂന്യ ||
		    children[i].താക്കോലുകൾ != ശൂന്യ ||
		    children[i].pid > 0)
			തുടരുക;
		child = &(children[i]);
		നിർത്തുക;
	}
	എങ്കിൽ (child == ശൂന്യ) {
		fatal_f("error: accepted connection when all %d child "
		    " slots full", options.max_startups);
	}
	child->pipefd = pipefd;
	child->early = 1;
	എങ്കിൽ ((child->config = sshbuf_fromb(config)) == ശൂന്യ)
		fatal_f("sshbuf_fromb failed");
	/* record peer address, if available */
	എങ്കിൽ (getpeername(sockfd, sa, &addrlen) == 0 &&
	   addr_sa_to_xaddr(sa, addrlen, &child->addr) == 0)
		child->have_addr = 1;
	/* format peer address string for logs */
	എങ്കിൽ ((lport = get_local_port(sockfd)) == 0 ||
	    (rport = get_peer_port(sockfd)) == 0) {
		/* Not a TCP socket */
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s", raddr);
	} അല്ലെങ്കിൽ {
		laddr = get_local_ipaddr(sockfd);
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s to %s", raddr, laddr);
	}
	സ്വതന്ത്രം(laddr);
	സ്വതന്ത്രം(raddr);
	എങ്കിൽ (++children_active > options.max_startups)
		fatal_f("internal error: more children than max_startups");

	തിരികെ child;
}

/*
 * Finally free a child entry. Don't call this directly.
 */
സ്ഥിതം ശൂന്യം
child_finish(ഘടന early_child *child)
{
	എങ്കിൽ (children_active == 0)
		fatal_f("internal error: children_active underflow");
	എങ്കിൽ (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
	}
	sshbuf_free(child->config);
	sshbuf_free(child->താക്കോലുകൾ);
	സ്വതന്ത്രം(child->id);
	memset(child, '\0', വലുപ്പം(*child));
	child->pipefd = -1;
	child->pid = -1;
	children_active--;
}

/*
 * Close a child's pipe. This will not stop tracking the child immediately
 * (it will still be tracked for waitpid()) unless force_final is set, or
 * child has already exited.
 */
സ്ഥിതം ശൂന്യം
child_close(ഘടന early_child *child, പൂർണ്ണസംഖ്യ force_final, പൂർണ്ണസംഖ്യ quiet)
{
	എങ്കിൽ (!quiet)
		debug_f("enter%s", force_final ? " (forcing)" : "");
	എങ്കിൽ (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
		child->pipefd = -1;
	}
	എങ്കിൽ (child->pid == -1 || force_final)
		child_finish(child);
}

/* Record a child exit. Safe to call from signal handlers */
സ്ഥിതം ശൂന്യം
child_exit(pid_t pid, പൂർണ്ണസംഖ്യ status)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (children == ശൂന്യ || pid <= 0)
		തിരികെ;
	വേണ്ടി (i = 0; i < options.max_startups; i++) {
		എങ്കിൽ (children[i].pid == pid) {
			children[i].have_status = 1;
			children[i].status = status;
			നിർത്തുക;
		}
	}
}

/*
 * Reap a child entry that has exited, as previously flagged
 * using child_exit().
 * Handles logging of exit condition and will finalise the child if its pipe
 * had already been closed.
 */
സ്ഥിതം ശൂന്യം
child_reap(ഘടന early_child *child)
{
	LogLevel level = SYSLOG_LEVEL_DEBUG1;
	പൂർണ്ണസംഖ്യ was_crash, penalty_type = SRCLIMIT_PENALTY_NONE;
	സ്ഥിരം അക്ഷരം *child_status;

	എങ്കിൽ (child->config)
		child_status = " (sending config)";
	അല്ലെങ്കിൽ എങ്കിൽ (child->താക്കോലുകൾ)
		child_status = " (sending keys)";
	അല്ലെങ്കിൽ എങ്കിൽ (child->early)
		child_status = " (early)";
	അല്ലെങ്കിൽ
		child_status = "";

	/* Log exit information */
	എങ്കിൽ (WIFSIGNALED(child->status)) {
		/*
		 * Increase logging for signals potentially associated
		 * with serious conditions.
		 */
		എങ്കിൽ ((was_crash = signal_is_crash(WTERMSIG(child->status))))
			level = SYSLOG_LEVEL_ERROR;
		do_log2(level, "session process %ld for %s killed by "
		    "signal %d%s", (long)child->pid, child->id,
		    WTERMSIG(child->status), child_status);
		എങ്കിൽ (was_crash)
			penalty_type = SRCLIMIT_PENALTY_CRASH;
	} അല്ലെങ്കിൽ എങ്കിൽ (!WIFEXITED(child->status)) {
		penalty_type = SRCLIMIT_PENALTY_CRASH;
		error("session process %ld for %s terminated abnormally, "
		    "status=0x%x%s", (long)child->pid, child->id, child->status,
		    child_status);
	} അല്ലെങ്കിൽ {
		/* Normal exit. We care about the status */
		തിരഞ്ഞെടുപ്പ് (WEXITSTATUS(child->status)) {
		അവസ്ഥ 0:
			debug3_f("preauth child %ld for %s completed "
			    "normally%s", (long)child->pid, child->id,
			    child_status);
			നിർത്തുക;
		അവസ്ഥ EXIT_LOGIN_GRACE:
			penalty_type = SRCLIMIT_PENALTY_GRACE_EXCEEDED;
			logit("Timeout before authentication for %s, "
			    "pid = %ld%s", child->id, (long)child->pid,
			    child_status);
			നിർത്തുക;
		അവസ്ഥ EXIT_CHILD_CRASH:
			penalty_type = SRCLIMIT_PENALTY_CRASH;
			logit("Session process %ld unpriv child crash for %s%s",
			    (long)child->pid, child->id, child_status);
			നിർത്തുക;
		അവസ്ഥ EXIT_AUTH_ATTEMPTED:
			penalty_type = SRCLIMIT_PENALTY_AUTHFAIL;
			debug_f("preauth child %ld for %s exited "
			    "after unsuccessful auth attempt%s",
			    (long)child->pid, child->id, child_status);
			നിർത്തുക;
		അവസ്ഥ EXIT_INVALID_USER:
			penalty_type = SRCLIMIT_PENALTY_INVALIDUSER;
			debug_f("preauth child %ld for %s exited "
			    "after auth attempt by invalid user%s",
			    (long)child->pid, child->id, child_status);
			നിർത്തുക;
		അവസ്ഥ EXIT_CONFIG_REFUSED:
			penalty_type = SRCLIMIT_PENALTY_REFUSECONNECTION;
			debug_f("preauth child %ld for %s prohibited by"
			    "RefuseConnection%s",
			    (long)child->pid, child->id, child_status);
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			penalty_type = SRCLIMIT_PENALTY_NOAUTH;
			debug_f("preauth child %ld for %s exited "
			    "with status %d%s", (long)child->pid, child->id,
			    WEXITSTATUS(child->status), child_status);
			നിർത്തുക;
		}
	}

	എങ്കിൽ (child->have_addr)
		srclimit_penalise(&child->addr, penalty_type);

	child->pid = -1;
	child->have_status = 0;
	എങ്കിൽ (child->pipefd == -1)
		child_finish(child);
}

/* Reap all children that have exited; called after SIGCHLD */
സ്ഥിതം ശൂന്യം
child_reap_all_exited(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ i;
	pid_t pid;
	പൂർണ്ണസംഖ്യ status;

	എങ്കിൽ (children == ശൂന്യ)
		തിരികെ;

	വേണ്ടി (;;) {
		എങ്കിൽ ((pid = waitpid(-1, &status, WNOHANG)) == 0)
			നിർത്തുക;
		അല്ലെങ്കിൽ എങ്കിൽ (pid == -1) {
			എങ്കിൽ (errno == EINTR || errno == EAGAIN)
				തുടരുക;
			എങ്കിൽ (errno != ECHILD)
				error_f("waitpid: %s", strerror(errno));
			നിർത്തുക;
		}
		child_exit(pid, status);
	}

	വേണ്ടി (i = 0; i < options.max_startups; i++) {
		എങ്കിൽ (!children[i].have_status)
			തുടരുക;
		child_reap(&(children[i]));
	}
}

സ്ഥിതം ശൂന്യം
close_startup_pipes(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (children == ശൂന്യ)
		തിരികെ;
	വേണ്ടി (i = 0; i < options.max_startups; i++) {
		എങ്കിൽ (children[i].pipefd != -1)
			child_close(&(children[i]), 1, 1);
	}
}

/* Called after SIGINFO */
സ്ഥിതം ശൂന്യം
show_info(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ i;
	സ്ഥിരം അക്ഷരം *child_status;

	/* XXX print listening sockets here too */
	എങ്കിൽ (children == ശൂന്യ)
		തിരികെ;
	logit("%d active startups", children_active);
	വേണ്ടി (i = 0; i < options.max_startups; i++) {
		എങ്കിൽ (children[i].pipefd == -1 && children[i].pid <= 0)
			തുടരുക;
		എങ്കിൽ (children[i].config)
			child_status = " (sending config)";
		അല്ലെങ്കിൽ എങ്കിൽ (children[i].താക്കോലുകൾ)
			child_status = " (sending keys)";
		അല്ലെങ്കിൽ എങ്കിൽ (children[i].early)
			child_status = " (early)";
		അല്ലെങ്കിൽ
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

സ്ഥിതം ശൂന്യം
sighup_handler(പൂർണ്ണസംഖ്യ sig)
{
	received_sighup = 1;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
സ്ഥിതം ശൂന്യം
sighup_restart(ശൂന്യം)
{
	logit("Received SIGHUP; restarting.");
	എങ്കിൽ (options.pid_file != ശൂന്യ)
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
സ്ഥിതം ശൂന്യം
sigterm_handler(പൂർണ്ണസംഖ്യ sig)
{
	received_sigterm = sig;
}

#ifdef SIGINFO
സ്ഥിതം ശൂന്യം
siginfo_handler(പൂർണ്ണസംഖ്യ sig)
{
	received_siginfo = 1;
}
#endif

സ്ഥിതം ശൂന്യം
main_sigchld_handler(പൂർണ്ണസംഖ്യ sig)
{
	received_sigchld = 1;
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
should_drop_connection(പൂർണ്ണസംഖ്യ startups)
{
	പൂർണ്ണസംഖ്യ p, r;

	എങ്കിൽ (startups < options.max_startups_begin)
		തിരികെ 0;
	എങ്കിൽ (startups >= options.max_startups)
		തിരികെ 1;
	എങ്കിൽ (options.max_startups_rate == 100)
		തിരികെ 1;

	p  = 100 - options.max_startups_rate;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_rate;
	r = arc4random_uniform(100);

	debug_f("p %d, r %d", p, r);
	തിരികെ (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups or for penalty.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
drop_connection(പൂർണ്ണസംഖ്യ sock, പൂർണ്ണസംഖ്യ startups, പൂർണ്ണസംഖ്യ notify_pipe)
{
	സ്ഥിതം ഘടന log_ratelimit_ctx ratelimit_maxstartups;
	സ്ഥിതം ഘടന log_ratelimit_ctx ratelimit_penalty;
	സ്ഥിതം പൂർണ്ണസംഖ്യ init_done;
	അക്ഷരം *laddr, *raddr;
	സ്ഥിരം അക്ഷരം *reason = ശൂന്യ, *subreason = ശൂന്യ;
	സ്ഥിരം അക്ഷരം സന്ദേശം[] = "Not allowed at this time\r\n";
	ഘടന log_ratelimit_ctx *rl = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ratelimited;
	u_int ndropped;

	എങ്കിൽ (!init_done) {
		init_done = 1;
		log_ratelimit_init(&ratelimit_maxstartups, 4, 60, 20, 5*60);
		log_ratelimit_init(&ratelimit_penalty, 8, 60, 30, 2*60);
	}

	/* PerSourcePenalties */
	എങ്കിൽ (!srclimit_penalty_check_allow(sock, &subreason)) {
		reason = "PerSourcePenalties";
		rl = &ratelimit_penalty;
	} അല്ലെങ്കിൽ {
		/* MaxStartups */
		എങ്കിൽ (!should_drop_connection(startups) &&
		    srclimit_check_allow(sock, notify_pipe) == 1)
			തിരികെ 0;
		reason = "MaxStartups";
		rl = &ratelimit_maxstartups;
	}

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	ratelimited = log_ratelimit(rl, time(ശൂന്യ), ശൂന്യ, &ndropped);
	do_log2(ratelimited ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    "drop connection #%d from [%s]:%d on [%s]:%d %s",
	    startups,
	    raddr, get_peer_port(sock),
	    laddr, get_local_port(sock),
	    subreason != ശൂന്യ ? subreason : reason);
	സ്വതന്ത്രം(laddr);
	സ്വതന്ത്രം(raddr);
	എങ്കിൽ (ndropped != 0) {
		logit("%s logging rate-limited: additional %u connections "
		    "dropped", reason, ndropped);
	}

	/* best-effort notification to client */
	(ശൂന്യം)ലിഖ(sock, സന്ദേശം, വലുപ്പം(സന്ദേശം) - 1);
	തിരികെ 1;
}

സ്ഥിതം ശൂന്യം
usage(ശൂന്യം)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

സ്ഥിതം ഘടന sshbuf *
pack_hostkeys(ശൂന്യം)
{
	ഘടന sshbuf *m = ശൂന്യ, *keybuf = ശൂന്യ, *hostkeys = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;
	u_int i;
	size_t len;

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ ||
	    (keybuf = sshbuf_new()) == ശൂന്യ ||
	    (hostkeys = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	വേണ്ടി (i = 0; i < options.അക്കം_host_താക്കോൽ_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		എങ്കിൽ (sensitive_data.host_താക്കോലുകൾ[i] != ശൂന്യ &&
		    (r = sshkey_private_serialize(sensitive_data.host_താക്കോലുകൾ[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		എങ്കിൽ ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		എങ്കിൽ (sensitive_data.host_pubkeys[i] != ശൂന്യ) {
			എങ്കിൽ ((r = sshkey_puts(sensitive_data.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} അല്ലെങ്കിൽ {
			എങ്കിൽ ((r = sshbuf_put_string(hostkeys, ശൂന്യ, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		എങ്കിൽ (sensitive_data.host_certificates[i] != ശൂന്യ) {
			എങ്കിൽ ((r = sshkey_puts(
			    sensitive_data.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} അല്ലെങ്കിൽ {
			എങ്കിൽ ((r = sshbuf_put_string(hostkeys, ശൂന്യ, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	എങ്കിൽ ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0)
		fatal_fr(r, "compose message");
	എങ്കിൽ ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(keybuf);
	sshbuf_free(hostkeys);
	തിരികെ m;
}

സ്ഥിതം ഘടന sshbuf *
pack_config(ഘടന sshbuf *conf)
{
	ഘടന sshbuf *m = ശൂന്യ, *inc = ശൂന്യ;
	ഘടന include_item *item = ശൂന്യ;
	size_t len;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("d config len %zu", sshbuf_len(conf));

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ ||
	    (inc = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(item, &includes, entry) {
		എങ്കിൽ ((r = sshbuf_put_cstring(inc, item->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, item->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	എങ്കിൽ ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	എങ്കിൽ ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(inc);

	debug3_f("done");
	തിരികെ m;
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
സ്ഥിതം ശൂന്യം
send_rexec_state(പൂർണ്ണസംഖ്യ fd)
{
	ഘടന sshbuf *താക്കോലുകൾ;
	u_int mlen;
	pid_t pid;

	എങ്കിൽ ((pid = fork()) == -1)
		fatal_f("fork failed: %s", strerror(errno));
	എങ്കിൽ (pid != 0)
		തിരികെ;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(config));

	mlen = sshbuf_len(config);
	എങ്കിൽ (atomicio(vwrite, fd, sshbuf_mutable_ptr(config), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	താക്കോലുകൾ = pack_hostkeys();
	mlen = sshbuf_len(താക്കോലുകൾ);
	എങ്കിൽ (atomicio(vwrite, fd, sshbuf_mutable_ptr(താക്കോലുകൾ), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	sshbuf_free(താക്കോലുകൾ);
	debug3_f("done");
	exit(0);
}

/*
 * Listen for TCP connections
 */
സ്ഥിതം ശൂന്യം
listen_on_addrs(ഘടന listenaddr *la)
{
	പൂർണ്ണസംഖ്യ ret, listen_sock;
	ഘടന addrinfo *ai;
	അക്ഷരം ntop[NI_MAXHOST], strport[NI_MAXSERV];

	വേണ്ടി (ai = la->addrs; ai; ai = ai->ai_next) {
		എങ്കിൽ (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			തുടരുക;
		എങ്കിൽ (അക്കം_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		എങ്കിൽ ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, വലുപ്പം(ntop), strport, വലുപ്പം(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			തുടരുക;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		എങ്കിൽ (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			തുടരുക;
		}
		എങ്കിൽ (set_nonblock(listen_sock) == -1) {
			close(listen_sock);
			തുടരുക;
		}
		എങ്കിൽ (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			തുടരുക;
		}
		/* Socket options */
		set_reuseaddr(listen_sock);
		എങ്കിൽ (la->rdomain != ശൂന്യ &&
		    set_rdomain(listen_sock, la->rdomain) == -1) {
			close(listen_sock);
			തുടരുക;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		എങ്കിൽ (ai->ai_family == AF_INET6)
			sock_set_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		എങ്കിൽ (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, strerror(errno));
			close(listen_sock);
			തുടരുക;
		}
		listen_socks[അക്കം_listen_socks] = listen_sock;
		അക്കം_listen_socks++;

		/* Start listening on the port. */
		എങ്കിൽ (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, strerror(errno));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == ശൂന്യ ? "" : " rdomain ",
		    la->rdomain == ശൂന്യ ? "" : la->rdomain);
	}
}

സ്ഥിതം ശൂന്യം
server_listen(ശൂന്യം)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups,
	    options.per_source_max_startups,
	    options.per_source_masklen_ipv4,
	    options.per_source_masklen_ipv6,
	    &options.per_source_penalty,
	    options.per_source_penalty_exempt);

	വേണ്ടി (i = 0; i < options.അക്കം_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		സ്വതന്ത്രം(options.listen_addrs[i].rdomain);
		memset(&options.listen_addrs[i], 0,
		    വലുപ്പം(options.listen_addrs[i]));
	}
	സ്വതന്ത്രം(options.listen_addrs);
	options.listen_addrs = ശൂന്യ;
	options.അക്കം_listen_addrs = 0;

	എങ്കിൽ (!അക്കം_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
സ്ഥിതം ശൂന്യം
server_accept_loop(പൂർണ്ണസംഖ്യ *sock_in, പൂർണ്ണസംഖ്യ *sock_out, പൂർണ്ണസംഖ്യ *newsock, പൂർണ്ണസംഖ്യ *config_s,
    പൂർണ്ണസംഖ്യ log_stderr)
{
	ഘടന pollfd *pfd = ശൂന്യ;
	പൂർണ്ണസംഖ്യ i, ret, npfd, r;
	പൂർണ്ണസംഖ്യ oactive = -1, listening = 0, lameduck = 0;
	പൂർണ്ണസംഖ്യ *startup_pollfd;
	ssize_t len;
	സ്ഥിരം u_char *ptr;
	അക്ഷരം c = 0;
	ഘടന sockaddr_storage from;
	ഘടന early_child *child;
	ഘടന sshbuf *buf;
	socklen_t fromlen;
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	child_alloc();
	startup_pollfd = xcalloc(options.max_startups, വലുപ്പം(പൂർണ്ണസംഖ്യ));

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
	pfd = xcalloc(അക്കം_listen_socks + options.max_startups,
	    വലുപ്പം(ഘടന pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	വേണ്ടി (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		എങ്കിൽ (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (പൂർണ്ണസംഖ്യ) received_sigterm);
			close_listen_socks();
			എങ്കിൽ (options.pid_file != ശൂന്യ)
				unlink(options.pid_file);
			exit(received_sigterm == SIGTERM ? 0 : 255);
		}
		എങ്കിൽ (received_sigchld) {
			child_reap_all_exited();
			received_sigchld = 0;
		}
		എങ്കിൽ (received_siginfo) {
			show_info();
			received_siginfo = 0;
		}
		എങ്കിൽ (oactive != children_active) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, children_active,
			    options.max_startups_begin, options.max_startups);
			oactive = children_active;
		}
		എങ്കിൽ (received_sighup) {
			എങ്കിൽ (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			എങ്കിൽ (listening <= 0) {
				/*
				 * Leave termination signals blocked, so
				 * they don't get lost across a restart.
				 */
				sigaddset(&osigset, SIGTERM);
				sigaddset(&osigset, SIGQUIT);
				sigprocmask(SIG_SETMASK, &osigset, ശൂന്യ);
				sighup_restart();
			}
		}

		വേണ്ടി (i = 0; i < അക്കം_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = അക്കം_listen_socks;
		വേണ്ടി (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			എങ്കിൽ (children[i].pipefd != -1) {
				pfd[npfd].fd = children[i].pipefd;
				pfd[npfd].events = POLLIN;
				എങ്കിൽ (children[i].config != ശൂന്യ ||
				    children[i].താക്കോലുകൾ != ശൂന്യ)
					pfd[npfd].events |= POLLOUT;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, ശൂന്യ, &osigset);
		എങ്കിൽ (ret == -1 && errno != EINTR) {
			error("ppoll: %.100s", strerror(errno));
			എങ്കിൽ (errno == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, ശൂന്യ);
		എങ്കിൽ (ret == -1)
			തുടരുക;

		വേണ്ടി (i = 0; i < options.max_startups; i++) {
			എങ്കിൽ (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & POLLOUT))
				തുടരുക;
			എങ്കിൽ (children[i].config)
				buf = children[i].config;
			അല്ലെങ്കിൽ എങ്കിൽ (children[i].താക്കോലുകൾ)
				buf = children[i].താക്കോലുകൾ;
			അല്ലെങ്കിൽ {
				error_f("no buffer to send");
				തുടരുക;
			}
			ptr = sshbuf_ptr(buf);
			len = sshbuf_len(buf);
			ret = ലിഖ(children[i].pipefd, ptr, len);
			എങ്കിൽ (ret == -1 && (errno == EINTR || errno == EAGAIN))
				തുടരുക;
			എങ്കിൽ (ret <= 0) {
				എങ്കിൽ (children[i].early)
					listening--;
				child_close(&(children[i]), 0, 0);
				തുടരുക;
			}
			എങ്കിൽ (ret == len) {
				/* finished sending buffer */
				sshbuf_free(buf);
				എങ്കിൽ (children[i].config == buf) {
					/* sent config, now send keys */
					children[i].config = ശൂന്യ;
					children[i].താക്കോലുകൾ = pack_hostkeys();
				} അല്ലെങ്കിൽ എങ്കിൽ (children[i].താക്കോലുകൾ == buf) {
					/* sent both config and keys */
					children[i].താക്കോലുകൾ = ശൂന്യ;
				} അല്ലെങ്കിൽ {
					fatal("config buf not set");
				}

			} അല്ലെങ്കിൽ {
				എങ്കിൽ ((r = sshbuf_consume(buf, ret)) != 0)
					fatal_fr(r, "config buf inconsistent");
			}
		}
		വേണ്ടി (i = 0; i < options.max_startups; i++) {
			എങ്കിൽ (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				തുടരുക;
			തിരഞ്ഞെടുപ്പ് (പഠ(children[i].pipefd, &c, വലുപ്പം(c))) {
			അവസ്ഥ -1:
				എങ്കിൽ (errno == EINTR || errno == EAGAIN)
					തുടരുക;
				എങ്കിൽ (errno != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, children[i].pipefd,
					    strerror(errno));
				}
				/* FALLTHROUGH */
			അവസ്ഥ 0:
				/* child closed pipe */
				എങ്കിൽ (children[i].early)
					listening--;
				debug3_f("child %lu for %s closed pipe",
				    (long)children[i].pid, children[i].id);
				child_close(&(children[i]), 0, 0);
				നിർത്തുക;
			അവസ്ഥ 1:
				എങ്കിൽ (children[i].config) {
					error_f("startup pipe %d (fd=%d)"
					    " early read",
					    i, children[i].pipefd);
					പോകുക problem_child;
				}
				എങ്കിൽ (children[i].early && c == '\0') {
					/* child has finished preliminaries */
					listening--;
					children[i].early = 0;
					debug2_f("child %lu for %s received "
					    "config", (long)children[i].pid,
					    children[i].id);
				} അല്ലെങ്കിൽ എങ്കിൽ (!children[i].early && c == '\001') {
					/* child has completed auth */
					debug2_f("child %lu for %s auth done",
					    (long)children[i].pid,
					    children[i].id);
					child_close(&(children[i]), 1, 0);
				} അല്ലെങ്കിൽ {
					error_f("unexpected message 0x%02x "
					    "child %ld for %s in state %d",
					    (പൂർണ്ണസംഖ്യ)c, (long)children[i].pid,
					    children[i].id, children[i].early);
 problem_child:
					എങ്കിൽ (children[i].early)
						listening--;
					എങ്കിൽ (children[i].pid > 0)
						kill(children[i].pid, SIGTERM);
					child_close(&(children[i]), 0, 0);
				}
				നിർത്തുക;
			}
		}
		വേണ്ടി (i = 0; i < അക്കം_listen_socks; i++) {
			എങ്കിൽ (!(pfd[i].revents & POLLIN))
				തുടരുക;
			fromlen = വലുപ്പം(from);
			*newsock = accept(listen_socks[i],
			    (ഘടന sockaddr *)&from, &fromlen);
			എങ്കിൽ (*newsock == -1) {
				എങ്കിൽ (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED && errno != EAGAIN)
					error("accept: %.100s",
					    strerror(errno));
				എങ്കിൽ (errno == EMFILE || errno == ENFILE)
					usleep(100 * 1000);
				തുടരുക;
			}
			എങ്കിൽ (unset_nonblock(*newsock) == -1) {
				close(*newsock);
				തുടരുക;
			}
			എങ്കിൽ (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    strerror(errno));
				close(*newsock);
				തുടരുക;
			}
			എങ്കിൽ (drop_connection(*newsock,
			    children_active, config_s[0])) {
				close(*newsock);
				close(config_s[0]);
				close(config_s[1]);
				തുടരുക;
			}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			എങ്കിൽ (debug_flag) {
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
				സ്വതന്ത്രം(pfd);
				സ്വതന്ത്രം(startup_pollfd);
				തിരികെ;
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
			എങ്കിൽ ((child->pid = fork()) == 0) {
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
				സ്വതന്ത്രം(pfd);
				സ്വതന്ത്രം(startup_pollfd);
				തിരികെ;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_parent(child->pid);
			എങ്കിൽ (child->pid == -1)
				error("fork: %.100s", strerror(errno));
			അല്ലെങ്കിൽ
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

സ്ഥിതം ശൂന്യം
accumulate_host_timing_secret(ഘടന sshbuf *server_cfg,
    ഘടന sshkey *താക്കോൽ)
{
	സ്ഥിതം ഘടന ssh_digest_ctx *ctx;
	u_char *hash;
	size_t len;
	ഘടന sshbuf *buf;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (ctx == ശൂന്യ && (ctx = ssh_digest_start(SSH_DIGEST_SHA512)) == ശൂന്യ)
		fatal_f("ssh_digest_start");
	എങ്കിൽ (താക്കോൽ == ശൂന്യ) { /* finalize */
		/* add server config in case we are using agent for host keys */
		എങ്കിൽ (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_bytes(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		എങ്കിൽ (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = ശൂന്യ;
		തിരികെ;
	}
	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ)
		fatal_f("could not allocate buffer");
	എങ്കിൽ ((r = sshkey_private_serialize(താക്കോൽ, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(താക്കോൽ));
	എങ്കിൽ (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

സ്ഥിതം അക്ഷരം *
prepare_proctitle(പൂർണ്ണസംഖ്യ ac, അക്ഷരം **av)
{
	അക്ഷരം *ret = ശൂന്യ;
	പൂർണ്ണസംഖ്യ i;

	വേണ്ടി (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	തിരികെ ret;
}

/* Disconnect from the controlling tty. */
സ്ഥിതം ശൂന്യം
disconnect_controlling_tty(ശൂന്യം)
{
#ifdef TIOCNOTTY
# ifndef O_NOCTTY
#  define O_NOCTTY 0
# endif
	പൂർണ്ണസംഖ്യ fd;

	എങ്കിൽ ((fd = open(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(ശൂന്യം) ioctl(fd, TIOCNOTTY, ശൂന്യ);
		close(fd);
	}
#endif /* TIOCNOTTY */
}

സ്ഥിതം ശൂന്യം
print_config(ഘടന connection_info *connection_info)
{
	connection_info->test = 1;
	parse_server_match_config(&options, &includes, connection_info);
	dump_config(&options);
	exit(0);
}

/*
 * Main program for the daemon.
 */
പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ ac, അക്ഷരം **av)
{
	ബാഹ്യ അക്ഷരം *optarg;
	ബാഹ്യ പൂർണ്ണസംഖ്യ optind;
	പൂർണ്ണസംഖ്യ log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	അക്ഷരം *config_file_name = _PATH_SERVER_CONFIG_FILE;
	പൂർണ്ണസംഖ്യ r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	പൂർണ്ണസംഖ്യ sock_in = -1, sock_out = -1, newsock = -1, rexec_argc = 0;
	പൂർണ്ണസംഖ്യ devnull, config_s[2] = { -1 , -1 }, have_connection_info = 0;
	പൂർണ്ണസംഖ്യ need_chroot = 1;
	അക്ഷരം *args, *fp, *വരി, *logfile = ശൂന്യ, **rexec_argv = ശൂന്യ;
	ഘടന stat sb;
	u_int i, j;
	mode_t new_umask;
	ഘടന sshkey *താക്കോൽ;
	ഘടന sshkey *pubkey;
	ഘടന connection_info connection_info;
	ഘടന utsname utsname;
	sigset_t sigmask;

	memset(&connection_info, 0, വലുപ്പം(connection_info));
#ifdef HAVE_SECUREWARE
	(ശൂന്യം)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ശൂന്യ);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, വലുപ്പം(*saved_argv));
	വേണ്ടി (i = 0; (പൂർണ്ണസംഖ്യ)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ശൂന്യ;

#ifndef HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#endif

	എങ്കിൽ (geteuid() == 0 && setgroups(0, ശൂന്യ) == -1)
		debug("setgroups(): %.200s", strerror(errno));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	ആകുമ്പോൾ ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		തിരഞ്ഞെടുപ്പ് (opt) {
		അവസ്ഥ '4':
			options.address_family = AF_INET;
			നിർത്തുക;
		അവസ്ഥ '6':
			options.address_family = AF_INET6;
			നിർത്തുക;
		അവസ്ഥ 'f':
			config_file_name = optarg;
			നിർത്തുക;
		അവസ്ഥ 'c':
			servconf_add_hostcert("[command-line]", 0,
			    &options, optarg);
			നിർത്തുക;
		അവസ്ഥ 'd':
			എങ്കിൽ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} അല്ലെങ്കിൽ എങ്കിൽ (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			നിർത്തുക;
		അവസ്ഥ 'D':
			no_daemon_flag = 1;
			നിർത്തുക;
		അവസ്ഥ 'G':
			do_dump_cfg = 1;
			നിർത്തുക;
		അവസ്ഥ 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		അവസ്ഥ 'e':
			log_stderr = 1;
			നിർത്തുക;
		അവസ്ഥ 'i':
			inetd_flag = 1;
			നിർത്തുക;
		അവസ്ഥ 'r':
			logit("-r option is deprecated");
			നിർത്തുക;
		അവസ്ഥ 'R':
			fatal("-R not supported here");
			നിർത്തുക;
		അവസ്ഥ 'Q':
			/* ignored */
			നിർത്തുക;
		അവസ്ഥ 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			നിർത്തുക;
		അവസ്ഥ 'b':
			/* protocol 1, ignored */
			നിർത്തുക;
		അവസ്ഥ 'p':
			options.ports_from_cmdline = 1;
			എങ്കിൽ (options.അക്കം_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				exit(1);
			}
			options.ports[options.അക്കം_ports++] = a2port(optarg);
			എങ്കിൽ (options.ports[options.അക്കം_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				exit(1);
			}
			നിർത്തുക;
		അവസ്ഥ 'g':
			എങ്കിൽ ((options.login_grace_time = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				exit(1);
			}
			നിർത്തുക;
		അവസ്ഥ 'k':
			/* protocol 1, ignored */
			നിർത്തുക;
		അവസ്ഥ 'h':
			servconf_add_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			നിർത്തുക;
		അവസ്ഥ 't':
			test_flag = 1;
			നിർത്തുക;
		അവസ്ഥ 'T':
			test_flag = 2;
			നിർത്തുക;
		അവസ്ഥ 'C':
			എങ്കിൽ (parse_server_match_testspec(&connection_info,
			    optarg) == -1)
				exit(1);
			have_connection_info = 1;
			നിർത്തുക;
		അവസ്ഥ 'u':
			utmp_len = (u_int)strtonum(optarg, 0,
			    HOST_NAME_MAX+1+1, ശൂന്യ);
			എങ്കിൽ (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			നിർത്തുക;
		അവസ്ഥ 'o':
			വരി = xstrdup(optarg);
			എങ്കിൽ (process_server_config_വരി(&options, വരി,
			    "command-line", 0, ശൂന്യ, ശൂന്യ, &includes) != 0)
				exit(1);
			സ്വതന്ത്രം(വരി);
			നിർത്തുക;
		അവസ്ഥ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
		സ്ഥിരസ്ഥിതി:
			usage();
			നിർത്തുക;
		}
	}

	എങ്കിൽ (getexecpath(execpath, വലുപ്പം execpath) != 0) {
		എങ്കിൽ (strlcpy(execpath, av[0], വലുപ്പം execpath) >=
		    വലുപ്പം execpath) {
			fprintf(stderr, "execution path is too long\n");
			exit(1);
		}
	}
	എങ്കിൽ (!test_flag && !inetd_flag && !do_dump_cfg && !path_absolute(execpath))
		fatal("sshd requires execution with an absolute path");

	closefrom(STDERR_FILENO + 1);

	/* Reserve fds we'll need later for reexec things */
	എങ്കിൽ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	ആകുമ്പോൾ (devnull < REEXEC_MIN_FREE_FD) {
		എങ്കിൽ ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	seed_rng();

	/* If requested, redirect the logs to the specified logfile. */
	എങ്കിൽ (logfile != ശൂന്യ) {
		അക്ഷരം *cp, pid_s[32];

		snprintf(pid_s, വലുപ്പം(pid_s), "%ld", (unsigned long)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (അക്ഷരം *)ശൂന്യ);
		log_redirect_stderr_to(cp);
		സ്വതന്ത്രം(cp);
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
	എങ്കിൽ (getenv("KRB5CCNAME") != ശൂന്യ)
		(ശൂന്യം) unsetenv("KRB5CCNAME");

	sensitive_data.have_ssh2_താക്കോൽ = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	എങ്കിൽ (test_flag < 2 && have_connection_info)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	debug("sshd version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);
	എങ്കിൽ (uname(&utsname) != 0) {
		memset(&utsname, 0, വലുപ്പം(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", വലുപ്പം(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	സ്വതന്ത്രം(args);

	/* Fetch our configuration */
	എങ്കിൽ ((cfg = sshbuf_new()) == ശൂന്യ)
		fatal("sshbuf_new config failed");
	എങ്കിൽ (strcasecmp(config_file_name, "none") != 0)
		load_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, ശൂന്യ, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	എങ്കിൽ (options.authorized_താക്കോലുകൾ_command_user == ശൂന്യ &&
	    (options.authorized_താക്കോലുകൾ_command != ശൂന്യ &&
	    strcasecmp(options.authorized_താക്കോലുകൾ_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	എങ്കിൽ (options.authorized_principals_command_user == ശൂന്യ &&
	    (options.authorized_principals_command != ശൂന്യ &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match blocks, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	എങ്കിൽ (options.അക്കം_auth_methods != 0) {
		വേണ്ടി (i = 0; i < options.അക്കം_auth_methods; i++) {
			എങ്കിൽ (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				നിർത്തുക;
		}
		എങ്കിൽ (i >= options.അക്കം_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	എങ്കിൽ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	എങ്കിൽ (do_dump_cfg)
		print_config(&connection_info);

	/* load host keys */
	sensitive_data.host_താക്കോലുകൾ = xcalloc(options.അക്കം_host_താക്കോൽ_files,
	    വലുപ്പം(ഘടന sshkey *));
	sensitive_data.host_pubkeys = xcalloc(options.അക്കം_host_താക്കോൽ_files,
	    വലുപ്പം(ഘടന sshkey *));

	എങ്കിൽ (options.host_താക്കോൽ_agent) {
		എങ്കിൽ (strcmp(options.host_താക്കോൽ_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_താക്കോൽ_agent, 1);
		എങ്കിൽ ((r = ssh_get_authentication_socket(ശൂന്യ)) == 0)
			have_agent = 1;
		അല്ലെങ്കിൽ
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_താക്കോൽ_agent);
	}

	വേണ്ടി (i = 0; i < options.അക്കം_host_താക്കോൽ_files; i++) {
		പൂർണ്ണസംഖ്യ ll = options.host_താക്കോൽ_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		എങ്കിൽ (options.host_താക്കോൽ_files[i] == ശൂന്യ)
			തുടരുക;
		എങ്കിൽ ((r = sshkey_load_private(options.host_താക്കോൽ_files[i], "",
		    &താക്കോൽ, ശൂന്യ)) != 0 &&
		    r != SSH_ERR_SYSTEM_ERROR && !have_agent)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_താക്കോൽ_files[i]);
		എങ്കിൽ (sshkey_is_sk(താക്കോൽ) &&
		    താക്കോൽ->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_താക്കോൽ_files[i]);
			താക്കോൽ->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		എങ്കിൽ (r == 0 && താക്കോൽ != ശൂന്യ &&
		    (r = sshkey_shield_private(താക്കോൽ)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_താക്കോൽ_files[i]);
			sshkey_free(താക്കോൽ);
			താക്കോൽ = ശൂന്യ;
		}
		എങ്കിൽ ((r = sshkey_load_public(options.host_താക്കോൽ_files[i],
		    &pubkey, ശൂന്യ)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_താക്കോൽ_files[i]);
		എങ്കിൽ (pubkey != ശൂന്യ && താക്കോൽ != ശൂന്യ) {
			എങ്കിൽ (!sshkey_equal(pubkey, താക്കോൽ)) {
				error("Public key for %s does not match "
				    "private key", options.host_താക്കോൽ_files[i]);
				sshkey_free(pubkey);
				pubkey = ശൂന്യ;
			}
		}
		എങ്കിൽ (pubkey == ശൂന്യ && താക്കോൽ != ശൂന്യ) {
			എങ്കിൽ ((r = sshkey_from_private(താക്കോൽ, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_താക്കോൽ_files[i]);
		}
		എങ്കിൽ (pubkey != ശൂന്യ && (r = sshkey_check_rsa_length(pubkey,
		    options.required_rsa_size)) != 0) {
			error_fr(r, "Host key %s", options.host_താക്കോൽ_files[i]);
			sshkey_free(pubkey);
			sshkey_free(താക്കോൽ);
			തുടരുക;
		}
		sensitive_data.host_താക്കോലുകൾ[i] = താക്കോൽ;
		sensitive_data.host_pubkeys[i] = pubkey;

		എങ്കിൽ (താക്കോൽ == ശൂന്യ && pubkey != ശൂന്യ && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_താക്കോൽ_files[i]);
			keytype = pubkey->type;
		} അല്ലെങ്കിൽ എങ്കിൽ (താക്കോൽ != ശൂന്യ) {
			keytype = താക്കോൽ->type;
			accumulate_host_timing_secret(cfg, താക്കോൽ);
		} അല്ലെങ്കിൽ {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_താക്കോൽ_files[i]);
			sensitive_data.host_താക്കോലുകൾ[i] = ശൂന്യ;
			sensitive_data.host_pubkeys[i] = ശൂന്യ;
			തുടരുക;
		}

		തിരഞ്ഞെടുപ്പ് (keytype) {
		അവസ്ഥ താക്കോൽ_RSA:
		അവസ്ഥ താക്കോൽ_ECDSA:
		അവസ്ഥ താക്കോൽ_ED25519:
		അവസ്ഥ താക്കോൽ_MLDSA44_ED25519:
		അവസ്ഥ താക്കോൽ_ECDSA_SK:
		അവസ്ഥ താക്കോൽ_ED25519_SK:
			എങ്കിൽ (have_agent || താക്കോൽ != ശൂന്യ)
				sensitive_data.have_ssh2_താക്കോൽ = 1;
			നിർത്തുക;
		}
		എങ്കിൽ ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == ശൂന്യ)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    താക്കോൽ ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		സ്വതന്ത്രം(fp);
	}
	accumulate_host_timing_secret(cfg, ശൂന്യ);
	എങ്കിൽ (!sensitive_data.have_ssh2_താക്കോൽ) {
		logit("sshd: no hostkeys available -- exiting.");
		exit(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_data.host_certificates = xcalloc(options.അക്കം_host_താക്കോൽ_files,
	    വലുപ്പം(ഘടന sshkey *));
	വേണ്ടി (i = 0; i < options.അക്കം_host_താക്കോൽ_files; i++)
		sensitive_data.host_certificates[i] = ശൂന്യ;

	വേണ്ടി (i = 0; i < options.അക്കം_host_cert_files; i++) {
		എങ്കിൽ (options.host_cert_files[i] == ശൂന്യ)
			തുടരുക;
		എങ്കിൽ ((r = sshkey_load_public(options.host_cert_files[i],
		    &താക്കോൽ, ശൂന്യ)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			തുടരുക;
		}
		എങ്കിൽ (!sshkey_is_cert(താക്കോൽ)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(താക്കോൽ);
			തുടരുക;
		}
		/* Find matching private key */
		വേണ്ടി (j = 0; j < options.അക്കം_host_താക്കോൽ_files; j++) {
			എങ്കിൽ (sshkey_equal_public(താക്കോൽ,
			    sensitive_data.host_pubkeys[j])) {
				sensitive_data.host_certificates[j] = താക്കോൽ;
				നിർത്തുക;
			}
		}
		എങ്കിൽ (j >= options.അക്കം_host_താക്കോൽ_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(താക്കോൽ);
			തുടരുക;
		}
		sensitive_data.host_certificates[j] = താക്കോൽ;
		debug("host certificate: #%u type %d %s", j, താക്കോൽ->type,
		    sshkey_type(താക്കോൽ));
	}

	/* Ensure privsep directory is correctly configured. */
	need_chroot = ((getuid() == 0 || geteuid() == 0) ||
	    options.kerberos_authentication);
	എങ്കിൽ ((getpwnam(SSH_PRIVSEP_USER)) == ശൂന്യ && need_chroot) {
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	}
	endpwent();

	എങ്കിൽ (need_chroot) {
		എങ്കിൽ ((stat(_PATH_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
		    (S_ISDIR(sb.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    _PATH_PRIVSEP_CHROOT_DIR);
#ifdef HAVE_CYGWIN
		എങ്കിൽ (check_ntsec(_PATH_PRIVSEP_CHROOT_DIR) &&
		    (sb.st_uid != getuid () ||
		    (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#അല്ലെങ്കിൽ
		എങ്കിൽ (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#endif
			fatal("%s must be owned by root and not group or "
			    "world-writable.", _PATH_PRIVSEP_CHROOT_DIR);
	}

	എങ്കിൽ (test_flag > 1)
		print_config(&connection_info);

	config = pack_config(cfg);
	എങ്കിൽ (sshbuf_len(config) > MONITOR_MAX_CFGLEN) {
		fatal("Configuration file is too large (have %zu, max %d)",
		    sshbuf_len(config), MONITOR_MAX_CFGLEN);
	}

	/* Configuration looks good, so exit if in test mode. */
	എങ്കിൽ (test_flag)
		exit(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	എങ്കിൽ (setgroups(0, ശൂന്യ) < 0)
		debug("setgroups() failed: %.200s", strerror(errno));

	/* Prepare arguments for sshd-session */
	എങ്കിൽ (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, വലുപ്പം(അക്ഷരം *));
	/* Point to the sshd-session binary instead of sshd */
	rexec_argv[0] = options.sshd_session_path;
	വേണ്ടി (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = ശൂന്യ;
	എങ്കിൽ (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	എങ്കിൽ (stat(options.sshd_auth_path, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_auth_path);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(ശൂന്യം) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	എങ്കിൽ (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	വേണ്ടി (i = 0; i < options.അക്കം_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	എങ്കിൽ (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		എങ്കിൽ (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", strerror(errno));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	എങ്കിൽ (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or a listening TCP socket */
	എങ്കിൽ (inetd_flag) {
		/* Send configuration to ancestor sshd-session process */
		എങ്കിൽ (socketpair(AF_UNIX, SOCK_STREAM, 0, config_s) == -1)
			fatal("socketpair: %s", strerror(errno));
		send_rexec_state(config_s[0]);
		close(config_s[0]);
	} അല്ലെങ്കിൽ {
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
		എങ്കിൽ (options.pid_file != ശൂന്യ && !debug_flag) {
			FILE *f = fopen(options.pid_file, "w");

			എങ്കിൽ (f == ശൂന്യ) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, strerror(errno));
			} അല്ലെങ്കിൽ {
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
	എങ്കിൽ (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	debug("rexec start in %d out %d newsock %d config_s %d/%d",
	    sock_in, sock_out, newsock, config_s[0], config_s[1]);
	എങ്കിൽ (!inetd_flag) {
		എങ്കിൽ (dup2(newsock, STDIN_FILENO) == -1)
			fatal("dup2 stdin: %s", strerror(errno));
		എങ്കിൽ (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			fatal("dup2 stdout: %s", strerror(errno));
		എങ്കിൽ (newsock > STDOUT_FILENO)
			close(newsock);
	}
	എങ്കിൽ (config_s[1] != REEXEC_CONFIG_PASS_FD) {
		എങ്കിൽ (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			fatal("dup2 config_s: %s", strerror(errno));
		close(config_s[1]);
	}
	log_redirect_stderr_to(ശൂന്യ);
	closefrom(REEXEC_MIN_FREE_FD);

	ssh_signal(SIGHUP, SIG_IGN); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], strerror(errno));
}

/* server specific fatal cleanup */
ശൂന്യം
cleanup_exit(പൂർണ്ണസംഖ്യ i)
{
	_exit(i);
}
