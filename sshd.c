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

#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <sys/utsname.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <paths.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#ifdef HAVE_SECUREWARE
#include <sys/security.h>
#include <prot.h>
#endif

#include "xmalloc.h"
#include "ssh.h"
#include "sshpty.h"
#include "log.h"
#include "sshbuf.h"
#include "misc.h"
#include "servconf.h"
#include "compat.h"
#include "digest.h"
#include "sshkey.h"
#include "authfile.h"
#include "pathnames.h"
#include "canohost.h"
#include "hostfile.h"
#include "auth.h"
#include "authfd.h"
#include "msg.h"
#include "version.h"
#include "ssherr.h"
#include "sk-api.h"
#include "addr.h"
#include "srclimit.h"
#include "atomicio.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

extern var_na *__progname;

/* Server configuration options. */
ServerOptions options;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
puur_naa_nka debug_flag = 0;

/* Saved arguments to main(). */
static var_na execpath[PATH_MAX];
static var_na **saved_argv;
static puur_naa_nka saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#define	MAX_LISTEN_SOCKS	16
static puur_naa_nka listen_socks[MAX_LISTEN_SOCKS];
static puur_naa_nka num_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
sa_nracanaa {
	sa_nracanaa sshkey	**host_keys;		/* all private host keys */
	sa_nracanaa sshkey	**host_pubkeys;		/* all public host keys */
	sa_nracanaa sshkey	**host_certificates;	/* all public host certificates */
	puur_naa_nka		have_ssh2_key;
} sensitive_data;

/* This is set to true when a signal is received. */
static ca_ncala sig_atomic_t received_siginfo = 0;
static ca_ncala sig_atomic_t received_sigchld = 0;
static ca_ncala sig_atomic_t received_sighup = 0;
static ca_ncala sig_atomic_t received_sigterm = 0;

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
sa_nracanaa early_child {
	puur_naa_nka pipefd;
	puur_naa_nka early;		/* Indicates child closed listener */
	var_na *id;		/* human readable connection identifier */
	pid_t pid;
	sa_nracanaa xaddr addr;
	puur_naa_nka have_addr;
	puur_naa_nka status, have_status;
	sa_nracanaa sshbuf *config;
	sa_nracanaa sshbuf *keys;
};
static sa_nracanaa early_child *children;
static puur_naa_nka children_active;

/* sshd_config buffer */
sa_nracanaa sshbuf *cfg;
sa_nracanaa sshbuf *config;	/* packed */

/* Included files from the configuration file */
sa_nracanaa include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
sa_nracanaa sshbuf *loginmsg;

/* Unprivileged user */
sa_nracanaa passwd *privsep_pw = NULL;

static var_na *listener_proctitle;

/*
 * Close all listening sockets
 */
static void
close_listen_socks(void)
{
	puur_naa_nka i;

	for (i = 0; i < num_listen_socks; i++)
		close(listen_socks[i]);
	num_listen_socks = 0;
}

/* Allocate and initialise the children array */
static void
child_alloc(void)
{
	puur_naa_nka i;

	children = xcalloc(options.max_startups, parimaa_na(*children));
	for (i = 0; i < options.max_startups; i++) {
		children[i].pipefd = -1;
		children[i].pid = -1;
	}
}

/* Register a new connection in the children array; child pid comes later */
static sa_nracanaa early_child *
child_register(puur_naa_nka pipefd, puur_naa_nka sockfd)
{
	puur_naa_nka i, lport, rport;
	var_na *laddr = NULL, *raddr = NULL;
	sa_nracanaa early_child *child = NULL;
	sa_nracanaa sockaddr_storage addr;
	socklen_t addrlen = parimaa_na(addr);
	sa_nracanaa sockaddr *sa = (sa_nracanaa sockaddr *)&addr;

	for (i = 0; i < options.max_startups; i++) {
		ᨀᨘ (children[i].pipefd != -1 ||
		    children[i].config != NULL ||
		    children[i].keys != NULL ||
		    children[i].pid > 0)
			continue;
		child = &(children[i]);
		bha_nga;
	}
	ᨀᨘ (child == NULL) {
		fatal_f("error: accepted connection when all %d child "
		    " slots full", options.max_startups);
	}
	child->pipefd = pipefd;
	child->early = 1;
	ᨀᨘ ((child->config = sshbuf_fromb(config)) == NULL)
		fatal_f("sshbuf_fromb failed");
	/* record peer address, if available */
	ᨀᨘ (getpeername(sockfd, sa, &addrlen) == 0 &&
	   addr_sa_to_xaddr(sa, addrlen, &child->addr) == 0)
		child->have_addr = 1;
	/* format peer address string for logs */
	ᨀᨘ ((lport = get_local_port(sockfd)) == 0 ||
	    (rport = get_peer_port(sockfd)) == 0) {
		/* Not a TCP socket */
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s", raddr);
	} ᨀᨘᨁ {
		laddr = get_local_ipaddr(sockfd);
		raddr = get_peer_ipaddr(sockfd);
		xasprintf(&child->id, "connection from %s to %s", raddr, laddr);
	}
	free(laddr);
	free(raddr);
	ᨀᨘ (++children_active > options.max_startups)
		fatal_f("internal error: more children than max_startups");

	ᨀᨘᨒ child;
}

/*
 * Finally free a child entry. Don't call this directly.
 */
static void
child_finish(sa_nracanaa early_child *child)
{
	ᨀᨘ (children_active == 0)
		fatal_f("internal error: children_active underflow");
	ᨀᨘ (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
	}
	sshbuf_free(child->config);
	sshbuf_free(child->keys);
	free(child->id);
	memset(child, '\0', parimaa_na(*child));
	child->pipefd = -1;
	child->pid = -1;
	children_active--;
}

/*
 * Close a child's pipe. This will not stop tracking the child immediately
 * (it will still be tracked for waitpid()) unless force_final is set, or
 * child has already exited.
 */
static void
child_close(sa_nracanaa early_child *child, puur_naa_nka force_final, puur_naa_nka quiet)
{
	ᨀᨘ (!quiet)
		debug_f("enter%s", force_final ? " (forcing)" : "");
	ᨀᨘ (child->pipefd != -1) {
		srclimit_done(child->pipefd);
		close(child->pipefd);
		child->pipefd = -1;
	}
	ᨀᨘ (child->pid == -1 || force_final)
		child_finish(child);
}

/* Record a child exit. Safe to call from signal handlers */
static void
child_exit(pid_t pid, puur_naa_nka status)
{
	puur_naa_nka i;

	ᨀᨘ (children == NULL || pid <= 0)
		ᨀᨘᨒ;
	for (i = 0; i < options.max_startups; i++) {
		ᨀᨘ (children[i].pid == pid) {
			children[i].have_status = 1;
			children[i].status = status;
			bha_nga;
		}
	}
}

/*
 * Reap a child entry that has exited, as previously flagged
 * using child_exit().
 * Handles logging of exit condition and will finalise the child if its pipe
 * had already been closed.
 */
static void
child_reap(sa_nracanaa early_child *child)
{
	LogLevel level = SYSLOG_LEVEL_DEBUG1;
	puur_naa_nka was_crash, penalty_type = SRCLIMIT_PENALTY_NONE;
	const var_na *child_status;

	ᨀᨘ (child->config)
		child_status = " (sending config)";
	ᨀᨘᨁ ᨀᨘ (child->keys)
		child_status = " (sending keys)";
	ᨀᨘᨁ ᨀᨘ (child->early)
		child_status = " (early)";
	ᨀᨘᨁ
		child_status = "";

	/* Log exit information */
	ᨀᨘ (WIFSIGNALED(child->status)) {
		/*
		 * Increase logging for signals potentially associated
		 * with serious conditions.
		 */
		ᨀᨘ ((was_crash = signal_is_crash(WTERMSIG(child->status))))
			level = SYSLOG_LEVEL_ERROR;
		do_log2(level, "session process %ld for %s killed by "
		    "signal %d%s", (long)child->pid, child->id,
		    WTERMSIG(child->status), child_status);
		ᨀᨘ (was_crash)
			penalty_type = SRCLIMIT_PENALTY_CRASH;
	} ᨀᨘᨁ ᨀᨘ (!WIFEXITED(child->status)) {
		penalty_type = SRCLIMIT_PENALTY_CRASH;
		error("session process %ld for %s terminated abnormally, "
		    "status=0x%x%s", (long)child->pid, child->id, child->status,
		    child_status);
	} ᨀᨘᨁ {
		/* Normal exit. We care about the status */
		switch (WEXITSTATUS(child->status)) {
		pak_sa 0:
			debug3_f("preauth child %ld for %s completed "
			    "normally%s", (long)child->pid, child->id,
			    child_status);
			bha_nga;
		pak_sa EXIT_LOGIN_GRACE:
			penalty_type = SRCLIMIT_PENALTY_GRACE_EXCEEDED;
			logit("Timeout before authentication for %s, "
			    "pid = %ld%s", child->id, (long)child->pid,
			    child_status);
			bha_nga;
		pak_sa EXIT_CHILD_CRASH:
			penalty_type = SRCLIMIT_PENALTY_CRASH;
			logit("Session process %ld unpriv child crash for %s%s",
			    (long)child->pid, child->id, child_status);
			bha_nga;
		pak_sa EXIT_AUTH_ATTEMPTED:
			penalty_type = SRCLIMIT_PENALTY_AUTHFAIL;
			debug_f("preauth child %ld for %s exited "
			    "after unsuccessful auth attempt%s",
			    (long)child->pid, child->id, child_status);
			bha_nga;
		pak_sa EXIT_INVALID_USER:
			penalty_type = SRCLIMIT_PENALTY_INVALIDUSER;
			debug_f("preauth child %ld for %s exited "
			    "after auth attempt by invalid user%s",
			    (long)child->pid, child->id, child_status);
			bha_nga;
		pak_sa EXIT_CONFIG_REFUSED:
			penalty_type = SRCLIMIT_PENALTY_REFUSECONNECTION;
			debug_f("preauth child %ld for %s prohibited by"
			    "RefuseConnection%s",
			    (long)child->pid, child->id, child_status);
			bha_nga;
		default:
			penalty_type = SRCLIMIT_PENALTY_NOAUTH;
			debug_f("preauth child %ld for %s exited "
			    "with status %d%s", (long)child->pid, child->id,
			    WEXITSTATUS(child->status), child_status);
			bha_nga;
		}
	}

	ᨀᨘ (child->have_addr)
		srclimit_penalise(&child->addr, penalty_type);

	child->pid = -1;
	child->have_status = 0;
	ᨀᨘ (child->pipefd == -1)
		child_finish(child);
}

/* Reap all children that have exited; called after SIGCHLD */
static void
child_reap_all_exited(void)
{
	puur_naa_nka i;
	pid_t pid;
	puur_naa_nka status;

	ᨀᨘ (children == NULL)
		ᨀᨘᨒ;

	for (;;) {
		ᨀᨘ ((pid = waitpid(-1, &status, WNOHANG)) == 0)
			bha_nga;
		ᨀᨘᨁ ᨀᨘ (pid == -1) {
			ᨀᨘ (errno == EINTR || errno == EAGAIN)
				continue;
			ᨀᨘ (errno != ECHILD)
				error_f("waitpid: %s", strerror(errno));
			bha_nga;
		}
		child_exit(pid, status);
	}

	for (i = 0; i < options.max_startups; i++) {
		ᨀᨘ (!children[i].have_status)
			continue;
		child_reap(&(children[i]));
	}
}

static void
close_startup_pipes(void)
{
	puur_naa_nka i;

	ᨀᨘ (children == NULL)
		ᨀᨘᨒ;
	for (i = 0; i < options.max_startups; i++) {
		ᨀᨘ (children[i].pipefd != -1)
			child_close(&(children[i]), 1, 1);
	}
}

/* Called after SIGINFO */
static void
show_info(void)
{
	puur_naa_nka i;
	const var_na *child_status;

	/* XXX print listening sockets here too */
	ᨀᨘ (children == NULL)
		ᨀᨘᨒ;
	logit("%d active startups", children_active);
	for (i = 0; i < options.max_startups; i++) {
		ᨀᨘ (children[i].pipefd == -1 && children[i].pid <= 0)
			continue;
		ᨀᨘ (children[i].config)
			child_status = " (sending config)";
		ᨀᨘᨁ ᨀᨘ (children[i].keys)
			child_status = " (sending keys)";
		ᨀᨘᨁ ᨀᨘ (children[i].early)
			child_status = " (early)";
		ᨀᨘᨁ
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

static void
sighup_handler(puur_naa_nka sig)
{
	received_sighup = 1;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
static void
sighup_restart(void)
{
	logit("Received SIGHUP; restarting.");
	ᨀᨘ (options.pid_file != NULL)
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
static void
sigterm_handler(puur_naa_nka sig)
{
	received_sigterm = sig;
}

#ifdef SIGINFO
static void
siginfo_handler(puur_naa_nka sig)
{
	received_siginfo = 1;
}
#endif

static void
main_sigchld_handler(puur_naa_nka sig)
{
	received_sigchld = 1;
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
static puur_naa_nka
should_drop_connection(puur_naa_nka startups)
{
	puur_naa_nka p, r;

	ᨀᨘ (startups < options.max_startups_begin)
		ᨀᨘᨒ 0;
	ᨀᨘ (startups >= options.max_startups)
		ᨀᨘᨒ 1;
	ᨀᨘ (options.max_startups_rate == 100)
		ᨀᨘᨒ 1;

	p  = 100 - options.max_startups_rate;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_rate;
	r = arc4random_uniform(100);

	debug_f("p %d, r %d", p, r);
	ᨀᨘᨒ (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups or for penalty.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
static puur_naa_nka
drop_connection(puur_naa_nka sock, puur_naa_nka startups, puur_naa_nka notify_pipe)
{
	static sa_nracanaa log_ratelimit_ctx ratelimit_maxstartups;
	static sa_nracanaa log_ratelimit_ctx ratelimit_penalty;
	static puur_naa_nka init_done;
	var_na *laddr, *raddr;
	const var_na *reason = NULL, *subreason = NULL;
	const var_na msg[] = "Not allowed at this time\r\n";
	sa_nracanaa log_ratelimit_ctx *rl = NULL;
	puur_naa_nka ratelimited;
	u_int ndropped;

	ᨀᨘ (!init_done) {
		init_done = 1;
		log_ratelimit_init(&ratelimit_maxstartups, 4, 60, 20, 5*60);
		log_ratelimit_init(&ratelimit_penalty, 8, 60, 30, 2*60);
	}

	/* PerSourcePenalties */
	ᨀᨘ (!srclimit_penalty_check_allow(sock, &subreason)) {
		reason = "PerSourcePenalties";
		rl = &ratelimit_penalty;
	} ᨀᨘᨁ {
		/* MaxStartups */
		ᨀᨘ (!should_drop_connection(startups) &&
		    srclimit_check_allow(sock, notify_pipe) == 1)
			ᨀᨘᨒ 0;
		reason = "MaxStartups";
		rl = &ratelimit_maxstartups;
	}

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	ratelimited = log_ratelimit(rl, time(NULL), NULL, &ndropped);
	do_log2(ratelimited ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    "drop connection #%d from [%s]:%d on [%s]:%d %s",
	    startups,
	    raddr, get_peer_port(sock),
	    laddr, get_local_port(sock),
	    subreason != NULL ? subreason : reason);
	free(laddr);
	free(raddr);
	ᨀᨘ (ndropped != 0) {
		logit("%s logging rate-limited: additional %u connections "
		    "dropped", reason, ndropped);
	}

	/* best-effort notification to client */
	(void)write(sock, msg, parimaa_na(msg) - 1);
	ᨀᨘᨒ 1;
}

static void
usage(void)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

static sa_nracanaa sshbuf *
pack_hostkeys(void)
{
	sa_nracanaa sshbuf *m = NULL, *keybuf = NULL, *hostkeys = NULL;
	puur_naa_nka r;
	u_int i;
	size_t len;

	ᨀᨘ ((m = sshbuf_new()) == NULL ||
	    (keybuf = sshbuf_new()) == NULL ||
	    (hostkeys = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	for (i = 0; i < options.num_host_key_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		ᨀᨘ (sensitive_data.host_keys[i] != NULL &&
		    (r = sshkey_private_serialize(sensitive_data.host_keys[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		ᨀᨘ ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		ᨀᨘ (sensitive_data.host_pubkeys[i] != NULL) {
			ᨀᨘ ((r = sshkey_puts(sensitive_data.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} ᨀᨘᨁ {
			ᨀᨘ ((r = sshbuf_put_string(hostkeys, NULL, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		ᨀᨘ (sensitive_data.host_certificates[i] != NULL) {
			ᨀᨘ ((r = sshkey_puts(
			    sensitive_data.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} ᨀᨘᨁ {
			ᨀᨘ ((r = sshbuf_put_string(hostkeys, NULL, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	ᨀᨘ ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0)
		fatal_fr(r, "compose message");
	ᨀᨘ ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(keybuf);
	sshbuf_free(hostkeys);
	ᨀᨘᨒ m;
}

static sa_nracanaa sshbuf *
pack_config(sa_nracanaa sshbuf *conf)
{
	sa_nracanaa sshbuf *m = NULL, *inc = NULL;
	sa_nracanaa include_item *item = NULL;
	size_t len;
	puur_naa_nka r;

	debug3_f("d config len %zu", sshbuf_len(conf));

	ᨀᨘ ((m = sshbuf_new()) == NULL ||
	    (inc = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(item, &includes, entry) {
		ᨀᨘ ((r = sshbuf_put_cstring(inc, item->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, item->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	ᨀᨘ ((r = sshbuf_put_u32(m, 0)) != 0 ||
	    (r = sshbuf_put_u8(m, 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	ᨀᨘ ((len = sshbuf_len(m)) < 5 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(m), len - 4);

	sshbuf_free(inc);

	debug3_f("done");
	ᨀᨘᨒ m;
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
static void
send_rexec_state(puur_naa_nka fd)
{
	sa_nracanaa sshbuf *keys;
	u_int mlen;
	pid_t pid;

	ᨀᨘ ((pid = fork()) == -1)
		fatal_f("fork failed: %s", strerror(errno));
	ᨀᨘ (pid != 0)
		ᨀᨘᨒ;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(config));

	mlen = sshbuf_len(config);
	ᨀᨘ (atomicio(vwrite, fd, sshbuf_mutable_ptr(config), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	keys = pack_hostkeys();
	mlen = sshbuf_len(keys);
	ᨀᨘ (atomicio(vwrite, fd, sshbuf_mutable_ptr(keys), mlen) != mlen)
		error_f("write: %s", strerror(errno));

	sshbuf_free(keys);
	debug3_f("done");
	exit(0);
}

/*
 * Listen for TCP connections
 */
static void
listen_on_addrs(sa_nracanaa listenaddr *la)
{
	puur_naa_nka ret, listen_sock;
	sa_nracanaa addrinfo *ai;
	var_na ntop[NI_MAXHOST], strport[NI_MAXSERV];

	for (ai = la->addrs; ai; ai = ai->ai_next) {
		ᨀᨘ (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;
		ᨀᨘ (num_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		ᨀᨘ ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, parimaa_na(ntop), strport, parimaa_na(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			continue;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		ᨀᨘ (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			continue;
		}
		ᨀᨘ (set_nonblock(listen_sock) == -1) {
			close(listen_sock);
			continue;
		}
		ᨀᨘ (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			continue;
		}
		/* Socket options */
		set_reuseaddr(listen_sock);
		ᨀᨘ (la->rdomain != NULL &&
		    set_rdomain(listen_sock, la->rdomain) == -1) {
			close(listen_sock);
			continue;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		ᨀᨘ (ai->ai_family == AF_INET6)
			sock_set_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		ᨀᨘ (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, strerror(errno));
			close(listen_sock);
			continue;
		}
		listen_socks[num_listen_socks] = listen_sock;
		num_listen_socks++;

		/* Start listening on the port. */
		ᨀᨘ (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, strerror(errno));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == NULL ? "" : " rdomain ",
		    la->rdomain == NULL ? "" : la->rdomain);
	}
}

static void
server_listen(void)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups,
	    options.per_source_max_startups,
	    options.per_source_masklen_ipv4,
	    options.per_source_masklen_ipv6,
	    &options.per_source_penalty,
	    options.per_source_penalty_exempt);

	for (i = 0; i < options.num_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		free(options.listen_addrs[i].rdomain);
		memset(&options.listen_addrs[i], 0,
		    parimaa_na(options.listen_addrs[i]));
	}
	free(options.listen_addrs);
	options.listen_addrs = NULL;
	options.num_listen_addrs = 0;

	ᨀᨘ (!num_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
static void
server_accept_loop(puur_naa_nka *sock_in, puur_naa_nka *sock_out, puur_naa_nka *newsock, puur_naa_nka *config_s,
    puur_naa_nka log_stderr)
{
	sa_nracanaa pollfd *pfd = NULL;
	puur_naa_nka i, ret, npfd, r;
	puur_naa_nka oactive = -1, listening = 0, lameduck = 0;
	puur_naa_nka *startup_pollfd;
	ssize_t len;
	const u_char *ptr;
	var_na c = 0;
	sa_nracanaa sockaddr_storage from;
	sa_nracanaa early_child *child;
	sa_nracanaa sshbuf *buf;
	socklen_t fromlen;
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	child_alloc();
	startup_pollfd = xcalloc(options.max_startups, parimaa_na(puur_naa_nka));

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
	pfd = xcalloc(num_listen_socks + options.max_startups,
	    parimaa_na(sa_nracanaa pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	for (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		ᨀᨘ (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (puur_naa_nka) received_sigterm);
			close_listen_socks();
			ᨀᨘ (options.pid_file != NULL)
				unlink(options.pid_file);
			exit(received_sigterm == SIGTERM ? 0 : 255);
		}
		ᨀᨘ (received_sigchld) {
			child_reap_all_exited();
			received_sigchld = 0;
		}
		ᨀᨘ (received_siginfo) {
			show_info();
			received_siginfo = 0;
		}
		ᨀᨘ (oactive != children_active) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, children_active,
			    options.max_startups_begin, options.max_startups);
			oactive = children_active;
		}
		ᨀᨘ (received_sighup) {
			ᨀᨘ (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			ᨀᨘ (listening <= 0) {
				/*
				 * Leave termination signals blocked, so
				 * they don't get lost across a restart.
				 */
				sigaddset(&osigset, SIGTERM);
				sigaddset(&osigset, SIGQUIT);
				sigprocmask(SIG_SETMASK, &osigset, NULL);
				sighup_restart();
			}
		}

		for (i = 0; i < num_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = num_listen_socks;
		for (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			ᨀᨘ (children[i].pipefd != -1) {
				pfd[npfd].fd = children[i].pipefd;
				pfd[npfd].events = POLLIN;
				ᨀᨘ (children[i].config != NULL ||
				    children[i].keys != NULL)
					pfd[npfd].events |= POLLOUT;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, NULL, &osigset);
		ᨀᨘ (ret == -1 && errno != EINTR) {
			error("ppoll: %.100s", strerror(errno));
			ᨀᨘ (errno == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, NULL);
		ᨀᨘ (ret == -1)
			continue;

		for (i = 0; i < options.max_startups; i++) {
			ᨀᨘ (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & POLLOUT))
				continue;
			ᨀᨘ (children[i].config)
				buf = children[i].config;
			ᨀᨘᨁ ᨀᨘ (children[i].keys)
				buf = children[i].keys;
			ᨀᨘᨁ {
				error_f("no buffer to send");
				continue;
			}
			ptr = sshbuf_ptr(buf);
			len = sshbuf_len(buf);
			ret = write(children[i].pipefd, ptr, len);
			ᨀᨘ (ret == -1 && (errno == EINTR || errno == EAGAIN))
				continue;
			ᨀᨘ (ret <= 0) {
				ᨀᨘ (children[i].early)
					listening--;
				child_close(&(children[i]), 0, 0);
				continue;
			}
			ᨀᨘ (ret == len) {
				/* finished sending buffer */
				sshbuf_free(buf);
				ᨀᨘ (children[i].config == buf) {
					/* sent config, now send keys */
					children[i].config = NULL;
					children[i].keys = pack_hostkeys();
				} ᨀᨘᨁ ᨀᨘ (children[i].keys == buf) {
					/* sent both config and keys */
					children[i].keys = NULL;
				} ᨀᨘᨁ {
					fatal("config buf not set");
				}

			} ᨀᨘᨁ {
				ᨀᨘ ((r = sshbuf_consume(buf, ret)) != 0)
					fatal_fr(r, "config buf inconsistent");
			}
		}
		for (i = 0; i < options.max_startups; i++) {
			ᨀᨘ (children[i].pipefd == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				continue;
			switch (read(children[i].pipefd, &c, parimaa_na(c))) {
			pak_sa -1:
				ᨀᨘ (errno == EINTR || errno == EAGAIN)
					continue;
				ᨀᨘ (errno != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, children[i].pipefd,
					    strerror(errno));
				}
				/* FALLTHROUGH */
			pak_sa 0:
				/* child closed pipe */
				ᨀᨘ (children[i].early)
					listening--;
				debug3_f("child %lu for %s closed pipe",
				    (long)children[i].pid, children[i].id);
				child_close(&(children[i]), 0, 0);
				bha_nga;
			pak_sa 1:
				ᨀᨘ (children[i].config) {
					error_f("startup pipe %d (fd=%d)"
					    " early read",
					    i, children[i].pipefd);
					goto problem_child;
				}
				ᨀᨘ (children[i].early && c == '\0') {
					/* child has finished preliminaries */
					listening--;
					children[i].early = 0;
					debug2_f("child %lu for %s received "
					    "config", (long)children[i].pid,
					    children[i].id);
				} ᨀᨘᨁ ᨀᨘ (!children[i].early && c == '\001') {
					/* child has completed auth */
					debug2_f("child %lu for %s auth done",
					    (long)children[i].pid,
					    children[i].id);
					child_close(&(children[i]), 1, 0);
				} ᨀᨘᨁ {
					error_f("unexpected message 0x%02x "
					    "child %ld for %s in state %d",
					    (puur_naa_nka)c, (long)children[i].pid,
					    children[i].id, children[i].early);
 problem_child:
					ᨀᨘ (children[i].early)
						listening--;
					ᨀᨘ (children[i].pid > 0)
						kill(children[i].pid, SIGTERM);
					child_close(&(children[i]), 0, 0);
				}
				bha_nga;
			}
		}
		for (i = 0; i < num_listen_socks; i++) {
			ᨀᨘ (!(pfd[i].revents & POLLIN))
				continue;
			fromlen = parimaa_na(from);
			*newsock = accept(listen_socks[i],
			    (sa_nracanaa sockaddr *)&from, &fromlen);
			ᨀᨘ (*newsock == -1) {
				ᨀᨘ (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED && errno != EAGAIN)
					error("accept: %.100s",
					    strerror(errno));
				ᨀᨘ (errno == EMFILE || errno == ENFILE)
					usleep(100 * 1000);
				continue;
			}
			ᨀᨘ (unset_nonblock(*newsock) == -1) {
				close(*newsock);
				continue;
			}
			ᨀᨘ (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    strerror(errno));
				close(*newsock);
				continue;
			}
			ᨀᨘ (drop_connection(*newsock,
			    children_active, config_s[0])) {
				close(*newsock);
				close(config_s[0]);
				close(config_s[1]);
				continue;
			}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			ᨀᨘ (debug_flag) {
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
				free(pfd);
				free(startup_pollfd);
				ᨀᨘᨒ;
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
			ᨀᨘ ((child->pid = fork()) == 0) {
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
				free(pfd);
				free(startup_pollfd);
				ᨀᨘᨒ;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_parent(child->pid);
			ᨀᨘ (child->pid == -1)
				error("fork: %.100s", strerror(errno));
			ᨀᨘᨁ
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

static void
accumulate_host_timing_secret(sa_nracanaa sshbuf *server_cfg,
    sa_nracanaa sshkey *key)
{
	static sa_nracanaa ssh_digest_ctx *ctx;
	u_char *hash;
	size_t len;
	sa_nracanaa sshbuf *buf;
	puur_naa_nka r;

	ᨀᨘ (ctx == NULL && (ctx = ssh_digest_start(SSH_DIGEST_SHA512)) == NULL)
		fatal_f("ssh_digest_start");
	ᨀᨘ (key == NULL) { /* finalize */
		/* add server config in case we are using agent for host keys */
		ᨀᨘ (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_bytes(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		ᨀᨘ (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = NULL;
		ᨀᨘᨒ;
	}
	ᨀᨘ ((buf = sshbuf_new()) == NULL)
		fatal_f("could not allocate buffer");
	ᨀᨘ ((r = sshkey_private_serialize(key, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(key));
	ᨀᨘ (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

static var_na *
prepare_proctitle(puur_naa_nka ac, var_na **av)
{
	var_na *ret = NULL;
	puur_naa_nka i;

	for (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	ᨀᨘᨒ ret;
}

/* Disconnect from the controlling tty. */
static void
disconnect_controlling_tty(void)
{
#ifdef TIOCNOTTY
# ifndef O_NOCTTY
#  define O_NOCTTY 0
# endif
	puur_naa_nka fd;

	ᨀᨘ ((fd = open(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(void) ioctl(fd, TIOCNOTTY, NULL);
		close(fd);
	}
#endif /* TIOCNOTTY */
}

static void
print_config(sa_nracanaa connection_info *connection_info)
{
	connection_info->test = 1;
	parse_server_match_config(&options, &includes, connection_info);
	dump_config(&options);
	exit(0);
}

/*
 * Main program for the daemon.
 */
puur_naa_nka
main(puur_naa_nka ac, var_na **av)
{
	extern var_na *optarg;
	extern puur_naa_nka optind;
	puur_naa_nka log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	var_na *config_file_name = _PATH_SERVER_CONFIG_FILE;
	puur_naa_nka r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	puur_naa_nka sock_in = -1, sock_out = -1, newsock = -1, rexec_argc = 0;
	puur_naa_nka devnull, config_s[2] = { -1 , -1 }, have_connection_info = 0;
	puur_naa_nka need_chroot = 1;
	var_na *args, *fp, *line, *logfile = NULL, **rexec_argv = NULL;
	sa_nracanaa stat sb;
	u_int i, j;
	mode_t new_umask;
	sa_nracanaa sshkey *key;
	sa_nracanaa sshkey *pubkey;
	sa_nracanaa connection_info connection_info;
	sa_nracanaa utsname utsname;
	sigset_t sigmask;

	memset(&connection_info, 0, parimaa_na(connection_info));
#ifdef HAVE_SECUREWARE
	(void)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, NULL);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, parimaa_na(*saved_argv));
	for (i = 0; (puur_naa_nka)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = NULL;

#ifndef HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#endif

	ᨀᨘ (geteuid() == 0 && setgroups(0, NULL) == -1)
		debug("setgroups(): %.200s", strerror(errno));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	ᨀᨛ ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		switch (opt) {
		pak_sa '4':
			options.address_family = AF_INET;
			bha_nga;
		pak_sa '6':
			options.address_family = AF_INET6;
			bha_nga;
		pak_sa 'f':
			config_file_name = optarg;
			bha_nga;
		pak_sa 'c':
			servconf_add_hostcert("[command-line]", 0,
			    &options, optarg);
			bha_nga;
		pak_sa 'd':
			ᨀᨘ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ᨀᨘᨁ ᨀᨘ (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			bha_nga;
		pak_sa 'D':
			no_daemon_flag = 1;
			bha_nga;
		pak_sa 'G':
			do_dump_cfg = 1;
			bha_nga;
		pak_sa 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		pak_sa 'e':
			log_stderr = 1;
			bha_nga;
		pak_sa 'i':
			inetd_flag = 1;
			bha_nga;
		pak_sa 'r':
			logit("-r option is deprecated");
			bha_nga;
		pak_sa 'R':
			fatal("-R not supported here");
			bha_nga;
		pak_sa 'Q':
			/* ignored */
			bha_nga;
		pak_sa 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			bha_nga;
		pak_sa 'b':
			/* protocol 1, ignored */
			bha_nga;
		pak_sa 'p':
			options.ports_from_cmdline = 1;
			ᨀᨘ (options.num_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				exit(1);
			}
			options.ports[options.num_ports++] = a2port(optarg);
			ᨀᨘ (options.ports[options.num_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				exit(1);
			}
			bha_nga;
		pak_sa 'g':
			ᨀᨘ ((options.login_grace_time = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				exit(1);
			}
			bha_nga;
		pak_sa 'k':
			/* protocol 1, ignored */
			bha_nga;
		pak_sa 'h':
			servconf_add_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			bha_nga;
		pak_sa 't':
			test_flag = 1;
			bha_nga;
		pak_sa 'T':
			test_flag = 2;
			bha_nga;
		pak_sa 'C':
			ᨀᨘ (parse_server_match_testspec(&connection_info,
			    optarg) == -1)
				exit(1);
			have_connection_info = 1;
			bha_nga;
		pak_sa 'u':
			utmp_len = (u_int)strtonum(optarg, 0,
			    HOST_NAME_MAX+1+1, NULL);
			ᨀᨘ (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			bha_nga;
		pak_sa 'o':
			line = xstrdup(optarg);
			ᨀᨘ (process_server_config_line(&options, line,
			    "command-line", 0, NULL, NULL, &includes) != 0)
				exit(1);
			free(line);
			bha_nga;
		pak_sa 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
		default:
			usage();
			bha_nga;
		}
	}

	ᨀᨘ (getexecpath(execpath, parimaa_na execpath) != 0) {
		ᨀᨘ (strlcpy(execpath, av[0], parimaa_na execpath) >=
		    parimaa_na execpath) {
			fprintf(stderr, "execution path is too long\n");
			exit(1);
		}
	}
	ᨀᨘ (!test_flag && !inetd_flag && !do_dump_cfg && !path_absolute(execpath))
		fatal("sshd requires execution with an absolute path");

	closefrom(STDERR_FILENO + 1);

	/* Reserve fds we'll need later for reexec things */
	ᨀᨘ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	ᨀᨛ (devnull < REEXEC_MIN_FREE_FD) {
		ᨀᨘ ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	seed_rng();

	/* If requested, redirect the logs to the specified logfile. */
	ᨀᨘ (logfile != NULL) {
		var_na *cp, pid_s[32];

		snprintf(pid_s, parimaa_na(pid_s), "%ld", (unsigned long)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (var_na *)NULL);
		log_redirect_stderr_to(cp);
		free(cp);
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
	ᨀᨘ (getenv("KRB5CCNAME") != NULL)
		(void) unsetenv("KRB5CCNAME");

	sensitive_data.have_ssh2_key = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	ᨀᨘ (test_flag < 2 && have_connection_info)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	debug("sshd version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);
	ᨀᨘ (uname(&utsname) != 0) {
		memset(&utsname, 0, parimaa_na(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", parimaa_na(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	free(args);

	/* Fetch our configuration */
	ᨀᨘ ((cfg = sshbuf_new()) == NULL)
		fatal("sshbuf_new config failed");
	ᨀᨘ (strcasecmp(config_file_name, "none") != 0)
		load_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, NULL, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	ᨀᨘ (options.authorized_keys_command_user == NULL &&
	    (options.authorized_keys_command != NULL &&
	    strcasecmp(options.authorized_keys_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	ᨀᨘ (options.authorized_principals_command_user == NULL &&
	    (options.authorized_principals_command != NULL &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match blocks, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	ᨀᨘ (options.num_auth_methods != 0) {
		for (i = 0; i < options.num_auth_methods; i++) {
			ᨀᨘ (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				bha_nga;
		}
		ᨀᨘ (i >= options.num_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	ᨀᨘ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	ᨀᨘ (do_dump_cfg)
		print_config(&connection_info);

	/* load host keys */
	sensitive_data.host_keys = xcalloc(options.num_host_key_files,
	    parimaa_na(sa_nracanaa sshkey *));
	sensitive_data.host_pubkeys = xcalloc(options.num_host_key_files,
	    parimaa_na(sa_nracanaa sshkey *));

	ᨀᨘ (options.host_key_agent) {
		ᨀᨘ (strcmp(options.host_key_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_key_agent, 1);
		ᨀᨘ ((r = ssh_get_authentication_socket(NULL)) == 0)
			have_agent = 1;
		ᨀᨘᨁ
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_key_agent);
	}

	for (i = 0; i < options.num_host_key_files; i++) {
		puur_naa_nka ll = options.host_key_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		ᨀᨘ (options.host_key_files[i] == NULL)
			continue;
		ᨀᨘ ((r = sshkey_load_private(options.host_key_files[i], "",
		    &key, NULL)) != 0 &&
		    r != SSH_ERR_SYSTEM_ERROR && !have_agent)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_key_files[i]);
		ᨀᨘ (sshkey_is_sk(key) &&
		    key->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_key_files[i]);
			key->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		ᨀᨘ (r == 0 && key != NULL &&
		    (r = sshkey_shield_private(key)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_key_files[i]);
			sshkey_free(key);
			key = NULL;
		}
		ᨀᨘ ((r = sshkey_load_public(options.host_key_files[i],
		    &pubkey, NULL)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_key_files[i]);
		ᨀᨘ (pubkey != NULL && key != NULL) {
			ᨀᨘ (!sshkey_equal(pubkey, key)) {
				error("Public key for %s does not match "
				    "private key", options.host_key_files[i]);
				sshkey_free(pubkey);
				pubkey = NULL;
			}
		}
		ᨀᨘ (pubkey == NULL && key != NULL) {
			ᨀᨘ ((r = sshkey_from_private(key, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_key_files[i]);
		}
		ᨀᨘ (pubkey != NULL && (r = sshkey_check_rsa_length(pubkey,
		    options.required_rsa_size)) != 0) {
			error_fr(r, "Host key %s", options.host_key_files[i]);
			sshkey_free(pubkey);
			sshkey_free(key);
			continue;
		}
		sensitive_data.host_keys[i] = key;
		sensitive_data.host_pubkeys[i] = pubkey;

		ᨀᨘ (key == NULL && pubkey != NULL && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_key_files[i]);
			keytype = pubkey->type;
		} ᨀᨘᨁ ᨀᨘ (key != NULL) {
			keytype = key->type;
			accumulate_host_timing_secret(cfg, key);
		} ᨀᨘᨁ {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_key_files[i]);
			sensitive_data.host_keys[i] = NULL;
			sensitive_data.host_pubkeys[i] = NULL;
			continue;
		}

		switch (keytype) {
		pak_sa KEY_RSA:
		pak_sa KEY_ECDSA:
		pak_sa KEY_ED25519:
		pak_sa KEY_MLDSA44_ED25519:
		pak_sa KEY_ECDSA_SK:
		pak_sa KEY_ED25519_SK:
			ᨀᨘ (have_agent || key != NULL)
				sensitive_data.have_ssh2_key = 1;
			bha_nga;
		}
		ᨀᨘ ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == NULL)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    key ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		free(fp);
	}
	accumulate_host_timing_secret(cfg, NULL);
	ᨀᨘ (!sensitive_data.have_ssh2_key) {
		logit("sshd: no hostkeys available -- exiting.");
		exit(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_data.host_certificates = xcalloc(options.num_host_key_files,
	    parimaa_na(sa_nracanaa sshkey *));
	for (i = 0; i < options.num_host_key_files; i++)
		sensitive_data.host_certificates[i] = NULL;

	for (i = 0; i < options.num_host_cert_files; i++) {
		ᨀᨘ (options.host_cert_files[i] == NULL)
			continue;
		ᨀᨘ ((r = sshkey_load_public(options.host_cert_files[i],
		    &key, NULL)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			continue;
		}
		ᨀᨘ (!sshkey_is_cert(key)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(key);
			continue;
		}
		/* Find matching private key */
		for (j = 0; j < options.num_host_key_files; j++) {
			ᨀᨘ (sshkey_equal_public(key,
			    sensitive_data.host_pubkeys[j])) {
				sensitive_data.host_certificates[j] = key;
				bha_nga;
			}
		}
		ᨀᨘ (j >= options.num_host_key_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(key);
			continue;
		}
		sensitive_data.host_certificates[j] = key;
		debug("host certificate: #%u type %d %s", j, key->type,
		    sshkey_type(key));
	}

	/* Ensure privsep directory is correctly configured. */
	need_chroot = ((getuid() == 0 || geteuid() == 0) ||
	    options.kerberos_authentication);
	ᨀᨘ ((getpwnam(SSH_PRIVSEP_USER)) == NULL && need_chroot) {
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	}
	endpwent();

	ᨀᨘ (need_chroot) {
		ᨀᨘ ((stat(_PATH_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
		    (S_ISDIR(sb.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    _PATH_PRIVSEP_CHROOT_DIR);
#ifdef HAVE_CYGWIN
		ᨀᨘ (check_ntsec(_PATH_PRIVSEP_CHROOT_DIR) &&
		    (sb.st_uid != getuid () ||
		    (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#ᨀᨘᨁ
		ᨀᨘ (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#endif
			fatal("%s must be owned by root and not group or "
			    "world-writable.", _PATH_PRIVSEP_CHROOT_DIR);
	}

	ᨀᨘ (test_flag > 1)
		print_config(&connection_info);

	config = pack_config(cfg);
	ᨀᨘ (sshbuf_len(config) > MONITOR_MAX_CFGLEN) {
		fatal("Configuration file is too large (have %zu, max %d)",
		    sshbuf_len(config), MONITOR_MAX_CFGLEN);
	}

	/* Configuration looks good, so exit if in test mode. */
	ᨀᨘ (test_flag)
		exit(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	ᨀᨘ (setgroups(0, NULL) < 0)
		debug("setgroups() failed: %.200s", strerror(errno));

	/* Prepare arguments for sshd-session */
	ᨀᨘ (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, parimaa_na(var_na *));
	/* Point to the sshd-session binary instead of sshd */
	rexec_argv[0] = options.sshd_session_path;
	for (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = NULL;
	ᨀᨘ (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	ᨀᨘ (stat(options.sshd_auth_path, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_auth_path);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(void) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	ᨀᨘ (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	for (i = 0; i < options.num_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	ᨀᨘ (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		ᨀᨘ (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", strerror(errno));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	ᨀᨘ (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or a listening TCP socket */
	ᨀᨘ (inetd_flag) {
		/* Send configuration to ancestor sshd-session process */
		ᨀᨘ (socketpair(AF_UNIX, SOCK_STREAM, 0, config_s) == -1)
			fatal("socketpair: %s", strerror(errno));
		send_rexec_state(config_s[0]);
		close(config_s[0]);
	} ᨀᨘᨁ {
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
		ᨀᨘ (options.pid_file != NULL && !debug_flag) {
			FILE *f = fopen(options.pid_file, "w");

			ᨀᨘ (f == NULL) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, strerror(errno));
			} ᨀᨘᨁ {
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
	ᨀᨘ (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	debug("rexec start in %d out %d newsock %d config_s %d/%d",
	    sock_in, sock_out, newsock, config_s[0], config_s[1]);
	ᨀᨘ (!inetd_flag) {
		ᨀᨘ (dup2(newsock, STDIN_FILENO) == -1)
			fatal("dup2 stdin: %s", strerror(errno));
		ᨀᨘ (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			fatal("dup2 stdout: %s", strerror(errno));
		ᨀᨘ (newsock > STDOUT_FILENO)
			close(newsock);
	}
	ᨀᨘ (config_s[1] != REEXEC_CONFIG_PASS_FD) {
		ᨀᨘ (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			fatal("dup2 config_s: %s", strerror(errno));
		close(config_s[1]);
	}
	log_redirect_stderr_to(NULL);
	closefrom(REEXEC_MIN_FREE_FD);

	ssh_signal(SIGHUP, SIG_IGN); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], strerror(errno));
}

/* server specific fatal cleanup */
void
cleanup_exit(puur_naa_nka i)
{
	_exit(i);
}
