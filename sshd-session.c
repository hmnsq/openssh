/* $OpenBSD: sshd-session.c,v 1.26 2026/09/16 00:13:58 djm Exp $ */
/*
 * SSH2 implementation:
 * Privilege Separation:
 *
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
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>
#ଅନ୍ତର୍ଭାଵ <sys/tree.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>
#ଅନ୍ତର୍ଭାଵ <sys/queue.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <paths.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <grp.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>

#ifdef HAVE_SECUREWARE
#ଅନ୍ତର୍ଭାଵ <sys/security.h>
#ଅନ୍ତର୍ଭାଵ <prot.h>
#endif
 
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "sshpty.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "uidswap.h"
#ଅନ୍ତର୍ଭାଵ "compat.h"
#ଅନ୍ତର୍ଭାଵ "cipher.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "authfd.h"
#ଅନ୍ତର୍ଭାଵ "msg.h"
#ଅନ୍ତର୍ଭାଵ "dispatch.h"
#ଅନ୍ତର୍ଭାଵ "channels.h"
#ଅନ୍ତର୍ଭାଵ "session.h"
#ଅନ୍ତର୍ଭାଵ "monitor.h"
#ifdef GSSAPI
#ଅନ୍ତର୍ଭାଵ "ssh-gss.h"
#endif
#ଅନ୍ତର୍ଭାଵ "monitor_wrap.h"
#ଅନ୍ତର୍ଭାଵ "auth-options.h"
#ଅନ୍ତର୍ଭାଵ "version.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sk-api.h"
#ଅନ୍ତର୍ଭାଵ "srclimit.h"
#ଅନ୍ତର୍ଭାଵ "dh.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

/* Privsep fds */
#define PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#define PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#define PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

ବାହ୍ୟ ଅକ୍ଷର *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
ଅକ୍ଷର *config_file_name = _PATH_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା inetd_flag = 0;

/* debug goes to stderr unless inetd_flag is set */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା log_stderr = 0;

/* Saved arguments to main(). */
ସ୍ଥିର ଅକ୍ଷର **saved_argv;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା saved_argc;

/* Daemon's agent connection */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା auth_sock = -1;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା have_agent = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
ସଂରଚନା {
	u_int		ଅଙ୍କ_hostkeys;
	ସଂରଚନା sshkey	**host_ଚାବିଗୁଡ଼ିକ;		/* all private host keys */
	ସଂରଚନା sshkey	**host_pubkeys;		/* all public host keys */
	ସଂରଚନା sshkey	**host_certificates;	/* all public host certificates */
} sensitive_data;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା startup_pipe = -1;		/* in child */

/* variables used for privilege separation */
ସଂରଚନା monitor *pmonitor = ଖାଲି;
ପୂର୍ଣ୍ଣସଂଖ୍ୟା privsep_is_preauth = 1;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା privsep_chroot = 1;

/* Unprivileged user */
ସଂରଚନା passwd *privsep_pw = ଖାଲି;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = ଖାଲି;
ସଂରଚନା ssh *the_active_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
ସଂରଚନା sshauthopt *auth_opts = ଖାଲି;

/* sshd_config buffer */
ସଂରଚନା sshbuf *cfg;

/* Included files from the configuration file */
ସଂରଚନା include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ସଂରଚନା sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
ଶୂନ୍ୟ destroy_sensitive_data(ଶୂନ୍ୟ);
ଶୂନ୍ୟ demote_sensitive_data(ଶୂନ୍ୟ);

/* XXX reduce to stub once postauth split */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_is_monitor(ଶୂନ୍ୟ)
{
	/*
	 * m_pid is only set in the privileged part, and
	 * points to the unprivileged child.
	 */
	ଫେରନ୍ତୁ (pmonitor && pmonitor->m_pid > 0);
}

/*
 * Signal handler for the alarm after the login grace period has expired.
 * As usual, this may only take signal-safe actions, even though it is
 * terminal.
 */
ସ୍ଥିର ଶୂନ୍ୟ
grace_alarm_handler(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	/*
	 * Try to kill any processes that we have spawned, E.g. authorized
	 * keys command helpers or privsep children.
	 */
	ଯଦି (getpgid(0) == getpid()) {
		ସଂରଚନା sigaction sa;

		/* mask all other signals while in handler */
		memset(&sa, 0, ଆକାର(sa));
		sa.sa_handler = SIG_IGN;
		sigfillset(&sa.sa_mask);
#ଯଦି defined(SA_RESTART)
		sa.sa_flags = SA_RESTART;
#endif
		(ଶୂନ୍ୟ)sigaction(SIGTERM, &sa, ଖାଲି);
		kill(0, SIGTERM);
	}
	_exit(EXIT_LOGIN_GRACE);
}

/* Destroy the host and server keys.  They will no longer be needed. */
ଶୂନ୍ୟ
destroy_sensitive_data(ଶୂନ୍ୟ)
{
	u_int i;

	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_host_ଚାବି_files; i++) {
		ଯଦି (sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i]) {
			sshkey_free(sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i]);
			sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i] = ଖାଲି;
		}
		ଯଦି (sensitive_data.host_certificates[i]) {
			sshkey_free(sensitive_data.host_certificates[i]);
			sensitive_data.host_certificates[i] = ଖାଲି;
		}
	}
}

/* Demote private to public keys for network child */
ଶୂନ୍ୟ
demote_sensitive_data(ଶୂନ୍ୟ)
{
	ସଂରଚନା sshkey *tmp;
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_host_ଚାବି_files; i++) {
		ଯଦି (sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i]) {
			ଯଦି ((r = sshkey_from_private(
			    sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i], &tmp)) != 0)
				fatal_r(r, "could not demote host %s key",
				    sshkey_type(sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i]));
			sshkey_free(sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i]);
			sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i] = tmp;
		}
		/* Certs do not need demotion */
	}
}

ସଂରଚନା sshbuf *
pack_hostkeys(ଶୂନ୍ୟ)
{
	ସଂରଚନା sshbuf *keybuf = ଖାଲି, *hostkeys = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i;

	ଯଦି ((hostkeys = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_host_ଚାବି_files; i++) {
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

	sshbuf_free(keybuf);
	ଫେରନ୍ତୁ hostkeys;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
privsep_preauth(ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	pid_t pid;

	/* Set up unprivileged child process to deal with network data */
	pmonitor = monitor_init();
	/* Store a pointer to the kex for later rekeying */
	pmonitor->m_pkex = &ssh->kex;

	ଯଦି ((pid = fork()) == -1)
		fatal("fork of unprivileged child failed");
	ଅନ୍ୟଥା ଯଦି (pid != 0) {
		debug2("Network child is on pid %ld", (long)pid);

		pmonitor->m_pid = pid;
		ଯଦି (have_agent) {
			r = ssh_get_authentication_socket(&auth_sock);
			ଯଦି (r != 0) {
				error_r(r, "Could not get agent socket");
				have_agent = 0;
			}
		}
		monitor_child_preauth(ssh, pmonitor);
		privsep_is_preauth = 0;
		ଫେରନ୍ତୁ 1;
	} ଅନ୍ୟଥା {
		/* child */
		close(pmonitor->m_sendfd);
		close(pmonitor->m_log_recvfd);

		/*
		 * Arrange unpriv-preauth child process fds:
		 * 0, 1 network socket
		 * 2 optional stderr
		 * 3 reserved
		 * 4 monitor message socket
		 * 5 monitor logging socket
		 *
		 * We know that the monitor sockets will have fds > 4 because
		 * of the reserved fds in main()
		 */

		ଯଦି (ssh_packet_get_connection_in(ssh) != STDIN_FILENO &&
		    dup2(ssh_packet_get_connection_in(ssh), STDIN_FILENO) == -1)
			fatal("dup2 stdin failed: %s", strerror(errno));
		ଯଦି (ssh_packet_get_connection_out(ssh) != STDOUT_FILENO &&
		    dup2(ssh_packet_get_connection_out(ssh),
		    STDOUT_FILENO) == -1)
			fatal("dup2 stdout failed: %s", strerror(errno));
		/* leave stderr as-is */
		log_redirect_stderr_to(ଖାଲି); /* dup can clobber log fd */
		ଯଦି (pmonitor->m_recvfd != PRIVSEP_MONITOR_FD &&
		    dup2(pmonitor->m_recvfd, PRIVSEP_MONITOR_FD) == -1)
			fatal("dup2 monitor fd: %s", strerror(errno));
		ଯଦି (pmonitor->m_log_sendfd != PRIVSEP_LOG_FD &&
		    dup2(pmonitor->m_log_sendfd, PRIVSEP_LOG_FD) == -1)
			fatal("dup2 log fd: %s", strerror(errno));
		closefrom(PRIVSEP_MIN_FREE_FD);

		saved_argv[0] = options.sshd_auth_path;
		execv(options.sshd_auth_path, saved_argv);

		fatal_f("exec of %s failed: %s",
		    options.sshd_auth_path, strerror(errno));
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
privsep_postauth(ସଂରଚନା ssh *ssh, Authctxt *authctxt)
{
	/* New socket pair */
	monitor_reinit(pmonitor);

	pmonitor->m_pid = fork();
	ଯଦି (pmonitor->m_pid == -1)
		fatal("fork of unprivileged child failed");
	ଅନ୍ୟଥା ଯଦି (pmonitor->m_pid != 0) {
		verbose("User child is on pid %ld", (long)pmonitor->m_pid);
		sshbuf_reset(loginmsg);
		monitor_clear_keystate(ssh, pmonitor);
		monitor_child_postauth(ssh, pmonitor);

		/* NEVERREACHED */
		exit(0);
	}

	/* child */

	close(pmonitor->m_sendfd);
	pmonitor->m_sendfd = -1;

	/* Demote the private keys to public keys. */
	demote_sensitive_data();

	reseed_prngs();

#ifndef SKIP_PRIVDROP
	/* Drop privileges */
	do_setusercontext(authctxt->pw);
#endif

	/* It is safe now to apply the key state */
	monitor_apply_keystate(ssh, pmonitor);

	/*
	 * Tell the packet layer that authentication was successful, since
	 * this information is not part of the key state.
	 */
	ssh_packet_set_authenticated(ssh);
}

ସ୍ଥିର ସଂରଚନା sshkey *
get_hostkey_by_type(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid, ପୂର୍ଣ୍ଣସଂଖ୍ୟା need_private, ସଂରଚନା ssh *ssh)
{
	u_int i;
	ସଂରଚନା sshkey *ଚାବି;

	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_host_ଚାବି_files; i++) {
		ବାଛ (type) {
		ସ୍ଥିତି ଚାବି_RSA_CERT:
		ସ୍ଥିତି ଚାବି_ECDSA_CERT:
		ସ୍ଥିତି ଚାବି_ED25519_CERT:
		ସ୍ଥିତି ଚାବି_ECDSA_SK_CERT:
		ସ୍ଥିତି ଚାବି_ED25519_SK_CERT:
		ସ୍ଥିତି ଚାବି_MLDSA44_ED25519_CERT:
			ଚାବି = sensitive_data.host_certificates[i];
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଚାବି = sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i];
			ଯଦି (ଚାବି == ଖାଲି && !need_private)
				ଚାବି = sensitive_data.host_pubkeys[i];
			ଭାଙ୍ଗ;
		}
		ଯଦି (ଚାବି == ଖାଲି || ଚାବି->type != type)
			ଜାରି;
		ବାଛ (type) {
		ସ୍ଥିତି ଚାବି_ECDSA:
		ସ୍ଥିତି ଚାବି_ECDSA_SK:
		ସ୍ଥିତି ଚାବି_ECDSA_CERT:
		ସ୍ଥିତି ଚାବି_ECDSA_SK_CERT:
			ଯଦି (ଚାବି->ecdsa_nid != nid)
				ଜାରି;
			/* FALLTHROUGH */
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଫେରନ୍ତୁ need_private ?
			    sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i] : ଚାବି;
		}
	}
	ଫେରନ୍ତୁ ଖାଲି;
}

ସଂରଚନା sshkey *
get_hostkey_public_by_type(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid, ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ get_hostkey_by_type(type, nid, 0, ssh);
}

ସଂରଚନା sshkey *
get_hostkey_private_by_type(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid, ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ get_hostkey_by_type(type, nid, 1, ssh);
}

ସଂରଚନା sshkey *
get_hostkey_by_index(ପୂର୍ଣ୍ଣସଂଖ୍ୟା ind)
{
	ଯଦି (ind < 0 || (u_int)ind >= options.ଅଙ୍କ_host_ଚାବି_files)
		ଫେରନ୍ତୁ (ଖାଲି);
	ଫେରନ୍ତୁ (sensitive_data.host_ଚାବିଗୁଡ଼ିକ[ind]);
}

ସଂରଚନା sshkey *
get_hostkey_public_by_index(ପୂର୍ଣ୍ଣସଂଖ୍ୟା ind, ସଂରଚନା ssh *ssh)
{
	ଯଦି (ind < 0 || (u_int)ind >= options.ଅଙ୍କ_host_ଚାବି_files)
		ଫେରନ୍ତୁ (ଖାଲି);
	ଫେରନ୍ତୁ (sensitive_data.host_pubkeys[ind]);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
get_hostkey_index(ସଂରଚନା sshkey *ଚାବି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା compare, ସଂରଚନା ssh *ssh)
{
	u_int i;

	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_host_ଚାବି_files; i++) {
		ଯଦି (sshkey_is_cert(ଚାବି)) {
			ଯଦି (ଚାବି == sensitive_data.host_certificates[i] ||
			    (compare && sensitive_data.host_certificates[i] &&
			    sshkey_equal(ଚାବି,
			    sensitive_data.host_certificates[i])))
				ଫେରନ୍ତୁ (i);
		} ଅନ୍ୟଥା {
			ଯଦି (ଚାବି == sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i] ||
			    (compare && sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i] &&
			    sshkey_equal(ଚାବି, sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i])))
				ଫେରନ୍ତୁ (i);
			ଯଦି (ଚାବି == sensitive_data.host_pubkeys[i] ||
			    (compare && sensitive_data.host_pubkeys[i] &&
			    sshkey_equal(ଚାବି, sensitive_data.host_pubkeys[i])))
				ଫେରନ୍ତୁ (i);
		}
	}
	ଫେରନ୍ତୁ (-1);
}

/* Inform the client of all hostkeys */
ସ୍ଥିର ଶୂନ୍ୟ
notify_hostkeys(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା sshbuf *buf;
	ସଂରଚନା sshkey *ଚାବି;
	u_int i, nkeys;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅକ୍ଷର *fp;

	/* Some clients cannot cope with the hostkeys message, skip those. */
	ଯଦି (ssh->compat & SSH_BUG_HOSTKEYS)
		ଫେରନ୍ତୁ;

	ଯଦି ((buf = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ପାଇଁ (i = nkeys = 0; i < options.ଅଙ୍କ_host_ଚାବି_files; i++) {
		ଚାବି = get_hostkey_public_by_index(i, ssh);
		ଯଦି (ଚାବି == ଖାଲି || ଚାବି->type == ଚାବି_UNSPEC ||
		    sshkey_is_cert(ଚାବି))
			ଜାରି;
		fp = sshkey_fingerprint(ଚାବି, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("key %d: %s %s", i, sshkey_ssh_name(ଚାବି), fp);
		ମୁକ୍ତ(fp);
		ଯଦି (nkeys == 0) {
			/*
			 * Start building the request when we find the
			 * first usable key.
			 */
			ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_GLOBAL_REQUEST)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "hostkeys-00@openssh.com")) != 0 ||
			    (r = sshpkt_put_u8(ssh, 0)) != 0) /* want reply */
				sshpkt_fatal(ssh, r, "%s: start request", __func__);
		}
		/* Append the key to the request */
		sshbuf_reset(buf);
		ଯଦି ((r = sshkey_putb(ଚାବି, buf)) != 0)
			fatal_fr(r, "couldn't put hostkey %d", i);
		ଯଦି ((r = sshpkt_put_stringb(ssh, buf)) != 0)
			sshpkt_fatal(ssh, r, "%s: append key", __func__);
		nkeys++;
	}
	debug3_f("sent %u hostkeys", nkeys);
	ଯଦି (nkeys == 0)
		fatal_f("no hostkeys");
	ଯଦି ((r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send", __func__);
	sshbuf_free(buf);
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

ସ୍ଥିର ଶୂନ୍ୟ
parse_hostkeys(ସଂରଚନା sshbuf *hostkeys)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ = 0;
	ସଂରଚନା sshkey *k;
	ସଂରଚନା sshbuf *kbuf;
	ଅଚଳ u_char *cp;
	size_t len;

	ଯେତେବେଳେ (sshbuf_len(hostkeys) != 0) {
		ଯଦି (ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ > 2048)
			fatal_f("too many hostkeys");
		sensitive_data.host_ଚାବିଗୁଡ଼ିକ = xrecallocarray(
		    sensitive_data.host_ଚାବିଗୁଡ଼ିକ, ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ, ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ + 1,
		    ଆକାର(*sensitive_data.host_pubkeys));
		sensitive_data.host_pubkeys = xrecallocarray(
		    sensitive_data.host_pubkeys, ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ, ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ + 1,
		    ଆକାର(*sensitive_data.host_pubkeys));
		sensitive_data.host_certificates = xrecallocarray(
		    sensitive_data.host_certificates, ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ, ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ + 1,
		    ଆକାର(*sensitive_data.host_certificates));
		/* private key */
		k = ଖାଲି;
		ଯଦି ((r = sshbuf_froms(hostkeys, &kbuf)) != 0)
			fatal_fr(r, "extract privkey");
		ଯଦି (sshbuf_len(kbuf) != 0 &&
		    (r = sshkey_private_deserialize(kbuf, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_ଚାବିଗୁଡ଼ିକ[ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ] = k;
		sshbuf_free(kbuf);
		ଯଦି (k)
			debug2_f("privkey %u: %s", ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ, sshkey_ssh_name(k));
		/* public key */
		k = ଖାଲି;
		ଯଦି ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ଯଦି (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_pubkeys[ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ] = k;
		ଯଦି (k)
			debug2_f("pubkey %u: %s", ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ, sshkey_ssh_name(k));
		/* certificate */
		k = ଖାଲି;
		ଯଦି ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ଯଦି (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_certificates[ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ] = k;
		ଯଦି (k)
			debug2_f("cert %u: %s", ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ, sshkey_ssh_name(k));
		ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ++;
	}
	sensitive_data.ଅଙ୍କ_hostkeys = ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ;
}

ସ୍ଥିର ଶୂନ୍ୟ
recv_rexec_state(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ସଂରଚନା sshbuf *conf, uint64_t *timing_secretp)
{
	ସଂରଚନା sshbuf *m, *inc, *hostkeys;
	u_char *cp, ver;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା include_item *item;

	debug3_f("entering fd = %d", fd);

	ଯଦି ((m = sshbuf_new()) == ଖାଲି || (inc = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	/* receive config */
	ଯଦି (ssh_ସନ୍ଦେଶ_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	ଯଦି ((r = sshbuf_get_u8(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	ଯଦି (ver != 0)
		fatal_f("rexec version mismatch");
	ଯଦି ((r = sshbuf_get_string(m, &cp, &len)) != 0 || /* XXX _direct */
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_get_stringb(m, inc)) != 0)
		fatal_fr(r, "parse config");

	ଯଦି (conf != ଖାଲି && (r = sshbuf_put(conf, cp, len)))
		fatal_fr(r, "sshbuf_put");

	ଯେତେବେଳେ (sshbuf_len(inc) != 0) {
		item = xcalloc(1, ଆକାର(*item));
		ଯଦି ((item->contents = sshbuf_new()) == ଖାଲି)
			fatal_f("sshbuf_new failed");
		ଯଦି ((r = sshbuf_get_cstring(inc, &item->selector, ଖାଲି)) != 0 ||
		    (r = sshbuf_get_cstring(inc, &item->filename, ଖାଲି)) != 0 ||
		    (r = sshbuf_get_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "parse includes");
		TAILQ_INSERT_TAIL(&includes, item, entry);
	}

	/* receive hostkeys */
	sshbuf_reset(m);
	ଯଦି (ssh_ସନ୍ଦେଶ_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	ଯଦି ((r = sshbuf_get_u8(m, ଖାଲି)) != 0 ||
	    (r = sshbuf_froms(m, &hostkeys)) != 0)
		fatal_fr(r, "parse config");
	parse_hostkeys(hostkeys);

	ମୁକ୍ତ(cp);
	sshbuf_free(m);
	sshbuf_free(hostkeys);
	sshbuf_free(inc);

	debug3_f("done");
}

/*
 * If IP options are supported, make sure there are none (log and
 * return an error if any are found).  Basically we are worried about
 * source routing; it can be used to pretend you are somebody
 * (ip-address) you are not. That itself may be "almost acceptable"
 * under certain circumstances, but rhosts authentication is useless
 * if source routing is accepted. Notice also that if we just dropped
 * source routing here, the other side could use IP spoofing to do
 * rest of the interaction and could still bypass security.  So we
 * exit here if we detect any IP options.
 */
ସ୍ଥିର ଶୂନ୍ୟ
check_ip_options(ସଂରଚନା ssh *ssh)
{
#ifdef IP_OPTIONS
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock_in = ssh_packet_get_connection_in(ssh);
	ସଂରଚନା sockaddr_storage from;
	u_char opts[200];
	socklen_t i, option_size = ଆକାର(opts), fromlen = ଆକାର(from);
	ଅକ୍ଷର text[ଆକାର(opts) * 3 + 1];

	memset(&from, 0, ଆକାର(from));
	ଯଦି (getpeername(sock_in, (ସଂରଚନା sockaddr *)&from,
	    &fromlen) == -1)
		ଫେରନ୍ତୁ;
	ଯଦି (from.ss_family != AF_INET)
		ଫେରନ୍ତୁ;
	/* XXX IPv6 options? */

	ଯଦି (getsockopt(sock_in, IPPROTO_IP, IP_OPTIONS, opts,
	    &option_size) >= 0 && option_size != 0) {
		text[0] = '\0';
		ପାଇଁ (i = 0; i < option_size; i++)
			snprintf(text + i*3, ଆକାର(text) - i*3,
			    " %2.2x", opts[i]);
		fatal("Connection from %.100s port %d with IP opts: %.800s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), text);
	}
#endif /* IP_OPTIONS */
}

/* Set the routing domain for this process */
ସ୍ଥିର ଶୂନ୍ୟ
set_process_rdomain(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *name)
{
#ଯଦି defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
	ଯଦି (name == ଖାଲି)
		ଫେରନ୍ତୁ; /* default */

	ଯଦି (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		ଯଦି ((name = ssh_packet_rdomain_in(ssh)) == ଖାଲି)
			ଫେରନ୍ତୁ;
	}
	/* NB. We don't pass 'ssh' to sys_set_process_rdomain() */
	ଫେରନ୍ତୁ sys_set_process_rdomain(name);
#ନଚେତଯଦି defined(__OpenBSD__)
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rtable, ortable = getrtable();
	ଅଚଳ ଅକ୍ଷର *errstr;

	ଯଦି (name == ଖାଲି)
		ଫେରନ୍ତୁ; /* default */

	ଯଦି (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		ଯଦି ((name = ssh_packet_rdomain_in(ssh)) == ଖାଲି)
			ଫେରନ୍ତୁ;
	}

	rtable = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)strtonum(name, 0, 255, &errstr);
	ଯଦି (errstr != ଖାଲି) /* Shouldn't happen */
		fatal("Invalid routing domain \"%s\": %s", name, errstr);
	ଯଦି (rtable != ortable && setrtable(rtable) != 0)
		fatal("Unable to set routing domain %d: %s",
		    rtable, strerror(errno));
	debug_f("set routing domain %d (was %d)", rtable, ortable);
#ଅନ୍ୟଥା /* defined(__OpenBSD__) */
	fatal("Unable to set routing domain: not supported in this platform");
#endif
}

/*
 * Main program for the daemon.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା ac, ଅକ୍ଷର **av)
{
	ସଂରଚନା ssh *ssh = ଖାଲି;
	ବାହ୍ୟ ଅକ୍ଷର *optarg;
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା optind;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା devnull, r, opt, remote_port;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock_in = -1, sock_out = -1, rexeced_flag = 0, have_ଚାବି = 0;
	ଅଚଳ ଅକ୍ଷର *remote_ip, *rdomain;
	ଅକ୍ଷର *ଧାଡ଼ି, *laddr, *logfile = ଖାଲି;
	u_int i;
	uint64_t ibytes, obytes;
	mode_t new_umask;
	Authctxt *authctxt;
	ସଂରଚନା connection_info *connection_info = ଖାଲି;
	sigset_t sigmask;
	uint64_t timing_secret = 0;
	ସଂରଚନା itimerval itv;

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ଖାଲି);

#ifdef HAVE_SECUREWARE
	(ଶୂନ୍ୟ)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, ଆକାର(*saved_argv));
	ପାଇଁ (i = 0; (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ଖାଲି;

#ifndef HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#endif

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
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
			/* ignore */
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
			/* ignore */
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'R':
			rexeced_flag = 1;
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
		ସ୍ଥିତି 'T':
		ସ୍ଥିତି 'G':
			fatal("test/dump modes not supported");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'C':
			connection_info = server_get_connection_info(ssh, 0, 0);
			ଯଦି (parse_server_match_testspec(connection_info,
			    optarg) == -1)
				exit(1);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, ଖାଲି);
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

	/* Check that there are no remaining arguments. */
	ଯଦି (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	ଯଦି (!rexeced_flag)
		fatal("sshd-session should not be executed directly");

	closefrom(REEXEC_MIN_FREE_FD);

	platform_pre_session_start();

	/* Reserve fds we'll need later for reexec things */
	ଯଦି ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	ଯେତେବେଳେ (devnull < PRIVSEP_MIN_FREE_FD) {
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
		    "P", "sshd-session",
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

	/* Fetch our configuration */
	ଯଦି ((cfg = sshbuf_new()) == ଖାଲି)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[rexeced]");
	recv_rexec_state(REEXEC_CONFIG_PASS_FD, cfg, &timing_secret);
	parse_server_config(&options, "rexec", cfg, &includes, ଖାଲି, 1);
	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);
	options.timing_secret = timing_secret;

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	debug("sshd-session version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	ଯଦି ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == ଖାଲି) {
		ଯଦି (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} ଅନ୍ୟଥା {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, strlen(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

	ଯଦି (!debug_flag && !inetd_flag) {
		ଯଦି ((startup_pipe = dup(REEXEC_CONFIG_PASS_FD)) == -1)
			fatal("internal error: no startup pipe");

		/*
		 * Signal parent that this child is at a point where
		 * they can go away if they have a SIGHUP pending.
		 */
		(ଶୂନ୍ୟ)atomicio(vwrite, startup_pipe, "\0", 1);
	}
	/* close the fd, but keep the slot reserved */
	ଯଦି (dup2(devnull, REEXEC_CONFIG_PASS_FD) == -1)
		fatal("dup2 devnull->config fd: %s", strerror(errno));

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
	 * daemonisation in the presence of Match block, but this catches
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

#ifdef WITH_OPENSSL
	ଯଦି (options.moduli_file != ଖାଲି)
		dh_set_moduli_file(options.moduli_file);
#endif

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

	ଯଦି (options.ଅଙ୍କ_host_ଚାବି_files != sensitive_data.ଅଙ୍କ_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.ଅଙ୍କ_host_ଚାବି_files, sensitive_data.ଅଙ୍କ_hostkeys);
	}

	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_host_ଚାବି_files; i++) {
		ଯଦି (sensitive_data.host_ଚାବିଗୁଡ଼ିକ[i] != ଖାଲି ||
		    (have_agent && sensitive_data.host_pubkeys[i] != ଖାଲି)) {
			have_ଚାବି = 1;
			ଭାଙ୍ଗ;
		}
	}
	ଯଦି (!have_ଚାବି)
		fatal("internal error: monitor received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(ଶୂନ୍ୟ) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	ଯଦି (debug_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

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

	/* Get a connection, either from inetd or rexec */
	ଯଦି (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_in = dup(STDIN_FILENO);
		sock_out = dup(STDOUT_FILENO);
	} ଅନ୍ୟଥା {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_in = sock_out = dup(STDIN_FILENO);
	}

	/*
	 * We intentionally do not close the descriptors 0, 1, and 2
	 * as our code for setting the descriptors won't work if
	 * ttyfd happens to be one of those.
	 */
	ଯଦି (stdfd_devnull(1, 1, !log_stderr) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_in, sock_out);

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_out);
	FD_CLOSEONEXEC(sock_in);

	/* We will not restart on SIGHUP since it no longer makes sense. */
	ssh_signal(SIGALRM, SIG_DFL);
	ssh_signal(SIGHUP, SIG_DFL);
	ssh_signal(SIGTERM, SIG_DFL);
	ssh_signal(SIGQUIT, SIG_DFL);
	ssh_signal(SIGCHLD, SIG_DFL);
	ssh_signal(SIGINT, SIG_DFL);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	ଯଦି ((ssh = ssh_packet_set_connection(ଖାଲି, sock_in, sock_out)) == ଖାଲି)
		fatal("Unable to create connection");
	the_active_state = ssh;
	ssh_packet_set_server(ssh);
	ssh_packet_set_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	check_ip_options(ssh);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_set_af(ssh, options.address_family);
	channel_set_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);

	/* Set SO_KEEPALIVE if requested. */
	ଯଦି (options.tcp_keep_alive && ssh_packet_connection_is_on_socket(ssh))
		set_keepalive(sock_in); /* logs errors */

	ଯଦି ((remote_port = ssh_remote_port(ssh)) < 0) {
		debug("ssh_remote_port failed");
		cleanup_exit(255);
	}

	/*
	 * The rest of the code depends on the fact that
	 * ssh_remote_ipaddr() caches the remote ip, even if
	 * the socket goes away.
	 */
	remote_ip = ssh_remote_ipaddr(ssh);

#ifdef SSH_AUDIT_EVENTS
	audit_connection_from(remote_ip, remote_port);
#endif

	rdomain = ssh_packet_rdomain_in(ssh);

	/* Log the connection. */
	laddr = get_local_ipaddr(sock_in);
	verbose("Connection from %s port %d on %s port %d%s%s%s",
	    remote_ip, remote_port, laddr,  ssh_local_port(ssh),
	    rdomain == ଖାଲି ? "" : " rdomain \"",
	    rdomain == ଖାଲି ? "" : rdomain,
	    rdomain == ଖାଲି ? "" : "\"");
	ମୁକ୍ତ(laddr);

	/*
	 * We don't want to listen forever unless the other side
	 * successfully authenticates itself.  So we set up an alarm which is
	 * cleared after successful authentication.  A limit of zero
	 * indicates no limit. Note that we don't set the alarm in debugging
	 * mode; it is just annoying to have the server exit just when you
	 * are about to discover the bug.
	 */
	ssh_signal(SIGALRM, grace_alarm_handler);
	ଯଦି (!debug_flag && options.login_grace_time > 0) {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା ujitter = arc4random_uniform(4 * 1000000);

		timerclear(&itv.it_interval);
		itv.it_value.tv_sec = options.login_grace_time;
		itv.it_value.tv_sec += ujitter / 1000000;
		itv.it_value.tv_usec = ujitter % 1000000; 

		ଯଦି (setitimer(ITIMER_REAL, &itv, ଖାଲି) == -1)
			fatal("login grace time setitimer failed");
	}

	ssh_packet_set_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, ଆକାର(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	ଯଦି ((auth_opts = sshauthopt_new_with_ଚାବିଗୁଡ଼ିକ_defaults()) == ଖାଲି)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	ଯଦି ((loginmsg = sshbuf_new()) == ଖାଲି)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

	ଯଦି (privsep_preauth(ssh) != 1)
		fatal("privsep_preauth failed");

	/* Now user is authenticated */

	setproctitle("%s [postauth]", authctxt->user);

	/*
	 * Cancel the alarm we set to limit the time taken for
	 * authentication.
	 */
	timerclear(&itv.it_interval);
	timerclear(&itv.it_value);
	ଯଦି (setitimer(ITIMER_REAL, &itv, ଖାଲି) == -1)
		fatal("login grace time clear failed");
	ssh_signal(SIGALRM, SIG_DFL);
	authctxt->authenticated = 1;
	ଯଦି (startup_pipe != -1) {
		/* signal listener that authentication completed successfully */
		(ଶୂନ୍ୟ)atomicio(vwrite, startup_pipe, "\001", 1);
		close(startup_pipe);
		startup_pipe = -1;
	}

	ଯଦି (options.routing_domain != ଖାଲି)
		set_process_rdomain(ssh, options.routing_domain);

#ifdef SSH_AUDIT_EVENTS
	audit_event(ssh, SSH_AUTH_SUCCESS);
#endif

#ifdef GSSAPI
	ଯଦି (options.gss_authentication) {
		temporarily_use_uid(authctxt->pw);
		ssh_gssapi_storecreds();
		restore_uid();
	}
#endif
#ifdef USE_PAM
	ଯଦି (options.use_pam) {
		do_pam_setcred();
		do_pam_session(ssh);
	}
#endif

	/*
	 * In privilege separation, we fork another child and prepare
	 * file descriptor passing.
	 */
	privsep_postauth(ssh, authctxt);
	/* the monitor process [priv] will not return */

	ssh_packet_set_timeout(ssh, options.client_alive_interval,
	    options.client_alive_ଗଣନା_max);

	/* Try to send all our hostkeys to the client */
	notify_hostkeys(ssh);

	/* Start session. */
	do_authenticated(ssh, authctxt);

	/* The connection has been terminated. */
	ssh_packet_get_bytes(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes",
	    (unsigned long long)obytes, (unsigned long long)ibytes);

	verbose("Closing connection to %.500s port %d", remote_ip, remote_port);

#ifdef USE_PAM
	ଯଦି (options.use_pam)
		finish_pam();
#endif /* USE_PAM */

#ifdef SSH_AUDIT_EVENTS
	mm_audit_event(ssh, SSH_CONNECTION_CLOSE);
#endif

	ssh_packet_close(ssh);

	mm_terminate();

	exit(0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshd_hostkey_sign(ସଂରଚନା ssh *ssh, ସଂରଚନା sshkey *privkey,
    ସଂରଚନା sshkey *pubkey, u_char **signature, size_t *slenp,
    ଅଚଳ u_char *data, size_t dlen, ଅଚଳ ଅକ୍ଷର *alg)
{
	ଯଦି (privkey) {
		ଯଦି (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, ଖାଲି,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} ଅନ୍ୟଥା {
		ଯଦି (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, ଖାଲି,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	ଫେରନ୍ତୁ 0;
}

/* server specific fatal cleanup */
ଶୂନ୍ୟ
cleanup_exit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା i)
{
	ଯଦି (the_active_state != ଖାଲି && the_authctxt != ଖାଲି) {
		do_cleanup(the_active_state, the_authctxt);
		ଯଦି (privsep_is_preauth &&
		    pmonitor != ଖାଲି && pmonitor->m_pid > 1) {
			debug("Killing privsep child %d", pmonitor->m_pid);
			ଯଦି (kill(pmonitor->m_pid, SIGKILL) != 0 &&
			    errno != ESRCH) {
				error_f("kill(%d): %s", pmonitor->m_pid,
				    strerror(errno));
			}
		}
	}
#ifdef SSH_AUDIT_EVENTS
	/* done after do_cleanup so it can cancel the PAM auth 'thread' */
	ଯଦି (the_active_state != ଖାଲି && mm_is_monitor())
		audit_event(the_active_state, SSH_CONNECTION_ABANDON);
#endif
	/* Override default fatal exit value when auth was attempted */
	ଯଦି (i == 255 && monitor_auth_attempted())
		_exit(EXIT_AUTH_ATTEMPTED);
	ଯଦି (i == 255 && monitor_invalid_user())
		_exit(EXIT_INVALID_USER);
	_exit(i);
}
