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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/ioctl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/tree.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <grp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SECUREWARE
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/security.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <prot.h>
#ਜੇ_ਅੰਤ
 
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshpty.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "uidswap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "msg.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dispatch.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "session.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_wrap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "version.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sk-api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "srclimit.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dh.h"

/* Re-exec fds */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

/* Privsep fds */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

ਬਾਹਰੀ ਅੱਖਰ *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
ਅੱਖਰ *config_file_name = ਰਸਤਾ_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
ਪੂਰਨ debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
ਸਥਿਰ ਪੂਰਨ inetd_flag = 0;

/* debug goes to stderr unless inetd_flag is set */
ਸਥਿਰ ਪੂਰਨ log_stderr = 0;

/* Saved arguments to main(). */
ਸਥਿਰ ਅੱਖਰ **saved_argv;
ਸਥਿਰ ਪੂਰਨ saved_argc;

/* Daemon's agent connection */
ਪੂਰਨ auth_sock = -1;
ਸਥਿਰ ਪੂਰਨ have_agent = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
ਬਣਤਰ {
	u_int		ਅੰਕ_hostkeys;
	ਬਣਤਰ sshkey	**host_ਕੁੰਜੀਆਂ;		/* all private host keys */
	ਬਣਤਰ sshkey	**host_pubkeys;		/* all public host keys */
	ਬਣਤਰ sshkey	**host_certificates;	/* all public host certificates */
} sensitive_ਅੰਕੜੇ;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

ਸਥਿਰ ਪੂਰਨ startup_pipe = -1;		/* in child */

/* variables used for privilege separation */
ਬਣਤਰ monitor *pmonitor = ਨਿਰਾ;
ਪੂਰਨ privsep_is_preauth = 1;
ਸਥਿਰ ਪੂਰਨ privsep_chroot = 1;

/* Unprivileged user */
ਬਣਤਰ passwd *privsep_pw = ਨਿਰਾ;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = ਨਿਰਾ;
ਬਣਤਰ ssh *the_ਸਰਗਰਮ_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
ਬਣਤਰ sshauthopt *auth_opts = ਨਿਰਾ;

/* sshd_config buffer */
ਬਣਤਰ sshbuf *cfg;

/* Included files from the configuration file */
ਬਣਤਰ include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ਬਣਤਰ sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
ਖਾਲੀ destroy_sensitive_ਅੰਕੜੇ(ਖਾਲੀ);
ਖਾਲੀ demote_sensitive_ਅੰਕੜੇ(ਖਾਲੀ);

/* XXX reduce to stub once postauth split */
ਪੂਰਨ
mm_is_monitor(ਖਾਲੀ)
{
	/*
	 * m_pid is only set in the privileged part, and
	 * points to the unprivileged child.
	 */
	ਵਾਪਸ (pmonitor && pmonitor->m_pid > 0);
}

/*
 * Signal handler for the alarm after the login grace period has expired.
 * As usual, this may only take signal-safe actions, even though it is
 * terminal.
 */
ਸਥਿਰ ਖਾਲੀ
grace_alarm_handler(ਪੂਰਨ sig)
{
	/*
	 * Try to kill any processes that we have spawned, E.g. authorized
	 * keys command helpers or privsep children.
	 */
	ਜੇ (getpgid(0) == getpid()) {
		ਬਣਤਰ sigaction sa;

		/* mask all other signals while in handler */
		memset(&sa, 0, ਆਕਾਰ(sa));
		sa.sa_handler = SIG_IGN;
		sigfillset(&sa.sa_mask);
#ਜੇ defined(SA_RESTART)
		sa.sa_flags = SA_RESTART;
#ਜੇ_ਅੰਤ
		(ਖਾਲੀ)sigaction(SIGTERM, &sa, ਨਿਰਾ);
		kill(0, SIGTERM);
	}
	_exit(EXIT_LOGIN_GRACE);
}

/* Destroy the host and server keys.  They will no longer be needed. */
ਖਾਲੀ
destroy_sensitive_ਅੰਕੜੇ(ਖਾਲੀ)
{
	u_int i;

	ਲਈ (i = 0; i < options.ਅੰਕ_host_ਕੁੰਜੀ_files; i++) {
		ਜੇ (sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i]) {
			sshkey_free(sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i]);
			sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i] = ਨਿਰਾ;
		}
		ਜੇ (sensitive_ਅੰਕੜੇ.host_certificates[i]) {
			sshkey_free(sensitive_ਅੰਕੜੇ.host_certificates[i]);
			sensitive_ਅੰਕੜੇ.host_certificates[i] = ਨਿਰਾ;
		}
	}
}

/* Demote private to public keys for network child */
ਖਾਲੀ
demote_sensitive_ਅੰਕੜੇ(ਖਾਲੀ)
{
	ਬਣਤਰ sshkey *tmp;
	u_int i;
	ਪੂਰਨ r;

	ਲਈ (i = 0; i < options.ਅੰਕ_host_ਕੁੰਜੀ_files; i++) {
		ਜੇ (sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i]) {
			ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(
			    sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i], &tmp)) != 0)
				fatal_r(r, "could not demote host %s key",
				    sshkey_type(sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i]));
			sshkey_free(sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i]);
			sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i] = tmp;
		}
		/* Certs do not need demotion */
	}
}

ਬਣਤਰ sshbuf *
pack_hostkeys(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *keybuf = ਨਿਰਾ, *hostkeys = ਨਿਰਾ;
	ਪੂਰਨ r;
	u_int i;

	ਜੇ ((hostkeys = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	ਲਈ (i = 0; i < options.ਅੰਕ_host_ਕੁੰਜੀ_files; i++) {
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

	sshbuf_free(keybuf);
	ਵਾਪਸ hostkeys;
}

ਸਥਿਰ ਪੂਰਨ
privsep_preauth(ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ r;
	pid_t pid;

	/* Set up unprivileged child process to deal with network data */
	pmonitor = monitor_init();
	/* Store a pointer to the kex for later rekeying */
	pmonitor->m_pkex = &ssh->kex;

	ਜੇ ((pid = fork()) == -1)
		fatal("fork of unprivileged child failed");
	ਨਹੀਂਤਾਂ ਜੇ (pid != 0) {
		debug2("Network child is on pid %ld", (ਲੰਮਾ)pid);

		pmonitor->m_pid = pid;
		ਜੇ (have_agent) {
			r = ssh_get_authentication_socket(&auth_sock);
			ਜੇ (r != 0) {
				error_r(r, "Could not get agent socket");
				have_agent = 0;
			}
		}
		monitor_ਬੱਚਾ_preauth(ssh, pmonitor);
		privsep_is_preauth = 0;
		ਵਾਪਸ 1;
	} ਨਹੀਂਤਾਂ {
		/*ਬੱਚਾ*/
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

		ਜੇ (ssh_packet_get_connection_ਵਿੱਚ(ssh) != STDIN_FILENO &&
		    dup2(ssh_packet_get_connection_ਵਿੱਚ(ssh), STDIN_FILENO) == -1)
			fatal("dup2 stdin failed: %s", strerror(errno));
		ਜੇ (ssh_packet_get_connection_ਬਾਹਰਲਾ(ssh) != STDOUT_FILENO &&
		    dup2(ssh_packet_get_connection_ਬਾਹਰਲਾ(ssh),
		    STDOUT_FILENO) == -1)
			fatal("dup2 stdout failed: %s", strerror(errno));
		/* leave stderr as-is */
		log_redirect_stderr_ਮੰਜ਼ਿਲ(ਨਿਰਾ); /* dup can clobber log fd */
		ਜੇ (pmonitor->m_recvfd != PRIVSEP_MONITOR_FD &&
		    dup2(pmonitor->m_recvfd, PRIVSEP_MONITOR_FD) == -1)
			fatal("dup2 monitor fd: %s", strerror(errno));
		ਜੇ (pmonitor->m_log_sendfd != PRIVSEP_LOG_FD &&
		    dup2(pmonitor->m_log_sendfd, PRIVSEP_LOG_FD) == -1)
			fatal("dup2 log fd: %s", strerror(errno));
		closefrom(PRIVSEP_MIN_FREE_FD);

		saved_argv[0] = options.sshd_auth_ਰਸਤਾ;
		execv(options.sshd_auth_ਰਸਤਾ, saved_argv);

		fatal_f("exec of %s failed: %s",
		    options.sshd_auth_ਰਸਤਾ, strerror(errno));
	}
}

ਸਥਿਰ ਖਾਲੀ
privsep_postauth(ਬਣਤਰ ssh *ssh, Authctxt *authctxt)
{
	/* New socket pair */
	monitor_reinit(pmonitor);

	pmonitor->m_pid = fork();
	ਜੇ (pmonitor->m_pid == -1)
		fatal("fork of unprivileged child failed");
	ਨਹੀਂਤਾਂ ਜੇ (pmonitor->m_pid != 0) {
		verbose("User child is on pid %ld", (ਲੰਮਾ)pmonitor->m_pid);
		sshbuf_reset(loginmsg);
		monitor_clear_keystate(ssh, pmonitor);
		monitor_ਬੱਚਾ_postauth(ssh, pmonitor);

		/* NEVERREACHED */
		ਬਾਹਰ_ਨਿਕਲੋ(0);
	}

	/*ਬੱਚਾ*/

	close(pmonitor->m_sendfd);
	pmonitor->m_sendfd = -1;

	/* Demote the private keys to public keys. */
	demote_sensitive_ਅੰਕੜੇ();

	reseed_prngs();

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SKIP_PRIVDROP
	/* Drop privileges */
	do_setusercontext(authctxt->pw);
#ਜੇ_ਅੰਤ

	/* It is safe now to apply the key state */
	monitor_apply_keystate(ssh, pmonitor);

	/*
	 * Tell the packet layer that authentication was successful, since
	 * this information is not part of the key state.
	 */
	ssh_packet_ਸੈੱਟ_authenticated(ssh);
}

ਸਥਿਰ ਬਣਤਰ sshkey *
get_hostkey_by_type(ਪੂਰਨ type, ਪੂਰਨ nid, ਪੂਰਨ need_ਨਿੱਜੀ, ਬਣਤਰ ssh *ssh)
{
	u_int i;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ;

	ਲਈ (i = 0; i < options.ਅੰਕ_host_ਕੁੰਜੀ_files; i++) {
		ਚੋਣ (type) {
		ਹਾਲਤ ਕੁੰਜੀ_RSA_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_ED25519_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_MLDSA44_ED25519_CERT:
			ਕੁੰਜੀ = sensitive_ਅੰਕੜੇ.host_certificates[i];
			ਰੋਕੋ;
		ਮੂਲ:
			ਕੁੰਜੀ = sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i];
			ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ && !need_ਨਿੱਜੀ)
				ਕੁੰਜੀ = sensitive_ਅੰਕੜੇ.host_pubkeys[i];
			ਰੋਕੋ;
		}
		ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ || ਕੁੰਜੀ->type != type)
			ਜਾਰੀ;
		ਚੋਣ (type) {
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK_CERT:
			ਜੇ (ਕੁੰਜੀ->ecdsa_nid != nid)
				ਜਾਰੀ;
			/* FALLTHROUGH */
		ਮੂਲ:
			ਵਾਪਸ need_ਨਿੱਜੀ ?
			    sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i] : ਕੁੰਜੀ;
		}
	}
	ਵਾਪਸ ਨਿਰਾ;
}

ਬਣਤਰ sshkey *
get_hostkey_ਜਨਤਕ_by_type(ਪੂਰਨ type, ਪੂਰਨ nid, ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ get_hostkey_by_type(type, nid, 0, ssh);
}

ਬਣਤਰ sshkey *
get_hostkey_ਨਿੱਜੀ_by_type(ਪੂਰਨ type, ਪੂਰਨ nid, ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ get_hostkey_by_type(type, nid, 1, ssh);
}

ਬਣਤਰ sshkey *
get_hostkey_by_ਸੂਚਕਾਂਕ(ਪੂਰਨ ind)
{
	ਜੇ (ind < 0 || (u_int)ind >= options.ਅੰਕ_host_ਕੁੰਜੀ_files)
		ਵਾਪਸ (ਨਿਰਾ);
	ਵਾਪਸ (sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[ind]);
}

ਬਣਤਰ sshkey *
get_hostkey_ਜਨਤਕ_by_ਸੂਚਕਾਂਕ(ਪੂਰਨ ind, ਬਣਤਰ ssh *ssh)
{
	ਜੇ (ind < 0 || (u_int)ind >= options.ਅੰਕ_host_ਕੁੰਜੀ_files)
		ਵਾਪਸ (ਨਿਰਾ);
	ਵਾਪਸ (sensitive_ਅੰਕੜੇ.host_pubkeys[ind]);
}

ਪੂਰਨ
get_hostkey_ਸੂਚਕਾਂਕ(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਪੂਰਨ compare, ਬਣਤਰ ssh *ssh)
{
	u_int i;

	ਲਈ (i = 0; i < options.ਅੰਕ_host_ਕੁੰਜੀ_files; i++) {
		ਜੇ (sshkey_is_cert(ਕੁੰਜੀ)) {
			ਜੇ (ਕੁੰਜੀ == sensitive_ਅੰਕੜੇ.host_certificates[i] ||
			    (compare && sensitive_ਅੰਕੜੇ.host_certificates[i] &&
			    sshkey_equal(ਕੁੰਜੀ,
			    sensitive_ਅੰਕੜੇ.host_certificates[i])))
				ਵਾਪਸ (i);
		} ਨਹੀਂਤਾਂ {
			ਜੇ (ਕੁੰਜੀ == sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i] ||
			    (compare && sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i] &&
			    sshkey_equal(ਕੁੰਜੀ, sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i])))
				ਵਾਪਸ (i);
			ਜੇ (ਕੁੰਜੀ == sensitive_ਅੰਕੜੇ.host_pubkeys[i] ||
			    (compare && sensitive_ਅੰਕੜੇ.host_pubkeys[i] &&
			    sshkey_equal(ਕੁੰਜੀ, sensitive_ਅੰਕੜੇ.host_pubkeys[i])))
				ਵਾਪਸ (i);
		}
	}
	ਵਾਪਸ (-1);
}

/* Inform the client of all hostkeys */
ਸਥਿਰ ਖਾਲੀ
notify_hostkeys(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ sshbuf *buf;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ;
	u_int i, nkeys;
	ਪੂਰਨ r;
	ਅੱਖਰ *fp;

	/* Some clients cannot cope with the hostkeys message, skip those. */
	ਜੇ (ssh->compat & SSH_BUG_HOSTKEYS)
		ਵਾਪਸ;

	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਲਈ (i = nkeys = 0; i < options.ਅੰਕ_host_ਕੁੰਜੀ_files; i++) {
		ਕੁੰਜੀ = get_hostkey_ਜਨਤਕ_by_ਸੂਚਕਾਂਕ(i, ssh);
		ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ || ਕੁੰਜੀ->type == ਕੁੰਜੀ_UNSPEC ||
		    sshkey_is_cert(ਕੁੰਜੀ))
			ਜਾਰੀ;
		fp = sshkey_fingerprint(ਕੁੰਜੀ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("key %d: %s %s", i, sshkey_ssh_name(ਕੁੰਜੀ), fp);
		ਮੁਕਤ(fp);
		ਜੇ (nkeys == 0) {
			/*
			 * Start building the request when we find the
			 * first usable key.
			 */
			ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_GLOBAL_REQUEST)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "hostkeys-00@openssh.com")) != 0 ||
			    (r = sshpkt_put_u8(ssh, 0)) != 0) /* want reply */
				sshpkt_fatal(ssh, r, "%s: start request", __func__);
		}
		/* Append the key to the request */
		sshbuf_reset(buf);
		ਜੇ ((r = sshkey_putb(ਕੁੰਜੀ, buf)) != 0)
			fatal_fr(r, "couldn't put hostkey %d", i);
		ਜੇ ((r = sshpkt_put_stringb(ssh, buf)) != 0)
			sshpkt_fatal(ssh, r, "%s: append key", __func__);
		nkeys++;
	}
	debug3_f("sent %u hostkeys", nkeys);
	ਜੇ (nkeys == 0)
		fatal_f("no hostkeys");
	ਜੇ ((r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send", __func__);
	sshbuf_free(buf);
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

ਸਥਿਰ ਖਾਲੀ
parse_hostkeys(ਬਣਤਰ sshbuf *hostkeys)
{
	ਪੂਰਨ r;
	u_int ਅੰਕ_ਕੁੰਜੀਆਂ = 0;
	ਬਣਤਰ sshkey *k;
	ਬਣਤਰ sshbuf *kbuf;
	ਅਚਲ u_char *cp;
	ਮਾਪ_t len;

	ਜਦੋਂ (sshbuf_len(hostkeys) != 0) {
		ਜੇ (ਅੰਕ_ਕੁੰਜੀਆਂ > 2048)
			fatal_f("too many hostkeys");
		sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ = xrecallocarray(
		    sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ, ਅੰਕ_ਕੁੰਜੀਆਂ, ਅੰਕ_ਕੁੰਜੀਆਂ + 1,
		    ਆਕਾਰ(*sensitive_ਅੰਕੜੇ.host_pubkeys));
		sensitive_ਅੰਕੜੇ.host_pubkeys = xrecallocarray(
		    sensitive_ਅੰਕੜੇ.host_pubkeys, ਅੰਕ_ਕੁੰਜੀਆਂ, ਅੰਕ_ਕੁੰਜੀਆਂ + 1,
		    ਆਕਾਰ(*sensitive_ਅੰਕੜੇ.host_pubkeys));
		sensitive_ਅੰਕੜੇ.host_certificates = xrecallocarray(
		    sensitive_ਅੰਕੜੇ.host_certificates, ਅੰਕ_ਕੁੰਜੀਆਂ, ਅੰਕ_ਕੁੰਜੀਆਂ + 1,
		    ਆਕਾਰ(*sensitive_ਅੰਕੜੇ.host_certificates));
		/* private key */
		k = ਨਿਰਾ;
		ਜੇ ((r = sshbuf_froms(hostkeys, &kbuf)) != 0)
			fatal_fr(r, "extract privkey");
		ਜੇ (sshbuf_len(kbuf) != 0 &&
		    (r = sshkey_ਨਿੱਜੀ_deserialize(kbuf, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[ਅੰਕ_ਕੁੰਜੀਆਂ] = k;
		sshbuf_free(kbuf);
		ਜੇ (k)
			debug2_f("privkey %u: %s", ਅੰਕ_ਕੁੰਜੀਆਂ, sshkey_ssh_name(k));
		/* public key */
		k = ਨਿਰਾ;
		ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ਜੇ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_ਅੰਕੜੇ.host_pubkeys[ਅੰਕ_ਕੁੰਜੀਆਂ] = k;
		ਜੇ (k)
			debug2_f("pubkey %u: %s", ਅੰਕ_ਕੁੰਜੀਆਂ, sshkey_ssh_name(k));
		/* certificate */
		k = ਨਿਰਾ;
		ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ਜੇ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_ਅੰਕੜੇ.host_certificates[ਅੰਕ_ਕੁੰਜੀਆਂ] = k;
		ਜੇ (k)
			debug2_f("cert %u: %s", ਅੰਕ_ਕੁੰਜੀਆਂ, sshkey_ssh_name(k));
		ਅੰਕ_ਕੁੰਜੀਆਂ++;
	}
	sensitive_ਅੰਕੜੇ.ਅੰਕ_hostkeys = ਅੰਕ_ਕੁੰਜੀਆਂ;
}

ਸਥਿਰ ਖਾਲੀ
recv_rexec_state(ਪੂਰਨ fd, ਬਣਤਰ sshbuf *conf, uint64_t *timing_secretp)
{
	ਬਣਤਰ sshbuf *m, *inc, *hostkeys;
	u_char *cp, ver;
	ਮਾਪ_t len;
	ਪੂਰਨ r;
	ਬਣਤਰ include_ਵਸਤੂ *ਵਸਤੂ;

	debug3_f("entering fd = %d", fd);

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ || (inc = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	/* receive config */
	ਜੇ (ssh_ਸੁਨੇਹਾ_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	ਜੇ ((r = sshbuf_get_u8(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	ਜੇ (ver != 0)
		fatal_f("rexec version mismatch");
	ਜੇ ((r = sshbuf_get_string(m, &cp, &len)) != 0 || /* XXX _direct */
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_get_stringb(m, inc)) != 0)
		fatal_fr(r, "parse config");

	ਜੇ (conf != ਨਿਰਾ && (r = sshbuf_put(conf, cp, len)))
		fatal_fr(r, "sshbuf_put");

	ਜਦੋਂ (sshbuf_len(inc) != 0) {
		ਵਸਤੂ = xcalloc(1, ਆਕਾਰ(*ਵਸਤੂ));
		ਜੇ ((ਵਸਤੂ->contents = sshbuf_new()) == ਨਿਰਾ)
			fatal_f("sshbuf_new failed");
		ਜੇ ((r = sshbuf_get_cstring(inc, &ਵਸਤੂ->selector, ਨਿਰਾ)) != 0 ||
		    (r = sshbuf_get_cstring(inc, &ਵਸਤੂ->filename, ਨਿਰਾ)) != 0 ||
		    (r = sshbuf_get_stringb(inc, ਵਸਤੂ->contents)) != 0)
			fatal_fr(r, "parse includes");
		TAILQ_INSERT_TAIL(&includes, ਵਸਤੂ, ਇੰਦਰਾਜ);
	}

	/* receive hostkeys */
	sshbuf_reset(m);
	ਜੇ (ssh_ਸੁਨੇਹਾ_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	ਜੇ ((r = sshbuf_get_u8(m, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_froms(m, &hostkeys)) != 0)
		fatal_fr(r, "parse config");
	parse_hostkeys(hostkeys);

	ਮੁਕਤ(cp);
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
ਸਥਿਰ ਖਾਲੀ
check_ip_options(ਬਣਤਰ ssh *ssh)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ IP_OPTIONS
	ਪੂਰਨ sock_ਵਿੱਚ = ssh_packet_get_connection_ਵਿੱਚ(ssh);
	ਬਣਤਰ sockaddr_storage from;
	u_char opts[200];
	socklen_t i, option_ਮਾਪ = ਆਕਾਰ(opts), fromlen = ਆਕਾਰ(from);
	ਅੱਖਰ ਪਾਠ[ਆਕਾਰ(opts) * 3 + 1];

	memset(&from, 0, ਆਕਾਰ(from));
	ਜੇ (getpeername(sock_ਵਿੱਚ, (ਬਣਤਰ sockaddr *)&from,
	    &fromlen) == -1)
		ਵਾਪਸ;
	ਜੇ (from.ss_family != AF_INET)
		ਵਾਪਸ;
	/* XXX IPv6 options? */

	ਜੇ (getsockopt(sock_ਵਿੱਚ, IPPROTO_IP, IP_OPTIONS, opts,
	    &option_ਮਾਪ) >= 0 && option_ਮਾਪ != 0) {
		ਪਾਠ[0] = '\0';
		ਲਈ (i = 0; i < option_ਮਾਪ; i++)
			snprintf(ਪਾਠ + i*3, ਆਕਾਰ(ਪਾਠ) - i*3,
			    " %2.2x", opts[i]);
		fatal("Connection from %.100s port %d with IP opts: %.800s",
		    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh), ਪਾਠ);
	}
#ਜੇ_ਅੰਤ /* IP_OPTIONS */
}

/* Set the routing domain for this process */
ਸਥਿਰ ਖਾਲੀ
ਸੈੱਟ_process_rdomain(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *name)
{
#ਜੇ defined(HAVE_SYS_ਸੈੱਟ_PROCESS_RDOMAIN)
	ਜੇ (name == ਨਿਰਾ)
		ਵਾਪਸ; /* default */

	ਜੇ (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		ਜੇ ((name = ssh_packet_rdomain_ਵਿੱਚ(ssh)) == ਨਿਰਾ)
			ਵਾਪਸ;
	}
	/* NB. We don't pass 'ssh' to sys_set_process_rdomain() */
	ਵਾਪਸ sys_ਸੈੱਟ_process_rdomain(name);
#ਜਾਂਜੇ defined(__OpenBSD__)
	ਪੂਰਨ rtable, ortable = getrtable();
	ਅਚਲ ਅੱਖਰ *errstr;

	ਜੇ (name == ਨਿਰਾ)
		ਵਾਪਸ; /* default */

	ਜੇ (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		ਜੇ ((name = ssh_packet_rdomain_ਵਿੱਚ(ssh)) == ਨਿਰਾ)
			ਵਾਪਸ;
	}

	rtable = (ਪੂਰਨ)strtonum(name, 0, 255, &errstr);
	ਜੇ (errstr != ਨਿਰਾ) /* Shouldn't happen */
		fatal("Invalid routing domain \"%s\": %s", name, errstr);
	ਜੇ (rtable != ortable && setrtable(rtable) != 0)
		fatal("Unable to set routing domain %d: %s",
		    rtable, strerror(errno));
	debug_f("set routing domain %d (was %d)", rtable, ortable);
#ਨਹੀਂਤਾਂ /* defined(__OpenBSD__) */
	fatal("Unable to set routing domain: not supported in this platform");
#ਜੇ_ਅੰਤ
}

/*
 * Main program for the daemon.
 */
ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ ac, ਅੱਖਰ **av)
{
	ਬਣਤਰ ssh *ssh = ਨਿਰਾ;
	ਬਾਹਰੀ ਅੱਖਰ *optarg;
	ਬਾਹਰੀ ਪੂਰਨ optind;
	ਪੂਰਨ devnull, r, opt, remote_ਪੋਰਟ;
	ਪੂਰਨ sock_ਵਿੱਚ = -1, sock_ਬਾਹਰਲਾ = -1, rexeced_flag = 0, have_ਕੁੰਜੀ = 0;
	ਅਚਲ ਅੱਖਰ *remote_ip, *rdomain;
	ਅੱਖਰ *ਸਤਰ, *laddr, *logfile = ਨਿਰਾ;
	u_int i;
	uint64_t ibytes, obytes;
	ਬਹੁਲਕ_t new_umask;
	Authctxt *authctxt;
	ਬਣਤਰ connection_info *connection_info = ਨਿਰਾ;
	sigset_t sigmask;
	uint64_t timing_secret = 0;
	ਬਣਤਰ itimerval itv;

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ਨਿਰਾ);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SECUREWARE
	(ਖਾਲੀ)ਸੈੱਟ_auth_parameters(ac, av);
#ਜੇ_ਅੰਤ
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, ਆਕਾਰ(*saved_argv));
	ਲਈ (i = 0; (ਪੂਰਨ)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ਨਿਰਾ;

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#ਜੇ_ਅੰਤ

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
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
			/* ignore */
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
			/* ignore */
			ਰੋਕੋ;
		ਹਾਲਤ 'R':
			rexeced_flag = 1;
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
		ਹਾਲਤ 'T':
		ਹਾਲਤ 'G':
			fatal("test/dump modes not supported");
			ਰੋਕੋ;
		ਹਾਲਤ 'C':
			connection_info = server_get_connection_info(ssh, 0, 0);
			ਜੇ (parse_server_ਮੇਲ_testspec(connection_info,
			    optarg) == -1)
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			ਰੋਕੋ;
		ਹਾਲਤ 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, ਨਿਰਾ);
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

	/* Check that there are no remaining arguments. */
	ਜੇ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}

	ਜੇ (!rexeced_flag)
		fatal("sshd-session should not be executed directly");

	closefrom(REEXEC_MIN_FREE_FD);

	platform_pre_session_ਸ਼ੁਰੂ();

	/* Reserve fds we'll need later for reexec things */
	ਜੇ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	ਜਦੋਂ (devnull < PRIVSEP_MIN_FREE_FD) {
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
		    "P", "sshd-session",
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

	/* Fetch our configuration */
	ਜੇ ((cfg = sshbuf_new()) == ਨਿਰਾ)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[rexeced]");
	recv_rexec_state(REEXEC_CONFIG_PASS_FD, cfg, &timing_secret);
	parse_server_config(&options, "rexec", cfg, &includes, ਨਿਰਾ, 1);
	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);
	options.timing_secret = timing_secret;

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	debug("sshd-session version %s, %s", SSH_ਸੰਸਕਰਣ, SSH_OPENSSL_ਸੰਸਕਰਣ);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	ਜੇ ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == ਨਿਰਾ) {
		ਜੇ (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} ਨਹੀਂਤਾਂ {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, ਲੜੀ_ਲੰਬਾਈ(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

	ਜੇ (!debug_flag && !inetd_flag) {
		ਜੇ ((startup_pipe = dup(REEXEC_CONFIG_PASS_FD)) == -1)
			fatal("internal error: no startup pipe");

		/*
		 * Signal parent that this child is at a point where
		 * they can go away if they have a SIGHUP pending.
		 */
		(ਖਾਲੀ)atomicio(vwrite, startup_pipe, "\0", 1);
	}
	/* close the fd, but keep the slot reserved */
	ਜੇ (dup2(devnull, REEXEC_CONFIG_PASS_FD) == -1)
		fatal("dup2 devnull->config fd: %s", strerror(errno));

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
	 * daemonisation in the presence of Match block, but this catches
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

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਜੇ (options.moduli_file != ਨਿਰਾ)
		dh_ਸੈੱਟ_moduli_file(options.moduli_file);
#ਜੇ_ਅੰਤ

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

	ਜੇ (options.ਅੰਕ_host_ਕੁੰਜੀ_files != sensitive_ਅੰਕੜੇ.ਅੰਕ_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.ਅੰਕ_host_ਕੁੰਜੀ_files, sensitive_ਅੰਕੜੇ.ਅੰਕ_hostkeys);
	}

	ਲਈ (i = 0; i < options.ਅੰਕ_host_ਕੁੰਜੀ_files; i++) {
		ਜੇ (sensitive_ਅੰਕੜੇ.host_ਕੁੰਜੀਆਂ[i] != ਨਿਰਾ ||
		    (have_agent && sensitive_ਅੰਕੜੇ.host_pubkeys[i] != ਨਿਰਾ)) {
			have_ਕੁੰਜੀ = 1;
			ਰੋਕੋ;
		}
	}
	ਜੇ (!have_ਕੁੰਜੀ)
		fatal("internal error: monitor received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(ਖਾਲੀ) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	ਜੇ (debug_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	ਲਈ (i = 0; i < options.ਅੰਕ_log_verbose; i++)
		log_verbose_ਜੋੜੋ(options.log_verbose[i]);

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

	/* Get a connection, either from inetd or rexec */
	ਜੇ (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_ਵਿੱਚ = dup(STDIN_FILENO);
		sock_ਬਾਹਰਲਾ = dup(STDOUT_FILENO);
	} ਨਹੀਂਤਾਂ {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_ਵਿੱਚ = sock_ਬਾਹਰਲਾ = dup(STDIN_FILENO);
	}

	/*
	 * We intentionally do not close the descriptors 0, 1, and 2
	 * as our code for setting the descriptors won't work if
	 * ttyfd happens to be one of those.
	 */
	ਜੇ (stdfd_devnull(1, 1, !log_stderr) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_ਵਿੱਚ, sock_ਬਾਹਰਲਾ);

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_ਬਾਹਰਲਾ);
	FD_CLOSEONEXEC(sock_ਵਿੱਚ);

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
	ਜੇ ((ssh = ssh_packet_ਸੈੱਟ_connection(ਨਿਰਾ, sock_ਵਿੱਚ, sock_ਬਾਹਰਲਾ)) == ਨਿਰਾ)
		fatal("Unable to create connection");
	the_ਸਰਗਰਮ_state = ssh;
	ssh_packet_ਸੈੱਟ_server(ssh);
	ssh_packet_ਸੈੱਟ_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	check_ip_options(ssh);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_ਸੈੱਟ_af(ssh, options.ਪਤਾ_family);
	channel_ਸੈੱਟ_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);

	/* Set SO_KEEPALIVE if requested. */
	ਜੇ (options.tcp_keep_alive && ssh_packet_connection_is_on_socket(ssh))
		ਸੈੱਟ_keepalive(sock_ਵਿੱਚ); /* logs errors */

	ਜੇ ((remote_ਪੋਰਟ = ssh_remote_ਪੋਰਟ(ssh)) < 0) {
		debug("ssh_remote_port failed");
		cleanup_exit(255);
	}

	/*
	 * The rest of the code depends on the fact that
	 * ssh_remote_ipaddr() caches the remote ip, even if
	 * the socket goes away.
	 */
	remote_ip = ssh_remote_ipaddr(ssh);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS
	audit_connection_from(remote_ip, remote_ਪੋਰਟ);
#ਜੇ_ਅੰਤ

	rdomain = ssh_packet_rdomain_ਵਿੱਚ(ssh);

	/* Log the connection. */
	laddr = get_local_ipaddr(sock_ਵਿੱਚ);
	verbose("Connection from %s port %d on %s port %d%s%s%s",
	    remote_ip, remote_ਪੋਰਟ, laddr,  ssh_local_ਪੋਰਟ(ssh),
	    rdomain == ਨਿਰਾ ? "" : " rdomain \"",
	    rdomain == ਨਿਰਾ ? "" : rdomain,
	    rdomain == ਨਿਰਾ ? "" : "\"");
	ਮੁਕਤ(laddr);

	/*
	 * We don't want to listen forever unless the other side
	 * successfully authenticates itself.  So we set up an alarm which is
	 * cleared after successful authentication.  A limit of zero
	 * indicates no limit. Note that we don't set the alarm in debugging
	 * mode; it is just annoying to have the server exit just when you
	 * are about to discover the bug.
	 */
	ssh_signal(SIGALRM, grace_alarm_handler);
	ਜੇ (!debug_flag && options.login_grace_ਸਮਾਂ > 0) {
		ਪੂਰਨ ujitter = arc4random_ਇਕਸਾਰ(4 * 1000000);

		timerclear(&itv.it_interval);
		itv.it_value.tv_sec = options.login_grace_ਸਮਾਂ;
		itv.it_value.tv_sec += ujitter / 1000000;
		itv.it_value.tv_usec = ujitter % 1000000; 

		ਜੇ (setitimer(ITIMER_REAL, &itv, ਨਿਰਾ) == -1)
			fatal("login grace time setitimer failed");
	}

	ssh_packet_ਸੈੱਟ_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, ਆਕਾਰ(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	ਜੇ ((auth_opts = sshauthopt_new_with_ਕੁੰਜੀਆਂ_defaults()) == ਨਿਰਾ)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	ਜੇ ((loginmsg = sshbuf_new()) == ਨਿਰਾ)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

	ਜੇ (privsep_preauth(ssh) != 1)
		fatal("privsep_preauth failed");

	/* Now user is authenticated */

	setproctitle("%s [postauth]", authctxt->user);

	/*
	 * Cancel the alarm we set to limit the time taken for
	 * authentication.
	 */
	timerclear(&itv.it_interval);
	timerclear(&itv.it_value);
	ਜੇ (setitimer(ITIMER_REAL, &itv, ਨਿਰਾ) == -1)
		fatal("login grace time clear failed");
	ssh_signal(SIGALRM, SIG_DFL);
	authctxt->authenticated = 1;
	ਜੇ (startup_pipe != -1) {
		/* signal listener that authentication completed successfully */
		(ਖਾਲੀ)atomicio(vwrite, startup_pipe, "\001", 1);
		close(startup_pipe);
		startup_pipe = -1;
	}

	ਜੇ (options.routing_domain != ਨਿਰਾ)
		ਸੈੱਟ_process_rdomain(ssh, options.routing_domain);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS
	audit_event(ssh, SSH_AUTH_SUCCESS);
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
	ਜੇ (options.gss_authentication) {
		temporarily_use_uid(authctxt->pw);
		ssh_gssapi_storecreds();
		restore_uid();
	}
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	ਜੇ (options.use_pam) {
		do_pam_setcred();
		do_pam_session(ssh);
	}
#ਜੇ_ਅੰਤ

	/*
	 * In privilege separation, we fork another child and prepare
	 * file descriptor passing.
	 */
	privsep_postauth(ssh, authctxt);
	/* the monitor process [priv] will not return */

	ssh_packet_ਸੈੱਟ_timeout(ssh, options.client_alive_interval,
	    options.client_alive_ਗਿਣਤੀ_max);

	/* Try to send all our hostkeys to the client */
	notify_hostkeys(ssh);

	/* Start session. */
	do_authenticated(ssh, authctxt);

	/* The connection has been terminated. */
	ssh_packet_get_ਬਾਈਟਾਂ(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes",
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)obytes, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ibytes);

	verbose("Closing connection to %.500s port %d", remote_ip, remote_ਪੋਰਟ);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	ਜੇ (options.use_pam)
		ਅੰਤ_pam();
#ਜੇ_ਅੰਤ /* USE_PAM */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS
	mm_audit_event(ssh, SSH_CONNECTION_CLOSE);
#ਜੇ_ਅੰਤ

	ssh_packet_close(ssh);

	mm_terminate();

	ਬਾਹਰ_ਨਿਕਲੋ(0);
}

ਪੂਰਨ
sshd_hostkey_sign(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshkey *privkey,
    ਬਣਤਰ sshkey *pubkey, u_char **signature, ਮਾਪ_t *slenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t dlen, ਅਚਲ ਅੱਖਰ *alg)
{
	ਜੇ (privkey) {
		ਜੇ (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    ਅੰਕੜੇ, dlen, alg, options.sk_provider, ਨਿਰਾ,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} ਨਹੀਂਤਾਂ {
		ਜੇ (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    ਅੰਕੜੇ, dlen, alg, options.sk_provider, ਨਿਰਾ,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	ਵਾਪਸ 0;
}

/* server specific fatal cleanup */
ਖਾਲੀ
cleanup_exit(ਪੂਰਨ i)
{
	ਜੇ (the_ਸਰਗਰਮ_state != ਨਿਰਾ && the_authctxt != ਨਿਰਾ) {
		do_cleanup(the_ਸਰਗਰਮ_state, the_authctxt);
		ਜੇ (privsep_is_preauth &&
		    pmonitor != ਨਿਰਾ && pmonitor->m_pid > 1) {
			debug("Killing privsep child %d", pmonitor->m_pid);
			ਜੇ (kill(pmonitor->m_pid, SIGKILL) != 0 &&
			    errno != ESRCH) {
				error_f("kill(%d): %s", pmonitor->m_pid,
				    strerror(errno));
			}
		}
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS
	/* done after do_cleanup so it can cancel the PAM auth 'thread' */
	ਜੇ (the_ਸਰਗਰਮ_state != ਨਿਰਾ && mm_is_monitor())
		audit_event(the_ਸਰਗਰਮ_state, SSH_CONNECTION_ABANDON);
#ਜੇ_ਅੰਤ
	/* Override default fatal exit value when auth was attempted */
	ਜੇ (i == 255 && monitor_auth_attempted())
		_exit(EXIT_AUTH_ATTEMPTED);
	ਜੇ (i == 255 && monitor_invalid_user())
		_exit(EXIT_INVALID_USER);
	_exit(i);
}
