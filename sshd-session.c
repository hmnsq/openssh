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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/ioctl.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ <sys/tree.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <grp.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SECUREWARE
#ಅನ್ತರ್ಭಾವ <sys/security.h>
#ಅನ್ತರ್ಭಾವ <prot.h>
#ಆದರೆ_ಅಂತ್ಯ
 
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "sshpty.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "uidswap.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "msg.h"
#ಅನ್ತರ್ಭಾವ "dispatch.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "session.h"
#ಅನ್ತರ್ಭಾವ "monitor.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ಅನ್ತರ್ಭಾವ "version.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sk-api.h"
#ಅನ್ತರ್ಭಾವ "srclimit.h"
#ಅನ್ತರ್ಭಾವ "dh.h"

/* Re-exec fds */
#ವ್ಯಾಖ್ಯಾನಿಸು REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#ವ್ಯಾಖ್ಯಾನಿಸು REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#ವ್ಯಾಖ್ಯಾನಿಸು REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

/* Privsep fds */
#ವ್ಯಾಖ್ಯಾನಿಸು PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#ವ್ಯಾಖ್ಯಾನಿಸು PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#ವ್ಯಾಖ್ಯಾನಿಸು PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
ಅಕ್ಷರ *config_file_name = ಮಾರ್ಗ_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
ಪೂರ್ಣಾಂಕ debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ inetd_flag = 0;

/* debug goes to stderr unless inetd_flag is set */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ log_stderr = 0;

/* Saved arguments to main(). */
ಸ್ಥಿರ ಅಕ್ಷರ **saved_argv;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ saved_argc;

/* Daemon's agent connection */
ಪೂರ್ಣಾಂಕ auth_sock = -1;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ have_agent = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
ರಚನೆ {
	u_int		ಅಂಕೆ_hostkeys;
	ರಚನೆ sshkey	**host_ಕೀಲಿಗಳು;		/* all private host keys */
	ರಚನೆ sshkey	**host_pubkeys;		/* all public host keys */
	ರಚನೆ sshkey	**host_certificates;	/* all public host certificates */
} sensitive_ದತ್ತಾಂಶ;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ startup_pipe = -1;		/* in child */

/* variables used for privilege separation */
ರಚನೆ monitor *pmonitor = ಖಾಲಿ;
ಪೂರ್ಣಾಂಕ privsep_is_preauth = 1;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ privsep_chroot = 1;

/* Unprivileged user */
ರಚನೆ passwd *privsep_pw = ಖಾಲಿ;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = ಖಾಲಿ;
ರಚನೆ ssh *the_ಸಕ್ರಿಯ_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
ರಚನೆ sshauthopt *auth_opts = ಖಾಲಿ;

/* sshd_config buffer */
ರಚನೆ sshbuf *cfg;

/* Included files from the configuration file */
ರಚನೆ include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ರಚನೆ sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
ಶೂನ್ಯ destroy_sensitive_ದತ್ತಾಂಶ(ಶೂನ್ಯ);
ಶೂನ್ಯ demote_sensitive_ದತ್ತಾಂಶ(ಶೂನ್ಯ);

/* XXX reduce to stub once postauth split */
ಪೂರ್ಣಾಂಕ
mm_is_monitor(ಶೂನ್ಯ)
{
	/*
	 * m_pid is only set in the privileged part, and
	 * points to the unprivileged child.
	 */
	ಹಿಂತಿರುಗಿ (pmonitor && pmonitor->m_pid > 0);
}

/*
 * Signal handler for the alarm after the login grace period has expired.
 * As usual, this may only take signal-safe actions, even though it is
 * terminal.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
grace_alarm_handler(ಪೂರ್ಣಾಂಕ sig)
{
	/*
	 * Try to kill any processes that we have spawned, E.g. authorized
	 * keys command helpers or privsep children.
	 */
	ಆದರೆ (getpgid(0) == getpid()) {
		ರಚನೆ sigaction sa;

		/* mask all other signals while in handler */
		memset(&sa, 0, ಗಾತ್ರ(sa));
		sa.sa_handler = SIG_IGN;
		sigfillset(&sa.sa_mask);
#ಆದರೆ defined(SA_RESTART)
		sa.sa_flags = SA_RESTART;
#ಆದರೆ_ಅಂತ್ಯ
		(ಶೂನ್ಯ)sigaction(SIGTERM, &sa, ಖಾಲಿ);
		kill(0, SIGTERM);
	}
	_exit(EXIT_LOGIN_GRACE);
}

/* Destroy the host and server keys.  They will no longer be needed. */
ಶೂನ್ಯ
destroy_sensitive_ದತ್ತಾಂಶ(ಶೂನ್ಯ)
{
	u_int i;

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಆದರೆ (sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i]) {
			sshkey_free(sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i]);
			sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i] = ಖಾಲಿ;
		}
		ಆದರೆ (sensitive_ದತ್ತಾಂಶ.host_certificates[i]) {
			sshkey_free(sensitive_ದತ್ತಾಂಶ.host_certificates[i]);
			sensitive_ದತ್ತಾಂಶ.host_certificates[i] = ಖಾಲಿ;
		}
	}
}

/* Demote private to public keys for network child */
ಶೂನ್ಯ
demote_sensitive_ದತ್ತಾಂಶ(ಶೂನ್ಯ)
{
	ರಚನೆ sshkey *tmp;
	u_int i;
	ಪೂರ್ಣಾಂಕ r;

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಆದರೆ (sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i]) {
			ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(
			    sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i], &tmp)) != 0)
				fatal_r(r, "could not demote host %s key",
				    sshkey_type(sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i]));
			sshkey_free(sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i]);
			sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i] = tmp;
		}
		/* Certs do not need demotion */
	}
}

ರಚನೆ sshbuf *
pack_hostkeys(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *keybuf = ಖಾಲಿ, *hostkeys = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;
	u_int i;

	ಆದರೆ ((hostkeys = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
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

	sshbuf_free(keybuf);
	ಹಿಂತಿರುಗಿ hostkeys;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
privsep_preauth(ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ r;
	pid_t pid;

	/* Set up unprivileged child process to deal with network data */
	pmonitor = monitor_init();
	/* Store a pointer to the kex for later rekeying */
	pmonitor->m_pkex = &ssh->kex;

	ಆದರೆ ((pid = fork()) == -1)
		fatal("fork of unprivileged child failed");
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (pid != 0) {
		debug2("Network child is on pid %ld", (ದೀರ್ಘ)pid);

		pmonitor->m_pid = pid;
		ಆದರೆ (have_agent) {
			r = ssh_get_authentication_socket(&auth_sock);
			ಆದರೆ (r != 0) {
				error_r(r, "Could not get agent socket");
				have_agent = 0;
			}
		}
		monitor_ಮಗು_preauth(ssh, pmonitor);
		privsep_is_preauth = 0;
		ಹಿಂತಿರುಗಿ 1;
	} ಇಲ್ಲದಿದ್ದರೆ {
		/*ಮಗು*/
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

		ಆದರೆ (ssh_packet_get_connection_ಒಳ(ssh) != STDIN_FILENO &&
		    dup2(ssh_packet_get_connection_ಒಳ(ssh), STDIN_FILENO) == -1)
			fatal("dup2 stdin failed: %s", strerror(errno));
		ಆದರೆ (ssh_packet_get_connection_ಹೊರಹೋಗು(ssh) != STDOUT_FILENO &&
		    dup2(ssh_packet_get_connection_ಹೊರಹೋಗು(ssh),
		    STDOUT_FILENO) == -1)
			fatal("dup2 stdout failed: %s", strerror(errno));
		/* leave stderr as-is */
		log_redirect_stderr_ಗಮ್ಯ(ಖಾಲಿ); /* dup can clobber log fd */
		ಆದರೆ (pmonitor->m_recvfd != PRIVSEP_MONITOR_FD &&
		    dup2(pmonitor->m_recvfd, PRIVSEP_MONITOR_FD) == -1)
			fatal("dup2 monitor fd: %s", strerror(errno));
		ಆದರೆ (pmonitor->m_log_sendfd != PRIVSEP_LOG_FD &&
		    dup2(pmonitor->m_log_sendfd, PRIVSEP_LOG_FD) == -1)
			fatal("dup2 log fd: %s", strerror(errno));
		closefrom(PRIVSEP_MIN_FREE_FD);

		saved_argv[0] = options.sshd_auth_ಮಾರ್ಗ;
		execv(options.sshd_auth_ಮಾರ್ಗ, saved_argv);

		fatal_f("exec of %s failed: %s",
		    options.sshd_auth_ಮಾರ್ಗ, strerror(errno));
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
privsep_postauth(ರಚನೆ ssh *ssh, Authctxt *authctxt)
{
	/* New socket pair */
	monitor_reinit(pmonitor);

	pmonitor->m_pid = fork();
	ಆದರೆ (pmonitor->m_pid == -1)
		fatal("fork of unprivileged child failed");
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (pmonitor->m_pid != 0) {
		verbose("User child is on pid %ld", (ದೀರ್ಘ)pmonitor->m_pid);
		sshbuf_reset(loginmsg);
		monitor_clear_keystate(ssh, pmonitor);
		monitor_ಮಗು_postauth(ssh, pmonitor);

		/* NEVERREACHED */
		ನಿರ್ಗಮಿಸು(0);
	}

	/*ಮಗು*/

	close(pmonitor->m_sendfd);
	pmonitor->m_sendfd = -1;

	/* Demote the private keys to public keys. */
	demote_sensitive_ದತ್ತಾಂಶ();

	reseed_prngs();

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SKIP_PRIVDROP
	/* Drop privileges */
	do_setusercontext(authctxt->pw);
#ಆದರೆ_ಅಂತ್ಯ

	/* It is safe now to apply the key state */
	monitor_apply_keystate(ssh, pmonitor);

	/*
	 * Tell the packet layer that authentication was successful, since
	 * this information is not part of the key state.
	 */
	ssh_packet_ಗಣ_authenticated(ssh);
}

ಸ್ಥಿರ ರಚನೆ sshkey *
get_hostkey_by_type(ಪೂರ್ಣಾಂಕ type, ಪೂರ್ಣಾಂಕ nid, ಪೂರ್ಣಾಂಕ need_ಖಾಸಗಿ, ರಚನೆ ssh *ssh)
{
	u_int i;
	ರಚನೆ sshkey *ಕೀಲಿ;

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಆಯ್ಕೆ (type) {
		ಸ್ಥಿತಿ ಕೀಲಿ_RSA_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_MLDSA44_ED25519_CERT:
			ಕೀಲಿ = sensitive_ದತ್ತಾಂಶ.host_certificates[i];
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಕೀಲಿ = sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i];
			ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ && !need_ಖಾಸಗಿ)
				ಕೀಲಿ = sensitive_ದತ್ತಾಂಶ.host_pubkeys[i];
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ || ಕೀಲಿ->type != type)
			ಮುಂದುವರಿ;
		ಆಯ್ಕೆ (type) {
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK_CERT:
			ಆದರೆ (ಕೀಲಿ->ecdsa_nid != nid)
				ಮುಂದುವರಿ;
			/* FALLTHROUGH */
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಹಿಂತಿರುಗಿ need_ಖಾಸಗಿ ?
			    sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i] : ಕೀಲಿ;
		}
	}
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ರಚನೆ sshkey *
get_hostkey_ಬಹಿರಂಗ_by_type(ಪೂರ್ಣಾಂಕ type, ಪೂರ್ಣಾಂಕ nid, ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ get_hostkey_by_type(type, nid, 0, ssh);
}

ರಚನೆ sshkey *
get_hostkey_ಖಾಸಗಿ_by_type(ಪೂರ್ಣಾಂಕ type, ಪೂರ್ಣಾಂಕ nid, ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ get_hostkey_by_type(type, nid, 1, ssh);
}

ರಚನೆ sshkey *
get_hostkey_by_ಸೂಚ್ಯಂಕ(ಪೂರ್ಣಾಂಕ ind)
{
	ಆದರೆ (ind < 0 || (u_int)ind >= options.ಅಂಕೆ_host_ಕೀಲಿ_files)
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	ಹಿಂತಿರುಗಿ (sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[ind]);
}

ರಚನೆ sshkey *
get_hostkey_ಬಹಿರಂಗ_by_ಸೂಚ್ಯಂಕ(ಪೂರ್ಣಾಂಕ ind, ರಚನೆ ssh *ssh)
{
	ಆದರೆ (ind < 0 || (u_int)ind >= options.ಅಂಕೆ_host_ಕೀಲಿ_files)
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	ಹಿಂತಿರುಗಿ (sensitive_ದತ್ತಾಂಶ.host_pubkeys[ind]);
}

ಪೂರ್ಣಾಂಕ
get_hostkey_ಸೂಚ್ಯಂಕ(ರಚನೆ sshkey *ಕೀಲಿ, ಪೂರ್ಣಾಂಕ compare, ರಚನೆ ssh *ssh)
{
	u_int i;

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಆದರೆ (sshkey_is_cert(ಕೀಲಿ)) {
			ಆದರೆ (ಕೀಲಿ == sensitive_ದತ್ತಾಂಶ.host_certificates[i] ||
			    (compare && sensitive_ದತ್ತಾಂಶ.host_certificates[i] &&
			    sshkey_equal(ಕೀಲಿ,
			    sensitive_ದತ್ತಾಂಶ.host_certificates[i])))
				ಹಿಂತಿರುಗಿ (i);
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (ಕೀಲಿ == sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i] ||
			    (compare && sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i] &&
			    sshkey_equal(ಕೀಲಿ, sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i])))
				ಹಿಂತಿರುಗಿ (i);
			ಆದರೆ (ಕೀಲಿ == sensitive_ದತ್ತಾಂಶ.host_pubkeys[i] ||
			    (compare && sensitive_ದತ್ತಾಂಶ.host_pubkeys[i] &&
			    sshkey_equal(ಕೀಲಿ, sensitive_ದತ್ತಾಂಶ.host_pubkeys[i])))
				ಹಿಂತಿರುಗಿ (i);
		}
	}
	ಹಿಂತಿರುಗಿ (-1);
}

/* Inform the client of all hostkeys */
ಸ್ಥಿರ ಶೂನ್ಯ
notify_hostkeys(ರಚನೆ ssh *ssh)
{
	ರಚನೆ sshbuf *buf;
	ರಚನೆ sshkey *ಕೀಲಿ;
	u_int i, nkeys;
	ಪೂರ್ಣಾಂಕ r;
	ಅಕ್ಷರ *fp;

	/* Some clients cannot cope with the hostkeys message, skip those. */
	ಆದರೆ (ssh->compat & SSH_BUG_HOSTKEYS)
		ಹಿಂತಿರುಗಿ;

	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಗಾಗಿ (i = nkeys = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಕೀಲಿ = get_hostkey_ಬಹಿರಂಗ_by_ಸೂಚ್ಯಂಕ(i, ssh);
		ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ || ಕೀಲಿ->type == ಕೀಲಿ_UNSPEC ||
		    sshkey_is_cert(ಕೀಲಿ))
			ಮುಂದುವರಿ;
		fp = sshkey_fingerprint(ಕೀಲಿ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("key %d: %s %s", i, sshkey_ssh_name(ಕೀಲಿ), fp);
		ಬಿಡುಗಡೆ(fp);
		ಆದರೆ (nkeys == 0) {
			/*
			 * Start building the request when we find the
			 * first usable key.
			 */
			ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "hostkeys-00@openssh.com")) != 0 ||
			    (r = sshpkt_put_u8(ssh, 0)) != 0) /* want reply */
				sshpkt_fatal(ssh, r, "%s: start request", __func__);
		}
		/* Append the key to the request */
		sshbuf_reset(buf);
		ಆದರೆ ((r = sshkey_putb(ಕೀಲಿ, buf)) != 0)
			fatal_fr(r, "couldn't put hostkey %d", i);
		ಆದರೆ ((r = sshpkt_put_stringb(ssh, buf)) != 0)
			sshpkt_fatal(ssh, r, "%s: append key", __func__);
		nkeys++;
	}
	debug3_f("sent %u hostkeys", nkeys);
	ಆದರೆ (nkeys == 0)
		fatal_f("no hostkeys");
	ಆದರೆ ((r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send", __func__);
	sshbuf_free(buf);
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

ಸ್ಥಿರ ಶೂನ್ಯ
parse_hostkeys(ರಚನೆ sshbuf *hostkeys)
{
	ಪೂರ್ಣಾಂಕ r;
	u_int ಅಂಕೆ_ಕೀಲಿಗಳು = 0;
	ರಚನೆ sshkey *k;
	ರಚನೆ sshbuf *kbuf;
	ಸ್ಥಿರಾಂಕ u_char *cp;
	ಗಾತ್ರ_t len;

	ಆಗ (sshbuf_len(hostkeys) != 0) {
		ಆದರೆ (ಅಂಕೆ_ಕೀಲಿಗಳು > 2048)
			fatal_f("too many hostkeys");
		sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು = xrecallocarray(
		    sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು, ಅಂಕೆ_ಕೀಲಿಗಳು, ಅಂಕೆ_ಕೀಲಿಗಳು + 1,
		    ಗಾತ್ರ(*sensitive_ದತ್ತಾಂಶ.host_pubkeys));
		sensitive_ದತ್ತಾಂಶ.host_pubkeys = xrecallocarray(
		    sensitive_ದತ್ತಾಂಶ.host_pubkeys, ಅಂಕೆ_ಕೀಲಿಗಳು, ಅಂಕೆ_ಕೀಲಿಗಳು + 1,
		    ಗಾತ್ರ(*sensitive_ದತ್ತಾಂಶ.host_pubkeys));
		sensitive_ದತ್ತಾಂಶ.host_certificates = xrecallocarray(
		    sensitive_ದತ್ತಾಂಶ.host_certificates, ಅಂಕೆ_ಕೀಲಿಗಳು, ಅಂಕೆ_ಕೀಲಿಗಳು + 1,
		    ಗಾತ್ರ(*sensitive_ದತ್ತಾಂಶ.host_certificates));
		/* private key */
		k = ಖಾಲಿ;
		ಆದರೆ ((r = sshbuf_froms(hostkeys, &kbuf)) != 0)
			fatal_fr(r, "extract privkey");
		ಆದರೆ (sshbuf_len(kbuf) != 0 &&
		    (r = sshkey_ಖಾಸಗಿ_deserialize(kbuf, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[ಅಂಕೆ_ಕೀಲಿಗಳು] = k;
		sshbuf_free(kbuf);
		ಆದರೆ (k)
			debug2_f("privkey %u: %s", ಅಂಕೆ_ಕೀಲಿಗಳು, sshkey_ssh_name(k));
		/* public key */
		k = ಖಾಲಿ;
		ಆದರೆ ((r = sshbuf_get_string_ನೇರ(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ಆದರೆ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_ದತ್ತಾಂಶ.host_pubkeys[ಅಂಕೆ_ಕೀಲಿಗಳು] = k;
		ಆದರೆ (k)
			debug2_f("pubkey %u: %s", ಅಂಕೆ_ಕೀಲಿಗಳು, sshkey_ssh_name(k));
		/* certificate */
		k = ಖಾಲಿ;
		ಆದರೆ ((r = sshbuf_get_string_ನೇರ(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ಆದರೆ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_ದತ್ತಾಂಶ.host_certificates[ಅಂಕೆ_ಕೀಲಿಗಳು] = k;
		ಆದರೆ (k)
			debug2_f("cert %u: %s", ಅಂಕೆ_ಕೀಲಿಗಳು, sshkey_ssh_name(k));
		ಅಂಕೆ_ಕೀಲಿಗಳು++;
	}
	sensitive_ದತ್ತಾಂಶ.ಅಂಕೆ_hostkeys = ಅಂಕೆ_ಕೀಲಿಗಳು;
}

ಸ್ಥಿರ ಶೂನ್ಯ
recv_rexec_state(ಪೂರ್ಣಾಂಕ fd, ರಚನೆ sshbuf *conf, uint64_t *timing_secretp)
{
	ರಚನೆ sshbuf *m, *inc, *hostkeys;
	u_char *cp, ver;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ include_ಅಂಶ *ಅಂಶ;

	debug3_f("entering fd = %d", fd);

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ || (inc = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	/* receive config */
	ಆದರೆ (ssh_ಸಂದೇಶ_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	ಆದರೆ ((r = sshbuf_get_u8(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	ಆದರೆ (ver != 0)
		fatal_f("rexec version mismatch");
	ಆದರೆ ((r = sshbuf_get_string(m, &cp, &len)) != 0 || /* XXX _direct */
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_get_stringb(m, inc)) != 0)
		fatal_fr(r, "parse config");

	ಆದರೆ (conf != ಖಾಲಿ && (r = sshbuf_put(conf, cp, len)))
		fatal_fr(r, "sshbuf_put");

	ಆಗ (sshbuf_len(inc) != 0) {
		ಅಂಶ = xcalloc(1, ಗಾತ್ರ(*ಅಂಶ));
		ಆದರೆ ((ಅಂಶ->contents = sshbuf_new()) == ಖಾಲಿ)
			fatal_f("sshbuf_new failed");
		ಆದರೆ ((r = sshbuf_get_cstring(inc, &ಅಂಶ->selector, ಖಾಲಿ)) != 0 ||
		    (r = sshbuf_get_cstring(inc, &ಅಂಶ->filename, ಖಾಲಿ)) != 0 ||
		    (r = sshbuf_get_stringb(inc, ಅಂಶ->contents)) != 0)
			fatal_fr(r, "parse includes");
		TAILQ_INSERT_TAIL(&includes, ಅಂಶ, ನಮೂದು);
	}

	/* receive hostkeys */
	sshbuf_reset(m);
	ಆದರೆ (ssh_ಸಂದೇಶ_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	ಆದರೆ ((r = sshbuf_get_u8(m, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_froms(m, &hostkeys)) != 0)
		fatal_fr(r, "parse config");
	parse_hostkeys(hostkeys);

	ಬಿಡುಗಡೆ(cp);
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
ಸ್ಥಿರ ಶೂನ್ಯ
check_ip_options(ರಚನೆ ssh *ssh)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ IP_OPTIONS
	ಪೂರ್ಣಾಂಕ sock_ಒಳ = ssh_packet_get_connection_ಒಳ(ssh);
	ರಚನೆ sockaddr_storage from;
	u_char opts[200];
	socklen_t i, option_ಗಾತ್ರ = ಗಾತ್ರ(opts), fromlen = ಗಾತ್ರ(from);
	ಅಕ್ಷರ ಪಠ್ಯ[ಗಾತ್ರ(opts) * 3 + 1];

	memset(&from, 0, ಗಾತ್ರ(from));
	ಆದರೆ (getpeername(sock_ಒಳ, (ರಚನೆ sockaddr *)&from,
	    &fromlen) == -1)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (from.ss_family != AF_INET)
		ಹಿಂತಿರುಗಿ;
	/* XXX IPv6 options? */

	ಆದರೆ (getsockopt(sock_ಒಳ, IPPROTO_IP, IP_OPTIONS, opts,
	    &option_ಗಾತ್ರ) >= 0 && option_ಗಾತ್ರ != 0) {
		ಪಠ್ಯ[0] = '\0';
		ಗಾಗಿ (i = 0; i < option_ಗಾತ್ರ; i++)
			snprintf(ಪಠ್ಯ + i*3, ಗಾತ್ರ(ಪಠ್ಯ) - i*3,
			    " %2.2x", opts[i]);
		fatal("Connection from %.100s port %d with IP opts: %.800s",
		    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh), ಪಠ್ಯ);
	}
#ಆದರೆ_ಅಂತ್ಯ /* IP_OPTIONS */
}

/* Set the routing domain for this process */
ಸ್ಥಿರ ಶೂನ್ಯ
ಗಣ_process_rdomain(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
#ಆದರೆ defined(HAVE_SYS_ಗಣ_PROCESS_RDOMAIN)
	ಆದರೆ (name == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ; /* default */

	ಆದರೆ (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		ಆದರೆ ((name = ssh_packet_rdomain_ಒಳ(ssh)) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ;
	}
	/* NB. We don't pass 'ssh' to sys_set_process_rdomain() */
	ಹಿಂತಿರುಗಿ sys_ಗಣ_process_rdomain(name);
#ಅಥವಾಆದರೆ defined(__OpenBSD__)
	ಪೂರ್ಣಾಂಕ rtable, ortable = getrtable();
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr;

	ಆದರೆ (name == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ; /* default */

	ಆದರೆ (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		ಆದರೆ ((name = ssh_packet_rdomain_ಒಳ(ssh)) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ;
	}

	rtable = (ಪೂರ್ಣಾಂಕ)strtonum(name, 0, 255, &errstr);
	ಆದರೆ (errstr != ಖಾಲಿ) /* Shouldn't happen */
		fatal("Invalid routing domain \"%s\": %s", name, errstr);
	ಆದರೆ (rtable != ortable && setrtable(rtable) != 0)
		fatal("Unable to set routing domain %d: %s",
		    rtable, strerror(errno));
	debug_f("set routing domain %d (was %d)", rtable, ortable);
#ಇಲ್ಲದಿದ್ದರೆ /* defined(__OpenBSD__) */
	fatal("Unable to set routing domain: not supported in this platform");
#ಆದರೆ_ಅಂತ್ಯ
}

/*
 * Main program for the daemon.
 */
ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ ac, ಅಕ್ಷರ **av)
{
	ರಚನೆ ssh *ssh = ಖಾಲಿ;
	ಬಾಹ್ಯ ಅಕ್ಷರ *optarg;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ optind;
	ಪೂರ್ಣಾಂಕ devnull, r, opt, remote_ಪೋರ್ಟ್;
	ಪೂರ್ಣಾಂಕ sock_ಒಳ = -1, sock_ಹೊರಹೋಗು = -1, rexeced_flag = 0, have_ಕೀಲಿ = 0;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_ip, *rdomain;
	ಅಕ್ಷರ *ಸಾಲು, *laddr, *logfile = ಖಾಲಿ;
	u_int i;
	uint64_t ibytes, obytes;
	ಬಹುಲಕ_t new_umask;
	Authctxt *authctxt;
	ರಚನೆ connection_info *connection_info = ಖಾಲಿ;
	sigset_t sigmask;
	uint64_t timing_secret = 0;
	ರಚನೆ itimerval itv;

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ಖಾಲಿ);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SECUREWARE
	(ಶೂನ್ಯ)ಗಣ_auth_parameters(ac, av);
#ಆದರೆ_ಅಂತ್ಯ
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, ಗಾತ್ರ(*saved_argv));
	ಗಾಗಿ (i = 0; (ಪೂರ್ಣಾಂಕ)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ಖಾಲಿ;

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#ಆದರೆ_ಅಂತ್ಯ

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
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
			/* ignore */
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
			/* ignore */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'R':
			rexeced_flag = 1;
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
		ಸ್ಥಿತಿ 'T':
		ಸ್ಥಿತಿ 'G':
			fatal("test/dump modes not supported");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'C':
			connection_info = server_get_connection_info(ssh, 0, 0);
			ಆದರೆ (parse_server_ಹೊಂದಿಕೆ_testspec(connection_info,
			    optarg) == -1)
				ನಿರ್ಗಮಿಸು(1);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, ಖಾಲಿ);
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

	/* Check that there are no remaining arguments. */
	ಆದರೆ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		ನಿರ್ಗಮಿಸು(1);
	}

	ಆದರೆ (!rexeced_flag)
		fatal("sshd-session should not be executed directly");

	closefrom(REEXEC_MIN_FREE_FD);

	platform_pre_session_ಆರಂಭ();

	/* Reserve fds we'll need later for reexec things */
	ಆದರೆ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	ಆಗ (devnull < PRIVSEP_MIN_FREE_FD) {
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
		    "P", "sshd-session",
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

	/* Fetch our configuration */
	ಆದರೆ ((cfg = sshbuf_new()) == ಖಾಲಿ)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[rexeced]");
	recv_rexec_state(REEXEC_CONFIG_PASS_FD, cfg, &timing_secret);
	parse_server_config(&options, "rexec", cfg, &includes, ಖಾಲಿ, 1);
	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);
	options.timing_secret = timing_secret;

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	debug("sshd-session version %s, %s", SSH_ಆವೃತ್ತಿ, SSH_OPENSSL_ಆವೃತ್ತಿ);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	ಆದರೆ ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == ಖಾಲಿ) {
		ಆದರೆ (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} ಇಲ್ಲದಿದ್ದರೆ {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

	ಆದರೆ (!debug_flag && !inetd_flag) {
		ಆದರೆ ((startup_pipe = dup(REEXEC_CONFIG_PASS_FD)) == -1)
			fatal("internal error: no startup pipe");

		/*
		 * Signal parent that this child is at a point where
		 * they can go away if they have a SIGHUP pending.
		 */
		(ಶೂನ್ಯ)atomicio(vwrite, startup_pipe, "\0", 1);
	}
	/* close the fd, but keep the slot reserved */
	ಆದರೆ (dup2(devnull, REEXEC_CONFIG_PASS_FD) == -1)
		fatal("dup2 devnull->config fd: %s", strerror(errno));

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
	 * daemonisation in the presence of Match block, but this catches
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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಆದರೆ (options.moduli_file != ಖಾಲಿ)
		dh_ಗಣ_moduli_file(options.moduli_file);
#ಆದರೆ_ಅಂತ್ಯ

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

	ಆದರೆ (options.ಅಂಕೆ_host_ಕೀಲಿ_files != sensitive_ದತ್ತಾಂಶ.ಅಂಕೆ_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.ಅಂಕೆ_host_ಕೀಲಿ_files, sensitive_ದತ್ತಾಂಶ.ಅಂಕೆ_hostkeys);
	}

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಆದರೆ (sensitive_ದತ್ತಾಂಶ.host_ಕೀಲಿಗಳು[i] != ಖಾಲಿ ||
		    (have_agent && sensitive_ದತ್ತಾಂಶ.host_pubkeys[i] != ಖಾಲಿ)) {
			have_ಕೀಲಿ = 1;
			ನಿಲ್ಲಿಸು;
		}
	}
	ಆದರೆ (!have_ಕೀಲಿ)
		fatal("internal error: monitor received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(ಶೂನ್ಯ) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	ಆದರೆ (debug_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_log_verbose; i++)
		log_verbose_ಕೂಡಿಸು(options.log_verbose[i]);

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

	/* Get a connection, either from inetd or rexec */
	ಆದರೆ (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_ಒಳ = dup(STDIN_FILENO);
		sock_ಹೊರಹೋಗು = dup(STDOUT_FILENO);
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_ಒಳ = sock_ಹೊರಹೋಗು = dup(STDIN_FILENO);
	}

	/*
	 * We intentionally do not close the descriptors 0, 1, and 2
	 * as our code for setting the descriptors won't work if
	 * ttyfd happens to be one of those.
	 */
	ಆದರೆ (stdfd_devnull(1, 1, !log_stderr) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_ಒಳ, sock_ಹೊರಹೋಗು);

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_ಹೊರಹೋಗು);
	FD_CLOSEONEXEC(sock_ಒಳ);

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
	ಆದರೆ ((ssh = ssh_packet_ಗಣ_connection(ಖಾಲಿ, sock_ಒಳ, sock_ಹೊರಹೋಗು)) == ಖಾಲಿ)
		fatal("Unable to create connection");
	the_ಸಕ್ರಿಯ_state = ssh;
	ssh_packet_ಗಣ_server(ssh);
	ssh_packet_ಗಣ_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	check_ip_options(ssh);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_ಗಣ_af(ssh, options.ವಿಳಾಸ_family);
	channel_ಗಣ_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);

	/* Set SO_KEEPALIVE if requested. */
	ಆದರೆ (options.tcp_keep_alive && ssh_packet_connection_is_on_socket(ssh))
		ಗಣ_keepalive(sock_ಒಳ); /* logs errors */

	ಆದರೆ ((remote_ಪೋರ್ಟ್ = ssh_remote_ಪೋರ್ಟ್(ssh)) < 0) {
		debug("ssh_remote_port failed");
		cleanup_exit(255);
	}

	/*
	 * The rest of the code depends on the fact that
	 * ssh_remote_ipaddr() caches the remote ip, even if
	 * the socket goes away.
	 */
	remote_ip = ssh_remote_ipaddr(ssh);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_AUDIT_EVENTS
	audit_connection_from(remote_ip, remote_ಪೋರ್ಟ್);
#ಆದರೆ_ಅಂತ್ಯ

	rdomain = ssh_packet_rdomain_ಒಳ(ssh);

	/* Log the connection. */
	laddr = get_local_ipaddr(sock_ಒಳ);
	verbose("Connection from %s port %d on %s port %d%s%s%s",
	    remote_ip, remote_ಪೋರ್ಟ್, laddr,  ssh_local_ಪೋರ್ಟ್(ssh),
	    rdomain == ಖಾಲಿ ? "" : " rdomain \"",
	    rdomain == ಖಾಲಿ ? "" : rdomain,
	    rdomain == ಖಾಲಿ ? "" : "\"");
	ಬಿಡುಗಡೆ(laddr);

	/*
	 * We don't want to listen forever unless the other side
	 * successfully authenticates itself.  So we set up an alarm which is
	 * cleared after successful authentication.  A limit of zero
	 * indicates no limit. Note that we don't set the alarm in debugging
	 * mode; it is just annoying to have the server exit just when you
	 * are about to discover the bug.
	 */
	ssh_signal(SIGALRM, grace_alarm_handler);
	ಆದರೆ (!debug_flag && options.login_grace_ಸಮಯ > 0) {
		ಪೂರ್ಣಾಂಕ ujitter = arc4random_ಏಕರೂಪ(4 * 1000000);

		timerclear(&itv.it_interval);
		itv.it_value.tv_sec = options.login_grace_ಸಮಯ;
		itv.it_value.tv_sec += ujitter / 1000000;
		itv.it_value.tv_usec = ujitter % 1000000; 

		ಆದರೆ (setitimer(ITIMER_REAL, &itv, ಖಾಲಿ) == -1)
			fatal("login grace time setitimer failed");
	}

	ssh_packet_ಗಣ_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, ಗಾತ್ರ(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	ಆದರೆ ((auth_opts = sshauthopt_new_with_ಕೀಲಿಗಳು_defaults()) == ಖಾಲಿ)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	ಆದರೆ ((loginmsg = sshbuf_new()) == ಖಾಲಿ)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

	ಆದರೆ (privsep_preauth(ssh) != 1)
		fatal("privsep_preauth failed");

	/* Now user is authenticated */

	setproctitle("%s [postauth]", authctxt->user);

	/*
	 * Cancel the alarm we set to limit the time taken for
	 * authentication.
	 */
	timerclear(&itv.it_interval);
	timerclear(&itv.it_value);
	ಆದರೆ (setitimer(ITIMER_REAL, &itv, ಖಾಲಿ) == -1)
		fatal("login grace time clear failed");
	ssh_signal(SIGALRM, SIG_DFL);
	authctxt->authenticated = 1;
	ಆದರೆ (startup_pipe != -1) {
		/* signal listener that authentication completed successfully */
		(ಶೂನ್ಯ)atomicio(vwrite, startup_pipe, "\001", 1);
		close(startup_pipe);
		startup_pipe = -1;
	}

	ಆದರೆ (options.routing_domain != ಖಾಲಿ)
		ಗಣ_process_rdomain(ssh, options.routing_domain);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_AUDIT_EVENTS
	audit_event(ssh, SSH_AUTH_SUCCESS);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
	ಆದರೆ (options.gss_authentication) {
		temporarily_use_uid(authctxt->pw);
		ssh_gssapi_storecreds();
		restore_uid();
	}
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	ಆದರೆ (options.use_pam) {
		do_pam_setcred();
		do_pam_session(ssh);
	}
#ಆದರೆ_ಅಂತ್ಯ

	/*
	 * In privilege separation, we fork another child and prepare
	 * file descriptor passing.
	 */
	privsep_postauth(ssh, authctxt);
	/* the monitor process [priv] will not return */

	ssh_packet_ಗಣ_timeout(ssh, options.client_alive_interval,
	    options.client_alive_ಎಣಿಕೆ_max);

	/* Try to send all our hostkeys to the client */
	notify_hostkeys(ssh);

	/* Start session. */
	do_authenticated(ssh, authctxt);

	/* The connection has been terminated. */
	ssh_packet_get_ಬೈಟುಗಳು(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes",
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)obytes, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ibytes);

	verbose("Closing connection to %.500s port %d", remote_ip, remote_ಪೋರ್ಟ್);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	ಆದರೆ (options.use_pam)
		ಮುಕ್ತಾಯ_pam();
#ಆದರೆ_ಅಂತ್ಯ /* USE_PAM */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_AUDIT_EVENTS
	mm_audit_event(ssh, SSH_CONNECTION_CLOSE);
#ಆದರೆ_ಅಂತ್ಯ

	ssh_packet_close(ssh);

	mm_terminate();

	ನಿರ್ಗಮಿಸು(0);
}

ಪೂರ್ಣಾಂಕ
sshd_hostkey_sign(ರಚನೆ ssh *ssh, ರಚನೆ sshkey *privkey,
    ರಚನೆ sshkey *pubkey, u_char **signature, ಗಾತ್ರ_t *slenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t dlen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg)
{
	ಆದರೆ (privkey) {
		ಆದರೆ (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    ದತ್ತಾಂಶ, dlen, alg, options.sk_provider, ಖಾಲಿ,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    ದತ್ತಾಂಶ, dlen, alg, options.sk_provider, ಖಾಲಿ,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* server specific fatal cleanup */
ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಂಕ i)
{
	ಆದರೆ (the_ಸಕ್ರಿಯ_state != ಖಾಲಿ && the_authctxt != ಖಾಲಿ) {
		do_cleanup(the_ಸಕ್ರಿಯ_state, the_authctxt);
		ಆದರೆ (privsep_is_preauth &&
		    pmonitor != ಖಾಲಿ && pmonitor->m_pid > 1) {
			debug("Killing privsep child %d", pmonitor->m_pid);
			ಆದರೆ (kill(pmonitor->m_pid, SIGKILL) != 0 &&
			    errno != ESRCH) {
				error_f("kill(%d): %s", pmonitor->m_pid,
				    strerror(errno));
			}
		}
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_AUDIT_EVENTS
	/* done after do_cleanup so it can cancel the PAM auth 'thread' */
	ಆದರೆ (the_ಸಕ್ರಿಯ_state != ಖಾಲಿ && mm_is_monitor())
		audit_event(the_ಸಕ್ರಿಯ_state, SSH_CONNECTION_ABANDON);
#ಆದರೆ_ಅಂತ್ಯ
	/* Override default fatal exit value when auth was attempted */
	ಆದರೆ (i == 255 && monitor_auth_attempted())
		_exit(EXIT_AUTH_ATTEMPTED);
	ಆದರೆ (i == 255 && monitor_invalid_user())
		_exit(EXIT_INVALID_USER);
	_exit(i);
}
