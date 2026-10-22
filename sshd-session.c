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

#ifdef HAVE_SECUREWARE
#ಅನ್ತರ್ಭಾವ <sys/security.h>
#ಅನ್ತರ್ಭಾವ <prot.h>
#endif
 
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
#ifdef GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#endif
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ಅನ್ತರ್ಭಾವ "version.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sk-api.h"
#ಅನ್ತರ್ಭಾವ "srclimit.h"
#ಅನ್ತರ್ಭಾವ "dh.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

/* Privsep fds */
#define PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#define PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#define PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

ಬಾಹ್ಯ ವರ್ಣ *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
ವರ್ಣ *config_file_name = _PATH_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
ಪೂರ್ಣಾಙ್ಕ debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ inetd_flag = 0;

/* debug goes to stderr unless inetd_flag is set */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ log_stderr = 0;

/* Saved arguments to main(). */
ಸ್ಥಿರ ವರ್ಣ **saved_argv;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ saved_argc;

/* Daemon's agent connection */
ಪೂರ್ಣಾಙ್ಕ auth_sock = -1;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ have_agent = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
ಸಂರಚನಾ {
	u_int		ಅಂಕೆ_hostkeys;
	ಸಂರಚನಾ sshkey	**host_ಕೀಲಿಗಳು;		/* all private host keys */
	ಸಂರಚನಾ sshkey	**host_pubkeys;		/* all public host keys */
	ಸಂರಚನಾ sshkey	**host_certificates;	/* all public host certificates */
} sensitive_data;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ startup_pipe = -1;		/* in child */

/* variables used for privilege separation */
ಸಂರಚನಾ monitor *pmonitor = ರಿಕ್ತ;
ಪೂರ್ಣಾಙ್ಕ privsep_is_preauth = 1;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ privsep_chroot = 1;

/* Unprivileged user */
ಸಂರಚನಾ passwd *privsep_pw = ರಿಕ್ತ;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = ರಿಕ್ತ;
ಸಂರಚನಾ ssh *the_active_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
ಸಂರಚನಾ sshauthopt *auth_opts = ರಿಕ್ತ;

/* sshd_config buffer */
ಸಂರಚನಾ sshbuf *cfg;

/* Included files from the configuration file */
ಸಂರಚನಾ include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ಸಂರಚನಾ sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
ಶೂನ್ಯ destroy_sensitive_data(ಶೂನ್ಯ);
ಶೂನ್ಯ demote_sensitive_data(ಶೂನ್ಯ);

/* XXX reduce to stub once postauth split */
ಪೂರ್ಣಾಙ್ಕ
mm_is_monitor(ಶೂನ್ಯ)
{
	/*
	 * m_pid is only set in the privileged part, and
	 * points to the unprivileged child.
	 */
	ಪ್ರತ್ಯಾಗಮ (pmonitor && pmonitor->m_pid > 0);
}

/*
 * Signal handler for the alarm after the login grace period has expired.
 * As usual, this may only take signal-safe actions, even though it is
 * terminal.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
grace_alarm_handler(ಪೂರ್ಣಾಙ್ಕ sig)
{
	/*
	 * Try to kill any processes that we have spawned, E.g. authorized
	 * keys command helpers or privsep children.
	 */
	ಯದಿ (getpgid(0) == getpid()) {
		ಸಂರಚನಾ sigaction sa;

		/* mask all other signals while in handler */
		memset(&sa, 0, ಪರಿಮಾಣ(sa));
		sa.sa_handler = SIG_IGN;
		sigfillset(&sa.sa_mask);
#ಯದಿ defined(SA_RESTART)
		sa.sa_flags = SA_RESTART;
#endif
		(ಶೂನ್ಯ)sigaction(SIGTERM, &sa, ರಿಕ್ತ);
		kill(0, SIGTERM);
	}
	_exit(EXIT_LOGIN_GRACE);
}

/* Destroy the host and server keys.  They will no longer be needed. */
ಶೂನ್ಯ
destroy_sensitive_data(ಶೂನ್ಯ)
{
	u_int i;

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಯದಿ (sensitive_data.host_ಕೀಲಿಗಳು[i]) {
			sshkey_free(sensitive_data.host_ಕೀಲಿಗಳು[i]);
			sensitive_data.host_ಕೀಲಿಗಳು[i] = ರಿಕ್ತ;
		}
		ಯದಿ (sensitive_data.host_certificates[i]) {
			sshkey_free(sensitive_data.host_certificates[i]);
			sensitive_data.host_certificates[i] = ರಿಕ್ತ;
		}
	}
}

/* Demote private to public keys for network child */
ಶೂನ್ಯ
demote_sensitive_data(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshkey *tmp;
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಯದಿ (sensitive_data.host_ಕೀಲಿಗಳು[i]) {
			ಯದಿ ((r = sshkey_from_private(
			    sensitive_data.host_ಕೀಲಿಗಳು[i], &tmp)) != 0)
				fatal_r(r, "could not demote host %s key",
				    sshkey_type(sensitive_data.host_ಕೀಲಿಗಳು[i]));
			sshkey_free(sensitive_data.host_ಕೀಲಿಗಳು[i]);
			sensitive_data.host_ಕೀಲಿಗಳು[i] = tmp;
		}
		/* Certs do not need demotion */
	}
}

ಸಂರಚನಾ sshbuf *
pack_hostkeys(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *keybuf = ರಿಕ್ತ, *hostkeys = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i;

	ಯದಿ ((hostkeys = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
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

	sshbuf_free(keybuf);
	ಪ್ರತ್ಯಾಗಮ hostkeys;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
privsep_preauth(ಸಂರಚನಾ ssh *ssh)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	pid_t pid;

	/* Set up unprivileged child process to deal with network data */
	pmonitor = monitor_init();
	/* Store a pointer to the kex for later rekeying */
	pmonitor->m_pkex = &ssh->kex;

	ಯದಿ ((pid = fork()) == -1)
		fatal("fork of unprivileged child failed");
	ಅನ್ಯಥಾ ಯದಿ (pid != 0) {
		debug2("Network child is on pid %ld", (long)pid);

		pmonitor->m_pid = pid;
		ಯದಿ (have_agent) {
			r = ssh_get_authentication_socket(&auth_sock);
			ಯದಿ (r != 0) {
				error_r(r, "Could not get agent socket");
				have_agent = 0;
			}
		}
		monitor_child_preauth(ssh, pmonitor);
		privsep_is_preauth = 0;
		ಪ್ರತ್ಯಾಗಮ 1;
	} ಅನ್ಯಥಾ {
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

		ಯದಿ (ssh_packet_get_connection_in(ssh) != STDIN_FILENO &&
		    dup2(ssh_packet_get_connection_in(ssh), STDIN_FILENO) == -1)
			fatal("dup2 stdin failed: %s", strerror(errno));
		ಯದಿ (ssh_packet_get_connection_out(ssh) != STDOUT_FILENO &&
		    dup2(ssh_packet_get_connection_out(ssh),
		    STDOUT_FILENO) == -1)
			fatal("dup2 stdout failed: %s", strerror(errno));
		/* leave stderr as-is */
		log_redirect_stderr_to(ರಿಕ್ತ); /* dup can clobber log fd */
		ಯದಿ (pmonitor->m_recvfd != PRIVSEP_MONITOR_FD &&
		    dup2(pmonitor->m_recvfd, PRIVSEP_MONITOR_FD) == -1)
			fatal("dup2 monitor fd: %s", strerror(errno));
		ಯದಿ (pmonitor->m_log_sendfd != PRIVSEP_LOG_FD &&
		    dup2(pmonitor->m_log_sendfd, PRIVSEP_LOG_FD) == -1)
			fatal("dup2 log fd: %s", strerror(errno));
		closefrom(PRIVSEP_MIN_FREE_FD);

		saved_argv[0] = options.sshd_auth_path;
		execv(options.sshd_auth_path, saved_argv);

		fatal_f("exec of %s failed: %s",
		    options.sshd_auth_path, strerror(errno));
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
privsep_postauth(ಸಂರಚನಾ ssh *ssh, Authctxt *authctxt)
{
	/* New socket pair */
	monitor_reinit(pmonitor);

	pmonitor->m_pid = fork();
	ಯದಿ (pmonitor->m_pid == -1)
		fatal("fork of unprivileged child failed");
	ಅನ್ಯಥಾ ಯದಿ (pmonitor->m_pid != 0) {
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

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
get_hostkey_by_type(ಪೂರ್ಣಾಙ್ಕ type, ಪೂರ್ಣಾಙ್ಕ nid, ಪೂರ್ಣಾಙ್ಕ need_private, ಸಂರಚನಾ ssh *ssh)
{
	u_int i;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ;

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ವಿಕಲ್ಪ (type) {
		ಪಕ್ಷ ಕೀಲಿ_RSA_CERT:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_CERT:
		ಪಕ್ಷ ಕೀಲಿ_ED25519_CERT:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK_CERT:
		ಪಕ್ಷ ಕೀಲಿ_ED25519_SK_CERT:
		ಪಕ್ಷ ಕೀಲಿ_MLDSA44_ED25519_CERT:
			ಕೀಲಿ = sensitive_data.host_certificates[i];
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			ಕೀಲಿ = sensitive_data.host_ಕೀಲಿಗಳು[i];
			ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ && !need_private)
				ಕೀಲಿ = sensitive_data.host_pubkeys[i];
			ಭಙ್ಗ;
		}
		ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ || ಕೀಲಿ->type != type)
			ಅನುವರ್ತ;
		ವಿಕಲ್ಪ (type) {
		ಪಕ್ಷ ಕೀಲಿ_ECDSA:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_CERT:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK_CERT:
			ಯದಿ (ಕೀಲಿ->ecdsa_nid != nid)
				ಅನುವರ್ತ;
			/* FALLTHROUGH */
		ಸ್ವಭಾವ:
			ಪ್ರತ್ಯಾಗಮ need_private ?
			    sensitive_data.host_ಕೀಲಿಗಳು[i] : ಕೀಲಿ;
		}
	}
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸಂರಚನಾ sshkey *
get_hostkey_public_by_type(ಪೂರ್ಣಾಙ್ಕ type, ಪೂರ್ಣಾಙ್ಕ nid, ಸಂರಚನಾ ssh *ssh)
{
	ಪ್ರತ್ಯಾಗಮ get_hostkey_by_type(type, nid, 0, ssh);
}

ಸಂರಚನಾ sshkey *
get_hostkey_private_by_type(ಪೂರ್ಣಾಙ್ಕ type, ಪೂರ್ಣಾಙ್ಕ nid, ಸಂರಚನಾ ssh *ssh)
{
	ಪ್ರತ್ಯಾಗಮ get_hostkey_by_type(type, nid, 1, ssh);
}

ಸಂರಚನಾ sshkey *
get_hostkey_by_index(ಪೂರ್ಣಾಙ್ಕ ind)
{
	ಯದಿ (ind < 0 || (u_int)ind >= options.ಅಂಕೆ_host_ಕೀಲಿ_files)
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	ಪ್ರತ್ಯಾಗಮ (sensitive_data.host_ಕೀಲಿಗಳು[ind]);
}

ಸಂರಚನಾ sshkey *
get_hostkey_public_by_index(ಪೂರ್ಣಾಙ್ಕ ind, ಸಂರಚನಾ ssh *ssh)
{
	ಯದಿ (ind < 0 || (u_int)ind >= options.ಅಂಕೆ_host_ಕೀಲಿ_files)
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	ಪ್ರತ್ಯಾಗಮ (sensitive_data.host_pubkeys[ind]);
}

ಪೂರ್ಣಾಙ್ಕ
get_hostkey_index(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಪೂರ್ಣಾಙ್ಕ compare, ಸಂರಚನಾ ssh *ssh)
{
	u_int i;

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಯದಿ (sshkey_is_cert(ಕೀಲಿ)) {
			ಯದಿ (ಕೀಲಿ == sensitive_data.host_certificates[i] ||
			    (compare && sensitive_data.host_certificates[i] &&
			    sshkey_equal(ಕೀಲಿ,
			    sensitive_data.host_certificates[i])))
				ಪ್ರತ್ಯಾಗಮ (i);
		} ಅನ್ಯಥಾ {
			ಯದಿ (ಕೀಲಿ == sensitive_data.host_ಕೀಲಿಗಳು[i] ||
			    (compare && sensitive_data.host_ಕೀಲಿಗಳು[i] &&
			    sshkey_equal(ಕೀಲಿ, sensitive_data.host_ಕೀಲಿಗಳು[i])))
				ಪ್ರತ್ಯಾಗಮ (i);
			ಯದಿ (ಕೀಲಿ == sensitive_data.host_pubkeys[i] ||
			    (compare && sensitive_data.host_pubkeys[i] &&
			    sshkey_equal(ಕೀಲಿ, sensitive_data.host_pubkeys[i])))
				ಪ್ರತ್ಯಾಗಮ (i);
		}
	}
	ಪ್ರತ್ಯಾಗಮ (-1);
}

/* Inform the client of all hostkeys */
ಸ್ಥಿರ ಶೂನ್ಯ
notify_hostkeys(ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ sshbuf *buf;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ;
	u_int i, nkeys;
	ಪೂರ್ಣಾಙ್ಕ r;
	ವರ್ಣ *fp;

	/* Some clients cannot cope with the hostkeys message, skip those. */
	ಯದಿ (ssh->compat & SSH_BUG_HOSTKEYS)
		ಪ್ರತ್ಯಾಗಮ;

	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಪ್ರತಿ (i = nkeys = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಕೀಲಿ = get_hostkey_public_by_index(i, ssh);
		ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ || ಕೀಲಿ->type == ಕೀಲಿ_UNSPEC ||
		    sshkey_is_cert(ಕೀಲಿ))
			ಅನುವರ್ತ;
		fp = sshkey_fingerprint(ಕೀಲಿ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("key %d: %s %s", i, sshkey_ssh_name(ಕೀಲಿ), fp);
		ಮುಕ್ತ(fp);
		ಯದಿ (nkeys == 0) {
			/*
			 * Start building the request when we find the
			 * first usable key.
			 */
			ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "hostkeys-00@openssh.com")) != 0 ||
			    (r = sshpkt_put_u8(ssh, 0)) != 0) /* want reply */
				sshpkt_fatal(ssh, r, "%s: start request", __func__);
		}
		/* Append the key to the request */
		sshbuf_reset(buf);
		ಯದಿ ((r = sshkey_putb(ಕೀಲಿ, buf)) != 0)
			fatal_fr(r, "couldn't put hostkey %d", i);
		ಯದಿ ((r = sshpkt_put_stringb(ssh, buf)) != 0)
			sshpkt_fatal(ssh, r, "%s: append key", __func__);
		nkeys++;
	}
	debug3_f("sent %u hostkeys", nkeys);
	ಯದಿ (nkeys == 0)
		fatal_f("no hostkeys");
	ಯದಿ ((r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send", __func__);
	sshbuf_free(buf);
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

ಸ್ಥಿರ ಶೂನ್ಯ
parse_hostkeys(ಸಂರಚನಾ sshbuf *hostkeys)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int ಅಂಕೆ_ಕೀಲಿಗಳು = 0;
	ಸಂರಚನಾ sshkey *k;
	ಸಂರಚನಾ sshbuf *kbuf;
	ಧ್ರುವ u_char *cp;
	size_t len;

	ಯಾವತ್ (sshbuf_len(hostkeys) != 0) {
		ಯದಿ (ಅಂಕೆ_ಕೀಲಿಗಳು > 2048)
			fatal_f("too many hostkeys");
		sensitive_data.host_ಕೀಲಿಗಳು = xrecallocarray(
		    sensitive_data.host_ಕೀಲಿಗಳು, ಅಂಕೆ_ಕೀಲಿಗಳು, ಅಂಕೆ_ಕೀಲಿಗಳು + 1,
		    ಪರಿಮಾಣ(*sensitive_data.host_pubkeys));
		sensitive_data.host_pubkeys = xrecallocarray(
		    sensitive_data.host_pubkeys, ಅಂಕೆ_ಕೀಲಿಗಳು, ಅಂಕೆ_ಕೀಲಿಗಳು + 1,
		    ಪರಿಮಾಣ(*sensitive_data.host_pubkeys));
		sensitive_data.host_certificates = xrecallocarray(
		    sensitive_data.host_certificates, ಅಂಕೆ_ಕೀಲಿಗಳು, ಅಂಕೆ_ಕೀಲಿಗಳು + 1,
		    ಪರಿಮಾಣ(*sensitive_data.host_certificates));
		/* private key */
		k = ರಿಕ್ತ;
		ಯದಿ ((r = sshbuf_froms(hostkeys, &kbuf)) != 0)
			fatal_fr(r, "extract privkey");
		ಯದಿ (sshbuf_len(kbuf) != 0 &&
		    (r = sshkey_private_deserialize(kbuf, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_ಕೀಲಿಗಳು[ಅಂಕೆ_ಕೀಲಿಗಳು] = k;
		sshbuf_free(kbuf);
		ಯದಿ (k)
			debug2_f("privkey %u: %s", ಅಂಕೆ_ಕೀಲಿಗಳು, sshkey_ssh_name(k));
		/* public key */
		k = ರಿಕ್ತ;
		ಯದಿ ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ಯದಿ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_pubkeys[ಅಂಕೆ_ಕೀಲಿಗಳು] = k;
		ಯದಿ (k)
			debug2_f("pubkey %u: %s", ಅಂಕೆ_ಕೀಲಿಗಳು, sshkey_ssh_name(k));
		/* certificate */
		k = ರಿಕ್ತ;
		ಯದಿ ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ಯದಿ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_certificates[ಅಂಕೆ_ಕೀಲಿಗಳು] = k;
		ಯದಿ (k)
			debug2_f("cert %u: %s", ಅಂಕೆ_ಕೀಲಿಗಳು, sshkey_ssh_name(k));
		ಅಂಕೆ_ಕೀಲಿಗಳು++;
	}
	sensitive_data.ಅಂಕೆ_hostkeys = ಅಂಕೆ_ಕೀಲಿಗಳು;
}

ಸ್ಥಿರ ಶೂನ್ಯ
recv_rexec_state(ಪೂರ್ಣಾಙ್ಕ fd, ಸಂರಚನಾ sshbuf *conf, uint64_t *timing_secretp)
{
	ಸಂರಚನಾ sshbuf *m, *inc, *hostkeys;
	u_char *cp, ver;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ include_item *item;

	debug3_f("entering fd = %d", fd);

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ || (inc = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	/* receive config */
	ಯದಿ (ssh_ಸಂದೇಶ_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	ಯದಿ ((r = sshbuf_get_u8(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	ಯದಿ (ver != 0)
		fatal_f("rexec version mismatch");
	ಯದಿ ((r = sshbuf_get_string(m, &cp, &len)) != 0 || /* XXX _direct */
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_get_stringb(m, inc)) != 0)
		fatal_fr(r, "parse config");

	ಯದಿ (conf != ರಿಕ್ತ && (r = sshbuf_put(conf, cp, len)))
		fatal_fr(r, "sshbuf_put");

	ಯಾವತ್ (sshbuf_len(inc) != 0) {
		item = xcalloc(1, ಪರಿಮಾಣ(*item));
		ಯದಿ ((item->contents = sshbuf_new()) == ರಿಕ್ತ)
			fatal_f("sshbuf_new failed");
		ಯದಿ ((r = sshbuf_get_cstring(inc, &item->selector, ರಿಕ್ತ)) != 0 ||
		    (r = sshbuf_get_cstring(inc, &item->filename, ರಿಕ್ತ)) != 0 ||
		    (r = sshbuf_get_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "parse includes");
		TAILQ_INSERT_TAIL(&includes, item, entry);
	}

	/* receive hostkeys */
	sshbuf_reset(m);
	ಯದಿ (ssh_ಸಂದೇಶ_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	ಯದಿ ((r = sshbuf_get_u8(m, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_froms(m, &hostkeys)) != 0)
		fatal_fr(r, "parse config");
	parse_hostkeys(hostkeys);

	ಮುಕ್ತ(cp);
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
check_ip_options(ಸಂರಚನಾ ssh *ssh)
{
#ifdef IP_OPTIONS
	ಪೂರ್ಣಾಙ್ಕ sock_in = ssh_packet_get_connection_in(ssh);
	ಸಂರಚನಾ sockaddr_storage from;
	u_char opts[200];
	socklen_t i, option_size = ಪರಿಮಾಣ(opts), fromlen = ಪರಿಮಾಣ(from);
	ವರ್ಣ text[ಪರಿಮಾಣ(opts) * 3 + 1];

	memset(&from, 0, ಪರಿಮಾಣ(from));
	ಯದಿ (getpeername(sock_in, (ಸಂರಚನಾ sockaddr *)&from,
	    &fromlen) == -1)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (from.ss_family != AF_INET)
		ಪ್ರತ್ಯಾಗಮ;
	/* XXX IPv6 options? */

	ಯದಿ (getsockopt(sock_in, IPPROTO_IP, IP_OPTIONS, opts,
	    &option_size) >= 0 && option_size != 0) {
		text[0] = '\0';
		ಪ್ರತಿ (i = 0; i < option_size; i++)
			snprintf(text + i*3, ಪರಿಮಾಣ(text) - i*3,
			    " %2.2x", opts[i]);
		fatal("Connection from %.100s port %d with IP opts: %.800s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), text);
	}
#endif /* IP_OPTIONS */
}

/* Set the routing domain for this process */
ಸ್ಥಿರ ಶೂನ್ಯ
set_process_rdomain(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *name)
{
#ಯದಿ defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
	ಯದಿ (name == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ; /* default */

	ಯದಿ (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		ಯದಿ ((name = ssh_packet_rdomain_in(ssh)) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ;
	}
	/* NB. We don't pass 'ssh' to sys_set_process_rdomain() */
	ಪ್ರತ್ಯಾಗಮ sys_set_process_rdomain(name);
#ನೋಚೇದ್ಯದಿ defined(__OpenBSD__)
	ಪೂರ್ಣಾಙ್ಕ rtable, ortable = getrtable();
	ಧ್ರುವ ವರ್ಣ *errstr;

	ಯದಿ (name == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ; /* default */

	ಯದಿ (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		ಯದಿ ((name = ssh_packet_rdomain_in(ssh)) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ;
	}

	rtable = (ಪೂರ್ಣಾಙ್ಕ)strtonum(name, 0, 255, &errstr);
	ಯದಿ (errstr != ರಿಕ್ತ) /* Shouldn't happen */
		fatal("Invalid routing domain \"%s\": %s", name, errstr);
	ಯದಿ (rtable != ortable && setrtable(rtable) != 0)
		fatal("Unable to set routing domain %d: %s",
		    rtable, strerror(errno));
	debug_f("set routing domain %d (was %d)", rtable, ortable);
#ಅನ್ಯಥಾ /* defined(__OpenBSD__) */
	fatal("Unable to set routing domain: not supported in this platform");
#endif
}

/*
 * Main program for the daemon.
 */
ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ ac, ವರ್ಣ **av)
{
	ಸಂರಚನಾ ssh *ssh = ರಿಕ್ತ;
	ಬಾಹ್ಯ ವರ್ಣ *optarg;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ optind;
	ಪೂರ್ಣಾಙ್ಕ devnull, r, opt, remote_port;
	ಪೂರ್ಣಾಙ್ಕ sock_in = -1, sock_out = -1, rexeced_flag = 0, have_ಕೀಲಿ = 0;
	ಧ್ರುವ ವರ್ಣ *remote_ip, *rdomain;
	ವರ್ಣ *ಸಾಲು, *laddr, *logfile = ರಿಕ್ತ;
	u_int i;
	uint64_t ibytes, obytes;
	mode_t new_umask;
	Authctxt *authctxt;
	ಸಂರಚನಾ connection_info *connection_info = ರಿಕ್ತ;
	sigset_t sigmask;
	uint64_t timing_secret = 0;
	ಸಂರಚನಾ itimerval itv;

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ರಿಕ್ತ);

#ifdef HAVE_SECUREWARE
	(ಶೂನ್ಯ)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, ಪರಿಮಾಣ(*saved_argv));
	ಪ್ರತಿ (i = 0; (ಪೂರ್ಣಾಙ್ಕ)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ರಿಕ್ತ;

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
			/* ignore */
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
			/* ignore */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'R':
			rexeced_flag = 1;
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
		ಪಕ್ಷ 'T':
		ಪಕ್ಷ 'G':
			fatal("test/dump modes not supported");
			ಭಙ್ಗ;
		ಪಕ್ಷ 'C':
			connection_info = server_get_connection_info(ssh, 0, 0);
			ಯದಿ (parse_server_match_testspec(connection_info,
			    optarg) == -1)
				exit(1);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, ರಿಕ್ತ);
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

	/* Check that there are no remaining arguments. */
	ಯದಿ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	ಯದಿ (!rexeced_flag)
		fatal("sshd-session should not be executed directly");

	closefrom(REEXEC_MIN_FREE_FD);

	platform_pre_session_start();

	/* Reserve fds we'll need later for reexec things */
	ಯದಿ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	ಯಾವತ್ (devnull < PRIVSEP_MIN_FREE_FD) {
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
		    "P", "sshd-session",
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

	/* Fetch our configuration */
	ಯದಿ ((cfg = sshbuf_new()) == ರಿಕ್ತ)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[rexeced]");
	recv_rexec_state(REEXEC_CONFIG_PASS_FD, cfg, &timing_secret);
	parse_server_config(&options, "rexec", cfg, &includes, ರಿಕ್ತ, 1);
	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);
	options.timing_secret = timing_secret;

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	debug("sshd-session version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	ಯದಿ ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == ರಿಕ್ತ) {
		ಯದಿ (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} ಅನ್ಯಥಾ {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, strlen(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

	ಯದಿ (!debug_flag && !inetd_flag) {
		ಯದಿ ((startup_pipe = dup(REEXEC_CONFIG_PASS_FD)) == -1)
			fatal("internal error: no startup pipe");

		/*
		 * Signal parent that this child is at a point where
		 * they can go away if they have a SIGHUP pending.
		 */
		(ಶೂನ್ಯ)atomicio(vwrite, startup_pipe, "\0", 1);
	}
	/* close the fd, but keep the slot reserved */
	ಯದಿ (dup2(devnull, REEXEC_CONFIG_PASS_FD) == -1)
		fatal("dup2 devnull->config fd: %s", strerror(errno));

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
	 * daemonisation in the presence of Match block, but this catches
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

#ifdef WITH_OPENSSL
	ಯದಿ (options.moduli_file != ರಿಕ್ತ)
		dh_set_moduli_file(options.moduli_file);
#endif

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

	ಯದಿ (options.ಅಂಕೆ_host_ಕೀಲಿ_files != sensitive_data.ಅಂಕೆ_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.ಅಂಕೆ_host_ಕೀಲಿ_files, sensitive_data.ಅಂಕೆ_hostkeys);
	}

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಯದಿ (sensitive_data.host_ಕೀಲಿಗಳು[i] != ರಿಕ್ತ ||
		    (have_agent && sensitive_data.host_pubkeys[i] != ರಿಕ್ತ)) {
			have_ಕೀಲಿ = 1;
			ಭಙ್ಗ;
		}
	}
	ಯದಿ (!have_ಕೀಲಿ)
		fatal("internal error: monitor received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(ಶೂನ್ಯ) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	ಯದಿ (debug_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

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

	/* Get a connection, either from inetd or rexec */
	ಯದಿ (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_in = dup(STDIN_FILENO);
		sock_out = dup(STDOUT_FILENO);
	} ಅನ್ಯಥಾ {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_in = sock_out = dup(STDIN_FILENO);
	}

	/*
	 * We intentionally do not close the descriptors 0, 1, and 2
	 * as our code for setting the descriptors won't work if
	 * ttyfd happens to be one of those.
	 */
	ಯದಿ (stdfd_devnull(1, 1, !log_stderr) == -1)
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
	ಯದಿ ((ssh = ssh_packet_set_connection(ರಿಕ್ತ, sock_in, sock_out)) == ರಿಕ್ತ)
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
	ಯದಿ (options.tcp_keep_alive && ssh_packet_connection_is_on_socket(ssh))
		set_keepalive(sock_in); /* logs errors */

	ಯದಿ ((remote_port = ssh_remote_port(ssh)) < 0) {
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
	    rdomain == ರಿಕ್ತ ? "" : " rdomain \"",
	    rdomain == ರಿಕ್ತ ? "" : rdomain,
	    rdomain == ರಿಕ್ತ ? "" : "\"");
	ಮುಕ್ತ(laddr);

	/*
	 * We don't want to listen forever unless the other side
	 * successfully authenticates itself.  So we set up an alarm which is
	 * cleared after successful authentication.  A limit of zero
	 * indicates no limit. Note that we don't set the alarm in debugging
	 * mode; it is just annoying to have the server exit just when you
	 * are about to discover the bug.
	 */
	ssh_signal(SIGALRM, grace_alarm_handler);
	ಯದಿ (!debug_flag && options.login_grace_time > 0) {
		ಪೂರ್ಣಾಙ್ಕ ujitter = arc4random_uniform(4 * 1000000);

		timerclear(&itv.it_interval);
		itv.it_value.tv_sec = options.login_grace_time;
		itv.it_value.tv_sec += ujitter / 1000000;
		itv.it_value.tv_usec = ujitter % 1000000; 

		ಯದಿ (setitimer(ITIMER_REAL, &itv, ರಿಕ್ತ) == -1)
			fatal("login grace time setitimer failed");
	}

	ssh_packet_set_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, ಪರಿಮಾಣ(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	ಯದಿ ((auth_opts = sshauthopt_new_with_ಕೀಲಿಗಳು_defaults()) == ರಿಕ್ತ)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	ಯದಿ ((loginmsg = sshbuf_new()) == ರಿಕ್ತ)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

	ಯದಿ (privsep_preauth(ssh) != 1)
		fatal("privsep_preauth failed");

	/* Now user is authenticated */

	setproctitle("%s [postauth]", authctxt->user);

	/*
	 * Cancel the alarm we set to limit the time taken for
	 * authentication.
	 */
	timerclear(&itv.it_interval);
	timerclear(&itv.it_value);
	ಯದಿ (setitimer(ITIMER_REAL, &itv, ರಿಕ್ತ) == -1)
		fatal("login grace time clear failed");
	ssh_signal(SIGALRM, SIG_DFL);
	authctxt->authenticated = 1;
	ಯದಿ (startup_pipe != -1) {
		/* signal listener that authentication completed successfully */
		(ಶೂನ್ಯ)atomicio(vwrite, startup_pipe, "\001", 1);
		close(startup_pipe);
		startup_pipe = -1;
	}

	ಯದಿ (options.routing_domain != ರಿಕ್ತ)
		set_process_rdomain(ssh, options.routing_domain);

#ifdef SSH_AUDIT_EVENTS
	audit_event(ssh, SSH_AUTH_SUCCESS);
#endif

#ifdef GSSAPI
	ಯದಿ (options.gss_authentication) {
		temporarily_use_uid(authctxt->pw);
		ssh_gssapi_storecreds();
		restore_uid();
	}
#endif
#ifdef USE_PAM
	ಯದಿ (options.use_pam) {
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
	    options.client_alive_ಎಣಿಕೆ_max);

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
	ಯದಿ (options.use_pam)
		finish_pam();
#endif /* USE_PAM */

#ifdef SSH_AUDIT_EVENTS
	mm_audit_event(ssh, SSH_CONNECTION_CLOSE);
#endif

	ssh_packet_close(ssh);

	mm_terminate();

	exit(0);
}

ಪೂರ್ಣಾಙ್ಕ
sshd_hostkey_sign(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshkey *privkey,
    ಸಂರಚನಾ sshkey *pubkey, u_char **signature, size_t *slenp,
    ಧ್ರುವ u_char *data, size_t dlen, ಧ್ರುವ ವರ್ಣ *alg)
{
	ಯದಿ (privkey) {
		ಯದಿ (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, ರಿಕ್ತ,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} ಅನ್ಯಥಾ {
		ಯದಿ (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, ರಿಕ್ತ,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* server specific fatal cleanup */
ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಙ್ಕ i)
{
	ಯದಿ (the_active_state != ರಿಕ್ತ && the_authctxt != ರಿಕ್ತ) {
		do_cleanup(the_active_state, the_authctxt);
		ಯದಿ (privsep_is_preauth &&
		    pmonitor != ರಿಕ್ತ && pmonitor->m_pid > 1) {
			debug("Killing privsep child %d", pmonitor->m_pid);
			ಯದಿ (kill(pmonitor->m_pid, SIGKILL) != 0 &&
			    errno != ESRCH) {
				error_f("kill(%d): %s", pmonitor->m_pid,
				    strerror(errno));
			}
		}
	}
#ifdef SSH_AUDIT_EVENTS
	/* done after do_cleanup so it can cancel the PAM auth 'thread' */
	ಯದಿ (the_active_state != ರಿಕ್ತ && mm_is_monitor())
		audit_event(the_active_state, SSH_CONNECTION_ABANDON);
#endif
	/* Override default fatal exit value when auth was attempted */
	ಯದಿ (i == 255 && monitor_auth_attempted())
		_exit(EXIT_AUTH_ATTEMPTED);
	ಯದಿ (i == 255 && monitor_invalid_user())
		_exit(EXIT_INVALID_USER);
	_exit(i);
}
