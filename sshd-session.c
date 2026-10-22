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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/ioctl.h>
#അന്തര്ഭാവ <sys/wait.h>
#അന്തര്ഭാവ <sys/tree.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/time.h>
#അന്തര്ഭാവ <sys/queue.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <grp.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>

#ifdef HAVE_SECUREWARE
#അന്തര്ഭാവ <sys/security.h>
#അന്തര്ഭാവ <prot.h>
#endif
 
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "sshpty.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "uidswap.h"
#അന്തര്ഭാവ "compat.h"
#അന്തര്ഭാവ "cipher.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "msg.h"
#അന്തര്ഭാവ "dispatch.h"
#അന്തര്ഭാവ "channels.h"
#അന്തര്ഭാവ "session.h"
#അന്തര്ഭാവ "monitor.h"
#ifdef GSSAPI
#അന്തര്ഭാവ "ssh-gss.h"
#endif
#അന്തര്ഭാവ "monitor_wrap.h"
#അന്തര്ഭാവ "auth-options.h"
#അന്തര്ഭാവ "version.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sk-api.h"
#അന്തര്ഭാവ "srclimit.h"
#അന്തര്ഭാവ "dh.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

/* Privsep fds */
#define PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#define PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#define PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

ബാഹ്യ അക്ഷരം *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
അക്ഷരം *config_file_name = _PATH_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
പൂർണ്ണസംഖ്യ debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
സ്ഥിതം പൂർണ്ണസംഖ്യ inetd_flag = 0;

/* debug goes to stderr unless inetd_flag is set */
സ്ഥിതം പൂർണ്ണസംഖ്യ log_stderr = 0;

/* Saved arguments to main(). */
സ്ഥിതം അക്ഷരം **saved_argv;
സ്ഥിതം പൂർണ്ണസംഖ്യ saved_argc;

/* Daemon's agent connection */
പൂർണ്ണസംഖ്യ auth_sock = -1;
സ്ഥിതം പൂർണ്ണസംഖ്യ have_agent = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
ഘടന {
	u_int		അക്കം_hostkeys;
	ഘടന sshkey	**host_താക്കോലുകൾ;		/* all private host keys */
	ഘടന sshkey	**host_pubkeys;		/* all public host keys */
	ഘടന sshkey	**host_certificates;	/* all public host certificates */
} sensitive_data;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

സ്ഥിതം പൂർണ്ണസംഖ്യ startup_pipe = -1;		/* in child */

/* variables used for privilege separation */
ഘടന monitor *pmonitor = ശൂന്യ;
പൂർണ്ണസംഖ്യ privsep_is_preauth = 1;
സ്ഥിതം പൂർണ്ണസംഖ്യ privsep_chroot = 1;

/* Unprivileged user */
ഘടന passwd *privsep_pw = ശൂന്യ;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = ശൂന്യ;
ഘടന ssh *the_active_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
ഘടന sshauthopt *auth_opts = ശൂന്യ;

/* sshd_config buffer */
ഘടന sshbuf *cfg;

/* Included files from the configuration file */
ഘടന include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ഘടന sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
ശൂന്യം destroy_sensitive_data(ശൂന്യം);
ശൂന്യം demote_sensitive_data(ശൂന്യം);

/* XXX reduce to stub once postauth split */
പൂർണ്ണസംഖ്യ
mm_is_monitor(ശൂന്യം)
{
	/*
	 * m_pid is only set in the privileged part, and
	 * points to the unprivileged child.
	 */
	തിരികെ (pmonitor && pmonitor->m_pid > 0);
}

/*
 * Signal handler for the alarm after the login grace period has expired.
 * As usual, this may only take signal-safe actions, even though it is
 * terminal.
 */
സ്ഥിതം ശൂന്യം
grace_alarm_handler(പൂർണ്ണസംഖ്യ sig)
{
	/*
	 * Try to kill any processes that we have spawned, E.g. authorized
	 * keys command helpers or privsep children.
	 */
	എങ്കിൽ (getpgid(0) == getpid()) {
		ഘടന sigaction sa;

		/* mask all other signals while in handler */
		memset(&sa, 0, വലുപ്പം(sa));
		sa.sa_handler = SIG_IGN;
		sigfillset(&sa.sa_mask);
#എങ്കിൽ defined(SA_RESTART)
		sa.sa_flags = SA_RESTART;
#endif
		(ശൂന്യം)sigaction(SIGTERM, &sa, ശൂന്യ);
		kill(0, SIGTERM);
	}
	_exit(EXIT_LOGIN_GRACE);
}

/* Destroy the host and server keys.  They will no longer be needed. */
ശൂന്യം
destroy_sensitive_data(ശൂന്യം)
{
	u_int i;

	വേണ്ടി (i = 0; i < options.അക്കം_host_താക്കോൽ_files; i++) {
		എങ്കിൽ (sensitive_data.host_താക്കോലുകൾ[i]) {
			sshkey_free(sensitive_data.host_താക്കോലുകൾ[i]);
			sensitive_data.host_താക്കോലുകൾ[i] = ശൂന്യ;
		}
		എങ്കിൽ (sensitive_data.host_certificates[i]) {
			sshkey_free(sensitive_data.host_certificates[i]);
			sensitive_data.host_certificates[i] = ശൂന്യ;
		}
	}
}

/* Demote private to public keys for network child */
ശൂന്യം
demote_sensitive_data(ശൂന്യം)
{
	ഘടന sshkey *tmp;
	u_int i;
	പൂർണ്ണസംഖ്യ r;

	വേണ്ടി (i = 0; i < options.അക്കം_host_താക്കോൽ_files; i++) {
		എങ്കിൽ (sensitive_data.host_താക്കോലുകൾ[i]) {
			എങ്കിൽ ((r = sshkey_from_private(
			    sensitive_data.host_താക്കോലുകൾ[i], &tmp)) != 0)
				fatal_r(r, "could not demote host %s key",
				    sshkey_type(sensitive_data.host_താക്കോലുകൾ[i]));
			sshkey_free(sensitive_data.host_താക്കോലുകൾ[i]);
			sensitive_data.host_താക്കോലുകൾ[i] = tmp;
		}
		/* Certs do not need demotion */
	}
}

ഘടന sshbuf *
pack_hostkeys(ശൂന്യം)
{
	ഘടന sshbuf *keybuf = ശൂന്യ, *hostkeys = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;
	u_int i;

	എങ്കിൽ ((hostkeys = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	വേണ്ടി (i = 0; i < options.അക്കം_host_താക്കോൽ_files; i++) {
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

	sshbuf_free(keybuf);
	തിരികെ hostkeys;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
privsep_preauth(ഘടന ssh *ssh)
{
	പൂർണ്ണസംഖ്യ r;
	pid_t pid;

	/* Set up unprivileged child process to deal with network data */
	pmonitor = monitor_init();
	/* Store a pointer to the kex for later rekeying */
	pmonitor->m_pkex = &ssh->kex;

	എങ്കിൽ ((pid = fork()) == -1)
		fatal("fork of unprivileged child failed");
	അല്ലെങ്കിൽ എങ്കിൽ (pid != 0) {
		debug2("Network child is on pid %ld", (long)pid);

		pmonitor->m_pid = pid;
		എങ്കിൽ (have_agent) {
			r = ssh_get_authentication_socket(&auth_sock);
			എങ്കിൽ (r != 0) {
				error_r(r, "Could not get agent socket");
				have_agent = 0;
			}
		}
		monitor_child_preauth(ssh, pmonitor);
		privsep_is_preauth = 0;
		തിരികെ 1;
	} അല്ലെങ്കിൽ {
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

		എങ്കിൽ (ssh_packet_get_connection_in(ssh) != STDIN_FILENO &&
		    dup2(ssh_packet_get_connection_in(ssh), STDIN_FILENO) == -1)
			fatal("dup2 stdin failed: %s", strerror(errno));
		എങ്കിൽ (ssh_packet_get_connection_out(ssh) != STDOUT_FILENO &&
		    dup2(ssh_packet_get_connection_out(ssh),
		    STDOUT_FILENO) == -1)
			fatal("dup2 stdout failed: %s", strerror(errno));
		/* leave stderr as-is */
		log_redirect_stderr_to(ശൂന്യ); /* dup can clobber log fd */
		എങ്കിൽ (pmonitor->m_recvfd != PRIVSEP_MONITOR_FD &&
		    dup2(pmonitor->m_recvfd, PRIVSEP_MONITOR_FD) == -1)
			fatal("dup2 monitor fd: %s", strerror(errno));
		എങ്കിൽ (pmonitor->m_log_sendfd != PRIVSEP_LOG_FD &&
		    dup2(pmonitor->m_log_sendfd, PRIVSEP_LOG_FD) == -1)
			fatal("dup2 log fd: %s", strerror(errno));
		closefrom(PRIVSEP_MIN_FREE_FD);

		saved_argv[0] = options.sshd_auth_path;
		execv(options.sshd_auth_path, saved_argv);

		fatal_f("exec of %s failed: %s",
		    options.sshd_auth_path, strerror(errno));
	}
}

സ്ഥിതം ശൂന്യം
privsep_postauth(ഘടന ssh *ssh, Authctxt *authctxt)
{
	/* New socket pair */
	monitor_reinit(pmonitor);

	pmonitor->m_pid = fork();
	എങ്കിൽ (pmonitor->m_pid == -1)
		fatal("fork of unprivileged child failed");
	അല്ലെങ്കിൽ എങ്കിൽ (pmonitor->m_pid != 0) {
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

സ്ഥിതം ഘടന sshkey *
get_hostkey_by_type(പൂർണ്ണസംഖ്യ type, പൂർണ്ണസംഖ്യ nid, പൂർണ്ണസംഖ്യ need_private, ഘടന ssh *ssh)
{
	u_int i;
	ഘടന sshkey *താക്കോൽ;

	വേണ്ടി (i = 0; i < options.അക്കം_host_താക്കോൽ_files; i++) {
		തിരഞ്ഞെടുപ്പ് (type) {
		അവസ്ഥ താക്കോൽ_RSA_CERT:
		അവസ്ഥ താക്കോൽ_ECDSA_CERT:
		അവസ്ഥ താക്കോൽ_ED25519_CERT:
		അവസ്ഥ താക്കോൽ_ECDSA_SK_CERT:
		അവസ്ഥ താക്കോൽ_ED25519_SK_CERT:
		അവസ്ഥ താക്കോൽ_MLDSA44_ED25519_CERT:
			താക്കോൽ = sensitive_data.host_certificates[i];
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			താക്കോൽ = sensitive_data.host_താക്കോലുകൾ[i];
			എങ്കിൽ (താക്കോൽ == ശൂന്യ && !need_private)
				താക്കോൽ = sensitive_data.host_pubkeys[i];
			നിർത്തുക;
		}
		എങ്കിൽ (താക്കോൽ == ശൂന്യ || താക്കോൽ->type != type)
			തുടരുക;
		തിരഞ്ഞെടുപ്പ് (type) {
		അവസ്ഥ താക്കോൽ_ECDSA:
		അവസ്ഥ താക്കോൽ_ECDSA_SK:
		അവസ്ഥ താക്കോൽ_ECDSA_CERT:
		അവസ്ഥ താക്കോൽ_ECDSA_SK_CERT:
			എങ്കിൽ (താക്കോൽ->ecdsa_nid != nid)
				തുടരുക;
			/* FALLTHROUGH */
		സ്ഥിരസ്ഥിതി:
			തിരികെ need_private ?
			    sensitive_data.host_താക്കോലുകൾ[i] : താക്കോൽ;
		}
	}
	തിരികെ ശൂന്യ;
}

ഘടന sshkey *
get_hostkey_public_by_type(പൂർണ്ണസംഖ്യ type, പൂർണ്ണസംഖ്യ nid, ഘടന ssh *ssh)
{
	തിരികെ get_hostkey_by_type(type, nid, 0, ssh);
}

ഘടന sshkey *
get_hostkey_private_by_type(പൂർണ്ണസംഖ്യ type, പൂർണ്ണസംഖ്യ nid, ഘടന ssh *ssh)
{
	തിരികെ get_hostkey_by_type(type, nid, 1, ssh);
}

ഘടന sshkey *
get_hostkey_by_index(പൂർണ്ണസംഖ്യ ind)
{
	എങ്കിൽ (ind < 0 || (u_int)ind >= options.അക്കം_host_താക്കോൽ_files)
		തിരികെ (ശൂന്യ);
	തിരികെ (sensitive_data.host_താക്കോലുകൾ[ind]);
}

ഘടന sshkey *
get_hostkey_public_by_index(പൂർണ്ണസംഖ്യ ind, ഘടന ssh *ssh)
{
	എങ്കിൽ (ind < 0 || (u_int)ind >= options.അക്കം_host_താക്കോൽ_files)
		തിരികെ (ശൂന്യ);
	തിരികെ (sensitive_data.host_pubkeys[ind]);
}

പൂർണ്ണസംഖ്യ
get_hostkey_index(ഘടന sshkey *താക്കോൽ, പൂർണ്ണസംഖ്യ compare, ഘടന ssh *ssh)
{
	u_int i;

	വേണ്ടി (i = 0; i < options.അക്കം_host_താക്കോൽ_files; i++) {
		എങ്കിൽ (sshkey_is_cert(താക്കോൽ)) {
			എങ്കിൽ (താക്കോൽ == sensitive_data.host_certificates[i] ||
			    (compare && sensitive_data.host_certificates[i] &&
			    sshkey_equal(താക്കോൽ,
			    sensitive_data.host_certificates[i])))
				തിരികെ (i);
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (താക്കോൽ == sensitive_data.host_താക്കോലുകൾ[i] ||
			    (compare && sensitive_data.host_താക്കോലുകൾ[i] &&
			    sshkey_equal(താക്കോൽ, sensitive_data.host_താക്കോലുകൾ[i])))
				തിരികെ (i);
			എങ്കിൽ (താക്കോൽ == sensitive_data.host_pubkeys[i] ||
			    (compare && sensitive_data.host_pubkeys[i] &&
			    sshkey_equal(താക്കോൽ, sensitive_data.host_pubkeys[i])))
				തിരികെ (i);
		}
	}
	തിരികെ (-1);
}

/* Inform the client of all hostkeys */
സ്ഥിതം ശൂന്യം
notify_hostkeys(ഘടന ssh *ssh)
{
	ഘടന sshbuf *buf;
	ഘടന sshkey *താക്കോൽ;
	u_int i, nkeys;
	പൂർണ്ണസംഖ്യ r;
	അക്ഷരം *fp;

	/* Some clients cannot cope with the hostkeys message, skip those. */
	എങ്കിൽ (ssh->compat & SSH_BUG_HOSTKEYS)
		തിരികെ;

	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	വേണ്ടി (i = nkeys = 0; i < options.അക്കം_host_താക്കോൽ_files; i++) {
		താക്കോൽ = get_hostkey_public_by_index(i, ssh);
		എങ്കിൽ (താക്കോൽ == ശൂന്യ || താക്കോൽ->type == താക്കോൽ_UNSPEC ||
		    sshkey_is_cert(താക്കോൽ))
			തുടരുക;
		fp = sshkey_fingerprint(താക്കോൽ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("key %d: %s %s", i, sshkey_ssh_name(താക്കോൽ), fp);
		സ്വതന്ത്രം(fp);
		എങ്കിൽ (nkeys == 0) {
			/*
			 * Start building the request when we find the
			 * first usable key.
			 */
			എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_GLOBAL_REQUEST)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "hostkeys-00@openssh.com")) != 0 ||
			    (r = sshpkt_put_u8(ssh, 0)) != 0) /* want reply */
				sshpkt_fatal(ssh, r, "%s: start request", __func__);
		}
		/* Append the key to the request */
		sshbuf_reset(buf);
		എങ്കിൽ ((r = sshkey_putb(താക്കോൽ, buf)) != 0)
			fatal_fr(r, "couldn't put hostkey %d", i);
		എങ്കിൽ ((r = sshpkt_put_stringb(ssh, buf)) != 0)
			sshpkt_fatal(ssh, r, "%s: append key", __func__);
		nkeys++;
	}
	debug3_f("sent %u hostkeys", nkeys);
	എങ്കിൽ (nkeys == 0)
		fatal_f("no hostkeys");
	എങ്കിൽ ((r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send", __func__);
	sshbuf_free(buf);
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

സ്ഥിതം ശൂന്യം
parse_hostkeys(ഘടന sshbuf *hostkeys)
{
	പൂർണ്ണസംഖ്യ r;
	u_int അക്കം_താക്കോലുകൾ = 0;
	ഘടന sshkey *k;
	ഘടന sshbuf *kbuf;
	സ്ഥിരം u_char *cp;
	size_t len;

	ആകുമ്പോൾ (sshbuf_len(hostkeys) != 0) {
		എങ്കിൽ (അക്കം_താക്കോലുകൾ > 2048)
			fatal_f("too many hostkeys");
		sensitive_data.host_താക്കോലുകൾ = xrecallocarray(
		    sensitive_data.host_താക്കോലുകൾ, അക്കം_താക്കോലുകൾ, അക്കം_താക്കോലുകൾ + 1,
		    വലുപ്പം(*sensitive_data.host_pubkeys));
		sensitive_data.host_pubkeys = xrecallocarray(
		    sensitive_data.host_pubkeys, അക്കം_താക്കോലുകൾ, അക്കം_താക്കോലുകൾ + 1,
		    വലുപ്പം(*sensitive_data.host_pubkeys));
		sensitive_data.host_certificates = xrecallocarray(
		    sensitive_data.host_certificates, അക്കം_താക്കോലുകൾ, അക്കം_താക്കോലുകൾ + 1,
		    വലുപ്പം(*sensitive_data.host_certificates));
		/* private key */
		k = ശൂന്യ;
		എങ്കിൽ ((r = sshbuf_froms(hostkeys, &kbuf)) != 0)
			fatal_fr(r, "extract privkey");
		എങ്കിൽ (sshbuf_len(kbuf) != 0 &&
		    (r = sshkey_private_deserialize(kbuf, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_താക്കോലുകൾ[അക്കം_താക്കോലുകൾ] = k;
		sshbuf_free(kbuf);
		എങ്കിൽ (k)
			debug2_f("privkey %u: %s", അക്കം_താക്കോലുകൾ, sshkey_ssh_name(k));
		/* public key */
		k = ശൂന്യ;
		എങ്കിൽ ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		എങ്കിൽ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_pubkeys[അക്കം_താക്കോലുകൾ] = k;
		എങ്കിൽ (k)
			debug2_f("pubkey %u: %s", അക്കം_താക്കോലുകൾ, sshkey_ssh_name(k));
		/* certificate */
		k = ശൂന്യ;
		എങ്കിൽ ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		എങ്കിൽ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_certificates[അക്കം_താക്കോലുകൾ] = k;
		എങ്കിൽ (k)
			debug2_f("cert %u: %s", അക്കം_താക്കോലുകൾ, sshkey_ssh_name(k));
		അക്കം_താക്കോലുകൾ++;
	}
	sensitive_data.അക്കം_hostkeys = അക്കം_താക്കോലുകൾ;
}

സ്ഥിതം ശൂന്യം
recv_rexec_state(പൂർണ്ണസംഖ്യ fd, ഘടന sshbuf *conf, uint64_t *timing_secretp)
{
	ഘടന sshbuf *m, *inc, *hostkeys;
	u_char *cp, ver;
	size_t len;
	പൂർണ്ണസംഖ്യ r;
	ഘടന include_item *item;

	debug3_f("entering fd = %d", fd);

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ || (inc = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	/* receive config */
	എങ്കിൽ (ssh_സന്ദേശം_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	എങ്കിൽ ((r = sshbuf_get_u8(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	എങ്കിൽ (ver != 0)
		fatal_f("rexec version mismatch");
	എങ്കിൽ ((r = sshbuf_get_string(m, &cp, &len)) != 0 || /* XXX _direct */
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_get_stringb(m, inc)) != 0)
		fatal_fr(r, "parse config");

	എങ്കിൽ (conf != ശൂന്യ && (r = sshbuf_put(conf, cp, len)))
		fatal_fr(r, "sshbuf_put");

	ആകുമ്പോൾ (sshbuf_len(inc) != 0) {
		item = xcalloc(1, വലുപ്പം(*item));
		എങ്കിൽ ((item->contents = sshbuf_new()) == ശൂന്യ)
			fatal_f("sshbuf_new failed");
		എങ്കിൽ ((r = sshbuf_get_cstring(inc, &item->selector, ശൂന്യ)) != 0 ||
		    (r = sshbuf_get_cstring(inc, &item->filename, ശൂന്യ)) != 0 ||
		    (r = sshbuf_get_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "parse includes");
		TAILQ_INSERT_TAIL(&includes, item, entry);
	}

	/* receive hostkeys */
	sshbuf_reset(m);
	എങ്കിൽ (ssh_സന്ദേശം_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	എങ്കിൽ ((r = sshbuf_get_u8(m, ശൂന്യ)) != 0 ||
	    (r = sshbuf_froms(m, &hostkeys)) != 0)
		fatal_fr(r, "parse config");
	parse_hostkeys(hostkeys);

	സ്വതന്ത്രം(cp);
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
സ്ഥിതം ശൂന്യം
check_ip_options(ഘടന ssh *ssh)
{
#ifdef IP_OPTIONS
	പൂർണ്ണസംഖ്യ sock_in = ssh_packet_get_connection_in(ssh);
	ഘടന sockaddr_storage from;
	u_char opts[200];
	socklen_t i, option_size = വലുപ്പം(opts), fromlen = വലുപ്പം(from);
	അക്ഷരം text[വലുപ്പം(opts) * 3 + 1];

	memset(&from, 0, വലുപ്പം(from));
	എങ്കിൽ (getpeername(sock_in, (ഘടന sockaddr *)&from,
	    &fromlen) == -1)
		തിരികെ;
	എങ്കിൽ (from.ss_family != AF_INET)
		തിരികെ;
	/* XXX IPv6 options? */

	എങ്കിൽ (getsockopt(sock_in, IPPROTO_IP, IP_OPTIONS, opts,
	    &option_size) >= 0 && option_size != 0) {
		text[0] = '\0';
		വേണ്ടി (i = 0; i < option_size; i++)
			snprintf(text + i*3, വലുപ്പം(text) - i*3,
			    " %2.2x", opts[i]);
		fatal("Connection from %.100s port %d with IP opts: %.800s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), text);
	}
#endif /* IP_OPTIONS */
}

/* Set the routing domain for this process */
സ്ഥിതം ശൂന്യം
set_process_rdomain(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *name)
{
#എങ്കിൽ defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
	എങ്കിൽ (name == ശൂന്യ)
		തിരികെ; /* default */

	എങ്കിൽ (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		എങ്കിൽ ((name = ssh_packet_rdomain_in(ssh)) == ശൂന്യ)
			തിരികെ;
	}
	/* NB. We don't pass 'ssh' to sys_set_process_rdomain() */
	തിരികെ sys_set_process_rdomain(name);
#അല്ലെങ്കിലെങ്കിൽ defined(__OpenBSD__)
	പൂർണ്ണസംഖ്യ rtable, ortable = getrtable();
	സ്ഥിരം അക്ഷരം *errstr;

	എങ്കിൽ (name == ശൂന്യ)
		തിരികെ; /* default */

	എങ്കിൽ (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		എങ്കിൽ ((name = ssh_packet_rdomain_in(ssh)) == ശൂന്യ)
			തിരികെ;
	}

	rtable = (പൂർണ്ണസംഖ്യ)strtonum(name, 0, 255, &errstr);
	എങ്കിൽ (errstr != ശൂന്യ) /* Shouldn't happen */
		fatal("Invalid routing domain \"%s\": %s", name, errstr);
	എങ്കിൽ (rtable != ortable && setrtable(rtable) != 0)
		fatal("Unable to set routing domain %d: %s",
		    rtable, strerror(errno));
	debug_f("set routing domain %d (was %d)", rtable, ortable);
#അല്ലെങ്കിൽ /* defined(__OpenBSD__) */
	fatal("Unable to set routing domain: not supported in this platform");
#endif
}

/*
 * Main program for the daemon.
 */
പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ ac, അക്ഷരം **av)
{
	ഘടന ssh *ssh = ശൂന്യ;
	ബാഹ്യ അക്ഷരം *optarg;
	ബാഹ്യ പൂർണ്ണസംഖ്യ optind;
	പൂർണ്ണസംഖ്യ devnull, r, opt, remote_port;
	പൂർണ്ണസംഖ്യ sock_in = -1, sock_out = -1, rexeced_flag = 0, have_താക്കോൽ = 0;
	സ്ഥിരം അക്ഷരം *remote_ip, *rdomain;
	അക്ഷരം *വരി, *laddr, *logfile = ശൂന്യ;
	u_int i;
	uint64_t ibytes, obytes;
	mode_t new_umask;
	Authctxt *authctxt;
	ഘടന connection_info *connection_info = ശൂന്യ;
	sigset_t sigmask;
	uint64_t timing_secret = 0;
	ഘടന itimerval itv;

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ശൂന്യ);

#ifdef HAVE_SECUREWARE
	(ശൂന്യം)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, വലുപ്പം(*saved_argv));
	വേണ്ടി (i = 0; (പൂർണ്ണസംഖ്യ)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ശൂന്യ;

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
			/* ignore */
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
			/* ignore */
			നിർത്തുക;
		അവസ്ഥ 'R':
			rexeced_flag = 1;
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
		അവസ്ഥ 'T':
		അവസ്ഥ 'G':
			fatal("test/dump modes not supported");
			നിർത്തുക;
		അവസ്ഥ 'C':
			connection_info = server_get_connection_info(ssh, 0, 0);
			എങ്കിൽ (parse_server_match_testspec(connection_info,
			    optarg) == -1)
				exit(1);
			നിർത്തുക;
		അവസ്ഥ 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, ശൂന്യ);
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

	/* Check that there are no remaining arguments. */
	എങ്കിൽ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	എങ്കിൽ (!rexeced_flag)
		fatal("sshd-session should not be executed directly");

	closefrom(REEXEC_MIN_FREE_FD);

	platform_pre_session_start();

	/* Reserve fds we'll need later for reexec things */
	എങ്കിൽ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	ആകുമ്പോൾ (devnull < PRIVSEP_MIN_FREE_FD) {
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
		    "P", "sshd-session",
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

	/* Fetch our configuration */
	എങ്കിൽ ((cfg = sshbuf_new()) == ശൂന്യ)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[rexeced]");
	recv_rexec_state(REEXEC_CONFIG_PASS_FD, cfg, &timing_secret);
	parse_server_config(&options, "rexec", cfg, &includes, ശൂന്യ, 1);
	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);
	options.timing_secret = timing_secret;

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	debug("sshd-session version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	എങ്കിൽ ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == ശൂന്യ) {
		എങ്കിൽ (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} അല്ലെങ്കിൽ {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, strlen(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

	എങ്കിൽ (!debug_flag && !inetd_flag) {
		എങ്കിൽ ((startup_pipe = dup(REEXEC_CONFIG_PASS_FD)) == -1)
			fatal("internal error: no startup pipe");

		/*
		 * Signal parent that this child is at a point where
		 * they can go away if they have a SIGHUP pending.
		 */
		(ശൂന്യം)atomicio(vwrite, startup_pipe, "\0", 1);
	}
	/* close the fd, but keep the slot reserved */
	എങ്കിൽ (dup2(devnull, REEXEC_CONFIG_PASS_FD) == -1)
		fatal("dup2 devnull->config fd: %s", strerror(errno));

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
	 * daemonisation in the presence of Match block, but this catches
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

#ifdef WITH_OPENSSL
	എങ്കിൽ (options.moduli_file != ശൂന്യ)
		dh_set_moduli_file(options.moduli_file);
#endif

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

	എങ്കിൽ (options.അക്കം_host_താക്കോൽ_files != sensitive_data.അക്കം_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.അക്കം_host_താക്കോൽ_files, sensitive_data.അക്കം_hostkeys);
	}

	വേണ്ടി (i = 0; i < options.അക്കം_host_താക്കോൽ_files; i++) {
		എങ്കിൽ (sensitive_data.host_താക്കോലുകൾ[i] != ശൂന്യ ||
		    (have_agent && sensitive_data.host_pubkeys[i] != ശൂന്യ)) {
			have_താക്കോൽ = 1;
			നിർത്തുക;
		}
	}
	എങ്കിൽ (!have_താക്കോൽ)
		fatal("internal error: monitor received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(ശൂന്യം) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	എങ്കിൽ (debug_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	വേണ്ടി (i = 0; i < options.അക്കം_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

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

	/* Get a connection, either from inetd or rexec */
	എങ്കിൽ (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_in = dup(STDIN_FILENO);
		sock_out = dup(STDOUT_FILENO);
	} അല്ലെങ്കിൽ {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_in = sock_out = dup(STDIN_FILENO);
	}

	/*
	 * We intentionally do not close the descriptors 0, 1, and 2
	 * as our code for setting the descriptors won't work if
	 * ttyfd happens to be one of those.
	 */
	എങ്കിൽ (stdfd_devnull(1, 1, !log_stderr) == -1)
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
	എങ്കിൽ ((ssh = ssh_packet_set_connection(ശൂന്യ, sock_in, sock_out)) == ശൂന്യ)
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
	എങ്കിൽ (options.tcp_keep_alive && ssh_packet_connection_is_on_socket(ssh))
		set_keepalive(sock_in); /* logs errors */

	എങ്കിൽ ((remote_port = ssh_remote_port(ssh)) < 0) {
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
	    rdomain == ശൂന്യ ? "" : " rdomain \"",
	    rdomain == ശൂന്യ ? "" : rdomain,
	    rdomain == ശൂന്യ ? "" : "\"");
	സ്വതന്ത്രം(laddr);

	/*
	 * We don't want to listen forever unless the other side
	 * successfully authenticates itself.  So we set up an alarm which is
	 * cleared after successful authentication.  A limit of zero
	 * indicates no limit. Note that we don't set the alarm in debugging
	 * mode; it is just annoying to have the server exit just when you
	 * are about to discover the bug.
	 */
	ssh_signal(SIGALRM, grace_alarm_handler);
	എങ്കിൽ (!debug_flag && options.login_grace_time > 0) {
		പൂർണ്ണസംഖ്യ ujitter = arc4random_uniform(4 * 1000000);

		timerclear(&itv.it_interval);
		itv.it_value.tv_sec = options.login_grace_time;
		itv.it_value.tv_sec += ujitter / 1000000;
		itv.it_value.tv_usec = ujitter % 1000000; 

		എങ്കിൽ (setitimer(ITIMER_REAL, &itv, ശൂന്യ) == -1)
			fatal("login grace time setitimer failed");
	}

	ssh_packet_set_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, വലുപ്പം(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	എങ്കിൽ ((auth_opts = sshauthopt_new_with_താക്കോലുകൾ_defaults()) == ശൂന്യ)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	എങ്കിൽ ((loginmsg = sshbuf_new()) == ശൂന്യ)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

	എങ്കിൽ (privsep_preauth(ssh) != 1)
		fatal("privsep_preauth failed");

	/* Now user is authenticated */

	setproctitle("%s [postauth]", authctxt->user);

	/*
	 * Cancel the alarm we set to limit the time taken for
	 * authentication.
	 */
	timerclear(&itv.it_interval);
	timerclear(&itv.it_value);
	എങ്കിൽ (setitimer(ITIMER_REAL, &itv, ശൂന്യ) == -1)
		fatal("login grace time clear failed");
	ssh_signal(SIGALRM, SIG_DFL);
	authctxt->authenticated = 1;
	എങ്കിൽ (startup_pipe != -1) {
		/* signal listener that authentication completed successfully */
		(ശൂന്യം)atomicio(vwrite, startup_pipe, "\001", 1);
		close(startup_pipe);
		startup_pipe = -1;
	}

	എങ്കിൽ (options.routing_domain != ശൂന്യ)
		set_process_rdomain(ssh, options.routing_domain);

#ifdef SSH_AUDIT_EVENTS
	audit_event(ssh, SSH_AUTH_SUCCESS);
#endif

#ifdef GSSAPI
	എങ്കിൽ (options.gss_authentication) {
		temporarily_use_uid(authctxt->pw);
		ssh_gssapi_storecreds();
		restore_uid();
	}
#endif
#ifdef USE_PAM
	എങ്കിൽ (options.use_pam) {
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
	    options.client_alive_എണ്ണം_max);

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
	എങ്കിൽ (options.use_pam)
		finish_pam();
#endif /* USE_PAM */

#ifdef SSH_AUDIT_EVENTS
	mm_audit_event(ssh, SSH_CONNECTION_CLOSE);
#endif

	ssh_packet_close(ssh);

	mm_terminate();

	exit(0);
}

പൂർണ്ണസംഖ്യ
sshd_hostkey_sign(ഘടന ssh *ssh, ഘടന sshkey *privkey,
    ഘടന sshkey *pubkey, u_char **signature, size_t *slenp,
    സ്ഥിരം u_char *data, size_t dlen, സ്ഥിരം അക്ഷരം *alg)
{
	എങ്കിൽ (privkey) {
		എങ്കിൽ (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, ശൂന്യ,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, ശൂന്യ,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	തിരികെ 0;
}

/* server specific fatal cleanup */
ശൂന്യം
cleanup_exit(പൂർണ്ണസംഖ്യ i)
{
	എങ്കിൽ (the_active_state != ശൂന്യ && the_authctxt != ശൂന്യ) {
		do_cleanup(the_active_state, the_authctxt);
		എങ്കിൽ (privsep_is_preauth &&
		    pmonitor != ശൂന്യ && pmonitor->m_pid > 1) {
			debug("Killing privsep child %d", pmonitor->m_pid);
			എങ്കിൽ (kill(pmonitor->m_pid, SIGKILL) != 0 &&
			    errno != ESRCH) {
				error_f("kill(%d): %s", pmonitor->m_pid,
				    strerror(errno));
			}
		}
	}
#ifdef SSH_AUDIT_EVENTS
	/* done after do_cleanup so it can cancel the PAM auth 'thread' */
	എങ്കിൽ (the_active_state != ശൂന്യ && mm_is_monitor())
		audit_event(the_active_state, SSH_CONNECTION_ABANDON);
#endif
	/* Override default fatal exit value when auth was attempted */
	എങ്കിൽ (i == 255 && monitor_auth_attempted())
		_exit(EXIT_AUTH_ATTEMPTED);
	എങ്കിൽ (i == 255 && monitor_invalid_user())
		_exit(EXIT_INVALID_USER);
	_exit(i);
}
