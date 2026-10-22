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

#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/tree.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/queue.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <paths.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>

#ifdef HAVE_SECUREWARE
#include <sys/security.h>
#include <prot.h>
#endif
 
#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "sshpty.h"
#include "packet.h"
#include "log.h"
#include "sshbuf.h"
#include "misc.h"
#include "match.h"
#include "servconf.h"
#include "uidswap.h"
#include "compat.h"
#include "cipher.h"
#include "digest.h"
#include "sshkey.h"
#include "kex.h"
#include "authfile.h"
#include "pathnames.h"
#include "atomicio.h"
#include "canohost.h"
#include "hostfile.h"
#include "auth.h"
#include "authfd.h"
#include "msg.h"
#include "dispatch.h"
#include "channels.h"
#include "session.h"
#include "monitor.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "auth-options.h"
#include "version.h"
#include "ssherr.h"
#include "sk-api.h"
#include "srclimit.h"
#include "dh.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

/* Privsep fds */
#define PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#define PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#define PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

extern var_na *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
var_na *config_file_name = _PATH_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
puur_naa_nka debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
static puur_naa_nka inetd_flag = 0;

/* debug goes to stderr unless inetd_flag is set */
static puur_naa_nka log_stderr = 0;

/* Saved arguments to main(). */
static var_na **saved_argv;
static puur_naa_nka saved_argc;

/* Daemon's agent connection */
puur_naa_nka auth_sock = -1;
static puur_naa_nka have_agent = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
sa_nracanaa {
	u_int		num_hostkeys;
	sa_nracanaa sshkey	**host_keys;		/* all private host keys */
	sa_nracanaa sshkey	**host_pubkeys;		/* all public host keys */
	sa_nracanaa sshkey	**host_certificates;	/* all public host certificates */
} sensitive_data;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

static puur_naa_nka startup_pipe = -1;		/* in child */

/* variables used for privilege separation */
sa_nracanaa monitor *pmonitor = NULL;
puur_naa_nka privsep_is_preauth = 1;
static puur_naa_nka privsep_chroot = 1;

/* Unprivileged user */
sa_nracanaa passwd *privsep_pw = NULL;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = NULL;
sa_nracanaa ssh *the_active_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
sa_nracanaa sshauthopt *auth_opts = NULL;

/* sshd_config buffer */
sa_nracanaa sshbuf *cfg;

/* Included files from the configuration file */
sa_nracanaa include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
sa_nracanaa sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
void destroy_sensitive_data(void);
void demote_sensitive_data(void);

/* XXX reduce to stub once postauth split */
puur_naa_nka
mm_is_monitor(void)
{
	/*
	 * m_pid is only set in the privileged part, and
	 * points to the unprivileged child.
	 */
	ᮝᮜᮤ (pmonitor && pmonitor->m_pid > 0);
}

/*
 * Signal handler for the alarm after the login grace period has expired.
 * As usual, this may only take signal-safe actions, even though it is
 * terminal.
 */
static void
grace_alarm_handler(puur_naa_nka sig)
{
	/*
	 * Try to kill any processes that we have spawned, E.g. authorized
	 * keys command helpers or privsep children.
	 */
	ᮚᮦᮔ᮪ (getpgid(0) == getpid()) {
		sa_nracanaa sigaction sa;

		/* mask all other signals while in handler */
		memset(&sa, 0, parimaa_na(sa));
		sa.sa_handler = SIG_IGN;
		sigfillset(&sa.sa_mask);
#ᮚᮦᮔ᮪ defined(SA_RESTART)
		sa.sa_flags = SA_RESTART;
#endif
		(void)sigaction(SIGTERM, &sa, NULL);
		kill(0, SIGTERM);
	}
	_exit(EXIT_LOGIN_GRACE);
}

/* Destroy the host and server keys.  They will no longer be needed. */
void
destroy_sensitive_data(void)
{
	u_int i;

	for (i = 0; i < options.num_host_key_files; i++) {
		ᮚᮦᮔ᮪ (sensitive_data.host_keys[i]) {
			sshkey_free(sensitive_data.host_keys[i]);
			sensitive_data.host_keys[i] = NULL;
		}
		ᮚᮦᮔ᮪ (sensitive_data.host_certificates[i]) {
			sshkey_free(sensitive_data.host_certificates[i]);
			sensitive_data.host_certificates[i] = NULL;
		}
	}
}

/* Demote private to public keys for network child */
void
demote_sensitive_data(void)
{
	sa_nracanaa sshkey *tmp;
	u_int i;
	puur_naa_nka r;

	for (i = 0; i < options.num_host_key_files; i++) {
		ᮚᮦᮔ᮪ (sensitive_data.host_keys[i]) {
			ᮚᮦᮔ᮪ ((r = sshkey_from_private(
			    sensitive_data.host_keys[i], &tmp)) != 0)
				fatal_r(r, "could not demote host %s key",
				    sshkey_type(sensitive_data.host_keys[i]));
			sshkey_free(sensitive_data.host_keys[i]);
			sensitive_data.host_keys[i] = tmp;
		}
		/* Certs do not need demotion */
	}
}

sa_nracanaa sshbuf *
pack_hostkeys(void)
{
	sa_nracanaa sshbuf *keybuf = NULL, *hostkeys = NULL;
	puur_naa_nka r;
	u_int i;

	ᮚᮦᮔ᮪ ((hostkeys = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	for (i = 0; i < options.num_host_key_files; i++) {
		/* public key */
		ᮚᮦᮔ᮪ (sensitive_data.host_pubkeys[i] != NULL) {
			ᮚᮦᮔ᮪ ((r = sshkey_puts(sensitive_data.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} ᮜᮤᮚ {
			ᮚᮦᮔ᮪ ((r = sshbuf_put_string(hostkeys, NULL, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		ᮚᮦᮔ᮪ (sensitive_data.host_certificates[i] != NULL) {
			ᮚᮦᮔ᮪ ((r = sshkey_puts(
			    sensitive_data.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} ᮜᮤᮚ {
			ᮚᮦᮔ᮪ ((r = sshbuf_put_string(hostkeys, NULL, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	sshbuf_free(keybuf);
	ᮝᮜᮤ hostkeys;
}

static puur_naa_nka
privsep_preauth(sa_nracanaa ssh *ssh)
{
	puur_naa_nka r;
	pid_t pid;

	/* Set up unprivileged child process to deal with network data */
	pmonitor = monitor_init();
	/* Store a pointer to the kex for later rekeying */
	pmonitor->m_pkex = &ssh->kex;

	ᮚᮦᮔ᮪ ((pid = fork()) == -1)
		fatal("fork of unprivileged child failed");
	ᮜᮤᮚ ᮚᮦᮔ᮪ (pid != 0) {
		debug2("Network child is on pid %ld", (long)pid);

		pmonitor->m_pid = pid;
		ᮚᮦᮔ᮪ (have_agent) {
			r = ssh_get_authentication_socket(&auth_sock);
			ᮚᮦᮔ᮪ (r != 0) {
				error_r(r, "Could not get agent socket");
				have_agent = 0;
			}
		}
		monitor_child_preauth(ssh, pmonitor);
		privsep_is_preauth = 0;
		ᮝᮜᮤ 1;
	} ᮜᮤᮚ {
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

		ᮚᮦᮔ᮪ (ssh_packet_get_connection_in(ssh) != STDIN_FILENO &&
		    dup2(ssh_packet_get_connection_in(ssh), STDIN_FILENO) == -1)
			fatal("dup2 stdin failed: %s", strerror(errno));
		ᮚᮦᮔ᮪ (ssh_packet_get_connection_out(ssh) != STDOUT_FILENO &&
		    dup2(ssh_packet_get_connection_out(ssh),
		    STDOUT_FILENO) == -1)
			fatal("dup2 stdout failed: %s", strerror(errno));
		/* leave stderr as-is */
		log_redirect_stderr_to(NULL); /* dup can clobber log fd */
		ᮚᮦᮔ᮪ (pmonitor->m_recvfd != PRIVSEP_MONITOR_FD &&
		    dup2(pmonitor->m_recvfd, PRIVSEP_MONITOR_FD) == -1)
			fatal("dup2 monitor fd: %s", strerror(errno));
		ᮚᮦᮔ᮪ (pmonitor->m_log_sendfd != PRIVSEP_LOG_FD &&
		    dup2(pmonitor->m_log_sendfd, PRIVSEP_LOG_FD) == -1)
			fatal("dup2 log fd: %s", strerror(errno));
		closefrom(PRIVSEP_MIN_FREE_FD);

		saved_argv[0] = options.sshd_auth_path;
		execv(options.sshd_auth_path, saved_argv);

		fatal_f("exec of %s failed: %s",
		    options.sshd_auth_path, strerror(errno));
	}
}

static void
privsep_postauth(sa_nracanaa ssh *ssh, Authctxt *authctxt)
{
	/* New socket pair */
	monitor_reinit(pmonitor);

	pmonitor->m_pid = fork();
	ᮚᮦᮔ᮪ (pmonitor->m_pid == -1)
		fatal("fork of unprivileged child failed");
	ᮜᮤᮚ ᮚᮦᮔ᮪ (pmonitor->m_pid != 0) {
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

static sa_nracanaa sshkey *
get_hostkey_by_type(puur_naa_nka type, puur_naa_nka nid, puur_naa_nka need_private, sa_nracanaa ssh *ssh)
{
	u_int i;
	sa_nracanaa sshkey *key;

	for (i = 0; i < options.num_host_key_files; i++) {
		switch (type) {
		pak_sa KEY_RSA_CERT:
		pak_sa KEY_ECDSA_CERT:
		pak_sa KEY_ED25519_CERT:
		pak_sa KEY_ECDSA_SK_CERT:
		pak_sa KEY_ED25519_SK_CERT:
		pak_sa KEY_MLDSA44_ED25519_CERT:
			key = sensitive_data.host_certificates[i];
			bha_nga;
		default:
			key = sensitive_data.host_keys[i];
			ᮚᮦᮔ᮪ (key == NULL && !need_private)
				key = sensitive_data.host_pubkeys[i];
			bha_nga;
		}
		ᮚᮦᮔ᮪ (key == NULL || key->type != type)
			continue;
		switch (type) {
		pak_sa KEY_ECDSA:
		pak_sa KEY_ECDSA_SK:
		pak_sa KEY_ECDSA_CERT:
		pak_sa KEY_ECDSA_SK_CERT:
			ᮚᮦᮔ᮪ (key->ecdsa_nid != nid)
				continue;
			/* FALLTHROUGH */
		default:
			ᮝᮜᮤ need_private ?
			    sensitive_data.host_keys[i] : key;
		}
	}
	ᮝᮜᮤ NULL;
}

sa_nracanaa sshkey *
get_hostkey_public_by_type(puur_naa_nka type, puur_naa_nka nid, sa_nracanaa ssh *ssh)
{
	ᮝᮜᮤ get_hostkey_by_type(type, nid, 0, ssh);
}

sa_nracanaa sshkey *
get_hostkey_private_by_type(puur_naa_nka type, puur_naa_nka nid, sa_nracanaa ssh *ssh)
{
	ᮝᮜᮤ get_hostkey_by_type(type, nid, 1, ssh);
}

sa_nracanaa sshkey *
get_hostkey_by_index(puur_naa_nka ind)
{
	ᮚᮦᮔ᮪ (ind < 0 || (u_int)ind >= options.num_host_key_files)
		ᮝᮜᮤ (NULL);
	ᮝᮜᮤ (sensitive_data.host_keys[ind]);
}

sa_nracanaa sshkey *
get_hostkey_public_by_index(puur_naa_nka ind, sa_nracanaa ssh *ssh)
{
	ᮚᮦᮔ᮪ (ind < 0 || (u_int)ind >= options.num_host_key_files)
		ᮝᮜᮤ (NULL);
	ᮝᮜᮤ (sensitive_data.host_pubkeys[ind]);
}

puur_naa_nka
get_hostkey_index(sa_nracanaa sshkey *key, puur_naa_nka compare, sa_nracanaa ssh *ssh)
{
	u_int i;

	for (i = 0; i < options.num_host_key_files; i++) {
		ᮚᮦᮔ᮪ (sshkey_is_cert(key)) {
			ᮚᮦᮔ᮪ (key == sensitive_data.host_certificates[i] ||
			    (compare && sensitive_data.host_certificates[i] &&
			    sshkey_equal(key,
			    sensitive_data.host_certificates[i])))
				ᮝᮜᮤ (i);
		} ᮜᮤᮚ {
			ᮚᮦᮔ᮪ (key == sensitive_data.host_keys[i] ||
			    (compare && sensitive_data.host_keys[i] &&
			    sshkey_equal(key, sensitive_data.host_keys[i])))
				ᮝᮜᮤ (i);
			ᮚᮦᮔ᮪ (key == sensitive_data.host_pubkeys[i] ||
			    (compare && sensitive_data.host_pubkeys[i] &&
			    sshkey_equal(key, sensitive_data.host_pubkeys[i])))
				ᮝᮜᮤ (i);
		}
	}
	ᮝᮜᮤ (-1);
}

/* Inform the client of all hostkeys */
static void
notify_hostkeys(sa_nracanaa ssh *ssh)
{
	sa_nracanaa sshbuf *buf;
	sa_nracanaa sshkey *key;
	u_int i, nkeys;
	puur_naa_nka r;
	var_na *fp;

	/* Some clients cannot cope with the hostkeys message, skip those. */
	ᮚᮦᮔ᮪ (ssh->compat & SSH_BUG_HOSTKEYS)
		ᮝᮜᮤ;

	ᮚᮦᮔ᮪ ((buf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	for (i = nkeys = 0; i < options.num_host_key_files; i++) {
		key = get_hostkey_public_by_index(i, ssh);
		ᮚᮦᮔ᮪ (key == NULL || key->type == KEY_UNSPEC ||
		    sshkey_is_cert(key))
			continue;
		fp = sshkey_fingerprint(key, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("key %d: %s %s", i, sshkey_ssh_name(key), fp);
		free(fp);
		ᮚᮦᮔ᮪ (nkeys == 0) {
			/*
			 * Start building the request when we find the
			 * first usable key.
			 */
			ᮚᮦᮔ᮪ ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "hostkeys-00@openssh.com")) != 0 ||
			    (r = sshpkt_put_u8(ssh, 0)) != 0) /* want reply */
				sshpkt_fatal(ssh, r, "%s: start request", __func__);
		}
		/* Append the key to the request */
		sshbuf_reset(buf);
		ᮚᮦᮔ᮪ ((r = sshkey_putb(key, buf)) != 0)
			fatal_fr(r, "couldn't put hostkey %d", i);
		ᮚᮦᮔ᮪ ((r = sshpkt_put_stringb(ssh, buf)) != 0)
			sshpkt_fatal(ssh, r, "%s: append key", __func__);
		nkeys++;
	}
	debug3_f("sent %u hostkeys", nkeys);
	ᮚᮦᮔ᮪ (nkeys == 0)
		fatal_f("no hostkeys");
	ᮚᮦᮔ᮪ ((r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send", __func__);
	sshbuf_free(buf);
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

static void
parse_hostkeys(sa_nracanaa sshbuf *hostkeys)
{
	puur_naa_nka r;
	u_int num_keys = 0;
	sa_nracanaa sshkey *k;
	sa_nracanaa sshbuf *kbuf;
	const u_char *cp;
	size_t len;

	ᮞᮨᮓᮨᮜ (sshbuf_len(hostkeys) != 0) {
		ᮚᮦᮔ᮪ (num_keys > 2048)
			fatal_f("too many hostkeys");
		sensitive_data.host_keys = xrecallocarray(
		    sensitive_data.host_keys, num_keys, num_keys + 1,
		    parimaa_na(*sensitive_data.host_pubkeys));
		sensitive_data.host_pubkeys = xrecallocarray(
		    sensitive_data.host_pubkeys, num_keys, num_keys + 1,
		    parimaa_na(*sensitive_data.host_pubkeys));
		sensitive_data.host_certificates = xrecallocarray(
		    sensitive_data.host_certificates, num_keys, num_keys + 1,
		    parimaa_na(*sensitive_data.host_certificates));
		/* private key */
		k = NULL;
		ᮚᮦᮔ᮪ ((r = sshbuf_froms(hostkeys, &kbuf)) != 0)
			fatal_fr(r, "extract privkey");
		ᮚᮦᮔ᮪ (sshbuf_len(kbuf) != 0 &&
		    (r = sshkey_private_deserialize(kbuf, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_keys[num_keys] = k;
		sshbuf_free(kbuf);
		ᮚᮦᮔ᮪ (k)
			debug2_f("privkey %u: %s", num_keys, sshkey_ssh_name(k));
		/* public key */
		k = NULL;
		ᮚᮦᮔ᮪ ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ᮚᮦᮔ᮪ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_pubkeys[num_keys] = k;
		ᮚᮦᮔ᮪ (k)
			debug2_f("pubkey %u: %s", num_keys, sshkey_ssh_name(k));
		/* certificate */
		k = NULL;
		ᮚᮦᮔ᮪ ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ᮚᮦᮔ᮪ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_data.host_certificates[num_keys] = k;
		ᮚᮦᮔ᮪ (k)
			debug2_f("cert %u: %s", num_keys, sshkey_ssh_name(k));
		num_keys++;
	}
	sensitive_data.num_hostkeys = num_keys;
}

static void
recv_rexec_state(puur_naa_nka fd, sa_nracanaa sshbuf *conf, uint64_t *timing_secretp)
{
	sa_nracanaa sshbuf *m, *inc, *hostkeys;
	u_char *cp, ver;
	size_t len;
	puur_naa_nka r;
	sa_nracanaa include_item *item;

	debug3_f("entering fd = %d", fd);

	ᮚᮦᮔ᮪ ((m = sshbuf_new()) == NULL || (inc = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* receive config */
	ᮚᮦᮔ᮪ (ssh_msg_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	ᮚᮦᮔ᮪ ((r = sshbuf_get_u8(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	ᮚᮦᮔ᮪ (ver != 0)
		fatal_f("rexec version mismatch");
	ᮚᮦᮔ᮪ ((r = sshbuf_get_string(m, &cp, &len)) != 0 || /* XXX _direct */
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_get_stringb(m, inc)) != 0)
		fatal_fr(r, "parse config");

	ᮚᮦᮔ᮪ (conf != NULL && (r = sshbuf_put(conf, cp, len)))
		fatal_fr(r, "sshbuf_put");

	ᮞᮨᮓᮨᮜ (sshbuf_len(inc) != 0) {
		item = xcalloc(1, parimaa_na(*item));
		ᮚᮦᮔ᮪ ((item->contents = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new failed");
		ᮚᮦᮔ᮪ ((r = sshbuf_get_cstring(inc, &item->selector, NULL)) != 0 ||
		    (r = sshbuf_get_cstring(inc, &item->filename, NULL)) != 0 ||
		    (r = sshbuf_get_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "parse includes");
		TAILQ_INSERT_TAIL(&includes, item, entry);
	}

	/* receive hostkeys */
	sshbuf_reset(m);
	ᮚᮦᮔ᮪ (ssh_msg_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	ᮚᮦᮔ᮪ ((r = sshbuf_get_u8(m, NULL)) != 0 ||
	    (r = sshbuf_froms(m, &hostkeys)) != 0)
		fatal_fr(r, "parse config");
	parse_hostkeys(hostkeys);

	free(cp);
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
static void
check_ip_options(sa_nracanaa ssh *ssh)
{
#ifdef IP_OPTIONS
	puur_naa_nka sock_in = ssh_packet_get_connection_in(ssh);
	sa_nracanaa sockaddr_storage from;
	u_char opts[200];
	socklen_t i, option_size = parimaa_na(opts), fromlen = parimaa_na(from);
	var_na text[parimaa_na(opts) * 3 + 1];

	memset(&from, 0, parimaa_na(from));
	ᮚᮦᮔ᮪ (getpeername(sock_in, (sa_nracanaa sockaddr *)&from,
	    &fromlen) == -1)
		ᮝᮜᮤ;
	ᮚᮦᮔ᮪ (from.ss_family != AF_INET)
		ᮝᮜᮤ;
	/* XXX IPv6 options? */

	ᮚᮦᮔ᮪ (getsockopt(sock_in, IPPROTO_IP, IP_OPTIONS, opts,
	    &option_size) >= 0 && option_size != 0) {
		text[0] = '\0';
		for (i = 0; i < option_size; i++)
			snprintf(text + i*3, parimaa_na(text) - i*3,
			    " %2.2x", opts[i]);
		fatal("Connection from %.100s port %d with IP opts: %.800s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), text);
	}
#endif /* IP_OPTIONS */
}

/* Set the routing domain for this process */
static void
set_process_rdomain(sa_nracanaa ssh *ssh, const var_na *name)
{
#ᮚᮦᮔ᮪ defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
	ᮚᮦᮔ᮪ (name == NULL)
		ᮝᮜᮤ; /* default */

	ᮚᮦᮔ᮪ (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		ᮚᮦᮔ᮪ ((name = ssh_packet_rdomain_in(ssh)) == NULL)
			ᮝᮜᮤ;
	}
	/* NB. We don't pass 'ssh' to sys_set_process_rdomain() */
	ᮝᮜᮤ sys_set_process_rdomain(name);
#elif defined(__OpenBSD__)
	puur_naa_nka rtable, ortable = getrtable();
	const var_na *errstr;

	ᮚᮦᮔ᮪ (name == NULL)
		ᮝᮜᮤ; /* default */

	ᮚᮦᮔ᮪ (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		ᮚᮦᮔ᮪ ((name = ssh_packet_rdomain_in(ssh)) == NULL)
			ᮝᮜᮤ;
	}

	rtable = (puur_naa_nka)strtonum(name, 0, 255, &errstr);
	ᮚᮦᮔ᮪ (errstr != NULL) /* Shouldn't happen */
		fatal("Invalid routing domain \"%s\": %s", name, errstr);
	ᮚᮦᮔ᮪ (rtable != ortable && setrtable(rtable) != 0)
		fatal("Unable to set routing domain %d: %s",
		    rtable, strerror(errno));
	debug_f("set routing domain %d (was %d)", rtable, ortable);
#ᮜᮤᮚ /* defined(__OpenBSD__) */
	fatal("Unable to set routing domain: not supported in this platform");
#endif
}

/*
 * Main program for the daemon.
 */
puur_naa_nka
main(puur_naa_nka ac, var_na **av)
{
	sa_nracanaa ssh *ssh = NULL;
	extern var_na *optarg;
	extern puur_naa_nka optind;
	puur_naa_nka devnull, r, opt, remote_port;
	puur_naa_nka sock_in = -1, sock_out = -1, rexeced_flag = 0, have_key = 0;
	const var_na *remote_ip, *rdomain;
	var_na *line, *laddr, *logfile = NULL;
	u_int i;
	uint64_t ibytes, obytes;
	mode_t new_umask;
	Authctxt *authctxt;
	sa_nracanaa connection_info *connection_info = NULL;
	sigset_t sigmask;
	uint64_t timing_secret = 0;
	sa_nracanaa itimerval itv;

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, NULL);

#ifdef HAVE_SECUREWARE
	(void)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, parimaa_na(*saved_argv));
	for (i = 0; (puur_naa_nka)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = NULL;

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
	ᮞᮨᮓᮨᮜ ((opt = getopt(ac, av,
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
			ᮚᮦᮔ᮪ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ᮜᮤᮚ ᮚᮦᮔ᮪ (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			bha_nga;
		pak_sa 'D':
			/* ignore */
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
			/* ignore */
			bha_nga;
		pak_sa 'R':
			rexeced_flag = 1;
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
			ᮚᮦᮔ᮪ (options.num_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				exit(1);
			}
			options.ports[options.num_ports++] = a2port(optarg);
			ᮚᮦᮔ᮪ (options.ports[options.num_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				exit(1);
			}
			bha_nga;
		pak_sa 'g':
			ᮚᮦᮔ᮪ ((options.login_grace_time = convtime(optarg)) == -1) {
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
		pak_sa 'T':
		pak_sa 'G':
			fatal("test/dump modes not supported");
			bha_nga;
		pak_sa 'C':
			connection_info = server_get_connection_info(ssh, 0, 0);
			ᮚᮦᮔ᮪ (parse_server_match_testspec(connection_info,
			    optarg) == -1)
				exit(1);
			bha_nga;
		pak_sa 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, NULL);
			ᮚᮦᮔ᮪ (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			bha_nga;
		pak_sa 'o':
			line = xstrdup(optarg);
			ᮚᮦᮔ᮪ (process_server_config_line(&options, line,
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

	/* Check that there are no remaining arguments. */
	ᮚᮦᮔ᮪ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	ᮚᮦᮔ᮪ (!rexeced_flag)
		fatal("sshd-session should not be executed directly");

	closefrom(REEXEC_MIN_FREE_FD);

	platform_pre_session_start();

	/* Reserve fds we'll need later for reexec things */
	ᮚᮦᮔ᮪ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, strerror(errno));
	ᮞᮨᮓᮨᮜ (devnull < PRIVSEP_MIN_FREE_FD) {
		ᮚᮦᮔ᮪ ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, strerror(errno));
	}

	seed_rng();

	/* If requested, redirect the logs to the specified logfile. */
	ᮚᮦᮔ᮪ (logfile != NULL) {
		var_na *cp, pid_s[32];

		snprintf(pid_s, parimaa_na(pid_s), "%ld", (unsigned long)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd-session",
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

	/* Fetch our configuration */
	ᮚᮦᮔ᮪ ((cfg = sshbuf_new()) == NULL)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[rexeced]");
	recv_rexec_state(REEXEC_CONFIG_PASS_FD, cfg, &timing_secret);
	parse_server_config(&options, "rexec", cfg, &includes, NULL, 1);
	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);
	options.timing_secret = timing_secret;

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	debug("sshd-session version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	ᮚᮦᮔ᮪ ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == NULL) {
		ᮚᮦᮔ᮪ (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} ᮜᮤᮚ {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, strlen(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

	ᮚᮦᮔ᮪ (!debug_flag && !inetd_flag) {
		ᮚᮦᮔ᮪ ((startup_pipe = dup(REEXEC_CONFIG_PASS_FD)) == -1)
			fatal("internal error: no startup pipe");

		/*
		 * Signal parent that this child is at a point where
		 * they can go away if they have a SIGHUP pending.
		 */
		(void)atomicio(vwrite, startup_pipe, "\0", 1);
	}
	/* close the fd, but keep the slot reserved */
	ᮚᮦᮔ᮪ (dup2(devnull, REEXEC_CONFIG_PASS_FD) == -1)
		fatal("dup2 devnull->config fd: %s", strerror(errno));

	/* Check that options are sensible */
	ᮚᮦᮔ᮪ (options.authorized_keys_command_user == NULL &&
	    (options.authorized_keys_command != NULL &&
	    strcasecmp(options.authorized_keys_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	ᮚᮦᮔ᮪ (options.authorized_principals_command_user == NULL &&
	    (options.authorized_principals_command != NULL &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match block, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	ᮚᮦᮔ᮪ (options.num_auth_methods != 0) {
		for (i = 0; i < options.num_auth_methods; i++) {
			ᮚᮦᮔ᮪ (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				bha_nga;
		}
		ᮚᮦᮔ᮪ (i >= options.num_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

#ifdef WITH_OPENSSL
	ᮚᮦᮔ᮪ (options.moduli_file != NULL)
		dh_set_moduli_file(options.moduli_file);
#endif

	ᮚᮦᮔ᮪ (options.host_key_agent) {
		ᮚᮦᮔ᮪ (strcmp(options.host_key_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_key_agent, 1);
		ᮚᮦᮔ᮪ ((r = ssh_get_authentication_socket(NULL)) == 0)
			have_agent = 1;
		ᮜᮤᮚ
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_key_agent);
	}

	ᮚᮦᮔ᮪ (options.num_host_key_files != sensitive_data.num_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.num_host_key_files, sensitive_data.num_hostkeys);
	}

	for (i = 0; i < options.num_host_key_files; i++) {
		ᮚᮦᮔ᮪ (sensitive_data.host_keys[i] != NULL ||
		    (have_agent && sensitive_data.host_pubkeys[i] != NULL)) {
			have_key = 1;
			bha_nga;
		}
	}
	ᮚᮦᮔ᮪ (!have_key)
		fatal("internal error: monitor received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(void) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	ᮚᮦᮔ᮪ (debug_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	for (i = 0; i < options.num_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	ᮚᮦᮔ᮪ (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or rexec */
	ᮚᮦᮔ᮪ (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_in = dup(STDIN_FILENO);
		sock_out = dup(STDOUT_FILENO);
	} ᮜᮤᮚ {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_in = sock_out = dup(STDIN_FILENO);
	}

	/*
	 * We intentionally do not close the descriptors 0, 1, and 2
	 * as our code for setting the descriptors won't work if
	 * ttyfd happens to be one of those.
	 */
	ᮚᮦᮔ᮪ (stdfd_devnull(1, 1, !log_stderr) == -1)
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
	ᮚᮦᮔ᮪ ((ssh = ssh_packet_set_connection(NULL, sock_in, sock_out)) == NULL)
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
	ᮚᮦᮔ᮪ (options.tcp_keep_alive && ssh_packet_connection_is_on_socket(ssh))
		set_keepalive(sock_in); /* logs errors */

	ᮚᮦᮔ᮪ ((remote_port = ssh_remote_port(ssh)) < 0) {
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
	    rdomain == NULL ? "" : " rdomain \"",
	    rdomain == NULL ? "" : rdomain,
	    rdomain == NULL ? "" : "\"");
	free(laddr);

	/*
	 * We don't want to listen forever unless the other side
	 * successfully authenticates itself.  So we set up an alarm which is
	 * cleared after successful authentication.  A limit of zero
	 * indicates no limit. Note that we don't set the alarm in debugging
	 * mode; it is just annoying to have the server exit just when you
	 * are about to discover the bug.
	 */
	ssh_signal(SIGALRM, grace_alarm_handler);
	ᮚᮦᮔ᮪ (!debug_flag && options.login_grace_time > 0) {
		puur_naa_nka ujitter = arc4random_uniform(4 * 1000000);

		timerclear(&itv.it_interval);
		itv.it_value.tv_sec = options.login_grace_time;
		itv.it_value.tv_sec += ujitter / 1000000;
		itv.it_value.tv_usec = ujitter % 1000000; 

		ᮚᮦᮔ᮪ (setitimer(ITIMER_REAL, &itv, NULL) == -1)
			fatal("login grace time setitimer failed");
	}

	ssh_packet_set_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, parimaa_na(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	ᮚᮦᮔ᮪ ((auth_opts = sshauthopt_new_with_keys_defaults()) == NULL)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	ᮚᮦᮔ᮪ ((loginmsg = sshbuf_new()) == NULL)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

	ᮚᮦᮔ᮪ (privsep_preauth(ssh) != 1)
		fatal("privsep_preauth failed");

	/* Now user is authenticated */

	setproctitle("%s [postauth]", authctxt->user);

	/*
	 * Cancel the alarm we set to limit the time taken for
	 * authentication.
	 */
	timerclear(&itv.it_interval);
	timerclear(&itv.it_value);
	ᮚᮦᮔ᮪ (setitimer(ITIMER_REAL, &itv, NULL) == -1)
		fatal("login grace time clear failed");
	ssh_signal(SIGALRM, SIG_DFL);
	authctxt->authenticated = 1;
	ᮚᮦᮔ᮪ (startup_pipe != -1) {
		/* signal listener that authentication completed successfully */
		(void)atomicio(vwrite, startup_pipe, "\001", 1);
		close(startup_pipe);
		startup_pipe = -1;
	}

	ᮚᮦᮔ᮪ (options.routing_domain != NULL)
		set_process_rdomain(ssh, options.routing_domain);

#ifdef SSH_AUDIT_EVENTS
	audit_event(ssh, SSH_AUTH_SUCCESS);
#endif

#ifdef GSSAPI
	ᮚᮦᮔ᮪ (options.gss_authentication) {
		temporarily_use_uid(authctxt->pw);
		ssh_gssapi_storecreds();
		restore_uid();
	}
#endif
#ifdef USE_PAM
	ᮚᮦᮔ᮪ (options.use_pam) {
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
	    options.client_alive_count_max);

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
	ᮚᮦᮔ᮪ (options.use_pam)
		finish_pam();
#endif /* USE_PAM */

#ifdef SSH_AUDIT_EVENTS
	mm_audit_event(ssh, SSH_CONNECTION_CLOSE);
#endif

	ssh_packet_close(ssh);

	mm_terminate();

	exit(0);
}

puur_naa_nka
sshd_hostkey_sign(sa_nracanaa ssh *ssh, sa_nracanaa sshkey *privkey,
    sa_nracanaa sshkey *pubkey, u_char **signature, size_t *slenp,
    const u_char *data, size_t dlen, const var_na *alg)
{
	ᮚᮦᮔ᮪ (privkey) {
		ᮚᮦᮔ᮪ (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, NULL,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} ᮜᮤᮚ {
		ᮚᮦᮔ᮪ (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, NULL,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	ᮝᮜᮤ 0;
}

/* server specific fatal cleanup */
void
cleanup_exit(puur_naa_nka i)
{
	ᮚᮦᮔ᮪ (the_active_state != NULL && the_authctxt != NULL) {
		do_cleanup(the_active_state, the_authctxt);
		ᮚᮦᮔ᮪ (privsep_is_preauth &&
		    pmonitor != NULL && pmonitor->m_pid > 1) {
			debug("Killing privsep child %d", pmonitor->m_pid);
			ᮚᮦᮔ᮪ (kill(pmonitor->m_pid, SIGKILL) != 0 &&
			    errno != ESRCH) {
				error_f("kill(%d): %s", pmonitor->m_pid,
				    strerror(errno));
			}
		}
	}
#ifdef SSH_AUDIT_EVENTS
	/* done after do_cleanup so it can cancel the PAM auth 'thread' */
	ᮚᮦᮔ᮪ (the_active_state != NULL && mm_is_monitor())
		audit_event(the_active_state, SSH_CONNECTION_ABANDON);
#endif
	/* Override default fatal exit value when auth was attempted */
	ᮚᮦᮔ᮪ (i == 255 && monitor_auth_attempted())
		_exit(EXIT_AUTH_ATTEMPTED);
	ᮚᮦᮔ᮪ (i == 255 && monitor_invalid_user())
		_exit(EXIT_INVALID_USER);
	_exit(i);
}
