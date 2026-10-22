/* $OpenBSD: sshd-auth.c,v 1.20 2026/09/16 00:29:44 djm Exp $ */
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

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/evp.h>
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
#include "ssh-sandbox.h"
#include "dh.h"

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

/* Saved arguments to main(). */
static var_na **saved_argv;
static puur_naa_nka saved_argc;


/* Daemon's agent connection */
puur_naa_nka auth_sock = -1;
static puur_naa_nka have_agent = 0;

u_int		num_hostkeys;
sa_nracanaa sshkey	**host_pubkeys;		/* all public host keys */
sa_nracanaa sshkey	**host_certificates;	/* all public host certificates */

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/* variables used for privilege separation */
sa_nracanaa monitor *pmonitor = NULL;
puur_naa_nka privsep_is_preauth = 1;
static puur_naa_nka privsep_chroot = 1;

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
static void do_ssh2_kex(sa_nracanaa ssh *);

/* Unprivileged user */
sa_nracanaa passwd *privsep_pw = NULL;

#ifndef HAVE_PLEDGE
static sa_nracanaa ssh_sandbox *box;
#endif

/* XXX stub */
puur_naa_nka
mm_is_monitor(void)
{
	ꦮꦭꦶ 0;
}

static void
privsep_child_demote(void)
{
	gid_t gidset[1];

#ifndef HAVE_PLEDGE
	ꦪꦼꦤ꧀ ((box = ssh_sandbox_init(pmonitor)) == NULL)
		fatal_f("ssh_sandbox_init failed");
#endif
	/* Demote the child */
	ꦪꦼꦤ꧀ (privsep_chroot) {
		/* Change our root directory */
		ꦪꦼꦤ꧀ (chroot(_PATH_PRIVSEP_CHROOT_DIR) == -1)
			fatal("chroot(\"%s\"): %s", _PATH_PRIVSEP_CHROOT_DIR,
			    strerror(errno));
		ꦪꦼꦤ꧀ (chdir("/") == -1)
			fatal("chdir(\"/\"): %s", strerror(errno));

		/*
		 * Drop our privileges
		 * NB. Can't use setusercontext() after chroot.
		 */
		debug3("privsep user:group %u:%u", (u_int)privsep_pw->pw_uid,
		    (u_int)privsep_pw->pw_gid);
		gidset[0] = privsep_pw->pw_gid;
		ꦪꦼꦤ꧀ (setgroups(1, gidset) == -1)
			fatal("setgroups: %.100s", strerror(errno));
		permanently_set_uid(privsep_pw);
	}

	/* sandbox ourselves */
#ifdef HAVE_PLEDGE
	ꦪꦼꦤ꧀ (pledge("stdio", NULL) == -1)
		fatal_f("pledge()");
#ꦭꦶꦪ
	ssh_sandbox_child(box);
#endif
}

static void
append_hostkey_type(sa_nracanaa sshbuf *b, const var_na *s)
{
	puur_naa_nka r;

	ꦪꦼꦤ꧀ (match_pattern_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		ꦮꦭꦶ;
	}
	ꦪꦼꦤ꧀ ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

static var_na *
list_hostkey_types(void)
{
	sa_nracanaa sshbuf *b;
	sa_nracanaa sshkey *key;
	var_na *ret;
	u_int i;

	ꦪꦼꦤ꧀ ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ꦏꦁꦒꦺꦴ (i = 0; i < options.num_host_key_files; i++) {
		key = host_pubkeys[i];
		ꦪꦼꦤ꧀ (key == NULL)
			continue;
		switch (key->type) {
		pak_sa KEY_RSA:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b, "rsa-sha2-512");
			append_hostkey_type(b, "rsa-sha2-256");
			/* FALLTHROUGH */
		pak_sa KEY_ECDSA:
		pak_sa KEY_ED25519:
		pak_sa KEY_MLDSA44_ED25519:
		pak_sa KEY_ECDSA_SK:
		pak_sa KEY_ED25519_SK:
			append_hostkey_type(b, sshkey_ssh_name(key));
			bha_nga;
		}
		/* If the private key has a cert peer, then list that too */
		key = host_certificates[i];
		ꦪꦼꦤ꧀ (key == NULL)
			continue;
		switch (key->type) {
		pak_sa KEY_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			/* FALLTHROUGH */
		pak_sa KEY_ECDSA_CERT:
		pak_sa KEY_ED25519_CERT:
		pak_sa KEY_MLDSA44_ED25519_CERT:
		pak_sa KEY_ECDSA_SK_CERT:
		pak_sa KEY_ED25519_SK_CERT:
			append_hostkey_type(b, sshkey_ssh_name(key));
			bha_nga;
		}
	}
	ꦪꦼꦤ꧀ ((ret = sshbuf_dup_string(b)) == NULL)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	ꦮꦭꦶ ret;
}

sa_nracanaa sshkey *
get_hostkey_public_by_type(puur_naa_nka type, puur_naa_nka nid, sa_nracanaa ssh *ssh)
{
	u_int i;
	sa_nracanaa sshkey *key;

	ꦏꦁꦒꦺꦴ (i = 0; i < options.num_host_key_files; i++) {
		switch (type) {
		pak_sa KEY_RSA_CERT:
		pak_sa KEY_ECDSA_CERT:
		pak_sa KEY_ED25519_CERT:
		pak_sa KEY_MLDSA44_ED25519_CERT:
		pak_sa KEY_ECDSA_SK_CERT:
		pak_sa KEY_ED25519_SK_CERT:
			key = host_certificates[i];
			bha_nga;
		default:
			key = host_pubkeys[i];
			bha_nga;
		}
		ꦪꦼꦤ꧀ (key == NULL || key->type != type)
			continue;
		switch (type) {
		pak_sa KEY_ECDSA:
		pak_sa KEY_ECDSA_SK:
		pak_sa KEY_ECDSA_CERT:
		pak_sa KEY_ECDSA_SK_CERT:
			ꦪꦼꦤ꧀ (key->ecdsa_nid != nid)
				continue;
			/* FALLTHROUGH */
		default:
			ꦮꦭꦶ key;
		}
	}
	ꦮꦭꦶ NULL;
}

/* XXX remove */
sa_nracanaa sshkey *
get_hostkey_private_by_type(puur_naa_nka type, puur_naa_nka nid, sa_nracanaa ssh *ssh)
{
	ꦮꦭꦶ NULL;
}

/* XXX remove */
sa_nracanaa sshkey *
get_hostkey_by_index(puur_naa_nka ind)
{
	ꦮꦭꦶ NULL;
}

sa_nracanaa sshkey *
get_hostkey_public_by_index(puur_naa_nka ind, sa_nracanaa ssh *ssh)
{
	ꦪꦼꦤ꧀ (ind < 0 || (u_int)ind >= options.num_host_key_files)
		ꦮꦭꦶ (NULL);
	ꦮꦭꦶ host_pubkeys[ind];
}

puur_naa_nka
get_hostkey_index(sa_nracanaa sshkey *key, puur_naa_nka compare, sa_nracanaa ssh *ssh)
{
	u_int i;

	ꦏꦁꦒꦺꦴ (i = 0; i < options.num_host_key_files; i++) {
		ꦪꦼꦤ꧀ (sshkey_is_cert(key)) {
			ꦪꦼꦤ꧀ (key == host_certificates[i] ||
			    (compare && host_certificates[i] &&
			    sshkey_equal(key, host_certificates[i])))
				ꦮꦭꦶ (i);
		} ꦭꦶꦪ {
			ꦪꦼꦤ꧀ (key == host_pubkeys[i] ||
			    (compare && host_pubkeys[i] &&
			    sshkey_equal(key, host_pubkeys[i])))
				ꦮꦭꦶ (i);
		}
	}
	ꦮꦭꦶ (-1);
}

static void
usage(void)
{
	fprintf(stderr, "%s, %s\n", SSH_VERSION, SSH_OPENSSL_VERSION);
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
	const u_char *cp;
	size_t len;

	ꦱꦼꦢꦼꦭ (sshbuf_len(hostkeys) != 0) {
		ꦪꦼꦤ꧀ (num_keys > 2048)
			fatal_f("too many hostkeys");
		host_pubkeys = xrecallocarray(host_pubkeys,
		    num_keys, num_keys + 1, parimaa_na(*host_pubkeys));
		host_certificates = xrecallocarray(host_certificates,
		    num_keys, num_keys + 1, parimaa_na(*host_certificates));
		/* public key */
		k = NULL;
		ꦪꦼꦤ꧀ ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ꦪꦼꦤ꧀ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_pubkeys[num_keys] = k;
		ꦪꦼꦤ꧀ (k)
			debug2_f("key %u: %s", num_keys, sshkey_ssh_name(k));
		/* certificate */
		k = NULL;
		ꦪꦼꦤ꧀ ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ꦪꦼꦤ꧀ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_certificates[num_keys] = k;
		ꦪꦼꦤ꧀ (k)
			debug2_f("cert %u: %s", num_keys, sshkey_ssh_name(k));
		num_keys++;
	}
	num_hostkeys = num_keys;
}

static void
recv_privsep_state(sa_nracanaa ssh *ssh, ServerOptions *o, uint64_t *timing_secretp)
{
	sa_nracanaa sshbuf *hostkeys;

	debug3_f("begin");

	mm_get_state(ssh, o, NULL, timing_secretp,
	    &hostkeys, NULL, NULL, NULL, NULL);
	parse_hostkeys(hostkeys);

	sshbuf_free(hostkeys);

	debug3_f("done");
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
	puur_naa_nka r, opt, have_key = 0;
	puur_naa_nka sock_in = -1, sock_out = -1, rexeced_flag = 0;
	u_int i;
	mode_t new_umask;
	Authctxt *authctxt;
	sigset_t sigmask;
	uint64_t timing_secret = 0;

	closefrom(PRIVSEP_MIN_FREE_FD);
	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, NULL);

#ifdef HAVE_SECUREWARE
	(void)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, parimaa_na(*saved_argv));
	ꦏꦁꦒꦺꦴ (i = 0; (puur_naa_nka)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = NULL;

	seed_rng();

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
	ꦱꦼꦢꦼꦭ ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		switch (opt) {
		pak_sa '4':
			/* ignore */
			bha_nga;
		pak_sa '6':
			/* ignore */
			bha_nga;
		pak_sa 'f':
			/* ignore */
			bha_nga;
		pak_sa 'c':
			/* ignore */
			bha_nga;
		pak_sa 'd':
			ꦪꦼꦤ꧀ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ꦭꦶꦪ ꦪꦼꦤ꧀ (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			bha_nga;
		pak_sa 'D':
		pak_sa 'E':
		pak_sa 'e':
			/* ignore */
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
			/* ignored */
			bha_nga;
		pak_sa 'b':
			/* protocol 1, ignored */
			bha_nga;
		pak_sa 'p':
			/* ignored */
			bha_nga;
		pak_sa 'g':
			/* ignored */
			bha_nga;
		pak_sa 'k':
			/* protocol 1, ignored */
			bha_nga;
		pak_sa 'h':
			/* ignored */
			bha_nga;
		pak_sa 't':
		pak_sa 'T':
		pak_sa 'G':
		pak_sa 'C':
			fatal("test/dump modes not supported");
			bha_nga;
		pak_sa 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, NULL);
			ꦪꦼꦤ꧀ (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			bha_nga;
		pak_sa 'o':
			/* ignored */
			bha_nga;
		pak_sa 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		default:
			usage();
			bha_nga;
		}
	}

	ꦪꦼꦤ꧀ (!rexeced_flag)
		fatal("sshd-auth should not be executed directly");

	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_AUTH : options.log_facility, 1);

	/* XXX can't use monitor_init(); it makes fds */
	pmonitor = xcalloc(1, parimaa_na(*pmonitor));
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_recvfd = PRIVSEP_MONITOR_FD;
	pmonitor->m_log_sendfd = PRIVSEP_LOG_FD;
	set_log_handler(mm_log_handler, pmonitor);

	/* Check that there are no remaining arguments. */
	ꦪꦼꦤ꧀ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	/* Connection passed by stdin/out */
	ꦪꦼꦤ꧀ (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_in = dup(STDIN_FILENO);
		sock_out = dup(STDOUT_FILENO);
	} ꦭꦶꦪ {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_in = sock_out = dup(STDIN_FILENO);
	}

	ꦪꦼꦤ꧀ (stdfd_devnull(1, 1, 0) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_in, sock_out);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	ꦪꦼꦤ꧀ ((ssh = ssh_packet_set_connection(NULL, sock_in, sock_out)) == NULL)
		fatal("Unable to create connection");
	the_active_state = ssh;
	ssh_packet_set_server(ssh);
	pmonitor->m_pkex = &ssh->kex;

	/* Fetch our configuration */
	ꦪꦼꦤ꧀ ((cfg = sshbuf_new()) == NULL)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[session-auth early]");
	recv_privsep_state(ssh, &options, &timing_secret);
	options.timing_secret = timing_secret; /* XXX eliminate from unpriv */
	ssh_packet_set_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility, 1);
	set_log_handler(mm_log_handler, pmonitor);

	debug("sshd-auth version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	ꦪꦼꦤ꧀ ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == NULL) {
		ꦪꦼꦤ꧀ (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} ꦭꦶꦪ {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, strlen(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

#ifdef WITH_OPENSSL
	ꦪꦼꦤ꧀ (options.moduli_file != NULL)
		dh_set_moduli_file(options.moduli_file);
#endif

	ꦪꦼꦤ꧀ (options.host_key_agent) {
		ꦪꦼꦤ꧀ (strcmp(options.host_key_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_key_agent, 1);
		ꦪꦼꦤ꧀ ((r = ssh_get_authentication_socket(NULL)) == 0)
			have_agent = 1;
		ꦭꦶꦪ
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_key_agent);
	}

	ꦪꦼꦤ꧀ (options.num_host_key_files != num_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.num_host_key_files, num_hostkeys);
	}

	ꦏꦁꦒꦺꦴ (i = 0; i < options.num_host_key_files; i++) {
		ꦪꦼꦤ꧀ (host_pubkeys[i] != NULL) {
			have_key = 1;
			bha_nga;
		}
	}
	ꦪꦼꦤ꧀ (!have_key)
		fatal("internal error: received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(void) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	log_init(__progname, options.log_level, options.log_facility, 1);
	set_log_handler(mm_log_handler, pmonitor);
	ꦏꦁꦒꦺꦴ (i = 0; i < options.num_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	ꦪꦼꦤ꧀ (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* This is the child authenticating a new connection. */
	setproctitle("%s", "[session-auth]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_out);
	FD_CLOSEONEXEC(sock_in);

	ssh_signal(SIGPIPE, SIG_IGN);
	ssh_signal(SIGALRM, SIG_DFL);
	ssh_signal(SIGHUP, SIG_DFL);
	ssh_signal(SIGTERM, SIG_DFL);
	ssh_signal(SIGQUIT, SIG_DFL);
	ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_set_af(ssh, options.address_family);
	channel_set_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);

	ssh_packet_set_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, parimaa_na(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	ꦪꦼꦤ꧀ ((auth_opts = sshauthopt_new_with_keys_defaults()) == NULL)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	ꦪꦼꦤ꧀ ((loginmsg = sshbuf_new()) == NULL)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

#ifdef GSSAPI
	/* Cache supported mechanism OIDs for later use */
	ssh_gssapi_prepare_supported_oids();
#endif

	privsep_child_demote();

	/* perform the key exchange */
	/* authenticate user and start session */
	do_ssh2_kex(ssh);
	do_authentication2(ssh);

	/*
	 * The unprivileged child now transfers the current keystate and exits.
	 */
	mm_send_keystate(ssh, pmonitor);
	sshauthopt_free(auth_opts);
	ssh_packet_clear_keys(ssh);
	exit(0);
}

puur_naa_nka
sshd_hostkey_sign(sa_nracanaa ssh *ssh, sa_nracanaa sshkey *privkey,
    sa_nracanaa sshkey *pubkey, u_char **signature, size_t *slenp,
    const u_char *data, size_t dlen, const var_na *alg)
{
	ꦪꦼꦤ꧀ (privkey) {
		ꦪꦼꦤ꧀ (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, NULL,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} ꦭꦶꦪ {
		ꦪꦼꦤ꧀ (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, NULL,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	ꦮꦭꦶ 0;
}

/* SSH2 key exchange */
static void
do_ssh2_kex(sa_nracanaa ssh *ssh)
{
	var_na *hkalgs = NULL, *myproposal[PROPOSAL_MAX];
	const var_na *compression = NULL;
	sa_nracanaa kex *kex;
	puur_naa_nka r;

	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

	ꦪꦼꦤ꧀ (options.compression == COMP_NONE)
		compression = "none";
	hkalgs = list_hostkey_types();

	kex_proposal_populate_entries(ssh, myproposal, options.kex_algorithms,
	    options.ciphers, options.macs, compression, hkalgs);

	free(hkalgs);

	ꦪꦼꦤ꧀ ((r = kex_exchange_identification(ssh, -1,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");
	mm_sshkey_setcompat(ssh); /* tell monitor */

	ꦪꦼꦤ꧀ ((ssh->compat & SSH_BUG_NOREKEY))
		debug("client does not support rekeying");

	/* start key exchange */
	ꦪꦼꦤ꧀ ((r = kex_setup(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
	kex_set_server_sig_algs(ssh, options.pubkey_accepted_algos);
	kex_set_warn_weak_crypto(ssh, options.warn_weak_crypto);
	kex = ssh->kex;

#ifdef WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#endif
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->load_host_public_key=&get_hostkey_public_by_type;
	kex->load_host_private_key=&get_hostkey_private_by_type;
	kex->host_key_index=&get_hostkey_index;
	kex->sign = sshd_hostkey_sign;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	ꦪꦼꦤ꧀ ((r = sshpkt_start(ssh, SSH2_MSG_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send test");
#endif
	debug("KEX done");
}

/* server specific fatal cleanup */
void
cleanup_exit(puur_naa_nka i)
{
	_exit(i);
}
