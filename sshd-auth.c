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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/ioctl.h>
#અન્તર્ભાવ <sys/wait.h>
#અન્તર્ભાવ <sys/tree.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/time.h>
#અન્તર્ભાવ <sys/queue.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <grp.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <limits.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/evp.h>
#endif

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "sshpty.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "uidswap.h"
#અન્તર્ભાવ "compat.h"
#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "msg.h"
#અન્તર્ભાવ "dispatch.h"
#અન્તર્ભાવ "channels.h"
#અન્તર્ભાવ "session.h"
#અન્તર્ભાવ "monitor.h"
#ifdef GSSAPI
#અન્તર્ભાવ "ssh-gss.h"
#endif
#અન્તર્ભાવ "monitor_wrap.h"
#અન્તર્ભાવ "auth-options.h"
#અન્તર્ભાવ "version.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sk-api.h"
#અન્તર્ભાવ "srclimit.h"
#અન્તર્ભાવ "ssh-sandbox.h"
#અન્તર્ભાવ "dh.h"

/* Privsep fds */
#define PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#define PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#define PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

બાહ્ય અક્ષર *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
અક્ષર *config_file_name = _PATH_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
પૂર્ણાંક debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
સ્થિર પૂર્ણાંક inetd_flag = 0;

/* Saved arguments to main(). */
સ્થિર અક્ષર **saved_argv;
સ્થિર પૂર્ણાંક saved_argc;


/* Daemon's agent connection */
પૂર્ણાંક auth_sock = -1;
સ્થિર પૂર્ણાંક have_agent = 0;

u_int		અંક_hostkeys;
સંરચના sshkey	**host_pubkeys;		/* all public host keys */
સંરચના sshkey	**host_certificates;	/* all public host certificates */

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/* variables used for privilege separation */
સંરચના monitor *pmonitor = ખાલી;
પૂર્ણાંક privsep_is_preauth = 1;
સ્થિર પૂર્ણાંક privsep_chroot = 1;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = ખાલી;
સંરચના ssh *the_active_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
સંરચના sshauthopt *auth_opts = ખાલી;

/* sshd_config buffer */
સંરચના sshbuf *cfg;

/* Included files from the configuration file */
સંરચના include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
સંરચના sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
સ્થિર શૂન્ય do_ssh2_kex(સંરચના ssh *);

/* Unprivileged user */
સંરચના passwd *privsep_pw = ખાલી;

#ifndef HAVE_PLEDGE
સ્થિર સંરચના ssh_sandbox *box;
#endif

/* XXX stub */
પૂર્ણાંક
mm_is_monitor(શૂન્ય)
{
	પાછા 0;
}

સ્થિર શૂન્ય
privsep_child_demote(શૂન્ય)
{
	gid_t gidset[1];

#ifndef HAVE_PLEDGE
	જો ((box = ssh_sandbox_init(pmonitor)) == ખાલી)
		fatal_f("ssh_sandbox_init failed");
#endif
	/* Demote the child */
	જો (privsep_chroot) {
		/* Change our root directory */
		જો (chroot(_PATH_PRIVSEP_CHROOT_DIR) == -1)
			fatal("chroot(\"%s\"): %s", _PATH_PRIVSEP_CHROOT_DIR,
			    strerror(errno));
		જો (chdir("/") == -1)
			fatal("chdir(\"/\"): %s", strerror(errno));

		/*
		 * Drop our privileges
		 * NB. Can't use setusercontext() after chroot.
		 */
		debug3("privsep user:group %u:%u", (u_int)privsep_pw->pw_uid,
		    (u_int)privsep_pw->pw_gid);
		gidset[0] = privsep_pw->pw_gid;
		જો (setgroups(1, gidset) == -1)
			fatal("setgroups: %.100s", strerror(errno));
		permanently_set_uid(privsep_pw);
	}

	/* sandbox ourselves */
#ifdef HAVE_PLEDGE
	જો (pledge("stdio", ખાલી) == -1)
		fatal_f("pledge()");
#નહીંતર
	ssh_sandbox_child(box);
#endif
}

સ્થિર શૂન્ય
append_hostkey_type(સંરચના sshbuf *b, અચલ અક્ષર *s)
{
	પૂર્ણાંક r;

	જો (match_pattern_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		પાછા;
	}
	જો ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

સ્થિર અક્ષર *
list_hostkey_types(શૂન્ય)
{
	સંરચના sshbuf *b;
	સંરચના sshkey *ચાવી;
	અક્ષર *ret;
	u_int i;

	જો ((b = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	માટે (i = 0; i < options.અંક_host_ચાવી_files; i++) {
		ચાવી = host_pubkeys[i];
		જો (ચાવી == ખાલી)
			ચાલુ;
		પસંદગી (ચાવી->type) {
		સ્થિતિ ચાવી_RSA:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b, "rsa-sha2-512");
			append_hostkey_type(b, "rsa-sha2-256");
			/* FALLTHROUGH */
		સ્થિતિ ચાવી_ECDSA:
		સ્થિતિ ચાવી_ED25519:
		સ્થિતિ ચાવી_MLDSA44_ED25519:
		સ્થિતિ ચાવી_ECDSA_SK:
		સ્થિતિ ચાવી_ED25519_SK:
			append_hostkey_type(b, sshkey_ssh_name(ચાવી));
			તોડો;
		}
		/* If the private key has a cert peer, then list that too */
		ચાવી = host_certificates[i];
		જો (ચાવી == ખાલી)
			ચાલુ;
		પસંદગી (ચાવી->type) {
		સ્થિતિ ચાવી_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			/* FALLTHROUGH */
		સ્થિતિ ચાવી_ECDSA_CERT:
		સ્થિતિ ચાવી_ED25519_CERT:
		સ્થિતિ ચાવી_MLDSA44_ED25519_CERT:
		સ્થિતિ ચાવી_ECDSA_SK_CERT:
		સ્થિતિ ચાવી_ED25519_SK_CERT:
			append_hostkey_type(b, sshkey_ssh_name(ચાવી));
			તોડો;
		}
	}
	જો ((ret = sshbuf_dup_string(b)) == ખાલી)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	પાછા ret;
}

સંરચના sshkey *
get_hostkey_public_by_type(પૂર્ણાંક type, પૂર્ણાંક nid, સંરચના ssh *ssh)
{
	u_int i;
	સંરચના sshkey *ચાવી;

	માટે (i = 0; i < options.અંક_host_ચાવી_files; i++) {
		પસંદગી (type) {
		સ્થિતિ ચાવી_RSA_CERT:
		સ્થિતિ ચાવી_ECDSA_CERT:
		સ્થિતિ ચાવી_ED25519_CERT:
		સ્થિતિ ચાવી_MLDSA44_ED25519_CERT:
		સ્થિતિ ચાવી_ECDSA_SK_CERT:
		સ્થિતિ ચાવી_ED25519_SK_CERT:
			ચાવી = host_certificates[i];
			તોડો;
		મૂળભૂત:
			ચાવી = host_pubkeys[i];
			તોડો;
		}
		જો (ચાવી == ખાલી || ચાવી->type != type)
			ચાલુ;
		પસંદગી (type) {
		સ્થિતિ ચાવી_ECDSA:
		સ્થિતિ ચાવી_ECDSA_SK:
		સ્થિતિ ચાવી_ECDSA_CERT:
		સ્થિતિ ચાવી_ECDSA_SK_CERT:
			જો (ચાવી->ecdsa_nid != nid)
				ચાલુ;
			/* FALLTHROUGH */
		મૂળભૂત:
			પાછા ચાવી;
		}
	}
	પાછા ખાલી;
}

/* XXX remove */
સંરચના sshkey *
get_hostkey_private_by_type(પૂર્ણાંક type, પૂર્ણાંક nid, સંરચના ssh *ssh)
{
	પાછા ખાલી;
}

/* XXX remove */
સંરચના sshkey *
get_hostkey_by_index(પૂર્ણાંક ind)
{
	પાછા ખાલી;
}

સંરચના sshkey *
get_hostkey_public_by_index(પૂર્ણાંક ind, સંરચના ssh *ssh)
{
	જો (ind < 0 || (u_int)ind >= options.અંક_host_ચાવી_files)
		પાછા (ખાલી);
	પાછા host_pubkeys[ind];
}

પૂર્ણાંક
get_hostkey_index(સંરચના sshkey *ચાવી, પૂર્ણાંક compare, સંરચના ssh *ssh)
{
	u_int i;

	માટે (i = 0; i < options.અંક_host_ચાવી_files; i++) {
		જો (sshkey_is_cert(ચાવી)) {
			જો (ચાવી == host_certificates[i] ||
			    (compare && host_certificates[i] &&
			    sshkey_equal(ચાવી, host_certificates[i])))
				પાછા (i);
		} નહીંતર {
			જો (ચાવી == host_pubkeys[i] ||
			    (compare && host_pubkeys[i] &&
			    sshkey_equal(ચાવી, host_pubkeys[i])))
				પાછા (i);
		}
	}
	પાછા (-1);
}

સ્થિર શૂન્ય
usage(શૂન્ય)
{
	fprintf(stderr, "%s, %s\n", SSH_VERSION, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

સ્થિર શૂન્ય
parse_hostkeys(સંરચના sshbuf *hostkeys)
{
	પૂર્ણાંક r;
	u_int અંક_ચાવીઓ = 0;
	સંરચના sshkey *k;
	અચલ u_char *cp;
	size_t len;

	જ્યારે (sshbuf_len(hostkeys) != 0) {
		જો (અંક_ચાવીઓ > 2048)
			fatal_f("too many hostkeys");
		host_pubkeys = xrecallocarray(host_pubkeys,
		    અંક_ચાવીઓ, અંક_ચાવીઓ + 1, કદ(*host_pubkeys));
		host_certificates = xrecallocarray(host_certificates,
		    અંક_ચાવીઓ, અંક_ચાવીઓ + 1, કદ(*host_certificates));
		/* public key */
		k = ખાલી;
		જો ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		જો (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_pubkeys[અંક_ચાવીઓ] = k;
		જો (k)
			debug2_f("key %u: %s", અંક_ચાવીઓ, sshkey_ssh_name(k));
		/* certificate */
		k = ખાલી;
		જો ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		જો (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_certificates[અંક_ચાવીઓ] = k;
		જો (k)
			debug2_f("cert %u: %s", અંક_ચાવીઓ, sshkey_ssh_name(k));
		અંક_ચાવીઓ++;
	}
	અંક_hostkeys = અંક_ચાવીઓ;
}

સ્થિર શૂન્ય
recv_privsep_state(સંરચના ssh *ssh, ServerOptions *o, uint64_t *timing_secretp)
{
	સંરચના sshbuf *hostkeys;

	debug3_f("begin");

	mm_get_state(ssh, o, ખાલી, timing_secretp,
	    &hostkeys, ખાલી, ખાલી, ખાલી, ખાલી);
	parse_hostkeys(hostkeys);

	sshbuf_free(hostkeys);

	debug3_f("done");
}

/*
 * Main program for the daemon.
 */
પૂર્ણાંક
મુખ્ય(પૂર્ણાંક ac, અક્ષર **av)
{
	સંરચના ssh *ssh = ખાલી;
	બાહ્ય અક્ષર *optarg;
	બાહ્ય પૂર્ણાંક optind;
	પૂર્ણાંક r, opt, have_ચાવી = 0;
	પૂર્ણાંક sock_in = -1, sock_out = -1, rexeced_flag = 0;
	u_int i;
	mode_t new_umask;
	Authctxt *authctxt;
	sigset_t sigmask;
	uint64_t timing_secret = 0;

	closefrom(PRIVSEP_MIN_FREE_FD);
	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ખાલી);

#ifdef HAVE_SECUREWARE
	(શૂન્ય)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, કદ(*saved_argv));
	માટે (i = 0; (પૂર્ણાંક)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ખાલી;

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
	જ્યારે ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		પસંદગી (opt) {
		સ્થિતિ '4':
			/* ignore */
			તોડો;
		સ્થિતિ '6':
			/* ignore */
			તોડો;
		સ્થિતિ 'f':
			/* ignore */
			તોડો;
		સ્થિતિ 'c':
			/* ignore */
			તોડો;
		સ્થિતિ 'd':
			જો (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} નહીંતર જો (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			તોડો;
		સ્થિતિ 'D':
		સ્થિતિ 'E':
		સ્થિતિ 'e':
			/* ignore */
			તોડો;
		સ્થિતિ 'i':
			inetd_flag = 1;
			તોડો;
		સ્થિતિ 'r':
			/* ignore */
			તોડો;
		સ્થિતિ 'R':
			rexeced_flag = 1;
			તોડો;
		સ્થિતિ 'Q':
			/* ignored */
			તોડો;
		સ્થિતિ 'q':
			/* ignored */
			તોડો;
		સ્થિતિ 'b':
			/* protocol 1, ignored */
			તોડો;
		સ્થિતિ 'p':
			/* ignored */
			તોડો;
		સ્થિતિ 'g':
			/* ignored */
			તોડો;
		સ્થિતિ 'k':
			/* protocol 1, ignored */
			તોડો;
		સ્થિતિ 'h':
			/* ignored */
			તોડો;
		સ્થિતિ 't':
		સ્થિતિ 'T':
		સ્થિતિ 'G':
		સ્થિતિ 'C':
			fatal("test/dump modes not supported");
			તોડો;
		સ્થિતિ 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, ખાલી);
			જો (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			તોડો;
		સ્થિતિ 'o':
			/* ignored */
			તોડો;
		સ્થિતિ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		મૂળભૂત:
			usage();
			તોડો;
		}
	}

	જો (!rexeced_flag)
		fatal("sshd-auth should not be executed directly");

	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_AUTH : options.log_facility, 1);

	/* XXX can't use monitor_init(); it makes fds */
	pmonitor = xcalloc(1, કદ(*pmonitor));
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_recvfd = PRIVSEP_MONITOR_FD;
	pmonitor->m_log_sendfd = PRIVSEP_LOG_FD;
	set_log_handler(mm_log_handler, pmonitor);

	/* Check that there are no remaining arguments. */
	જો (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	/* Connection passed by stdin/out */
	જો (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_in = dup(STDIN_FILENO);
		sock_out = dup(STDOUT_FILENO);
	} નહીંતર {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_in = sock_out = dup(STDIN_FILENO);
	}

	જો (stdfd_devnull(1, 1, 0) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_in, sock_out);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	જો ((ssh = ssh_packet_set_connection(ખાલી, sock_in, sock_out)) == ખાલી)
		fatal("Unable to create connection");
	the_active_state = ssh;
	ssh_packet_set_server(ssh);
	pmonitor->m_pkex = &ssh->kex;

	/* Fetch our configuration */
	જો ((cfg = sshbuf_new()) == ખાલી)
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
	જો ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == ખાલી) {
		જો (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} નહીંતર {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, strlen(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

#ifdef WITH_OPENSSL
	જો (options.moduli_file != ખાલી)
		dh_set_moduli_file(options.moduli_file);
#endif

	જો (options.host_ચાવી_agent) {
		જો (strcmp(options.host_ચાવી_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_ચાવી_agent, 1);
		જો ((r = ssh_get_authentication_socket(ખાલી)) == 0)
			have_agent = 1;
		નહીંતર
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_ચાવી_agent);
	}

	જો (options.અંક_host_ચાવી_files != અંક_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.અંક_host_ચાવી_files, અંક_hostkeys);
	}

	માટે (i = 0; i < options.અંક_host_ચાવી_files; i++) {
		જો (host_pubkeys[i] != ખાલી) {
			have_ચાવી = 1;
			તોડો;
		}
	}
	જો (!have_ચાવી)
		fatal("internal error: received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(શૂન્ય) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	log_init(__progname, options.log_level, options.log_facility, 1);
	set_log_handler(mm_log_handler, pmonitor);
	માટે (i = 0; i < options.અંક_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	જો (chdir("/") == -1)
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
	authctxt = xcalloc(1, કદ(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	જો ((auth_opts = sshauthopt_new_with_ચાવીઓ_defaults()) == ખાલી)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	જો ((loginmsg = sshbuf_new()) == ખાલી)
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
	ssh_packet_clear_ચાવીઓ(ssh);
	exit(0);
}

પૂર્ણાંક
sshd_hostkey_sign(સંરચના ssh *ssh, સંરચના sshkey *privkey,
    સંરચના sshkey *pubkey, u_char **signature, size_t *slenp,
    અચલ u_char *data, size_t dlen, અચલ અક્ષર *alg)
{
	જો (privkey) {
		જો (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, ખાલી,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} નહીંતર {
		જો (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, ખાલી,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	પાછા 0;
}

/* SSH2 key exchange */
સ્થિર શૂન્ય
do_ssh2_kex(સંરચના ssh *ssh)
{
	અક્ષર *hkalgs = ખાલી, *myproposal[PROPOSAL_MAX];
	અચલ અક્ષર *compression = ખાલી;
	સંરચના kex *kex;
	પૂર્ણાંક r;

	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

	જો (options.compression == COMP_NONE)
		compression = "none";
	hkalgs = list_hostkey_types();

	kex_proposal_populate_entries(ssh, myproposal, options.kex_algorithms,
	    options.ciphers, options.macs, compression, hkalgs);

	મુક્ત(hkalgs);

	જો ((r = kex_exchange_identification(ssh, -1,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");
	mm_sshkey_setcompat(ssh); /* tell monitor */

	જો ((ssh->compat & SSH_BUG_NOREKEY))
		debug("client does not support rekeying");

	/* start key exchange */
	જો ((r = kex_setup(ssh, myproposal)) != 0)
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
	kex->load_host_public_ચાવી=&get_hostkey_public_by_type;
	kex->load_host_private_ચાવી=&get_hostkey_private_by_type;
	kex->host_ચાવી_index=&get_hostkey_index;
	kex->sign = sshd_hostkey_sign;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send test");
#endif
	debug("KEX done");
}

/* server specific fatal cleanup */
શૂન્ય
cleanup_exit(પૂર્ણાંક i)
{
	_exit(i);
}
