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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/ioctl.h>
#அந்தர்பாவ <sys/wait.h>
#அந்தர்பாவ <sys/tree.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/time.h>
#அந்தர்பாவ <sys/queue.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <grp.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/evp.h>
#endif

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "sshpty.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "uidswap.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "msg.h"
#அந்தர்பாவ "dispatch.h"
#அந்தர்பாவ "channels.h"
#அந்தர்பாவ "session.h"
#அந்தர்பாவ "monitor.h"
#ifdef GSSAPI
#அந்தர்பாவ "ssh-gss.h"
#endif
#அந்தர்பாவ "monitor_wrap.h"
#அந்தர்பாவ "auth-options.h"
#அந்தர்பாவ "version.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sk-api.h"
#அந்தர்பாவ "srclimit.h"
#அந்தர்பாவ "ssh-sandbox.h"
#அந்தர்பாவ "dh.h"

/* Privsep fds */
#define PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#define PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#define PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

வெளி எழுத்து *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
எழுத்து *config_file_name = _PATH_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
முழு debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
நிலையான முழு inetd_flag = 0;

/* Saved arguments to main(). */
நிலையான எழுத்து **saved_argv;
நிலையான முழு saved_argc;


/* Daemon's agent connection */
முழு auth_sock = -1;
நிலையான முழு have_agent = 0;

u_int		இலக்கம்_hostkeys;
கட்டமைப்பு sshkey	**host_pubkeys;		/* all public host keys */
கட்டமைப்பு sshkey	**host_certificates;	/* all public host certificates */

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/* variables used for privilege separation */
கட்டமைப்பு monitor *pmonitor = வெற்று;
முழு privsep_is_preauth = 1;
நிலையான முழு privsep_chroot = 1;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = வெற்று;
கட்டமைப்பு ssh *the_active_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
கட்டமைப்பு sshauthopt *auth_opts = வெற்று;

/* sshd_config buffer */
கட்டமைப்பு sshbuf *cfg;

/* Included files from the configuration file */
கட்டமைப்பு include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
கட்டமைப்பு sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
நிலையான வெறுமை do_ssh2_kex(கட்டமைப்பு ssh *);

/* Unprivileged user */
கட்டமைப்பு passwd *privsep_pw = வெற்று;

#ifndef HAVE_PLEDGE
நிலையான கட்டமைப்பு ssh_sandbox *box;
#endif

/* XXX stub */
முழு
mm_is_monitor(வெறுமை)
{
	திரும்பு 0;
}

நிலையான வெறுமை
privsep_child_demote(வெறுமை)
{
	gid_t gidset[1];

#ifndef HAVE_PLEDGE
	எனில் ((box = ssh_sandbox_init(pmonitor)) == வெற்று)
		fatal_f("ssh_sandbox_init failed");
#endif
	/* Demote the child */
	எனில் (privsep_chroot) {
		/* Change our root directory */
		எனில் (chroot(_PATH_PRIVSEP_CHROOT_DIR) == -1)
			fatal("chroot(\"%s\"): %s", _PATH_PRIVSEP_CHROOT_DIR,
			    strerror(errno));
		எனில் (chdir("/") == -1)
			fatal("chdir(\"/\"): %s", strerror(errno));

		/*
		 * Drop our privileges
		 * NB. Can't use setusercontext() after chroot.
		 */
		debug3("privsep user:group %u:%u", (u_int)privsep_pw->pw_uid,
		    (u_int)privsep_pw->pw_gid);
		gidset[0] = privsep_pw->pw_gid;
		எனில் (setgroups(1, gidset) == -1)
			fatal("setgroups: %.100s", strerror(errno));
		permanently_set_uid(privsep_pw);
	}

	/* sandbox ourselves */
#ifdef HAVE_PLEDGE
	எனில் (pledge("stdio", வெற்று) == -1)
		fatal_f("pledge()");
#இல்லையெனில்
	ssh_sandbox_child(box);
#endif
}

நிலையான வெறுமை
append_hostkey_type(கட்டமைப்பு sshbuf *b, மாறிலி எழுத்து *s)
{
	முழு r;

	எனில் (match_pattern_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		திரும்பு;
	}
	எனில் ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

நிலையான எழுத்து *
list_hostkey_types(வெறுமை)
{
	கட்டமைப்பு sshbuf *b;
	கட்டமைப்பு sshkey *சாவி;
	எழுத்து *ret;
	u_int i;

	எனில் ((b = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	க்கு (i = 0; i < options.இலக்கம்_host_சாவி_files; i++) {
		சாவி = host_pubkeys[i];
		எனில் (சாவி == வெற்று)
			தொடர்;
		தேர்வு (சாவி->type) {
		நிலை சாவி_RSA:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b, "rsa-sha2-512");
			append_hostkey_type(b, "rsa-sha2-256");
			/* FALLTHROUGH */
		நிலை சாவி_ECDSA:
		நிலை சாவி_ED25519:
		நிலை சாவி_MLDSA44_ED25519:
		நிலை சாவி_ECDSA_SK:
		நிலை சாவி_ED25519_SK:
			append_hostkey_type(b, sshkey_ssh_name(சாவி));
			நிறுத்து;
		}
		/* If the private key has a cert peer, then list that too */
		சாவி = host_certificates[i];
		எனில் (சாவி == வெற்று)
			தொடர்;
		தேர்வு (சாவி->type) {
		நிலை சாவி_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			/* FALLTHROUGH */
		நிலை சாவி_ECDSA_CERT:
		நிலை சாவி_ED25519_CERT:
		நிலை சாவி_MLDSA44_ED25519_CERT:
		நிலை சாவி_ECDSA_SK_CERT:
		நிலை சாவி_ED25519_SK_CERT:
			append_hostkey_type(b, sshkey_ssh_name(சாவி));
			நிறுத்து;
		}
	}
	எனில் ((ret = sshbuf_dup_string(b)) == வெற்று)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	திரும்பு ret;
}

கட்டமைப்பு sshkey *
get_hostkey_public_by_type(முழு type, முழு nid, கட்டமைப்பு ssh *ssh)
{
	u_int i;
	கட்டமைப்பு sshkey *சாவி;

	க்கு (i = 0; i < options.இலக்கம்_host_சாவி_files; i++) {
		தேர்வு (type) {
		நிலை சாவி_RSA_CERT:
		நிலை சாவி_ECDSA_CERT:
		நிலை சாவி_ED25519_CERT:
		நிலை சாவி_MLDSA44_ED25519_CERT:
		நிலை சாவி_ECDSA_SK_CERT:
		நிலை சாவி_ED25519_SK_CERT:
			சாவி = host_certificates[i];
			நிறுத்து;
		இயல்பு:
			சாவி = host_pubkeys[i];
			நிறுத்து;
		}
		எனில் (சாவி == வெற்று || சாவி->type != type)
			தொடர்;
		தேர்வு (type) {
		நிலை சாவி_ECDSA:
		நிலை சாவி_ECDSA_SK:
		நிலை சாவி_ECDSA_CERT:
		நிலை சாவி_ECDSA_SK_CERT:
			எனில் (சாவி->ecdsa_nid != nid)
				தொடர்;
			/* FALLTHROUGH */
		இயல்பு:
			திரும்பு சாவி;
		}
	}
	திரும்பு வெற்று;
}

/* XXX remove */
கட்டமைப்பு sshkey *
get_hostkey_private_by_type(முழு type, முழு nid, கட்டமைப்பு ssh *ssh)
{
	திரும்பு வெற்று;
}

/* XXX remove */
கட்டமைப்பு sshkey *
get_hostkey_by_index(முழு ind)
{
	திரும்பு வெற்று;
}

கட்டமைப்பு sshkey *
get_hostkey_public_by_index(முழு ind, கட்டமைப்பு ssh *ssh)
{
	எனில் (ind < 0 || (u_int)ind >= options.இலக்கம்_host_சாவி_files)
		திரும்பு (வெற்று);
	திரும்பு host_pubkeys[ind];
}

முழு
get_hostkey_index(கட்டமைப்பு sshkey *சாவி, முழு compare, கட்டமைப்பு ssh *ssh)
{
	u_int i;

	க்கு (i = 0; i < options.இலக்கம்_host_சாவி_files; i++) {
		எனில் (sshkey_is_cert(சாவி)) {
			எனில் (சாவி == host_certificates[i] ||
			    (compare && host_certificates[i] &&
			    sshkey_equal(சாவி, host_certificates[i])))
				திரும்பு (i);
		} இல்லையெனில் {
			எனில் (சாவி == host_pubkeys[i] ||
			    (compare && host_pubkeys[i] &&
			    sshkey_equal(சாவி, host_pubkeys[i])))
				திரும்பு (i);
		}
	}
	திரும்பு (-1);
}

நிலையான வெறுமை
usage(வெறுமை)
{
	fprintf(stderr, "%s, %s\n", SSH_VERSION, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

நிலையான வெறுமை
parse_hostkeys(கட்டமைப்பு sshbuf *hostkeys)
{
	முழு r;
	u_int இலக்கம்_சாவிகள் = 0;
	கட்டமைப்பு sshkey *k;
	மாறிலி u_char *cp;
	size_t len;

	போது (sshbuf_len(hostkeys) != 0) {
		எனில் (இலக்கம்_சாவிகள் > 2048)
			fatal_f("too many hostkeys");
		host_pubkeys = xrecallocarray(host_pubkeys,
		    இலக்கம்_சாவிகள், இலக்கம்_சாவிகள் + 1, அளவு(*host_pubkeys));
		host_certificates = xrecallocarray(host_certificates,
		    இலக்கம்_சாவிகள், இலக்கம்_சாவிகள் + 1, அளவு(*host_certificates));
		/* public key */
		k = வெற்று;
		எனில் ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		எனில் (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_pubkeys[இலக்கம்_சாவிகள்] = k;
		எனில் (k)
			debug2_f("key %u: %s", இலக்கம்_சாவிகள், sshkey_ssh_name(k));
		/* certificate */
		k = வெற்று;
		எனில் ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		எனில் (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_certificates[இலக்கம்_சாவிகள்] = k;
		எனில் (k)
			debug2_f("cert %u: %s", இலக்கம்_சாவிகள், sshkey_ssh_name(k));
		இலக்கம்_சாவிகள்++;
	}
	இலக்கம்_hostkeys = இலக்கம்_சாவிகள்;
}

நிலையான வெறுமை
recv_privsep_state(கட்டமைப்பு ssh *ssh, ServerOptions *o, uint64_t *timing_secretp)
{
	கட்டமைப்பு sshbuf *hostkeys;

	debug3_f("begin");

	mm_get_state(ssh, o, வெற்று, timing_secretp,
	    &hostkeys, வெற்று, வெற்று, வெற்று, வெற்று);
	parse_hostkeys(hostkeys);

	sshbuf_free(hostkeys);

	debug3_f("done");
}

/*
 * Main program for the daemon.
 */
முழு
முதன்மை(முழு ac, எழுத்து **av)
{
	கட்டமைப்பு ssh *ssh = வெற்று;
	வெளி எழுத்து *optarg;
	வெளி முழு optind;
	முழு r, opt, have_சாவி = 0;
	முழு sock_in = -1, sock_out = -1, rexeced_flag = 0;
	u_int i;
	mode_t new_umask;
	Authctxt *authctxt;
	sigset_t sigmask;
	uint64_t timing_secret = 0;

	closefrom(PRIVSEP_MIN_FREE_FD);
	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, வெற்று);

#ifdef HAVE_SECUREWARE
	(வெறுமை)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, அளவு(*saved_argv));
	க்கு (i = 0; (முழு)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = வெற்று;

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
	போது ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		தேர்வு (opt) {
		நிலை '4':
			/* ignore */
			நிறுத்து;
		நிலை '6':
			/* ignore */
			நிறுத்து;
		நிலை 'f':
			/* ignore */
			நிறுத்து;
		நிலை 'c':
			/* ignore */
			நிறுத்து;
		நிலை 'd':
			எனில் (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} இல்லையெனில் எனில் (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			நிறுத்து;
		நிலை 'D':
		நிலை 'E':
		நிலை 'e':
			/* ignore */
			நிறுத்து;
		நிலை 'i':
			inetd_flag = 1;
			நிறுத்து;
		நிலை 'r':
			/* ignore */
			நிறுத்து;
		நிலை 'R':
			rexeced_flag = 1;
			நிறுத்து;
		நிலை 'Q':
			/* ignored */
			நிறுத்து;
		நிலை 'q':
			/* ignored */
			நிறுத்து;
		நிலை 'b':
			/* protocol 1, ignored */
			நிறுத்து;
		நிலை 'p':
			/* ignored */
			நிறுத்து;
		நிலை 'g':
			/* ignored */
			நிறுத்து;
		நிலை 'k':
			/* protocol 1, ignored */
			நிறுத்து;
		நிலை 'h':
			/* ignored */
			நிறுத்து;
		நிலை 't':
		நிலை 'T':
		நிலை 'G':
		நிலை 'C':
			fatal("test/dump modes not supported");
			நிறுத்து;
		நிலை 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, வெற்று);
			எனில் (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			நிறுத்து;
		நிலை 'o':
			/* ignored */
			நிறுத்து;
		நிலை 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		இயல்பு:
			usage();
			நிறுத்து;
		}
	}

	எனில் (!rexeced_flag)
		fatal("sshd-auth should not be executed directly");

	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_AUTH : options.log_facility, 1);

	/* XXX can't use monitor_init(); it makes fds */
	pmonitor = xcalloc(1, அளவு(*pmonitor));
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_recvfd = PRIVSEP_MONITOR_FD;
	pmonitor->m_log_sendfd = PRIVSEP_LOG_FD;
	set_log_handler(mm_log_handler, pmonitor);

	/* Check that there are no remaining arguments. */
	எனில் (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	/* Connection passed by stdin/out */
	எனில் (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_in = dup(STDIN_FILENO);
		sock_out = dup(STDOUT_FILENO);
	} இல்லையெனில் {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_in = sock_out = dup(STDIN_FILENO);
	}

	எனில் (stdfd_devnull(1, 1, 0) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_in, sock_out);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	எனில் ((ssh = ssh_packet_set_connection(வெற்று, sock_in, sock_out)) == வெற்று)
		fatal("Unable to create connection");
	the_active_state = ssh;
	ssh_packet_set_server(ssh);
	pmonitor->m_pkex = &ssh->kex;

	/* Fetch our configuration */
	எனில் ((cfg = sshbuf_new()) == வெற்று)
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
	எனில் ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == வெற்று) {
		எனில் (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} இல்லையெனில் {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, strlen(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

#ifdef WITH_OPENSSL
	எனில் (options.moduli_file != வெற்று)
		dh_set_moduli_file(options.moduli_file);
#endif

	எனில் (options.host_சாவி_agent) {
		எனில் (strcmp(options.host_சாவி_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_சாவி_agent, 1);
		எனில் ((r = ssh_get_authentication_socket(வெற்று)) == 0)
			have_agent = 1;
		இல்லையெனில்
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_சாவி_agent);
	}

	எனில் (options.இலக்கம்_host_சாவி_files != இலக்கம்_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.இலக்கம்_host_சாவி_files, இலக்கம்_hostkeys);
	}

	க்கு (i = 0; i < options.இலக்கம்_host_சாவி_files; i++) {
		எனில் (host_pubkeys[i] != வெற்று) {
			have_சாவி = 1;
			நிறுத்து;
		}
	}
	எனில் (!have_சாவி)
		fatal("internal error: received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(வெறுமை) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	log_init(__progname, options.log_level, options.log_facility, 1);
	set_log_handler(mm_log_handler, pmonitor);
	க்கு (i = 0; i < options.இலக்கம்_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	எனில் (chdir("/") == -1)
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
	authctxt = xcalloc(1, அளவு(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	எனில் ((auth_opts = sshauthopt_new_with_சாவிகள்_defaults()) == வெற்று)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	எனில் ((loginmsg = sshbuf_new()) == வெற்று)
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
	ssh_packet_clear_சாவிகள்(ssh);
	exit(0);
}

முழு
sshd_hostkey_sign(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshkey *privkey,
    கட்டமைப்பு sshkey *pubkey, u_char **signature, size_t *slenp,
    மாறிலி u_char *data, size_t dlen, மாறிலி எழுத்து *alg)
{
	எனில் (privkey) {
		எனில் (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, வெற்று,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} இல்லையெனில் {
		எனில் (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, வெற்று,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	திரும்பு 0;
}

/* SSH2 key exchange */
நிலையான வெறுமை
do_ssh2_kex(கட்டமைப்பு ssh *ssh)
{
	எழுத்து *hkalgs = வெற்று, *myproposal[PROPOSAL_MAX];
	மாறிலி எழுத்து *compression = வெற்று;
	கட்டமைப்பு kex *kex;
	முழு r;

	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

	எனில் (options.compression == COMP_NONE)
		compression = "none";
	hkalgs = list_hostkey_types();

	kex_proposal_populate_entries(ssh, myproposal, options.kex_algorithms,
	    options.ciphers, options.macs, compression, hkalgs);

	விடுவி(hkalgs);

	எனில் ((r = kex_exchange_identification(ssh, -1,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");
	mm_sshkey_setcompat(ssh); /* tell monitor */

	எனில் ((ssh->compat & SSH_BUG_NOREKEY))
		debug("client does not support rekeying");

	/* start key exchange */
	எனில் ((r = kex_setup(ssh, myproposal)) != 0)
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
	kex->load_host_public_சாவி=&get_hostkey_public_by_type;
	kex->load_host_private_சாவி=&get_hostkey_private_by_type;
	kex->host_சாவி_index=&get_hostkey_index;
	kex->sign = sshd_hostkey_sign;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send test");
#endif
	debug("KEX done");
}

/* server specific fatal cleanup */
வெறுமை
cleanup_exit(முழு i)
{
	_exit(i);
}
