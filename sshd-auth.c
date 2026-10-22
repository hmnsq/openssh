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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/ioctl.h>
#شامل <sys/wait.h>
#شامل <sys/tree.h>
#شامل <sys/stat.h>
#شامل <sys/socket.h>
#شامل <sys/time.h>
#شامل <sys/queue.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <netdb.h>
#شامل <paths.h>
#شامل <pwd.h>
#شامل <grp.h>
#شامل <signal.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <unistd.h>
#شامل <limits.h>

#ifdef WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/evp.h>
#endif

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "ssh2.h"
#شامل "sshpty.h"
#شامل "packet.h"
#شامل "log.h"
#شامل "sshbuf.h"
#شامل "misc.h"
#شامل "match.h"
#شامل "servconf.h"
#شامل "uidswap.h"
#شامل "compat.h"
#شامل "cipher.h"
#شامل "digest.h"
#شامل "sshkey.h"
#شامل "kex.h"
#شامل "authfile.h"
#شامل "pathnames.h"
#شامل "atomicio.h"
#شامل "canohost.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "authfd.h"
#شامل "msg.h"
#شامل "dispatch.h"
#شامل "channels.h"
#شامل "session.h"
#شامل "monitor.h"
#ifdef GSSAPI
#شامل "ssh-gss.h"
#endif
#شامل "monitor_wrap.h"
#شامل "auth-options.h"
#شامل "version.h"
#شامل "ssherr.h"
#شامل "sk-api.h"
#شامل "srclimit.h"
#شامل "ssh-sandbox.h"
#شامل "dh.h"

/* Privsep fds */
#define PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#define PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#define PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

بیرونی نویسه *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
نویسه *config_file_name = _PATH_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
صحیح debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
ایستا صحیح inetd_flag = 0;

/* Saved arguments to main(). */
ایستا نویسه **saved_argv;
ایستا صحیح saved_argc;


/* Daemon's agent connection */
صحیح auth_sock = -1;
ایستا صحیح have_agent = 0;

u_int		رقم_hostkeys;
ساختار sshkey	**host_pubkeys;		/* all public host keys */
ساختار sshkey	**host_certificates;	/* all public host certificates */

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/* variables used for privilege separation */
ساختار monitor *pmonitor = پوچ;
صحیح privsep_is_preauth = 1;
ایستا صحیح privsep_chroot = 1;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = پوچ;
ساختار ssh *the_active_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
ساختار sshauthopt *auth_opts = پوچ;

/* sshd_config buffer */
ساختار sshbuf *cfg;

/* Included files from the configuration file */
ساختار include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ساختار sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
ایستا تهی do_ssh2_kex(ساختار ssh *);

/* Unprivileged user */
ساختار passwd *privsep_pw = پوچ;

#ifndef HAVE_PLEDGE
ایستا ساختار ssh_sandbox *box;
#endif

/* XXX stub */
صحیح
mm_is_monitor(تهی)
{
	بازگشت 0;
}

ایستا تهی
privsep_child_demote(تهی)
{
	gid_t gidset[1];

#ifndef HAVE_PLEDGE
	اگر ((box = ssh_sandbox_init(pmonitor)) == پوچ)
		fatal_f("ssh_sandbox_init failed");
#endif
	/* Demote the child */
	اگر (privsep_chroot) {
		/* Change our root directory */
		اگر (chroot(_PATH_PRIVSEP_CHROOT_DIR) == -1)
			fatal("chroot(\"%s\"): %s", _PATH_PRIVSEP_CHROOT_DIR,
			    strerror(errno));
		اگر (chdir("/") == -1)
			fatal("chdir(\"/\"): %s", strerror(errno));

		/*
		 * Drop our privileges
		 * NB. Can't use setusercontext() after chroot.
		 */
		debug3("privsep user:group %u:%u", (u_int)privsep_pw->pw_uid,
		    (u_int)privsep_pw->pw_gid);
		gidset[0] = privsep_pw->pw_gid;
		اگر (setgroups(1, gidset) == -1)
			fatal("setgroups: %.100s", strerror(errno));
		permanently_set_uid(privsep_pw);
	}

	/* sandbox ourselves */
#ifdef HAVE_PLEDGE
	اگر (pledge("stdio", پوچ) == -1)
		fatal_f("pledge()");
#وگرنه
	ssh_sandbox_child(box);
#endif
}

ایستا تهی
append_hostkey_type(ساختار sshbuf *b, ثابت نویسه *s)
{
	صحیح r;

	اگر (match_pattern_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		بازگشت;
	}
	اگر ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

ایستا نویسه *
list_hostkey_types(تهی)
{
	ساختار sshbuf *b;
	ساختار sshkey *کلید;
	نویسه *ret;
	u_int i;

	اگر ((b = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	برای (i = 0; i < options.رقم_host_کلید_files; i++) {
		کلید = host_pubkeys[i];
		اگر (کلید == پوچ)
			ادامه;
		انتخاب (کلید->type) {
		حالت کلید_RSA:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b, "rsa-sha2-512");
			append_hostkey_type(b, "rsa-sha2-256");
			/* FALLTHROUGH */
		حالت کلید_ECDSA:
		حالت کلید_ED25519:
		حالت کلید_MLDSA44_ED25519:
		حالت کلید_ECDSA_SK:
		حالت کلید_ED25519_SK:
			append_hostkey_type(b, sshkey_ssh_name(کلید));
			بشکن;
		}
		/* If the private key has a cert peer, then list that too */
		کلید = host_certificates[i];
		اگر (کلید == پوچ)
			ادامه;
		انتخاب (کلید->type) {
		حالت کلید_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			/* FALLTHROUGH */
		حالت کلید_ECDSA_CERT:
		حالت کلید_ED25519_CERT:
		حالت کلید_MLDSA44_ED25519_CERT:
		حالت کلید_ECDSA_SK_CERT:
		حالت کلید_ED25519_SK_CERT:
			append_hostkey_type(b, sshkey_ssh_name(کلید));
			بشکن;
		}
	}
	اگر ((ret = sshbuf_dup_string(b)) == پوچ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	بازگشت ret;
}

ساختار sshkey *
get_hostkey_public_by_type(صحیح type, صحیح nid, ساختار ssh *ssh)
{
	u_int i;
	ساختار sshkey *کلید;

	برای (i = 0; i < options.رقم_host_کلید_files; i++) {
		انتخاب (type) {
		حالت کلید_RSA_CERT:
		حالت کلید_ECDSA_CERT:
		حالت کلید_ED25519_CERT:
		حالت کلید_MLDSA44_ED25519_CERT:
		حالت کلید_ECDSA_SK_CERT:
		حالت کلید_ED25519_SK_CERT:
			کلید = host_certificates[i];
			بشکن;
		پیشفرض:
			کلید = host_pubkeys[i];
			بشکن;
		}
		اگر (کلید == پوچ || کلید->type != type)
			ادامه;
		انتخاب (type) {
		حالت کلید_ECDSA:
		حالت کلید_ECDSA_SK:
		حالت کلید_ECDSA_CERT:
		حالت کلید_ECDSA_SK_CERT:
			اگر (کلید->ecdsa_nid != nid)
				ادامه;
			/* FALLTHROUGH */
		پیشفرض:
			بازگشت کلید;
		}
	}
	بازگشت پوچ;
}

/* XXX remove */
ساختار sshkey *
get_hostkey_private_by_type(صحیح type, صحیح nid, ساختار ssh *ssh)
{
	بازگشت پوچ;
}

/* XXX remove */
ساختار sshkey *
get_hostkey_by_index(صحیح ind)
{
	بازگشت پوچ;
}

ساختار sshkey *
get_hostkey_public_by_index(صحیح ind, ساختار ssh *ssh)
{
	اگر (ind < 0 || (u_int)ind >= options.رقم_host_کلید_files)
		بازگشت (پوچ);
	بازگشت host_pubkeys[ind];
}

صحیح
get_hostkey_index(ساختار sshkey *کلید, صحیح compare, ساختار ssh *ssh)
{
	u_int i;

	برای (i = 0; i < options.رقم_host_کلید_files; i++) {
		اگر (sshkey_is_cert(کلید)) {
			اگر (کلید == host_certificates[i] ||
			    (compare && host_certificates[i] &&
			    sshkey_equal(کلید, host_certificates[i])))
				بازگشت (i);
		} وگرنه {
			اگر (کلید == host_pubkeys[i] ||
			    (compare && host_pubkeys[i] &&
			    sshkey_equal(کلید, host_pubkeys[i])))
				بازگشت (i);
		}
	}
	بازگشت (-1);
}

ایستا تهی
usage(تهی)
{
	fprintf(stderr, "%s, %s\n", SSH_VERSION, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

ایستا تهی
parse_hostkeys(ساختار sshbuf *hostkeys)
{
	صحیح r;
	u_int رقم_کلیدها = 0;
	ساختار sshkey *k;
	ثابت u_char *cp;
	size_t len;

	وقتی (sshbuf_len(hostkeys) != 0) {
		اگر (رقم_کلیدها > 2048)
			fatal_f("too many hostkeys");
		host_pubkeys = xrecallocarray(host_pubkeys,
		    رقم_کلیدها, رقم_کلیدها + 1, اندازه(*host_pubkeys));
		host_certificates = xrecallocarray(host_certificates,
		    رقم_کلیدها, رقم_کلیدها + 1, اندازه(*host_certificates));
		/* public key */
		k = پوچ;
		اگر ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		اگر (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_pubkeys[رقم_کلیدها] = k;
		اگر (k)
			debug2_f("key %u: %s", رقم_کلیدها, sshkey_ssh_name(k));
		/* certificate */
		k = پوچ;
		اگر ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		اگر (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_certificates[رقم_کلیدها] = k;
		اگر (k)
			debug2_f("cert %u: %s", رقم_کلیدها, sshkey_ssh_name(k));
		رقم_کلیدها++;
	}
	رقم_hostkeys = رقم_کلیدها;
}

ایستا تهی
recv_privsep_state(ساختار ssh *ssh, ServerOptions *o, uint64_t *timing_secretp)
{
	ساختار sshbuf *hostkeys;

	debug3_f("begin");

	mm_get_state(ssh, o, پوچ, timing_secretp,
	    &hostkeys, پوچ, پوچ, پوچ, پوچ);
	parse_hostkeys(hostkeys);

	sshbuf_free(hostkeys);

	debug3_f("done");
}

/*
 * Main program for the daemon.
 */
صحیح
اصلی(صحیح ac, نویسه **av)
{
	ساختار ssh *ssh = پوچ;
	بیرونی نویسه *optarg;
	بیرونی صحیح optind;
	صحیح r, opt, have_کلید = 0;
	صحیح sock_in = -1, sock_out = -1, rexeced_flag = 0;
	u_int i;
	mode_t new_umask;
	Authctxt *authctxt;
	sigset_t sigmask;
	uint64_t timing_secret = 0;

	closefrom(PRIVSEP_MIN_FREE_FD);
	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, پوچ);

#ifdef HAVE_SECUREWARE
	(تهی)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, اندازه(*saved_argv));
	برای (i = 0; (صحیح)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = پوچ;

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
	وقتی ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		انتخاب (opt) {
		حالت '4':
			/* ignore */
			بشکن;
		حالت '6':
			/* ignore */
			بشکن;
		حالت 'f':
			/* ignore */
			بشکن;
		حالت 'c':
			/* ignore */
			بشکن;
		حالت 'd':
			اگر (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} وگرنه اگر (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			بشکن;
		حالت 'D':
		حالت 'E':
		حالت 'e':
			/* ignore */
			بشکن;
		حالت 'i':
			inetd_flag = 1;
			بشکن;
		حالت 'r':
			/* ignore */
			بشکن;
		حالت 'R':
			rexeced_flag = 1;
			بشکن;
		حالت 'Q':
			/* ignored */
			بشکن;
		حالت 'q':
			/* ignored */
			بشکن;
		حالت 'b':
			/* protocol 1, ignored */
			بشکن;
		حالت 'p':
			/* ignored */
			بشکن;
		حالت 'g':
			/* ignored */
			بشکن;
		حالت 'k':
			/* protocol 1, ignored */
			بشکن;
		حالت 'h':
			/* ignored */
			بشکن;
		حالت 't':
		حالت 'T':
		حالت 'G':
		حالت 'C':
			fatal("test/dump modes not supported");
			بشکن;
		حالت 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, پوچ);
			اگر (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			بشکن;
		حالت 'o':
			/* ignored */
			بشکن;
		حالت 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		پیشفرض:
			usage();
			بشکن;
		}
	}

	اگر (!rexeced_flag)
		fatal("sshd-auth should not be executed directly");

	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_AUTH : options.log_facility, 1);

	/* XXX can't use monitor_init(); it makes fds */
	pmonitor = xcalloc(1, اندازه(*pmonitor));
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_recvfd = PRIVSEP_MONITOR_FD;
	pmonitor->m_log_sendfd = PRIVSEP_LOG_FD;
	set_log_handler(mm_log_handler, pmonitor);

	/* Check that there are no remaining arguments. */
	اگر (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	/* Connection passed by stdin/out */
	اگر (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_in = dup(STDIN_FILENO);
		sock_out = dup(STDOUT_FILENO);
	} وگرنه {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_in = sock_out = dup(STDIN_FILENO);
	}

	اگر (stdfd_devnull(1, 1, 0) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_in, sock_out);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	اگر ((ssh = ssh_packet_set_connection(پوچ, sock_in, sock_out)) == پوچ)
		fatal("Unable to create connection");
	the_active_state = ssh;
	ssh_packet_set_server(ssh);
	pmonitor->m_pkex = &ssh->kex;

	/* Fetch our configuration */
	اگر ((cfg = sshbuf_new()) == پوچ)
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
	اگر ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == پوچ) {
		اگر (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} وگرنه {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, strlen(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

#ifdef WITH_OPENSSL
	اگر (options.moduli_file != پوچ)
		dh_set_moduli_file(options.moduli_file);
#endif

	اگر (options.host_کلید_agent) {
		اگر (strcmp(options.host_کلید_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_کلید_agent, 1);
		اگر ((r = ssh_get_authentication_socket(پوچ)) == 0)
			have_agent = 1;
		وگرنه
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_کلید_agent);
	}

	اگر (options.رقم_host_کلید_files != رقم_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.رقم_host_کلید_files, رقم_hostkeys);
	}

	برای (i = 0; i < options.رقم_host_کلید_files; i++) {
		اگر (host_pubkeys[i] != پوچ) {
			have_کلید = 1;
			بشکن;
		}
	}
	اگر (!have_کلید)
		fatal("internal error: received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(تهی) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	log_init(__progname, options.log_level, options.log_facility, 1);
	set_log_handler(mm_log_handler, pmonitor);
	برای (i = 0; i < options.رقم_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	اگر (chdir("/") == -1)
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
	authctxt = xcalloc(1, اندازه(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	اگر ((auth_opts = sshauthopt_new_with_کلیدها_defaults()) == پوچ)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	اگر ((loginmsg = sshbuf_new()) == پوچ)
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
	ssh_packet_clear_کلیدها(ssh);
	exit(0);
}

صحیح
sshd_hostkey_sign(ساختار ssh *ssh, ساختار sshkey *privkey,
    ساختار sshkey *pubkey, u_char **signature, size_t *slenp,
    ثابت u_char *data, size_t dlen, ثابت نویسه *alg)
{
	اگر (privkey) {
		اگر (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, پوچ,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} وگرنه {
		اگر (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, پوچ,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	بازگشت 0;
}

/* SSH2 key exchange */
ایستا تهی
do_ssh2_kex(ساختار ssh *ssh)
{
	نویسه *hkalgs = پوچ, *myproposal[PROPOSAL_MAX];
	ثابت نویسه *compression = پوچ;
	ساختار kex *kex;
	صحیح r;

	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

	اگر (options.compression == COMP_NONE)
		compression = "none";
	hkalgs = list_hostkey_types();

	kex_proposal_populate_entries(ssh, myproposal, options.kex_algorithms,
	    options.ciphers, options.macs, compression, hkalgs);

	آزاد(hkalgs);

	اگر ((r = kex_exchange_identification(ssh, -1,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");
	mm_sshkey_setcompat(ssh); /* tell monitor */

	اگر ((ssh->compat & SSH_BUG_NOREKEY))
		debug("client does not support rekeying");

	/* start key exchange */
	اگر ((r = kex_setup(ssh, myproposal)) != 0)
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
	kex->load_host_public_کلید=&get_hostkey_public_by_type;
	kex->load_host_private_کلید=&get_hostkey_private_by_type;
	kex->host_کلید_index=&get_hostkey_index;
	kex->sign = sshd_hostkey_sign;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send test");
#endif
	debug("KEX done");
}

/* server specific fatal cleanup */
تهی
cleanup_exit(صحیح i)
{
	_exit(i);
}
