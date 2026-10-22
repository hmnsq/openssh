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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/ioctl.h>
#अन्तर्भाव <sys/wait.h>
#अन्तर्भाव <sys/tree.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/queue.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <grp.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/evp.h>
#endif

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "sshpty.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "uidswap.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "msg.h"
#अन्तर्भाव "dispatch.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "session.h"
#अन्तर्भाव "monitor.h"
#ifdef GSSAPI
#अन्तर्भाव "ssh-gss.h"
#endif
#अन्तर्भाव "monitor_wrap.h"
#अन्तर्भाव "auth-options.h"
#अन्तर्भाव "version.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sk-api.h"
#अन्तर्भाव "srclimit.h"
#अन्तर्भाव "ssh-sandbox.h"
#अन्तर्भाव "dh.h"

/* Privsep fds */
#define PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#define PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#define PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

बाह्य वर्ण *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
वर्ण *config_file_name = _PATH_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
पूर्णाङ्क debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
स्थिर पूर्णाङ्क inetd_flag = 0;

/* Saved arguments to main(). */
स्थिर वर्ण **saved_argv;
स्थिर पूर्णाङ्क saved_argc;


/* Daemon's agent connection */
पूर्णाङ्क auth_sock = -1;
स्थिर पूर्णाङ्क have_agent = 0;

u_int		अंक_hostkeys;
संरचना sshkey	**host_pubkeys;		/* all public host keys */
संरचना sshkey	**host_certificates;	/* all public host certificates */

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/* variables used for privilege separation */
संरचना monitor *pmonitor = रिक्त;
पूर्णाङ्क privsep_is_preauth = 1;
स्थिर पूर्णाङ्क privsep_chroot = 1;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = रिक्त;
संरचना ssh *the_active_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
संरचना sshauthopt *auth_opts = रिक्त;

/* sshd_config buffer */
संरचना sshbuf *cfg;

/* Included files from the configuration file */
संरचना include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
संरचना sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
स्थिर शून्य do_ssh2_kex(संरचना ssh *);

/* Unprivileged user */
संरचना passwd *privsep_pw = रिक्त;

#ifndef HAVE_PLEDGE
स्थिर संरचना ssh_sandbox *box;
#endif

/* XXX stub */
पूर्णाङ्क
mm_is_monitor(शून्य)
{
	प्रत्यागम 0;
}

स्थिर शून्य
privsep_child_demote(शून्य)
{
	gid_t gidset[1];

#ifndef HAVE_PLEDGE
	यदि ((box = ssh_sandbox_init(pmonitor)) == रिक्त)
		fatal_f("ssh_sandbox_init failed");
#endif
	/* Demote the child */
	यदि (privsep_chroot) {
		/* Change our root directory */
		यदि (chroot(_PATH_PRIVSEP_CHROOT_DIR) == -1)
			fatal("chroot(\"%s\"): %s", _PATH_PRIVSEP_CHROOT_DIR,
			    strerror(errno));
		यदि (chdir("/") == -1)
			fatal("chdir(\"/\"): %s", strerror(errno));

		/*
		 * Drop our privileges
		 * NB. Can't use setusercontext() after chroot.
		 */
		debug3("privsep user:group %u:%u", (u_int)privsep_pw->pw_uid,
		    (u_int)privsep_pw->pw_gid);
		gidset[0] = privsep_pw->pw_gid;
		यदि (setgroups(1, gidset) == -1)
			fatal("setgroups: %.100s", strerror(errno));
		permanently_set_uid(privsep_pw);
	}

	/* sandbox ourselves */
#ifdef HAVE_PLEDGE
	यदि (pledge("stdio", रिक्त) == -1)
		fatal_f("pledge()");
#अन्यथा
	ssh_sandbox_child(box);
#endif
}

स्थिर शून्य
append_hostkey_type(संरचना sshbuf *b, ध्रुव वर्ण *s)
{
	पूर्णाङ्क r;

	यदि (match_pattern_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		प्रत्यागम;
	}
	यदि ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

स्थिर वर्ण *
list_hostkey_types(शून्य)
{
	संरचना sshbuf *b;
	संरचना sshkey *कुंजी;
	वर्ण *ret;
	u_int i;

	यदि ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	प्रति (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		कुंजी = host_pubkeys[i];
		यदि (कुंजी == रिक्त)
			अनुवर्त;
		विकल्प (कुंजी->type) {
		पक्ष कुंजी_RSA:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b, "rsa-sha2-512");
			append_hostkey_type(b, "rsa-sha2-256");
			/* FALLTHROUGH */
		पक्ष कुंजी_ECDSA:
		पक्ष कुंजी_ED25519:
		पक्ष कुंजी_MLDSA44_ED25519:
		पक्ष कुंजी_ECDSA_SK:
		पक्ष कुंजी_ED25519_SK:
			append_hostkey_type(b, sshkey_ssh_name(कुंजी));
			भङ्ग;
		}
		/* If the private key has a cert peer, then list that too */
		कुंजी = host_certificates[i];
		यदि (कुंजी == रिक्त)
			अनुवर्त;
		विकल्प (कुंजी->type) {
		पक्ष कुंजी_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			/* FALLTHROUGH */
		पक्ष कुंजी_ECDSA_CERT:
		पक्ष कुंजी_ED25519_CERT:
		पक्ष कुंजी_MLDSA44_ED25519_CERT:
		पक्ष कुंजी_ECDSA_SK_CERT:
		पक्ष कुंजी_ED25519_SK_CERT:
			append_hostkey_type(b, sshkey_ssh_name(कुंजी));
			भङ्ग;
		}
	}
	यदि ((ret = sshbuf_dup_string(b)) == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	प्रत्यागम ret;
}

संरचना sshkey *
get_hostkey_public_by_type(पूर्णाङ्क type, पूर्णाङ्क nid, संरचना ssh *ssh)
{
	u_int i;
	संरचना sshkey *कुंजी;

	प्रति (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		विकल्प (type) {
		पक्ष कुंजी_RSA_CERT:
		पक्ष कुंजी_ECDSA_CERT:
		पक्ष कुंजी_ED25519_CERT:
		पक्ष कुंजी_MLDSA44_ED25519_CERT:
		पक्ष कुंजी_ECDSA_SK_CERT:
		पक्ष कुंजी_ED25519_SK_CERT:
			कुंजी = host_certificates[i];
			भङ्ग;
		स्वभाव:
			कुंजी = host_pubkeys[i];
			भङ्ग;
		}
		यदि (कुंजी == रिक्त || कुंजी->type != type)
			अनुवर्त;
		विकल्प (type) {
		पक्ष कुंजी_ECDSA:
		पक्ष कुंजी_ECDSA_SK:
		पक्ष कुंजी_ECDSA_CERT:
		पक्ष कुंजी_ECDSA_SK_CERT:
			यदि (कुंजी->ecdsa_nid != nid)
				अनुवर्त;
			/* FALLTHROUGH */
		स्वभाव:
			प्रत्यागम कुंजी;
		}
	}
	प्रत्यागम रिक्त;
}

/* XXX remove */
संरचना sshkey *
get_hostkey_private_by_type(पूर्णाङ्क type, पूर्णाङ्क nid, संरचना ssh *ssh)
{
	प्रत्यागम रिक्त;
}

/* XXX remove */
संरचना sshkey *
get_hostkey_by_index(पूर्णाङ्क ind)
{
	प्रत्यागम रिक्त;
}

संरचना sshkey *
get_hostkey_public_by_index(पूर्णाङ्क ind, संरचना ssh *ssh)
{
	यदि (ind < 0 || (u_int)ind >= options.अंक_host_कुंजी_files)
		प्रत्यागम (रिक्त);
	प्रत्यागम host_pubkeys[ind];
}

पूर्णाङ्क
get_hostkey_index(संरचना sshkey *कुंजी, पूर्णाङ्क compare, संरचना ssh *ssh)
{
	u_int i;

	प्रति (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		यदि (sshkey_is_cert(कुंजी)) {
			यदि (कुंजी == host_certificates[i] ||
			    (compare && host_certificates[i] &&
			    sshkey_equal(कुंजी, host_certificates[i])))
				प्रत्यागम (i);
		} अन्यथा {
			यदि (कुंजी == host_pubkeys[i] ||
			    (compare && host_pubkeys[i] &&
			    sshkey_equal(कुंजी, host_pubkeys[i])))
				प्रत्यागम (i);
		}
	}
	प्रत्यागम (-1);
}

स्थिर शून्य
usage(शून्य)
{
	fprintf(stderr, "%s, %s\n", SSH_VERSION, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

स्थिर शून्य
parse_hostkeys(संरचना sshbuf *hostkeys)
{
	पूर्णाङ्क r;
	u_int अंक_कुंजियाँ = 0;
	संरचना sshkey *k;
	ध्रुव u_char *cp;
	size_t len;

	यावत् (sshbuf_len(hostkeys) != 0) {
		यदि (अंक_कुंजियाँ > 2048)
			fatal_f("too many hostkeys");
		host_pubkeys = xrecallocarray(host_pubkeys,
		    अंक_कुंजियाँ, अंक_कुंजियाँ + 1, परिमाण(*host_pubkeys));
		host_certificates = xrecallocarray(host_certificates,
		    अंक_कुंजियाँ, अंक_कुंजियाँ + 1, परिमाण(*host_certificates));
		/* public key */
		k = रिक्त;
		यदि ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		यदि (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_pubkeys[अंक_कुंजियाँ] = k;
		यदि (k)
			debug2_f("key %u: %s", अंक_कुंजियाँ, sshkey_ssh_name(k));
		/* certificate */
		k = रिक्त;
		यदि ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		यदि (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_certificates[अंक_कुंजियाँ] = k;
		यदि (k)
			debug2_f("cert %u: %s", अंक_कुंजियाँ, sshkey_ssh_name(k));
		अंक_कुंजियाँ++;
	}
	अंक_hostkeys = अंक_कुंजियाँ;
}

स्थिर शून्य
recv_privsep_state(संरचना ssh *ssh, ServerOptions *o, uint64_t *timing_secretp)
{
	संरचना sshbuf *hostkeys;

	debug3_f("begin");

	mm_get_state(ssh, o, रिक्त, timing_secretp,
	    &hostkeys, रिक्त, रिक्त, रिक्त, रिक्त);
	parse_hostkeys(hostkeys);

	sshbuf_free(hostkeys);

	debug3_f("done");
}

/*
 * Main program for the daemon.
 */
पूर्णाङ्क
main(पूर्णाङ्क ac, वर्ण **av)
{
	संरचना ssh *ssh = रिक्त;
	बाह्य वर्ण *optarg;
	बाह्य पूर्णाङ्क optind;
	पूर्णाङ्क r, opt, have_कुंजी = 0;
	पूर्णाङ्क sock_in = -1, sock_out = -1, rexeced_flag = 0;
	u_int i;
	mode_t new_umask;
	Authctxt *authctxt;
	sigset_t sigmask;
	uint64_t timing_secret = 0;

	closefrom(PRIVSEP_MIN_FREE_FD);
	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, रिक्त);

#ifdef HAVE_SECUREWARE
	(शून्य)set_auth_parameters(ac, av);
#endif
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, परिमाण(*saved_argv));
	प्रति (i = 0; (पूर्णाङ्क)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = रिक्त;

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
	यावत् ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		विकल्प (opt) {
		पक्ष '4':
			/* ignore */
			भङ्ग;
		पक्ष '6':
			/* ignore */
			भङ्ग;
		पक्ष 'f':
			/* ignore */
			भङ्ग;
		पक्ष 'c':
			/* ignore */
			भङ्ग;
		पक्ष 'd':
			यदि (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} अन्यथा यदि (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			भङ्ग;
		पक्ष 'D':
		पक्ष 'E':
		पक्ष 'e':
			/* ignore */
			भङ्ग;
		पक्ष 'i':
			inetd_flag = 1;
			भङ्ग;
		पक्ष 'r':
			/* ignore */
			भङ्ग;
		पक्ष 'R':
			rexeced_flag = 1;
			भङ्ग;
		पक्ष 'Q':
			/* ignored */
			भङ्ग;
		पक्ष 'q':
			/* ignored */
			भङ्ग;
		पक्ष 'b':
			/* protocol 1, ignored */
			भङ्ग;
		पक्ष 'p':
			/* ignored */
			भङ्ग;
		पक्ष 'g':
			/* ignored */
			भङ्ग;
		पक्ष 'k':
			/* protocol 1, ignored */
			भङ्ग;
		पक्ष 'h':
			/* ignored */
			भङ्ग;
		पक्ष 't':
		पक्ष 'T':
		पक्ष 'G':
		पक्ष 'C':
			fatal("test/dump modes not supported");
			भङ्ग;
		पक्ष 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, रिक्त);
			यदि (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			भङ्ग;
		पक्ष 'o':
			/* ignored */
			भङ्ग;
		पक्ष 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		स्वभाव:
			usage();
			भङ्ग;
		}
	}

	यदि (!rexeced_flag)
		fatal("sshd-auth should not be executed directly");

	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_AUTH : options.log_facility, 1);

	/* XXX can't use monitor_init(); it makes fds */
	pmonitor = xcalloc(1, परिमाण(*pmonitor));
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_recvfd = PRIVSEP_MONITOR_FD;
	pmonitor->m_log_sendfd = PRIVSEP_LOG_FD;
	set_log_handler(mm_log_handler, pmonitor);

	/* Check that there are no remaining arguments. */
	यदि (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	/* Connection passed by stdin/out */
	यदि (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_in = dup(STDIN_FILENO);
		sock_out = dup(STDOUT_FILENO);
	} अन्यथा {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_in = sock_out = dup(STDIN_FILENO);
	}

	यदि (stdfd_devnull(1, 1, 0) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_in, sock_out);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	यदि ((ssh = ssh_packet_set_connection(रिक्त, sock_in, sock_out)) == रिक्त)
		fatal("Unable to create connection");
	the_active_state = ssh;
	ssh_packet_set_server(ssh);
	pmonitor->m_pkex = &ssh->kex;

	/* Fetch our configuration */
	यदि ((cfg = sshbuf_new()) == रिक्त)
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
	यदि ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == रिक्त) {
		यदि (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} अन्यथा {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, strlen(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

#ifdef WITH_OPENSSL
	यदि (options.moduli_file != रिक्त)
		dh_set_moduli_file(options.moduli_file);
#endif

	यदि (options.host_कुंजी_agent) {
		यदि (strcmp(options.host_कुंजी_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_कुंजी_agent, 1);
		यदि ((r = ssh_get_authentication_socket(रिक्त)) == 0)
			have_agent = 1;
		अन्यथा
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_कुंजी_agent);
	}

	यदि (options.अंक_host_कुंजी_files != अंक_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.अंक_host_कुंजी_files, अंक_hostkeys);
	}

	प्रति (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		यदि (host_pubkeys[i] != रिक्त) {
			have_कुंजी = 1;
			भङ्ग;
		}
	}
	यदि (!have_कुंजी)
		fatal("internal error: received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(शून्य) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	log_init(__progname, options.log_level, options.log_facility, 1);
	set_log_handler(mm_log_handler, pmonitor);
	प्रति (i = 0; i < options.अंक_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	यदि (chdir("/") == -1)
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
	authctxt = xcalloc(1, परिमाण(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	यदि ((auth_opts = sshauthopt_new_with_कुंजियाँ_defaults()) == रिक्त)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	यदि ((loginmsg = sshbuf_new()) == रिक्त)
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
	ssh_packet_clear_कुंजियाँ(ssh);
	exit(0);
}

पूर्णाङ्क
sshd_hostkey_sign(संरचना ssh *ssh, संरचना sshkey *privkey,
    संरचना sshkey *pubkey, u_char **signature, size_t *slenp,
    ध्रुव u_char *data, size_t dlen, ध्रुव वर्ण *alg)
{
	यदि (privkey) {
		यदि (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, रिक्त,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} अन्यथा {
		यदि (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    data, dlen, alg, options.sk_provider, रिक्त,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	प्रत्यागम 0;
}

/* SSH2 key exchange */
स्थिर शून्य
do_ssh2_kex(संरचना ssh *ssh)
{
	वर्ण *hkalgs = रिक्त, *myproposal[PROPOSAL_MAX];
	ध्रुव वर्ण *compression = रिक्त;
	संरचना kex *kex;
	पूर्णाङ्क r;

	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

	यदि (options.compression == COMP_NONE)
		compression = "none";
	hkalgs = list_hostkey_types();

	kex_proposal_populate_entries(ssh, myproposal, options.kex_algorithms,
	    options.ciphers, options.macs, compression, hkalgs);

	मुक्त(hkalgs);

	यदि ((r = kex_exchange_identification(ssh, -1,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");
	mm_sshkey_setcompat(ssh); /* tell monitor */

	यदि ((ssh->compat & SSH_BUG_NOREKEY))
		debug("client does not support rekeying");

	/* start key exchange */
	यदि ((r = kex_setup(ssh, myproposal)) != 0)
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
	kex->load_host_public_कुंजी=&get_hostkey_public_by_type;
	kex->load_host_private_कुंजी=&get_hostkey_private_by_type;
	kex->host_कुंजी_index=&get_hostkey_index;
	kex->sign = sshd_hostkey_sign;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	यदि ((r = sshpkt_start(ssh, SSH2_संदेश_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send test");
#endif
	debug("KEX done");
}

/* server specific fatal cleanup */
शून्य
cleanup_exit(पूर्णाङ्क i)
{
	_exit(i);
}
