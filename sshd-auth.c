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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/ioctl.h>
#समावेश <sys/wait.h>
#समावेश <sys/tree.h>
#समावेश <sys/stat.h>
#समावेश <sys/socket.h>
#समावेश <sys/time.h>
#समावेश <sys/queue.h>

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <netdb.h>
#समावेश <paths.h>
#समावेश <pwd.h>
#समावेश <grp.h>
#समावेश <signal.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <stdarg.h>
#समावेश <unistd.h>
#समावेश <limits.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/bn.h>
#समावेश <openssl/evp.h>
#पूर्ण_अगर

#समावेश "xmalloc.h"
#समावेश "ssh.h"
#समावेश "ssh2.h"
#समावेश "sshpty.h"
#समावेश "packet.h"
#समावेश "log.h"
#समावेश "sshbuf.h"
#समावेश "misc.h"
#समावेश "match.h"
#समावेश "servconf.h"
#समावेश "uidswap.h"
#समावेश "compat.h"
#समावेश "cipher.h"
#समावेश "digest.h"
#समावेश "sshkey.h"
#समावेश "kex.h"
#समावेश "authfile.h"
#समावेश "pathnames.h"
#समावेश "atomicio.h"
#समावेश "canohost.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "authfd.h"
#समावेश "msg.h"
#समावेश "dispatch.h"
#समावेश "channels.h"
#समावेश "session.h"
#समावेश "monitor.h"
#अगर_घोषित GSSAPI
#समावेश "ssh-gss.h"
#पूर्ण_अगर
#समावेश "monitor_wrap.h"
#समावेश "auth-options.h"
#समावेश "version.h"
#समावेश "ssherr.h"
#समावेश "sk-api.h"
#समावेश "srclimit.h"
#समावेश "ssh-sandbox.h"
#समावेश "dh.h"

/* Privsep fds */
#घोषणा PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#घोषणा PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#घोषणा PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

बाह्य अक्षर *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
अक्षर *config_file_name = _PATH_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
पूर्णांक debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
अटल पूर्णांक inetd_flag = 0;

/* Saved arguments to main(). */
अटल अक्षर **saved_argv;
अटल पूर्णांक saved_argc;


/* Daemon's agent connection */
पूर्णांक auth_sock = -1;
अटल पूर्णांक have_agent = 0;

u_int		अंक_hostkeys;
काष्ठा sshkey	**host_pubkeys;		/* all public host keys */
काष्ठा sshkey	**host_certificates;	/* all public host certificates */

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/* variables used for privilege separation */
काष्ठा monitor *pmonitor = शून्य;
पूर्णांक privsep_is_preauth = 1;
अटल पूर्णांक privsep_chroot = 1;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = शून्य;
काष्ठा ssh *the_active_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
काष्ठा sshauthopt *auth_opts = शून्य;

/* sshd_config buffer */
काष्ठा sshbuf *cfg;

/* Included files from the configuration file */
काष्ठा include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
काष्ठा sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
अटल व्योम do_ssh2_kex(काष्ठा ssh *);

/* Unprivileged user */
काष्ठा passwd *privsep_pw = शून्य;

#अगर_अघोषित HAVE_PLEDGE
अटल काष्ठा ssh_sandbox *box;
#पूर्ण_अगर

/* XXX stub */
पूर्णांक
mm_is_monitor(व्योम)
{
	वापस 0;
}

अटल व्योम
privsep_child_demote(व्योम)
{
	gid_t gidset[1];

#अगर_अघोषित HAVE_PLEDGE
	अगर ((box = ssh_sandbox_init(pmonitor)) == शून्य)
		fatal_f("ssh_sandbox_init failed");
#पूर्ण_अगर
	/* Demote the child */
	अगर (privsep_chroot) {
		/* Change our root directory */
		अगर (chroot(_PATH_PRIVSEP_CHROOT_DIR) == -1)
			fatal("chroot(\"%s\"): %s", _PATH_PRIVSEP_CHROOT_DIR,
			    म_त्रुटि(त्रुटि_सं));
		अगर (स_बदलो("/") == -1)
			fatal("chdir(\"/\"): %s", म_त्रुटि(त्रुटि_सं));

		/*
		 * Drop our privileges
		 * NB. Can't use setusercontext() after chroot.
		 */
		debug3("privsep user:group %u:%u", (u_int)privsep_pw->pw_uid,
		    (u_int)privsep_pw->pw_gid);
		gidset[0] = privsep_pw->pw_gid;
		अगर (setgroups(1, gidset) == -1)
			fatal("setgroups: %.100s", म_त्रुटि(त्रुटि_सं));
		permanently_set_uid(privsep_pw);
	}

	/* sandbox ourselves */
#अगर_घोषित HAVE_PLEDGE
	अगर (pledge("stdio", शून्य) == -1)
		fatal_f("pledge()");
#अन्यथा
	ssh_sandbox_child(box);
#पूर्ण_अगर
}

अटल व्योम
append_hostkey_type(काष्ठा sshbuf *b, स्थिर अक्षर *s)
{
	पूर्णांक r;

	अगर (match_pattern_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		वापस;
	}
	अगर ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

अटल अक्षर *
list_hostkey_types(व्योम)
{
	काष्ठा sshbuf *b;
	काष्ठा sshkey *कुंजी;
	अक्षर *ret;
	u_int i;

	अगर ((b = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	क्रम (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		कुंजी = host_pubkeys[i];
		अगर (कुंजी == शून्य)
			जारी;
		चयन (कुंजी->type) {
		हाल कुंजी_RSA:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b, "rsa-sha2-512");
			append_hostkey_type(b, "rsa-sha2-256");
			/* FALLTHROUGH */
		हाल कुंजी_ECDSA:
		हाल कुंजी_ED25519:
		हाल कुंजी_MLDSA44_ED25519:
		हाल कुंजी_ECDSA_SK:
		हाल कुंजी_ED25519_SK:
			append_hostkey_type(b, sshkey_ssh_name(कुंजी));
			अवरोध;
		}
		/* If the private key has a cert peer, then list that too */
		कुंजी = host_certificates[i];
		अगर (कुंजी == शून्य)
			जारी;
		चयन (कुंजी->type) {
		हाल कुंजी_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			/* FALLTHROUGH */
		हाल कुंजी_ECDSA_CERT:
		हाल कुंजी_ED25519_CERT:
		हाल कुंजी_MLDSA44_ED25519_CERT:
		हाल कुंजी_ECDSA_SK_CERT:
		हाल कुंजी_ED25519_SK_CERT:
			append_hostkey_type(b, sshkey_ssh_name(कुंजी));
			अवरोध;
		}
	}
	अगर ((ret = sshbuf_dup_string(b)) == शून्य)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	वापस ret;
}

काष्ठा sshkey *
get_hostkey_public_by_type(पूर्णांक type, पूर्णांक nid, काष्ठा ssh *ssh)
{
	u_int i;
	काष्ठा sshkey *कुंजी;

	क्रम (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		चयन (type) {
		हाल कुंजी_RSA_CERT:
		हाल कुंजी_ECDSA_CERT:
		हाल कुंजी_ED25519_CERT:
		हाल कुंजी_MLDSA44_ED25519_CERT:
		हाल कुंजी_ECDSA_SK_CERT:
		हाल कुंजी_ED25519_SK_CERT:
			कुंजी = host_certificates[i];
			अवरोध;
		शेष:
			कुंजी = host_pubkeys[i];
			अवरोध;
		}
		अगर (कुंजी == शून्य || कुंजी->type != type)
			जारी;
		चयन (type) {
		हाल कुंजी_ECDSA:
		हाल कुंजी_ECDSA_SK:
		हाल कुंजी_ECDSA_CERT:
		हाल कुंजी_ECDSA_SK_CERT:
			अगर (कुंजी->ecdsa_nid != nid)
				जारी;
			/* FALLTHROUGH */
		शेष:
			वापस कुंजी;
		}
	}
	वापस शून्य;
}

/* XXX remove */
काष्ठा sshkey *
get_hostkey_private_by_type(पूर्णांक type, पूर्णांक nid, काष्ठा ssh *ssh)
{
	वापस शून्य;
}

/* XXX remove */
काष्ठा sshkey *
get_hostkey_by_सूचकांक(पूर्णांक ind)
{
	वापस शून्य;
}

काष्ठा sshkey *
get_hostkey_public_by_सूचकांक(पूर्णांक ind, काष्ठा ssh *ssh)
{
	अगर (ind < 0 || (u_int)ind >= options.अंक_host_कुंजी_files)
		वापस (शून्य);
	वापस host_pubkeys[ind];
}

पूर्णांक
get_hostkey_सूचकांक(काष्ठा sshkey *कुंजी, पूर्णांक compare, काष्ठा ssh *ssh)
{
	u_int i;

	क्रम (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		अगर (sshkey_is_cert(कुंजी)) {
			अगर (कुंजी == host_certificates[i] ||
			    (compare && host_certificates[i] &&
			    sshkey_equal(कुंजी, host_certificates[i])))
				वापस (i);
		} अन्यथा {
			अगर (कुंजी == host_pubkeys[i] ||
			    (compare && host_pubkeys[i] &&
			    sshkey_equal(कुंजी, host_pubkeys[i])))
				वापस (i);
		}
	}
	वापस (-1);
}

अटल व्योम
usage(व्योम)
{
	ख_लिखो(मानक_त्रुटि, "%s, %s\n", SSH_VERSION, SSH_OPENSSL_VERSION);
	ख_लिखो(मानक_त्रुटि,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	निकास(1);
}

अटल व्योम
parse_hostkeys(काष्ठा sshbuf *hostkeys)
{
	पूर्णांक r;
	u_int अंक_कुंजियाँ = 0;
	काष्ठा sshkey *k;
	स्थिर u_char *cp;
	माप_प्रकार len;

	जबतक (sshbuf_len(hostkeys) != 0) {
		अगर (अंक_कुंजियाँ > 2048)
			fatal_f("too many hostkeys");
		host_pubkeys = xrecallocarray(host_pubkeys,
		    अंक_कुंजियाँ, अंक_कुंजियाँ + 1, माप(*host_pubkeys));
		host_certificates = xrecallocarray(host_certificates,
		    अंक_कुंजियाँ, अंक_कुंजियाँ + 1, माप(*host_certificates));
		/* public key */
		k = शून्य;
		अगर ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		अगर (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_pubkeys[अंक_कुंजियाँ] = k;
		अगर (k)
			debug2_f("key %u: %s", अंक_कुंजियाँ, sshkey_ssh_name(k));
		/* certificate */
		k = शून्य;
		अगर ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		अगर (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_certificates[अंक_कुंजियाँ] = k;
		अगर (k)
			debug2_f("cert %u: %s", अंक_कुंजियाँ, sshkey_ssh_name(k));
		अंक_कुंजियाँ++;
	}
	अंक_hostkeys = अंक_कुंजियाँ;
}

अटल व्योम
recv_privsep_state(काष्ठा ssh *ssh, ServerOptions *o, uint64_t *timing_secretp)
{
	काष्ठा sshbuf *hostkeys;

	debug3_f("begin");

	mm_get_state(ssh, o, शून्य, timing_secretp,
	    &hostkeys, शून्य, शून्य, शून्य, शून्य);
	parse_hostkeys(hostkeys);

	sshbuf_free(hostkeys);

	debug3_f("done");
}

/*
 * Main program for the daemon.
 */
पूर्णांक
मुख्य(पूर्णांक ac, अक्षर **av)
{
	काष्ठा ssh *ssh = शून्य;
	बाह्य अक्षर *optarg;
	बाह्य पूर्णांक optind;
	पूर्णांक r, opt, have_कुंजी = 0;
	पूर्णांक sock_in = -1, sock_out = -1, rexeced_flag = 0;
	u_int i;
	mode_t new_umask;
	Authctxt *authctxt;
	sigset_t sigmask;
	uint64_t timing_secret = 0;

	closefrom(PRIVSEP_MIN_FREE_FD);
	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, शून्य);

#अगर_घोषित HAVE_SECUREWARE
	(व्योम)set_auth_parameters(ac, av);
#पूर्ण_अगर
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, माप(*saved_argv));
	क्रम (i = 0; (पूर्णांक)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = शून्य;

	seed_rng();

#अगर_अघोषित HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#पूर्ण_अगर

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	जबतक ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		चयन (opt) {
		हाल '4':
			/* ignore */
			अवरोध;
		हाल '6':
			/* ignore */
			अवरोध;
		हाल 'f':
			/* ignore */
			अवरोध;
		हाल 'c':
			/* ignore */
			अवरोध;
		हाल 'd':
			अगर (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} अन्यथा अगर (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			अवरोध;
		हाल 'D':
		हाल 'E':
		हाल 'e':
			/* ignore */
			अवरोध;
		हाल 'i':
			inetd_flag = 1;
			अवरोध;
		हाल 'r':
			/* ignore */
			अवरोध;
		हाल 'R':
			rexeced_flag = 1;
			अवरोध;
		हाल 'Q':
			/* ignored */
			अवरोध;
		हाल 'q':
			/* ignored */
			अवरोध;
		हाल 'b':
			/* protocol 1, ignored */
			अवरोध;
		हाल 'p':
			/* ignored */
			अवरोध;
		हाल 'g':
			/* ignored */
			अवरोध;
		हाल 'k':
			/* protocol 1, ignored */
			अवरोध;
		हाल 'h':
			/* ignored */
			अवरोध;
		हाल 't':
		हाल 'T':
		हाल 'G':
		हाल 'C':
			fatal("test/dump modes not supported");
			अवरोध;
		हाल 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, शून्य);
			अगर (utmp_len > HOST_NAME_MAX+1) {
				ख_लिखो(मानक_त्रुटि, "Invalid utmp length.\n");
				निकास(1);
			}
			अवरोध;
		हाल 'o':
			/* ignored */
			अवरोध;
		हाल 'V':
			ख_लिखो(मानक_त्रुटि, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			निकास(0);
		शेष:
			usage();
			अवरोध;
		}
	}

	अगर (!rexeced_flag)
		fatal("sshd-auth should not be executed directly");

	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_AUTH : options.log_facility, 1);

	/* XXX can't use monitor_init(); it makes fds */
	pmonitor = xcalloc(1, माप(*pmonitor));
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_recvfd = PRIVSEP_MONITOR_FD;
	pmonitor->m_log_sendfd = PRIVSEP_LOG_FD;
	set_log_handler(mm_log_handler, pmonitor);

	/* Check that there are no remaining arguments. */
	अगर (optind < ac) {
		ख_लिखो(मानक_त्रुटि, "Extra argument %s.\n", av[optind]);
		निकास(1);
	}

	/* Connection passed by stdin/out */
	अगर (inetd_flag) {
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

	अगर (stdfd_devnull(1, 1, 0) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_in, sock_out);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	अगर ((ssh = ssh_packet_set_connection(शून्य, sock_in, sock_out)) == शून्य)
		fatal("Unable to create connection");
	the_active_state = ssh;
	ssh_packet_set_server(ssh);
	pmonitor->m_pkex = &ssh->kex;

	/* Fetch our configuration */
	अगर ((cfg = sshbuf_new()) == शून्य)
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
	अगर ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == शून्य) {
		अगर (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} अन्यथा {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, म_माप(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

#अगर_घोषित WITH_OPENSSL
	अगर (options.moduli_file != शून्य)
		dh_set_moduli_file(options.moduli_file);
#पूर्ण_अगर

	अगर (options.host_कुंजी_agent) {
		अगर (म_भेद(options.host_कुंजी_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_कुंजी_agent, 1);
		अगर ((r = ssh_get_authentication_socket(शून्य)) == 0)
			have_agent = 1;
		अन्यथा
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_कुंजी_agent);
	}

	अगर (options.अंक_host_कुंजी_files != अंक_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.अंक_host_कुंजी_files, अंक_hostkeys);
	}

	क्रम (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		अगर (host_pubkeys[i] != शून्य) {
			have_कुंजी = 1;
			अवरोध;
		}
	}
	अगर (!have_कुंजी)
		fatal("internal error: received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(व्योम) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	log_init(__progname, options.log_level, options.log_facility, 1);
	set_log_handler(mm_log_handler, pmonitor);
	क्रम (i = 0; i < options.अंक_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	अगर (स_बदलो("/") == -1)
		error("chdir(\"/\"): %s", म_त्रुटि(त्रुटि_सं));

	/* This is the child authenticating a new connection. */
	setproctitle("%s", "[session-auth]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_out);
	FD_CLOSEONEXEC(sock_in);

	ssh_signal(SIGPIPE, संक_छोड़ो);
	ssh_signal(SIGALRM, संक_पूर्व);
	ssh_signal(SIGHUP, संक_पूर्व);
	ssh_signal(संक_इति, संक_पूर्व);
	ssh_signal(SIGQUIT, संक_पूर्व);
	ssh_signal(SIGCHLD, संक_पूर्व);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_set_af(ssh, options.address_family);
	channel_set_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);

	ssh_packet_set_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, माप(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	अगर ((auth_opts = sshauthopt_new_with_कुंजियाँ_defaults()) == शून्य)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	अगर ((loginmsg = sshbuf_new()) == शून्य)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

#अगर_घोषित GSSAPI
	/* Cache supported mechanism OIDs for later use */
	ssh_gssapi_prepare_supported_oids();
#पूर्ण_अगर

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
	निकास(0);
}

पूर्णांक
sshd_hostkey_sign(काष्ठा ssh *ssh, काष्ठा sshkey *privkey,
    काष्ठा sshkey *pubkey, u_char **signature, माप_प्रकार *slenp,
    स्थिर u_char *तथ्य, माप_प्रकार dlen, स्थिर अक्षर *alg)
{
	अगर (privkey) {
		अगर (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    तथ्य, dlen, alg, options.sk_provider, शून्य,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} अन्यथा {
		अगर (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    तथ्य, dlen, alg, options.sk_provider, शून्य,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	वापस 0;
}

/* SSH2 key exchange */
अटल व्योम
do_ssh2_kex(काष्ठा ssh *ssh)
{
	अक्षर *hkalgs = शून्य, *myproposal[PROPOSAL_MAX];
	स्थिर अक्षर *compression = शून्य;
	काष्ठा kex *kex;
	पूर्णांक r;

	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

	अगर (options.compression == COMP_NONE)
		compression = "none";
	hkalgs = list_hostkey_types();

	kex_proposal_populate_entries(ssh, myproposal, options.kex_algorithms,
	    options.ciphers, options.macs, compression, hkalgs);

	मुक्त(hkalgs);

	अगर ((r = kex_exchange_identification(ssh, -1,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");
	mm_sshkey_setcompat(ssh); /* tell monitor */

	अगर ((ssh->compat & SSH_BUG_NOREKEY))
		debug("client does not support rekeying");

	/* start key exchange */
	अगर ((r = kex_setup(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
	kex_set_server_sig_algs(ssh, options.pubkey_accepted_algos);
	kex_set_warn_weak_crypto(ssh, options.warn_weak_crypto);
	kex = ssh->kex;

#अगर_घोषित WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#पूर्ण_अगर
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->load_host_public_कुंजी=&get_hostkey_public_by_type;
	kex->load_host_private_कुंजी=&get_hostkey_private_by_type;
	kex->host_कुंजी_सूचकांक=&get_hostkey_सूचकांक;
	kex->sign = sshd_hostkey_sign;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &kex->done);
	kex_proposal_free_entries(myproposal);

#अगर_घोषित DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send test");
#पूर्ण_अगर
	debug("KEX done");
}

/* server specific fatal cleanup */
व्योम
cleanup_exit(पूर्णांक i)
{
	_निकास(i);
}
