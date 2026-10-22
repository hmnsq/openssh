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

#अगर_घोषित HAVE_SECUREWARE
#समावेश <sys/security.h>
#समावेश <prot.h>
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
#समावेश "dh.h"

/* Re-exec fds */
#घोषणा REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#घोषणा REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 2)
#घोषणा REEXEC_MIN_FREE_FD		(STDERR_FILENO + 3)

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

/* debug goes to stderr unless inetd_flag is set */
अटल पूर्णांक log_stderr = 0;

/* Saved arguments to main(). */
अटल अक्षर **saved_argv;
अटल पूर्णांक saved_argc;

/* Daemon's agent connection */
पूर्णांक auth_sock = -1;
अटल पूर्णांक have_agent = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
काष्ठा {
	u_int		अंक_hostkeys;
	काष्ठा sshkey	**host_कुंजियाँ;		/* all private host keys */
	काष्ठा sshkey	**host_pubkeys;		/* all public host keys */
	काष्ठा sshkey	**host_certificates;	/* all public host certificates */
} sensitive_तथ्य;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

अटल पूर्णांक startup_pipe = -1;		/* in child */

/* variables used for privilege separation */
काष्ठा monitor *pmonitor = शून्य;
पूर्णांक privsep_is_preauth = 1;
अटल पूर्णांक privsep_chroot = 1;

/* Unprivileged user */
काष्ठा passwd *privsep_pw = शून्य;

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
व्योम destroy_sensitive_तथ्य(व्योम);
व्योम demote_sensitive_तथ्य(व्योम);

/* XXX reduce to stub once postauth split */
पूर्णांक
mm_is_monitor(व्योम)
{
	/*
	 * m_pid is only set in the privileged part, and
	 * points to the unprivileged child.
	 */
	वापस (pmonitor && pmonitor->m_pid > 0);
}

/*
 * Signal handler for the alarm after the login grace period has expired.
 * As usual, this may only take signal-safe actions, even though it is
 * terminal.
 */
अटल व्योम
grace_alarm_handler(पूर्णांक sig)
{
	/*
	 * Try to kill any processes that we have spawned, E.g. authorized
	 * keys command helpers or privsep children.
	 */
	अगर (getpgid(0) == getpid()) {
		काष्ठा sigaction sa;

		/* mask all other signals while in handler */
		स_रखो(&sa, 0, माप(sa));
		sa.sa_handler = संक_छोड़ो;
		sigfillset(&sa.sa_mask);
#अगर defined(SA_RESTART)
		sa.sa_flags = SA_RESTART;
#पूर्ण_अगर
		(व्योम)sigaction(संक_इति, &sa, शून्य);
		समाप्त(0, संक_इति);
	}
	_निकास(EXIT_LOGIN_GRACE);
}

/* Destroy the host and server keys.  They will no longer be needed. */
व्योम
destroy_sensitive_तथ्य(व्योम)
{
	u_int i;

	क्रम (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		अगर (sensitive_तथ्य.host_कुंजियाँ[i]) {
			sshkey_free(sensitive_तथ्य.host_कुंजियाँ[i]);
			sensitive_तथ्य.host_कुंजियाँ[i] = शून्य;
		}
		अगर (sensitive_तथ्य.host_certificates[i]) {
			sshkey_free(sensitive_तथ्य.host_certificates[i]);
			sensitive_तथ्य.host_certificates[i] = शून्य;
		}
	}
}

/* Demote private to public keys for network child */
व्योम
demote_sensitive_तथ्य(व्योम)
{
	काष्ठा sshkey *tmp;
	u_int i;
	पूर्णांक r;

	क्रम (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		अगर (sensitive_तथ्य.host_कुंजियाँ[i]) {
			अगर ((r = sshkey_from_private(
			    sensitive_तथ्य.host_कुंजियाँ[i], &tmp)) != 0)
				fatal_r(r, "could not demote host %s key",
				    sshkey_type(sensitive_तथ्य.host_कुंजियाँ[i]));
			sshkey_free(sensitive_तथ्य.host_कुंजियाँ[i]);
			sensitive_तथ्य.host_कुंजियाँ[i] = tmp;
		}
		/* Certs do not need demotion */
	}
}

काष्ठा sshbuf *
pack_hostkeys(व्योम)
{
	काष्ठा sshbuf *keybuf = शून्य, *hostkeys = शून्य;
	पूर्णांक r;
	u_int i;

	अगर ((hostkeys = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	क्रम (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		/* public key */
		अगर (sensitive_तथ्य.host_pubkeys[i] != शून्य) {
			अगर ((r = sshkey_puts(sensitive_तथ्य.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} अन्यथा {
			अगर ((r = sshbuf_put_string(hostkeys, शून्य, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		अगर (sensitive_तथ्य.host_certificates[i] != शून्य) {
			अगर ((r = sshkey_puts(
			    sensitive_तथ्य.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} अन्यथा {
			अगर ((r = sshbuf_put_string(hostkeys, शून्य, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	sshbuf_free(keybuf);
	वापस hostkeys;
}

अटल पूर्णांक
privsep_preauth(काष्ठा ssh *ssh)
{
	पूर्णांक r;
	pid_t pid;

	/* Set up unprivileged child process to deal with network data */
	pmonitor = monitor_init();
	/* Store a pointer to the kex for later rekeying */
	pmonitor->m_pkex = &ssh->kex;

	अगर ((pid = विभाजन()) == -1)
		fatal("fork of unprivileged child failed");
	अन्यथा अगर (pid != 0) {
		debug2("Network child is on pid %ld", (दीर्घ)pid);

		pmonitor->m_pid = pid;
		अगर (have_agent) {
			r = ssh_get_authentication_socket(&auth_sock);
			अगर (r != 0) {
				error_r(r, "Could not get agent socket");
				have_agent = 0;
			}
		}
		monitor_child_preauth(ssh, pmonitor);
		privsep_is_preauth = 0;
		वापस 1;
	} अन्यथा {
		/* child */
		बंद(pmonitor->m_sendfd);
		बंद(pmonitor->m_log_recvfd);

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

		अगर (ssh_packet_get_connection_in(ssh) != STDIN_FILENO &&
		    dup2(ssh_packet_get_connection_in(ssh), STDIN_FILENO) == -1)
			fatal("dup2 stdin failed: %s", म_त्रुटि(त्रुटि_सं));
		अगर (ssh_packet_get_connection_out(ssh) != STDOUT_FILENO &&
		    dup2(ssh_packet_get_connection_out(ssh),
		    STDOUT_FILENO) == -1)
			fatal("dup2 stdout failed: %s", म_त्रुटि(त्रुटि_सं));
		/* leave stderr as-is */
		log_redirect_stderr_to(शून्य); /* dup can clobber log fd */
		अगर (pmonitor->m_recvfd != PRIVSEP_MONITOR_FD &&
		    dup2(pmonitor->m_recvfd, PRIVSEP_MONITOR_FD) == -1)
			fatal("dup2 monitor fd: %s", म_त्रुटि(त्रुटि_सं));
		अगर (pmonitor->m_log_sendfd != PRIVSEP_LOG_FD &&
		    dup2(pmonitor->m_log_sendfd, PRIVSEP_LOG_FD) == -1)
			fatal("dup2 log fd: %s", म_त्रुटि(त्रुटि_सं));
		closefrom(PRIVSEP_MIN_FREE_FD);

		saved_argv[0] = options.sshd_auth_path;
		execv(options.sshd_auth_path, saved_argv);

		fatal_f("exec of %s failed: %s",
		    options.sshd_auth_path, म_त्रुटि(त्रुटि_सं));
	}
}

अटल व्योम
privsep_postauth(काष्ठा ssh *ssh, Authctxt *authctxt)
{
	/* New socket pair */
	monitor_reinit(pmonitor);

	pmonitor->m_pid = विभाजन();
	अगर (pmonitor->m_pid == -1)
		fatal("fork of unprivileged child failed");
	अन्यथा अगर (pmonitor->m_pid != 0) {
		verbose("User child is on pid %ld", (दीर्घ)pmonitor->m_pid);
		sshbuf_reset(loginmsg);
		monitor_clear_keystate(ssh, pmonitor);
		monitor_child_postauth(ssh, pmonitor);

		/* NEVERREACHED */
		निकास(0);
	}

	/* child */

	बंद(pmonitor->m_sendfd);
	pmonitor->m_sendfd = -1;

	/* Demote the private keys to public keys. */
	demote_sensitive_तथ्य();

	reseed_prngs();

#अगर_अघोषित SKIP_PRIVDROP
	/* Drop privileges */
	do_setusercontext(authctxt->pw);
#पूर्ण_अगर

	/* It is safe now to apply the key state */
	monitor_apply_keystate(ssh, pmonitor);

	/*
	 * Tell the packet layer that authentication was successful, since
	 * this information is not part of the key state.
	 */
	ssh_packet_set_authenticated(ssh);
}

अटल काष्ठा sshkey *
get_hostkey_by_type(पूर्णांक type, पूर्णांक nid, पूर्णांक need_private, काष्ठा ssh *ssh)
{
	u_int i;
	काष्ठा sshkey *कुंजी;

	क्रम (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		चयन (type) {
		हाल कुंजी_RSA_CERT:
		हाल कुंजी_ECDSA_CERT:
		हाल कुंजी_ED25519_CERT:
		हाल कुंजी_ECDSA_SK_CERT:
		हाल कुंजी_ED25519_SK_CERT:
		हाल कुंजी_MLDSA44_ED25519_CERT:
			कुंजी = sensitive_तथ्य.host_certificates[i];
			अवरोध;
		शेष:
			कुंजी = sensitive_तथ्य.host_कुंजियाँ[i];
			अगर (कुंजी == शून्य && !need_private)
				कुंजी = sensitive_तथ्य.host_pubkeys[i];
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
			वापस need_private ?
			    sensitive_तथ्य.host_कुंजियाँ[i] : कुंजी;
		}
	}
	वापस शून्य;
}

काष्ठा sshkey *
get_hostkey_public_by_type(पूर्णांक type, पूर्णांक nid, काष्ठा ssh *ssh)
{
	वापस get_hostkey_by_type(type, nid, 0, ssh);
}

काष्ठा sshkey *
get_hostkey_private_by_type(पूर्णांक type, पूर्णांक nid, काष्ठा ssh *ssh)
{
	वापस get_hostkey_by_type(type, nid, 1, ssh);
}

काष्ठा sshkey *
get_hostkey_by_सूचकांक(पूर्णांक ind)
{
	अगर (ind < 0 || (u_int)ind >= options.अंक_host_कुंजी_files)
		वापस (शून्य);
	वापस (sensitive_तथ्य.host_कुंजियाँ[ind]);
}

काष्ठा sshkey *
get_hostkey_public_by_सूचकांक(पूर्णांक ind, काष्ठा ssh *ssh)
{
	अगर (ind < 0 || (u_int)ind >= options.अंक_host_कुंजी_files)
		वापस (शून्य);
	वापस (sensitive_तथ्य.host_pubkeys[ind]);
}

पूर्णांक
get_hostkey_सूचकांक(काष्ठा sshkey *कुंजी, पूर्णांक compare, काष्ठा ssh *ssh)
{
	u_int i;

	क्रम (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		अगर (sshkey_is_cert(कुंजी)) {
			अगर (कुंजी == sensitive_तथ्य.host_certificates[i] ||
			    (compare && sensitive_तथ्य.host_certificates[i] &&
			    sshkey_equal(कुंजी,
			    sensitive_तथ्य.host_certificates[i])))
				वापस (i);
		} अन्यथा {
			अगर (कुंजी == sensitive_तथ्य.host_कुंजियाँ[i] ||
			    (compare && sensitive_तथ्य.host_कुंजियाँ[i] &&
			    sshkey_equal(कुंजी, sensitive_तथ्य.host_कुंजियाँ[i])))
				वापस (i);
			अगर (कुंजी == sensitive_तथ्य.host_pubkeys[i] ||
			    (compare && sensitive_तथ्य.host_pubkeys[i] &&
			    sshkey_equal(कुंजी, sensitive_तथ्य.host_pubkeys[i])))
				वापस (i);
		}
	}
	वापस (-1);
}

/* Inform the client of all hostkeys */
अटल व्योम
notify_hostkeys(काष्ठा ssh *ssh)
{
	काष्ठा sshbuf *buf;
	काष्ठा sshkey *कुंजी;
	u_int i, nkeys;
	पूर्णांक r;
	अक्षर *fp;

	/* Some clients cannot cope with the hostkeys message, skip those. */
	अगर (ssh->compat & SSH_BUG_HOSTKEYS)
		वापस;

	अगर ((buf = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	क्रम (i = nkeys = 0; i < options.अंक_host_कुंजी_files; i++) {
		कुंजी = get_hostkey_public_by_सूचकांक(i, ssh);
		अगर (कुंजी == शून्य || कुंजी->type == कुंजी_UNSPEC ||
		    sshkey_is_cert(कुंजी))
			जारी;
		fp = sshkey_fingerprint(कुंजी, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("key %d: %s %s", i, sshkey_ssh_name(कुंजी), fp);
		मुक्त(fp);
		अगर (nkeys == 0) {
			/*
			 * Start building the request when we find the
			 * first usable key.
			 */
			अगर ((r = sshpkt_start(ssh, SSH2_संदेश_GLOBAL_REQUEST)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "hostkeys-00@openssh.com")) != 0 ||
			    (r = sshpkt_put_u8(ssh, 0)) != 0) /* want reply */
				sshpkt_fatal(ssh, r, "%s: start request", __func__);
		}
		/* Append the key to the request */
		sshbuf_reset(buf);
		अगर ((r = sshkey_putb(कुंजी, buf)) != 0)
			fatal_fr(r, "couldn't put hostkey %d", i);
		अगर ((r = sshpkt_put_stringb(ssh, buf)) != 0)
			sshpkt_fatal(ssh, r, "%s: append key", __func__);
		nkeys++;
	}
	debug3_f("sent %u hostkeys", nkeys);
	अगर (nkeys == 0)
		fatal_f("no hostkeys");
	अगर ((r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send", __func__);
	sshbuf_free(buf);
}

अटल व्योम
usage(व्योम)
{
	ख_लिखो(मानक_त्रुटि, "%s, %s\n", SSH_RELEASE, SSH_OPENSSL_VERSION);
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
	काष्ठा sshbuf *kbuf;
	स्थिर u_char *cp;
	माप_प्रकार len;

	जबतक (sshbuf_len(hostkeys) != 0) {
		अगर (अंक_कुंजियाँ > 2048)
			fatal_f("too many hostkeys");
		sensitive_तथ्य.host_कुंजियाँ = xrecallocarray(
		    sensitive_तथ्य.host_कुंजियाँ, अंक_कुंजियाँ, अंक_कुंजियाँ + 1,
		    माप(*sensitive_तथ्य.host_pubkeys));
		sensitive_तथ्य.host_pubkeys = xrecallocarray(
		    sensitive_तथ्य.host_pubkeys, अंक_कुंजियाँ, अंक_कुंजियाँ + 1,
		    माप(*sensitive_तथ्य.host_pubkeys));
		sensitive_तथ्य.host_certificates = xrecallocarray(
		    sensitive_तथ्य.host_certificates, अंक_कुंजियाँ, अंक_कुंजियाँ + 1,
		    माप(*sensitive_तथ्य.host_certificates));
		/* private key */
		k = शून्य;
		अगर ((r = sshbuf_froms(hostkeys, &kbuf)) != 0)
			fatal_fr(r, "extract privkey");
		अगर (sshbuf_len(kbuf) != 0 &&
		    (r = sshkey_private_deserialize(kbuf, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_तथ्य.host_कुंजियाँ[अंक_कुंजियाँ] = k;
		sshbuf_free(kbuf);
		अगर (k)
			debug2_f("privkey %u: %s", अंक_कुंजियाँ, sshkey_ssh_name(k));
		/* public key */
		k = शून्य;
		अगर ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		अगर (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_तथ्य.host_pubkeys[अंक_कुंजियाँ] = k;
		अगर (k)
			debug2_f("pubkey %u: %s", अंक_कुंजियाँ, sshkey_ssh_name(k));
		/* certificate */
		k = शून्य;
		अगर ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		अगर (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		sensitive_तथ्य.host_certificates[अंक_कुंजियाँ] = k;
		अगर (k)
			debug2_f("cert %u: %s", अंक_कुंजियाँ, sshkey_ssh_name(k));
		अंक_कुंजियाँ++;
	}
	sensitive_तथ्य.अंक_hostkeys = अंक_कुंजियाँ;
}

अटल व्योम
recv_rexec_state(पूर्णांक fd, काष्ठा sshbuf *conf, uint64_t *timing_secretp)
{
	काष्ठा sshbuf *m, *inc, *hostkeys;
	u_char *cp, ver;
	माप_प्रकार len;
	पूर्णांक r;
	काष्ठा include_item *item;

	debug3_f("entering fd = %d", fd);

	अगर ((m = sshbuf_new()) == शून्य || (inc = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	/* receive config */
	अगर (ssh_संदेश_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	अगर ((r = sshbuf_get_u8(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	अगर (ver != 0)
		fatal_f("rexec version mismatch");
	अगर ((r = sshbuf_get_string(m, &cp, &len)) != 0 || /* XXX _direct */
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_get_stringb(m, inc)) != 0)
		fatal_fr(r, "parse config");

	अगर (conf != शून्य && (r = sshbuf_put(conf, cp, len)))
		fatal_fr(r, "sshbuf_put");

	जबतक (sshbuf_len(inc) != 0) {
		item = xcalloc(1, माप(*item));
		अगर ((item->contents = sshbuf_new()) == शून्य)
			fatal_f("sshbuf_new failed");
		अगर ((r = sshbuf_get_cstring(inc, &item->selector, शून्य)) != 0 ||
		    (r = sshbuf_get_cstring(inc, &item->filename, शून्य)) != 0 ||
		    (r = sshbuf_get_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "parse includes");
		TAILQ_INSERT_TAIL(&includes, item, entry);
	}

	/* receive hostkeys */
	sshbuf_reset(m);
	अगर (ssh_संदेश_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	अगर ((r = sshbuf_get_u8(m, शून्य)) != 0 ||
	    (r = sshbuf_froms(m, &hostkeys)) != 0)
		fatal_fr(r, "parse config");
	parse_hostkeys(hostkeys);

	मुक्त(cp);
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
अटल व्योम
check_ip_options(काष्ठा ssh *ssh)
{
#अगर_घोषित IP_OPTIONS
	पूर्णांक sock_in = ssh_packet_get_connection_in(ssh);
	काष्ठा sockaddr_storage from;
	u_char opts[200];
	socklen_t i, option_आकार = माप(opts), fromlen = माप(from);
	अक्षर text[माप(opts) * 3 + 1];

	स_रखो(&from, 0, माप(from));
	अगर (getpeername(sock_in, (काष्ठा sockaddr *)&from,
	    &fromlen) == -1)
		वापस;
	अगर (from.ss_family != AF_INET)
		वापस;
	/* XXX IPv6 options? */

	अगर (getsockopt(sock_in, IPPROTO_IP, IP_OPTIONS, opts,
	    &option_आकार) >= 0 && option_आकार != 0) {
		text[0] = '\0';
		क्रम (i = 0; i < option_आकार; i++)
			snprintf(text + i*3, माप(text) - i*3,
			    " %2.2x", opts[i]);
		fatal("Connection from %.100s port %d with IP opts: %.800s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), text);
	}
#पूर्ण_अगर /* IP_OPTIONS */
}

/* Set the routing domain for this process */
अटल व्योम
set_process_rdomain(काष्ठा ssh *ssh, स्थिर अक्षर *name)
{
#अगर defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
	अगर (name == शून्य)
		वापस; /* default */

	अगर (म_भेद(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		अगर ((name = ssh_packet_rdomain_in(ssh)) == शून्य)
			वापस;
	}
	/* NB. We don't pass 'ssh' to sys_set_process_rdomain() */
	वापस sys_set_process_rdomain(name);
#या_अगर defined(__OpenBSD__)
	पूर्णांक rtable, ortable = getrtable();
	स्थिर अक्षर *errstr;

	अगर (name == शून्य)
		वापस; /* default */

	अगर (म_भेद(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		अगर ((name = ssh_packet_rdomain_in(ssh)) == शून्य)
			वापस;
	}

	rtable = (पूर्णांक)strtonum(name, 0, 255, &errstr);
	अगर (errstr != शून्य) /* Shouldn't happen */
		fatal("Invalid routing domain \"%s\": %s", name, errstr);
	अगर (rtable != ortable && setrtable(rtable) != 0)
		fatal("Unable to set routing domain %d: %s",
		    rtable, म_त्रुटि(त्रुटि_सं));
	debug_f("set routing domain %d (was %d)", rtable, ortable);
#अन्यथा /* defined(__OpenBSD__) */
	fatal("Unable to set routing domain: not supported in this platform");
#पूर्ण_अगर
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
	पूर्णांक devnull, r, opt, remote_port;
	पूर्णांक sock_in = -1, sock_out = -1, rexeced_flag = 0, have_कुंजी = 0;
	स्थिर अक्षर *remote_ip, *rdomain;
	अक्षर *पंक्ति, *laddr, *logfile = शून्य;
	u_int i;
	uint64_t ibytes, obytes;
	mode_t new_umask;
	Authctxt *authctxt;
	काष्ठा connection_info *connection_info = शून्य;
	sigset_t sigmask;
	uint64_t timing_secret = 0;
	काष्ठा itimerval itv;

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
			options.address_family = AF_INET;
			अवरोध;
		हाल '6':
			options.address_family = AF_INET6;
			अवरोध;
		हाल 'f':
			config_file_name = optarg;
			अवरोध;
		हाल 'c':
			servconf_add_hostcert("[command-line]", 0,
			    &options, optarg);
			अवरोध;
		हाल 'd':
			अगर (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} अन्यथा अगर (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			अवरोध;
		हाल 'D':
			/* ignore */
			अवरोध;
		हाल 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		हाल 'e':
			log_stderr = 1;
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
			options.log_level = SYSLOG_LEVEL_QUIET;
			अवरोध;
		हाल 'b':
			/* protocol 1, ignored */
			अवरोध;
		हाल 'p':
			options.ports_from_cmdline = 1;
			अगर (options.अंक_ports >= MAX_PORTS) {
				ख_लिखो(मानक_त्रुटि, "too many ports.\n");
				निकास(1);
			}
			options.ports[options.अंक_ports++] = a2port(optarg);
			अगर (options.ports[options.अंक_ports-1] <= 0) {
				ख_लिखो(मानक_त्रुटि, "Bad port number.\n");
				निकास(1);
			}
			अवरोध;
		हाल 'g':
			अगर ((options.login_grace_time = convtime(optarg)) == -1) {
				ख_लिखो(मानक_त्रुटि, "Invalid login grace time.\n");
				निकास(1);
			}
			अवरोध;
		हाल 'k':
			/* protocol 1, ignored */
			अवरोध;
		हाल 'h':
			servconf_add_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			अवरोध;
		हाल 't':
		हाल 'T':
		हाल 'G':
			fatal("test/dump modes not supported");
			अवरोध;
		हाल 'C':
			connection_info = server_get_connection_info(ssh, 0, 0);
			अगर (parse_server_match_testspec(connection_info,
			    optarg) == -1)
				निकास(1);
			अवरोध;
		हाल 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, शून्य);
			अगर (utmp_len > HOST_NAME_MAX+1) {
				ख_लिखो(मानक_त्रुटि, "Invalid utmp length.\n");
				निकास(1);
			}
			अवरोध;
		हाल 'o':
			पंक्ति = xstrdup(optarg);
			अगर (process_server_config_पंक्ति(&options, पंक्ति,
			    "command-line", 0, शून्य, शून्य, &includes) != 0)
				निकास(1);
			मुक्त(पंक्ति);
			अवरोध;
		हाल 'V':
			ख_लिखो(मानक_त्रुटि, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			निकास(0);
		शेष:
			usage();
			अवरोध;
		}
	}

	/* Check that there are no remaining arguments. */
	अगर (optind < ac) {
		ख_लिखो(मानक_त्रुटि, "Extra argument %s.\n", av[optind]);
		निकास(1);
	}

	अगर (!rexeced_flag)
		fatal("sshd-session should not be executed directly");

	closefrom(REEXEC_MIN_FREE_FD);

	platform_pre_session_start();

	/* Reserve fds we'll need later for reexec things */
	अगर ((devnull = खोलो(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open %s: %s", _PATH_DEVNULL, म_त्रुटि(त्रुटि_सं));
	जबतक (devnull < PRIVSEP_MIN_FREE_FD) {
		अगर ((devnull = dup(devnull)) == -1)
			fatal("dup %s: %s", _PATH_DEVNULL, म_त्रुटि(त्रुटि_सं));
	}

	seed_rng();

	/* If requested, redirect the logs to the specified logfile. */
	अगर (logfile != शून्य) {
		अक्षर *cp, pid_s[32];

		snprintf(pid_s, माप(pid_s), "%ld", (अचिन्हित दीर्घ)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd-session",
		    (अक्षर *)शून्य);
		log_redirect_stderr_to(cp);
		मुक्त(cp);
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
	अगर ((cfg = sshbuf_new()) == शून्य)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[rexeced]");
	recv_rexec_state(REEXEC_CONFIG_PASS_FD, cfg, &timing_secret);
	parse_server_config(&options, "rexec", cfg, &includes, शून्य, 1);
	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);
	options.timing_secret = timing_secret;

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	debug("sshd-session version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);

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

	अगर (!debug_flag && !inetd_flag) {
		अगर ((startup_pipe = dup(REEXEC_CONFIG_PASS_FD)) == -1)
			fatal("internal error: no startup pipe");

		/*
		 * Signal parent that this child is at a point where
		 * they can go away if they have a SIGHUP pending.
		 */
		(व्योम)atomicio(vwrite, startup_pipe, "\0", 1);
	}
	/* close the fd, but keep the slot reserved */
	अगर (dup2(devnull, REEXEC_CONFIG_PASS_FD) == -1)
		fatal("dup2 devnull->config fd: %s", म_त्रुटि(त्रुटि_सं));

	/* Check that options are sensible */
	अगर (options.authorized_कुंजियाँ_command_user == शून्य &&
	    (options.authorized_कुंजियाँ_command != शून्य &&
	    strcasecmp(options.authorized_कुंजियाँ_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	अगर (options.authorized_principals_command_user == शून्य &&
	    (options.authorized_principals_command != शून्य &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match block, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	अगर (options.अंक_auth_methods != 0) {
		क्रम (i = 0; i < options.अंक_auth_methods; i++) {
			अगर (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				अवरोध;
		}
		अगर (i >= options.अंक_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

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

	अगर (options.अंक_host_कुंजी_files != sensitive_तथ्य.अंक_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.अंक_host_कुंजी_files, sensitive_तथ्य.अंक_hostkeys);
	}

	क्रम (i = 0; i < options.अंक_host_कुंजी_files; i++) {
		अगर (sensitive_तथ्य.host_कुंजियाँ[i] != शून्य ||
		    (have_agent && sensitive_तथ्य.host_pubkeys[i] != शून्य)) {
			have_कुंजी = 1;
			अवरोध;
		}
	}
	अगर (!have_कुंजी)
		fatal("internal error: monitor received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(व्योम) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	अगर (debug_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	क्रम (i = 0; i < options.अंक_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	अगर (स_बदलो("/") == -1)
		error("chdir(\"/\"): %s", म_त्रुटि(त्रुटि_सं));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, संक_छोड़ो);

	/* Get a connection, either from inetd or rexec */
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

	/*
	 * We intentionally do not close the descriptors 0, 1, and 2
	 * as our code for setting the descriptors won't work if
	 * ttyfd happens to be one of those.
	 */
	अगर (stdfd_devnull(1, 1, !log_stderr) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_in, sock_out);

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_out);
	FD_CLOSEONEXEC(sock_in);

	/* We will not restart on SIGHUP since it no longer makes sense. */
	ssh_signal(SIGALRM, संक_पूर्व);
	ssh_signal(SIGHUP, संक_पूर्व);
	ssh_signal(संक_इति, संक_पूर्व);
	ssh_signal(SIGQUIT, संक_पूर्व);
	ssh_signal(SIGCHLD, संक_पूर्व);
	ssh_signal(संक_विघ्न, संक_पूर्व);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	अगर ((ssh = ssh_packet_set_connection(शून्य, sock_in, sock_out)) == शून्य)
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
	अगर (options.tcp_keep_alive && ssh_packet_connection_is_on_socket(ssh))
		set_keepalive(sock_in); /* logs errors */

	अगर ((remote_port = ssh_remote_port(ssh)) < 0) {
		debug("ssh_remote_port failed");
		cleanup_exit(255);
	}

	/*
	 * The rest of the code depends on the fact that
	 * ssh_remote_ipaddr() caches the remote ip, even if
	 * the socket goes away.
	 */
	remote_ip = ssh_remote_ipaddr(ssh);

#अगर_घोषित SSH_AUDIT_EVENTS
	audit_connection_from(remote_ip, remote_port);
#पूर्ण_अगर

	rdomain = ssh_packet_rdomain_in(ssh);

	/* Log the connection. */
	laddr = get_local_ipaddr(sock_in);
	verbose("Connection from %s port %d on %s port %d%s%s%s",
	    remote_ip, remote_port, laddr,  ssh_local_port(ssh),
	    rdomain == शून्य ? "" : " rdomain \"",
	    rdomain == शून्य ? "" : rdomain,
	    rdomain == शून्य ? "" : "\"");
	मुक्त(laddr);

	/*
	 * We don't want to listen forever unless the other side
	 * successfully authenticates itself.  So we set up an alarm which is
	 * cleared after successful authentication.  A limit of zero
	 * indicates no limit. Note that we don't set the alarm in debugging
	 * mode; it is just annoying to have the server exit just when you
	 * are about to discover the bug.
	 */
	ssh_signal(SIGALRM, grace_alarm_handler);
	अगर (!debug_flag && options.login_grace_time > 0) {
		पूर्णांक ujitter = arc4random_uniform(4 * 1000000);

		timerclear(&itv.it_interval);
		itv.it_value.tv_sec = options.login_grace_time;
		itv.it_value.tv_sec += ujitter / 1000000;
		itv.it_value.tv_usec = ujitter % 1000000; 

		अगर (setitimer(ITIMER_REAL, &itv, शून्य) == -1)
			fatal("login grace time setitimer failed");
	}

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

	अगर (privsep_preauth(ssh) != 1)
		fatal("privsep_preauth failed");

	/* Now user is authenticated */

	setproctitle("%s [postauth]", authctxt->user);

	/*
	 * Cancel the alarm we set to limit the time taken for
	 * authentication.
	 */
	timerclear(&itv.it_interval);
	timerclear(&itv.it_value);
	अगर (setitimer(ITIMER_REAL, &itv, शून्य) == -1)
		fatal("login grace time clear failed");
	ssh_signal(SIGALRM, संक_पूर्व);
	authctxt->authenticated = 1;
	अगर (startup_pipe != -1) {
		/* signal listener that authentication completed successfully */
		(व्योम)atomicio(vwrite, startup_pipe, "\001", 1);
		बंद(startup_pipe);
		startup_pipe = -1;
	}

	अगर (options.routing_domain != शून्य)
		set_process_rdomain(ssh, options.routing_domain);

#अगर_घोषित SSH_AUDIT_EVENTS
	audit_event(ssh, SSH_AUTH_SUCCESS);
#पूर्ण_अगर

#अगर_घोषित GSSAPI
	अगर (options.gss_authentication) {
		temporarily_use_uid(authctxt->pw);
		ssh_gssapi_storecreds();
		restore_uid();
	}
#पूर्ण_अगर
#अगर_घोषित USE_PAM
	अगर (options.use_pam) {
		do_pam_setcred();
		do_pam_session(ssh);
	}
#पूर्ण_अगर

	/*
	 * In privilege separation, we fork another child and prepare
	 * file descriptor passing.
	 */
	privsep_postauth(ssh, authctxt);
	/* the monitor process [priv] will not return */

	ssh_packet_set_timeout(ssh, options.client_alive_interval,
	    options.client_alive_गिनती_max);

	/* Try to send all our hostkeys to the client */
	notify_hostkeys(ssh);

	/* Start session. */
	do_authenticated(ssh, authctxt);

	/* The connection has been terminated. */
	ssh_packet_get_bytes(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes",
	    (अचिन्हित दीर्घ दीर्घ)obytes, (अचिन्हित दीर्घ दीर्घ)ibytes);

	verbose("Closing connection to %.500s port %d", remote_ip, remote_port);

#अगर_घोषित USE_PAM
	अगर (options.use_pam)
		finish_pam();
#पूर्ण_अगर /* USE_PAM */

#अगर_घोषित SSH_AUDIT_EVENTS
	mm_audit_event(ssh, SSH_CONNECTION_CLOSE);
#पूर्ण_अगर

	ssh_packet_close(ssh);

	mm_terminate();

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

/* server specific fatal cleanup */
व्योम
cleanup_exit(पूर्णांक i)
{
	अगर (the_active_state != शून्य && the_authctxt != शून्य) {
		do_cleanup(the_active_state, the_authctxt);
		अगर (privsep_is_preauth &&
		    pmonitor != शून्य && pmonitor->m_pid > 1) {
			debug("Killing privsep child %d", pmonitor->m_pid);
			अगर (समाप्त(pmonitor->m_pid, SIGKILL) != 0 &&
			    त्रुटि_सं != ESRCH) {
				error_f("kill(%d): %s", pmonitor->m_pid,
				    म_त्रुटि(त्रुटि_सं));
			}
		}
	}
#अगर_घोषित SSH_AUDIT_EVENTS
	/* done after do_cleanup so it can cancel the PAM auth 'thread' */
	अगर (the_active_state != शून्य && mm_is_monitor())
		audit_event(the_active_state, SSH_CONNECTION_ABANDON);
#पूर्ण_अगर
	/* Override default fatal exit value when auth was attempted */
	अगर (i == 255 && monitor_auth_attempted())
		_निकास(EXIT_AUTH_ATTEMPTED);
	अगर (i == 255 && monitor_invalid_user())
		_निकास(EXIT_INVALID_USER);
	_निकास(i);
}
