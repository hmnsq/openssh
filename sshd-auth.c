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

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/evp.h>
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
#അന്തര്ഭാവ "ssh-sandbox.h"
#അന്തര്ഭാവ "dh.h"

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

/* Saved arguments to main(). */
സ്ഥിതം അക്ഷരം **saved_argv;
സ്ഥിതം പൂർണ്ണസംഖ്യ saved_argc;


/* Daemon's agent connection */
പൂർണ്ണസംഖ്യ auth_sock = -1;
സ്ഥിതം പൂർണ്ണസംഖ്യ have_agent = 0;

u_int		അക്കം_hostkeys;
ഘടന sshkey	**host_pubkeys;		/* all public host keys */
ഘടന sshkey	**host_certificates;	/* all public host certificates */

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/* variables used for privilege separation */
ഘടന monitor *pmonitor = ശൂന്യ;
പൂർണ്ണസംഖ്യ privsep_is_preauth = 1;
സ്ഥിതം പൂർണ്ണസംഖ്യ privsep_chroot = 1;

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
സ്ഥിതം ശൂന്യം do_ssh2_kex(ഘടന ssh *);

/* Unprivileged user */
ഘടന passwd *privsep_pw = ശൂന്യ;

#ifndef HAVE_PLEDGE
സ്ഥിതം ഘടന ssh_sandbox *box;
#endif

/* XXX stub */
പൂർണ്ണസംഖ്യ
mm_is_monitor(ശൂന്യം)
{
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
privsep_child_demote(ശൂന്യം)
{
	gid_t gidset[1];

#ifndef HAVE_PLEDGE
	എങ്കിൽ ((box = ssh_sandbox_init(pmonitor)) == ശൂന്യ)
		fatal_f("ssh_sandbox_init failed");
#endif
	/* Demote the child */
	എങ്കിൽ (privsep_chroot) {
		/* Change our root directory */
		എങ്കിൽ (chroot(_PATH_PRIVSEP_CHROOT_DIR) == -1)
			fatal("chroot(\"%s\"): %s", _PATH_PRIVSEP_CHROOT_DIR,
			    strerror(errno));
		എങ്കിൽ (chdir("/") == -1)
			fatal("chdir(\"/\"): %s", strerror(errno));

		/*
		 * Drop our privileges
		 * NB. Can't use setusercontext() after chroot.
		 */
		debug3("privsep user:group %u:%u", (u_int)privsep_pw->pw_uid,
		    (u_int)privsep_pw->pw_gid);
		gidset[0] = privsep_pw->pw_gid;
		എങ്കിൽ (setgroups(1, gidset) == -1)
			fatal("setgroups: %.100s", strerror(errno));
		permanently_set_uid(privsep_pw);
	}

	/* sandbox ourselves */
#ifdef HAVE_PLEDGE
	എങ്കിൽ (pledge("stdio", ശൂന്യ) == -1)
		fatal_f("pledge()");
#അല്ലെങ്കിൽ
	ssh_sandbox_child(box);
#endif
}

സ്ഥിതം ശൂന്യം
append_hostkey_type(ഘടന sshbuf *b, സ്ഥിരം അക്ഷരം *s)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (match_pattern_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		തിരികെ;
	}
	എങ്കിൽ ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

സ്ഥിതം അക്ഷരം *
list_hostkey_types(ശൂന്യം)
{
	ഘടന sshbuf *b;
	ഘടന sshkey *താക്കോൽ;
	അക്ഷരം *ret;
	u_int i;

	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	വേണ്ടി (i = 0; i < options.അക്കം_host_താക്കോൽ_files; i++) {
		താക്കോൽ = host_pubkeys[i];
		എങ്കിൽ (താക്കോൽ == ശൂന്യ)
			തുടരുക;
		തിരഞ്ഞെടുപ്പ് (താക്കോൽ->type) {
		അവസ്ഥ താക്കോൽ_RSA:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b, "rsa-sha2-512");
			append_hostkey_type(b, "rsa-sha2-256");
			/* FALLTHROUGH */
		അവസ്ഥ താക്കോൽ_ECDSA:
		അവസ്ഥ താക്കോൽ_ED25519:
		അവസ്ഥ താക്കോൽ_MLDSA44_ED25519:
		അവസ്ഥ താക്കോൽ_ECDSA_SK:
		അവസ്ഥ താക്കോൽ_ED25519_SK:
			append_hostkey_type(b, sshkey_ssh_name(താക്കോൽ));
			നിർത്തുക;
		}
		/* If the private key has a cert peer, then list that too */
		താക്കോൽ = host_certificates[i];
		എങ്കിൽ (താക്കോൽ == ശൂന്യ)
			തുടരുക;
		തിരഞ്ഞെടുപ്പ് (താക്കോൽ->type) {
		അവസ്ഥ താക്കോൽ_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			/* FALLTHROUGH */
		അവസ്ഥ താക്കോൽ_ECDSA_CERT:
		അവസ്ഥ താക്കോൽ_ED25519_CERT:
		അവസ്ഥ താക്കോൽ_MLDSA44_ED25519_CERT:
		അവസ്ഥ താക്കോൽ_ECDSA_SK_CERT:
		അവസ്ഥ താക്കോൽ_ED25519_SK_CERT:
			append_hostkey_type(b, sshkey_ssh_name(താക്കോൽ));
			നിർത്തുക;
		}
	}
	എങ്കിൽ ((ret = sshbuf_dup_string(b)) == ശൂന്യ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	തിരികെ ret;
}

ഘടന sshkey *
get_hostkey_public_by_type(പൂർണ്ണസംഖ്യ type, പൂർണ്ണസംഖ്യ nid, ഘടന ssh *ssh)
{
	u_int i;
	ഘടന sshkey *താക്കോൽ;

	വേണ്ടി (i = 0; i < options.അക്കം_host_താക്കോൽ_files; i++) {
		തിരഞ്ഞെടുപ്പ് (type) {
		അവസ്ഥ താക്കോൽ_RSA_CERT:
		അവസ്ഥ താക്കോൽ_ECDSA_CERT:
		അവസ്ഥ താക്കോൽ_ED25519_CERT:
		അവസ്ഥ താക്കോൽ_MLDSA44_ED25519_CERT:
		അവസ്ഥ താക്കോൽ_ECDSA_SK_CERT:
		അവസ്ഥ താക്കോൽ_ED25519_SK_CERT:
			താക്കോൽ = host_certificates[i];
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			താക്കോൽ = host_pubkeys[i];
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
			തിരികെ താക്കോൽ;
		}
	}
	തിരികെ ശൂന്യ;
}

/* XXX remove */
ഘടന sshkey *
get_hostkey_private_by_type(പൂർണ്ണസംഖ്യ type, പൂർണ്ണസംഖ്യ nid, ഘടന ssh *ssh)
{
	തിരികെ ശൂന്യ;
}

/* XXX remove */
ഘടന sshkey *
get_hostkey_by_index(പൂർണ്ണസംഖ്യ ind)
{
	തിരികെ ശൂന്യ;
}

ഘടന sshkey *
get_hostkey_public_by_index(പൂർണ്ണസംഖ്യ ind, ഘടന ssh *ssh)
{
	എങ്കിൽ (ind < 0 || (u_int)ind >= options.അക്കം_host_താക്കോൽ_files)
		തിരികെ (ശൂന്യ);
	തിരികെ host_pubkeys[ind];
}

പൂർണ്ണസംഖ്യ
get_hostkey_index(ഘടന sshkey *താക്കോൽ, പൂർണ്ണസംഖ്യ compare, ഘടന ssh *ssh)
{
	u_int i;

	വേണ്ടി (i = 0; i < options.അക്കം_host_താക്കോൽ_files; i++) {
		എങ്കിൽ (sshkey_is_cert(താക്കോൽ)) {
			എങ്കിൽ (താക്കോൽ == host_certificates[i] ||
			    (compare && host_certificates[i] &&
			    sshkey_equal(താക്കോൽ, host_certificates[i])))
				തിരികെ (i);
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (താക്കോൽ == host_pubkeys[i] ||
			    (compare && host_pubkeys[i] &&
			    sshkey_equal(താക്കോൽ, host_pubkeys[i])))
				തിരികെ (i);
		}
	}
	തിരികെ (-1);
}

സ്ഥിതം ശൂന്യം
usage(ശൂന്യം)
{
	fprintf(stderr, "%s, %s\n", SSH_VERSION, SSH_OPENSSL_VERSION);
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
	സ്ഥിരം u_char *cp;
	size_t len;

	ആകുമ്പോൾ (sshbuf_len(hostkeys) != 0) {
		എങ്കിൽ (അക്കം_താക്കോലുകൾ > 2048)
			fatal_f("too many hostkeys");
		host_pubkeys = xrecallocarray(host_pubkeys,
		    അക്കം_താക്കോലുകൾ, അക്കം_താക്കോലുകൾ + 1, വലുപ്പം(*host_pubkeys));
		host_certificates = xrecallocarray(host_certificates,
		    അക്കം_താക്കോലുകൾ, അക്കം_താക്കോലുകൾ + 1, വലുപ്പം(*host_certificates));
		/* public key */
		k = ശൂന്യ;
		എങ്കിൽ ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		എങ്കിൽ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_pubkeys[അക്കം_താക്കോലുകൾ] = k;
		എങ്കിൽ (k)
			debug2_f("key %u: %s", അക്കം_താക്കോലുകൾ, sshkey_ssh_name(k));
		/* certificate */
		k = ശൂന്യ;
		എങ്കിൽ ((r = sshbuf_get_string_direct(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		എങ്കിൽ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_certificates[അക്കം_താക്കോലുകൾ] = k;
		എങ്കിൽ (k)
			debug2_f("cert %u: %s", അക്കം_താക്കോലുകൾ, sshkey_ssh_name(k));
		അക്കം_താക്കോലുകൾ++;
	}
	അക്കം_hostkeys = അക്കം_താക്കോലുകൾ;
}

സ്ഥിതം ശൂന്യം
recv_privsep_state(ഘടന ssh *ssh, ServerOptions *o, uint64_t *timing_secretp)
{
	ഘടന sshbuf *hostkeys;

	debug3_f("begin");

	mm_get_state(ssh, o, ശൂന്യ, timing_secretp,
	    &hostkeys, ശൂന്യ, ശൂന്യ, ശൂന്യ, ശൂന്യ);
	parse_hostkeys(hostkeys);

	sshbuf_free(hostkeys);

	debug3_f("done");
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
	പൂർണ്ണസംഖ്യ r, opt, have_താക്കോൽ = 0;
	പൂർണ്ണസംഖ്യ sock_in = -1, sock_out = -1, rexeced_flag = 0;
	u_int i;
	mode_t new_umask;
	Authctxt *authctxt;
	sigset_t sigmask;
	uint64_t timing_secret = 0;

	closefrom(PRIVSEP_MIN_FREE_FD);
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
	ആകുമ്പോൾ ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		തിരഞ്ഞെടുപ്പ് (opt) {
		അവസ്ഥ '4':
			/* ignore */
			നിർത്തുക;
		അവസ്ഥ '6':
			/* ignore */
			നിർത്തുക;
		അവസ്ഥ 'f':
			/* ignore */
			നിർത്തുക;
		അവസ്ഥ 'c':
			/* ignore */
			നിർത്തുക;
		അവസ്ഥ 'd':
			എങ്കിൽ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} അല്ലെങ്കിൽ എങ്കിൽ (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			നിർത്തുക;
		അവസ്ഥ 'D':
		അവസ്ഥ 'E':
		അവസ്ഥ 'e':
			/* ignore */
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
			/* ignored */
			നിർത്തുക;
		അവസ്ഥ 'b':
			/* protocol 1, ignored */
			നിർത്തുക;
		അവസ്ഥ 'p':
			/* ignored */
			നിർത്തുക;
		അവസ്ഥ 'g':
			/* ignored */
			നിർത്തുക;
		അവസ്ഥ 'k':
			/* protocol 1, ignored */
			നിർത്തുക;
		അവസ്ഥ 'h':
			/* ignored */
			നിർത്തുക;
		അവസ്ഥ 't':
		അവസ്ഥ 'T':
		അവസ്ഥ 'G':
		അവസ്ഥ 'C':
			fatal("test/dump modes not supported");
			നിർത്തുക;
		അവസ്ഥ 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, ശൂന്യ);
			എങ്കിൽ (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			നിർത്തുക;
		അവസ്ഥ 'o':
			/* ignored */
			നിർത്തുക;
		അവസ്ഥ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		സ്ഥിരസ്ഥിതി:
			usage();
			നിർത്തുക;
		}
	}

	എങ്കിൽ (!rexeced_flag)
		fatal("sshd-auth should not be executed directly");

	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_AUTH : options.log_facility, 1);

	/* XXX can't use monitor_init(); it makes fds */
	pmonitor = xcalloc(1, വലുപ്പം(*pmonitor));
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_recvfd = PRIVSEP_MONITOR_FD;
	pmonitor->m_log_sendfd = PRIVSEP_LOG_FD;
	set_log_handler(mm_log_handler, pmonitor);

	/* Check that there are no remaining arguments. */
	എങ്കിൽ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	/* Connection passed by stdin/out */
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

	എങ്കിൽ (stdfd_devnull(1, 1, 0) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_in, sock_out);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	എങ്കിൽ ((ssh = ssh_packet_set_connection(ശൂന്യ, sock_in, sock_out)) == ശൂന്യ)
		fatal("Unable to create connection");
	the_active_state = ssh;
	ssh_packet_set_server(ssh);
	pmonitor->m_pkex = &ssh->kex;

	/* Fetch our configuration */
	എങ്കിൽ ((cfg = sshbuf_new()) == ശൂന്യ)
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

	എങ്കിൽ (options.അക്കം_host_താക്കോൽ_files != അക്കം_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.അക്കം_host_താക്കോൽ_files, അക്കം_hostkeys);
	}

	വേണ്ടി (i = 0; i < options.അക്കം_host_താക്കോൽ_files; i++) {
		എങ്കിൽ (host_pubkeys[i] != ശൂന്യ) {
			have_താക്കോൽ = 1;
			നിർത്തുക;
		}
	}
	എങ്കിൽ (!have_താക്കോൽ)
		fatal("internal error: received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(ശൂന്യം) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	log_init(__progname, options.log_level, options.log_facility, 1);
	set_log_handler(mm_log_handler, pmonitor);
	വേണ്ടി (i = 0; i < options.അക്കം_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	എങ്കിൽ (chdir("/") == -1)
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
	ssh_packet_clear_താക്കോലുകൾ(ssh);
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

/* SSH2 key exchange */
സ്ഥിതം ശൂന്യം
do_ssh2_kex(ഘടന ssh *ssh)
{
	അക്ഷരം *hkalgs = ശൂന്യ, *myproposal[PROPOSAL_MAX];
	സ്ഥിരം അക്ഷരം *compression = ശൂന്യ;
	ഘടന kex *kex;
	പൂർണ്ണസംഖ്യ r;

	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

	എങ്കിൽ (options.compression == COMP_NONE)
		compression = "none";
	hkalgs = list_hostkey_types();

	kex_proposal_populate_entries(ssh, myproposal, options.kex_algorithms,
	    options.ciphers, options.macs, compression, hkalgs);

	സ്വതന്ത്രം(hkalgs);

	എങ്കിൽ ((r = kex_exchange_identification(ssh, -1,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");
	mm_sshkey_setcompat(ssh); /* tell monitor */

	എങ്കിൽ ((ssh->compat & SSH_BUG_NOREKEY))
		debug("client does not support rekeying");

	/* start key exchange */
	എങ്കിൽ ((r = kex_setup(ssh, myproposal)) != 0)
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
	kex->load_host_public_താക്കോൽ=&get_hostkey_public_by_type;
	kex->load_host_private_താക്കോൽ=&get_hostkey_private_by_type;
	kex->host_താക്കോൽ_index=&get_hostkey_index;
	kex->sign = sshd_hostkey_sign;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send test");
#endif
	debug("KEX done");
}

/* server specific fatal cleanup */
ശൂന്യം
cleanup_exit(പൂർണ്ണസംഖ്യ i)
{
	_exit(i);
}
