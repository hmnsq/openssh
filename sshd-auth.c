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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/ioctl.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ <sys/tree.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <grp.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "sshpty.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "uidswap.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "msg.h"
#ಅನ್ತರ್ಭಾವ "dispatch.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "session.h"
#ಅನ್ತರ್ಭಾವ "monitor.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ಅನ್ತರ್ಭಾವ "version.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sk-api.h"
#ಅನ್ತರ್ಭಾವ "srclimit.h"
#ಅನ್ತರ್ಭಾವ "ssh-sandbox.h"
#ಅನ್ತರ್ಭಾವ "dh.h"

/* Privsep fds */
#ವ್ಯಾಖ್ಯಾನಿಸು PRIVSEP_MONITOR_FD		(STDERR_FILENO + 1)
#ವ್ಯಾಖ್ಯಾನಿಸು PRIVSEP_LOG_FD			(STDERR_FILENO + 2)
#ವ್ಯಾಖ್ಯಾನಿಸು PRIVSEP_MIN_FREE_FD		(STDERR_FILENO + 3)

ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
ಅಕ್ಷರ *config_file_name = ಮಾರ್ಗ_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
ಪೂರ್ಣಾಂಕ debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ inetd_flag = 0;

/* Saved arguments to main(). */
ಸ್ಥಿರ ಅಕ್ಷರ **saved_argv;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ saved_argc;


/* Daemon's agent connection */
ಪೂರ್ಣಾಂಕ auth_sock = -1;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ have_agent = 0;

u_int		ಅಂಕೆ_hostkeys;
ರಚನೆ sshkey	**host_pubkeys;		/* all public host keys */
ರಚನೆ sshkey	**host_certificates;	/* all public host certificates */

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/* variables used for privilege separation */
ರಚನೆ monitor *pmonitor = ಖಾಲಿ;
ಪೂರ್ಣಾಂಕ privsep_is_preauth = 1;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ privsep_chroot = 1;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = ಖಾಲಿ;
ರಚನೆ ssh *the_ಸಕ್ರಿಯ_state;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
ರಚನೆ sshauthopt *auth_opts = ಖಾಲಿ;

/* sshd_config buffer */
ರಚನೆ sshbuf *cfg;

/* Included files from the configuration file */
ರಚನೆ include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
ರಚನೆ sshbuf *loginmsg;

/* Prototypes for various functions defined later in this file. */
ಸ್ಥಿರ ಶೂನ್ಯ do_ssh2_kex(ರಚನೆ ssh *);

/* Unprivileged user */
ರಚನೆ passwd *privsep_pw = ಖಾಲಿ;

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_PLEDGE
ಸ್ಥಿರ ರಚನೆ ssh_sandbox *box;
#ಆದರೆ_ಅಂತ್ಯ

/* XXX stub */
ಪೂರ್ಣಾಂಕ
mm_is_monitor(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
privsep_ಮಗು_demote(ಶೂನ್ಯ)
{
	gid_t gidset[1];

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_PLEDGE
	ಆದರೆ ((box = ssh_sandbox_init(pmonitor)) == ಖಾಲಿ)
		fatal_f("ssh_sandbox_init failed");
#ಆದರೆ_ಅಂತ್ಯ
	/* Demote the child */
	ಆದರೆ (privsep_chroot) {
		/* Change our root directory */
		ಆದರೆ (chroot(ಮಾರ್ಗ_PRIVSEP_CHROOT_DIR) == -1)
			fatal("chroot(\"%s\"): %s", ಮಾರ್ಗ_PRIVSEP_CHROOT_DIR,
			    strerror(errno));
		ಆದರೆ (chdir("/") == -1)
			fatal("chdir(\"/\"): %s", strerror(errno));

		/*
		 * Drop our privileges
		 * NB. Can't use setusercontext() after chroot.
		 */
		debug3("privsep user:group %u:%u", (u_int)privsep_pw->pw_uid,
		    (u_int)privsep_pw->pw_gid);
		gidset[0] = privsep_pw->pw_gid;
		ಆದರೆ (setgroups(1, gidset) == -1)
			fatal("setgroups: %.100s", strerror(errno));
		permanently_ಗಣ_uid(privsep_pw);
	}

	/* sandbox ourselves */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_PLEDGE
	ಆದರೆ (pledge("stdio", ಖಾಲಿ) == -1)
		fatal_f("pledge()");
#ಇಲ್ಲದಿದ್ದರೆ
	ssh_sandbox_ಮಗು(box);
#ಆದರೆ_ಅಂತ್ಯ
}

ಸ್ಥಿರ ಶೂನ್ಯ
append_hostkey_type(ರಚನೆ sshbuf *b, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

ಸ್ಥಿರ ಅಕ್ಷರ *
list_hostkey_types(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *b;
	ರಚನೆ sshkey *ಕೀಲಿ;
	ಅಕ್ಷರ *ret;
	u_int i;

	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಕೀಲಿ = host_pubkeys[i];
		ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆಯ್ಕೆ (ಕೀಲಿ->type) {
		ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b, "rsa-sha2-512");
			append_hostkey_type(b, "rsa-sha2-256");
			/* FALLTHROUGH */
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
		ಸ್ಥಿತಿ ಕೀಲಿ_ED25519:
		ಸ್ಥಿತಿ ಕೀಲಿ_MLDSA44_ED25519:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
		ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK:
			append_hostkey_type(b, sshkey_ssh_name(ಕೀಲಿ));
			ನಿಲ್ಲಿಸು;
		}
		/* If the private key has a cert peer, then list that too */
		ಕೀಲಿ = host_certificates[i];
		ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆಯ್ಕೆ (ಕೀಲಿ->type) {
		ಸ್ಥಿತಿ ಕೀಲಿ_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			/* FALLTHROUGH */
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_MLDSA44_ED25519_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK_CERT:
			append_hostkey_type(b, sshkey_ssh_name(ಕೀಲಿ));
			ನಿಲ್ಲಿಸು;
		}
	}
	ಆದರೆ ((ret = sshbuf_dup_string(b)) == ಖಾಲಿ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	ಹಿಂತಿರುಗಿ ret;
}

ರಚನೆ sshkey *
get_hostkey_ಬಹಿರಂಗ_by_type(ಪೂರ್ಣಾಂಕ type, ಪೂರ್ಣಾಂಕ nid, ರಚನೆ ssh *ssh)
{
	u_int i;
	ರಚನೆ sshkey *ಕೀಲಿ;

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಆಯ್ಕೆ (type) {
		ಸ್ಥಿತಿ ಕೀಲಿ_RSA_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_MLDSA44_ED25519_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK_CERT:
			ಕೀಲಿ = host_certificates[i];
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಕೀಲಿ = host_pubkeys[i];
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ || ಕೀಲಿ->type != type)
			ಮುಂದುವರಿ;
		ಆಯ್ಕೆ (type) {
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK_CERT:
			ಆದರೆ (ಕೀಲಿ->ecdsa_nid != nid)
				ಮುಂದುವರಿ;
			/* FALLTHROUGH */
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಹಿಂತಿರುಗಿ ಕೀಲಿ;
		}
	}
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

/* XXX remove */
ರಚನೆ sshkey *
get_hostkey_ಖಾಸಗಿ_by_type(ಪೂರ್ಣಾಂಕ type, ಪೂರ್ಣಾಂಕ nid, ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

/* XXX remove */
ರಚನೆ sshkey *
get_hostkey_by_ಸೂಚ್ಯಂಕ(ಪೂರ್ಣಾಂಕ ind)
{
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ರಚನೆ sshkey *
get_hostkey_ಬಹಿರಂಗ_by_ಸೂಚ್ಯಂಕ(ಪೂರ್ಣಾಂಕ ind, ರಚನೆ ssh *ssh)
{
	ಆದರೆ (ind < 0 || (u_int)ind >= options.ಅಂಕೆ_host_ಕೀಲಿ_files)
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	ಹಿಂತಿರುಗಿ host_pubkeys[ind];
}

ಪೂರ್ಣಾಂಕ
get_hostkey_ಸೂಚ್ಯಂಕ(ರಚನೆ sshkey *ಕೀಲಿ, ಪೂರ್ಣಾಂಕ compare, ರಚನೆ ssh *ssh)
{
	u_int i;

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಆದರೆ (sshkey_is_cert(ಕೀಲಿ)) {
			ಆದರೆ (ಕೀಲಿ == host_certificates[i] ||
			    (compare && host_certificates[i] &&
			    sshkey_equal(ಕೀಲಿ, host_certificates[i])))
				ಹಿಂತಿರುಗಿ (i);
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (ಕೀಲಿ == host_pubkeys[i] ||
			    (compare && host_pubkeys[i] &&
			    sshkey_equal(ಕೀಲಿ, host_pubkeys[i])))
				ಹಿಂತಿರುಗಿ (i);
		}
	}
	ಹಿಂತಿರುಗಿ (-1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
{
	fprintf(stderr, "%s, %s\n", SSH_ಆವೃತ್ತಿ, SSH_OPENSSL_ಆವೃತ್ತಿ);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	ನಿರ್ಗಮಿಸು(1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
parse_hostkeys(ರಚನೆ sshbuf *hostkeys)
{
	ಪೂರ್ಣಾಂಕ r;
	u_int ಅಂಕೆ_ಕೀಲಿಗಳು = 0;
	ರಚನೆ sshkey *k;
	ಸ್ಥಿರಾಂಕ u_char *cp;
	ಗಾತ್ರ_t len;

	ಆಗ (sshbuf_len(hostkeys) != 0) {
		ಆದರೆ (ಅಂಕೆ_ಕೀಲಿಗಳು > 2048)
			fatal_f("too many hostkeys");
		host_pubkeys = xrecallocarray(host_pubkeys,
		    ಅಂಕೆ_ಕೀಲಿಗಳು, ಅಂಕೆ_ಕೀಲಿಗಳು + 1, ಗಾತ್ರ(*host_pubkeys));
		host_certificates = xrecallocarray(host_certificates,
		    ಅಂಕೆ_ಕೀಲಿಗಳು, ಅಂಕೆ_ಕೀಲಿಗಳು + 1, ಗಾತ್ರ(*host_certificates));
		/* public key */
		k = ಖಾಲಿ;
		ಆದರೆ ((r = sshbuf_get_string_ನೇರ(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ಆದರೆ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_pubkeys[ಅಂಕೆ_ಕೀಲಿಗಳು] = k;
		ಆದರೆ (k)
			debug2_f("key %u: %s", ಅಂಕೆ_ಕೀಲಿಗಳು, sshkey_ssh_name(k));
		/* certificate */
		k = ಖಾಲಿ;
		ಆದರೆ ((r = sshbuf_get_string_ನೇರ(hostkeys, &cp, &len)) != 0)
			fatal_fr(r, "extract pubkey");
		ಆದರೆ (len != 0 && (r = sshkey_from_blob(cp, len, &k)) != 0)
			fatal_fr(r, "parse pubkey");
		host_certificates[ಅಂಕೆ_ಕೀಲಿಗಳು] = k;
		ಆದರೆ (k)
			debug2_f("cert %u: %s", ಅಂಕೆ_ಕೀಲಿಗಳು, sshkey_ssh_name(k));
		ಅಂಕೆ_ಕೀಲಿಗಳು++;
	}
	ಅಂಕೆ_hostkeys = ಅಂಕೆ_ಕೀಲಿಗಳು;
}

ಸ್ಥಿರ ಶೂನ್ಯ
recv_privsep_state(ರಚನೆ ssh *ssh, ServerOptions *o, uint64_t *timing_secretp)
{
	ರಚನೆ sshbuf *hostkeys;

	debug3_f("begin");

	mm_get_state(ssh, o, ಖಾಲಿ, timing_secretp,
	    &hostkeys, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ);
	parse_hostkeys(hostkeys);

	sshbuf_free(hostkeys);

	debug3_f("done");
}

/*
 * Main program for the daemon.
 */
ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ ac, ಅಕ್ಷರ **av)
{
	ರಚನೆ ssh *ssh = ಖಾಲಿ;
	ಬಾಹ್ಯ ಅಕ್ಷರ *optarg;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ optind;
	ಪೂರ್ಣಾಂಕ r, opt, have_ಕೀಲಿ = 0;
	ಪೂರ್ಣಾಂಕ sock_ಒಳ = -1, sock_ಹೊರಹೋಗು = -1, rexeced_flag = 0;
	u_int i;
	ಬಹುಲಕ_t new_umask;
	Authctxt *authctxt;
	sigset_t sigmask;
	uint64_t timing_secret = 0;

	closefrom(PRIVSEP_MIN_FREE_FD);
	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, ಖಾಲಿ);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SECUREWARE
	(ಶೂನ್ಯ)ಗಣ_auth_parameters(ac, av);
#ಆದರೆ_ಅಂತ್ಯ
	__progname = ssh_get_progname(av[0]);

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	saved_argv = xcalloc(ac + 1, ಗಾತ್ರ(*saved_argv));
	ಗಾಗಿ (i = 0; (ಪೂರ್ಣಾಂಕ)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = ಖಾಲಿ;

	ಬೀಜ_rng();

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#ಆದರೆ_ಅಂತ್ಯ

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	ಆಗ ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		ಆಯ್ಕೆ (opt) {
		ಸ್ಥಿತಿ '4':
			/* ignore */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '6':
			/* ignore */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'f':
			/* ignore */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'c':
			/* ignore */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'd':
			ಆದರೆ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'D':
		ಸ್ಥಿತಿ 'E':
		ಸ್ಥಿತಿ 'e':
			/* ignore */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'i':
			inetd_flag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'r':
			/* ignore */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'R':
			rexeced_flag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'Q':
			/* ignored */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'q':
			/* ignored */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'b':
			/* protocol 1, ignored */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'p':
			/* ignored */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'g':
			/* ignored */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'k':
			/* protocol 1, ignored */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'h':
			/* ignored */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 't':
		ಸ್ಥಿತಿ 'T':
		ಸ್ಥಿತಿ 'G':
		ಸ್ಥಿತಿ 'C':
			fatal("test/dump modes not supported");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, ಖಾಲಿ);
			ಆದರೆ (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				ನಿರ್ಗಮಿಸು(1);
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'o':
			/* ignored */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_ಆವೃತ್ತಿ, SSH_OPENSSL_ಆವೃತ್ತಿ);
			ನಿರ್ಗಮಿಸು(0);
		ಪೂರ್ವನಿಯೋಜಿತ:
			usage();
			ನಿಲ್ಲಿಸು;
		}
	}

	ಆದರೆ (!rexeced_flag)
		fatal("sshd-auth should not be executed directly");

	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_ಗಣ ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_ಗಣ ?
	    SYSLOG_FACILITY_AUTH : options.log_facility, 1);

	/* XXX can't use monitor_init(); it makes fds */
	pmonitor = xcalloc(1, ಗಾತ್ರ(*pmonitor));
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_recvfd = PRIVSEP_MONITOR_FD;
	pmonitor->m_log_sendfd = PRIVSEP_LOG_FD;
	ಗಣ_log_handler(mm_log_handler, pmonitor);

	/* Check that there are no remaining arguments. */
	ಆದರೆ (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		ನಿರ್ಗಮಿಸು(1);
	}

	/* Connection passed by stdin/out */
	ಆದರೆ (inetd_flag) {
		/*
		 * NB. must be different fd numbers for the !socket case,
		 * as packet_connection_is_on_socket() depends on this.
		 */
		sock_ಒಳ = dup(STDIN_FILENO);
		sock_ಹೊರಹೋಗು = dup(STDOUT_FILENO);
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* rexec case; accept()ed socket in ancestor listener */
		sock_ಒಳ = sock_ಹೊರಹೋಗು = dup(STDIN_FILENO);
	}

	ಆದರೆ (stdfd_devnull(1, 1, 0) == -1)
		error("stdfd_devnull failed");
	debug("network sockets: %d, %d", sock_ಒಳ, sock_ಹೊರಹೋಗು);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	ಆದರೆ ((ssh = ssh_packet_ಗಣ_connection(ಖಾಲಿ, sock_ಒಳ, sock_ಹೊರಹೋಗು)) == ಖಾಲಿ)
		fatal("Unable to create connection");
	the_ಸಕ್ರಿಯ_state = ssh;
	ssh_packet_ಗಣ_server(ssh);
	pmonitor->m_pkex = &ssh->kex;

	/* Fetch our configuration */
	ಆದರೆ ((cfg = sshbuf_new()) == ಖಾಲಿ)
		fatal("sshbuf_new config buf failed");
	setproctitle("%s", "[session-auth early]");
	recv_privsep_state(ssh, &options, &timing_secret);
	options.timing_secret = timing_secret; /* XXX eliminate from unpriv */
	ssh_packet_ಗಣ_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Reinit logging in case config set Level, Facility or Verbose. */
	log_init(__progname, options.log_level, options.log_facility, 1);
	ಗಣ_log_handler(mm_log_handler, pmonitor);

	debug("sshd-auth version %s, %s", SSH_ಆವೃತ್ತಿ, SSH_OPENSSL_ಆವೃತ್ತಿ);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = (getuid() == 0 || geteuid() == 0);
	ಆದರೆ ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == ಖಾಲಿ) {
		ಆದರೆ (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} ಇಲ್ಲದಿದ್ದರೆ {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಆದರೆ (options.moduli_file != ಖಾಲಿ)
		dh_ಗಣ_moduli_file(options.moduli_file);
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (options.host_ಕೀಲಿ_agent) {
		ಆದರೆ (strcmp(options.host_ಕೀಲಿ_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_ಕೀಲಿ_agent, 1);
		ಆದರೆ ((r = ssh_get_authentication_socket(ಖಾಲಿ)) == 0)
			have_agent = 1;
		ಇಲ್ಲದಿದ್ದರೆ
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_ಕೀಲಿ_agent);
	}

	ಆದರೆ (options.ಅಂಕೆ_host_ಕೀಲಿ_files != ಅಂಕೆ_hostkeys) {
		fatal("internal error: hostkeys confused (config %u recvd %u)",
		    options.ಅಂಕೆ_host_ಕೀಲಿ_files, ಅಂಕೆ_hostkeys);
	}

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಆದರೆ (host_pubkeys[i] != ಖಾಲಿ) {
			have_ಕೀಲಿ = 1;
			ನಿಲ್ಲಿಸು;
		}
	}
	ಆದರೆ (!have_ಕೀಲಿ)
		fatal("internal error: received no hostkeys");

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(ಶೂನ್ಯ) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	log_init(__progname, options.log_level, options.log_facility, 1);
	ಗಣ_log_handler(mm_log_handler, pmonitor);
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_log_verbose; i++)
		log_verbose_ಕೂಡಿಸು(options.log_verbose[i]);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	ಆದರೆ (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* This is the child authenticating a new connection. */
	setproctitle("%s", "[session-auth]");

	/* Executed child processes don't need these. */
	FD_CLOSEONEXEC(sock_ಹೊರಹೋಗು);
	FD_CLOSEONEXEC(sock_ಒಳ);

	ssh_signal(SIGPIPE, SIG_IGN);
	ssh_signal(SIGALRM, SIG_DFL);
	ssh_signal(SIGHUP, SIG_DFL);
	ssh_signal(SIGTERM, SIG_DFL);
	ssh_signal(SIGQUIT, SIG_DFL);
	ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_ಗಣ_af(ssh, options.ವಿಳಾಸ_family);
	channel_ಗಣ_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);

	ssh_packet_ಗಣ_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, ಗಾತ್ರ(*authctxt));
	ssh->authctxt = authctxt;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	ಆದರೆ ((auth_opts = sshauthopt_new_with_ಕೀಲಿಗಳು_defaults()) == ಖಾಲಿ)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	ಆದರೆ ((loginmsg = sshbuf_new()) == ಖಾಲಿ)
		fatal("sshbuf_new loginmsg failed");
	auth_debug_reset();

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
	/* Cache supported mechanism OIDs for later use */
	ssh_gssapi_prepare_supported_oids();
#ಆದರೆ_ಅಂತ್ಯ

	privsep_ಮಗು_demote();

	/* perform the key exchange */
	/* authenticate user and start session */
	do_ssh2_kex(ssh);
	do_authentication2(ssh);

	/*
	 * The unprivileged child now transfers the current keystate and exits.
	 */
	mm_send_keystate(ssh, pmonitor);
	sshauthopt_free(auth_opts);
	ssh_packet_clear_ಕೀಲಿಗಳು(ssh);
	ನಿರ್ಗಮಿಸು(0);
}

ಪೂರ್ಣಾಂಕ
sshd_hostkey_sign(ರಚನೆ ssh *ssh, ರಚನೆ sshkey *privkey,
    ರಚನೆ sshkey *pubkey, u_char **signature, ಗಾತ್ರ_t *slenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t dlen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg)
{
	ಆದರೆ (privkey) {
		ಆದರೆ (mm_sshkey_sign(ssh, privkey, signature, slenp,
		    ದತ್ತಾಂಶ, dlen, alg, options.sk_provider, ಖಾಲಿ,
		    ssh->compat) < 0)
			fatal_f("privkey sign failed");
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (mm_sshkey_sign(ssh, pubkey, signature, slenp,
		    ದತ್ತಾಂಶ, dlen, alg, options.sk_provider, ಖಾಲಿ,
		    ssh->compat) < 0)
			fatal_f("pubkey sign failed");
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* SSH2 key exchange */
ಸ್ಥಿರ ಶೂನ್ಯ
do_ssh2_kex(ರಚನೆ ssh *ssh)
{
	ಅಕ್ಷರ *hkalgs = ಖಾಲಿ, *myproposal[PROPOSAL_MAX];
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *compression = ಖಾಲಿ;
	ರಚನೆ kex *kex;
	ಪೂರ್ಣಾಂಕ r;

	ssh_packet_ಗಣ_rekey_limits(ssh, options.rekey_ಎಲ್ಲೆ,
	    options.rekey_interval);

	ಆದರೆ (options.compression == COMP_NONE)
		compression = "none";
	hkalgs = list_hostkey_types();

	kex_proposal_populate_entries(ssh, myproposal, options.kex_algorithms,
	    options.ciphers, options.macs, compression, hkalgs);

	ಬಿಡುಗಡೆ(hkalgs);

	ಆದರೆ ((r = kex_exchange_identification(ssh, -1,
	    options.ಆವೃತ್ತಿ_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");
	mm_sshkey_setcompat(ssh); /* tell monitor */

	ಆದರೆ ((ssh->compat & SSH_BUG_NOREKEY))
		debug("client does not support rekeying");

	/* start key exchange */
	ಆದರೆ ((r = kex_ಸಿದ್ಧತೆ(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
	kex_ಗಣ_server_sig_algs(ssh, options.pubkey_accepted_algos);
	kex_ಗಣ_warn_weak_crypto(ssh, options.warn_weak_crypto);
	kex = ssh->kex;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#ಆದರೆ_ಅಂತ್ಯ
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->ತುಂಬು_host_ಬಹಿರಂಗ_ಕೀಲಿ=&get_hostkey_ಬಹಿರಂಗ_by_type;
	kex->ತುಂಬು_host_ಖಾಸಗಿ_ಕೀಲಿ=&get_hostkey_ಖಾಸಗಿ_by_type;
	kex->host_ಕೀಲಿ_ಸೂಚ್ಯಂಕ=&get_hostkey_ಸೂಚ್ಯಂಕ;
	kex->sign = sshd_hostkey_sign;

	ssh_dispatch_ಸತತ_fatal(ssh, DISPATCH_ಖಂಡ, &kex->ಮುಗಿದ);
	kex_proposal_free_entries(myproposal);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send test");
#ಆದರೆ_ಅಂತ್ಯ
	debug("KEX done");
}

/* server specific fatal cleanup */
ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಂಕ i)
{
	_exit(i);
}
