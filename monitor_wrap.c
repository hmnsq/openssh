/* $OpenBSD: monitor_wrap.c,v 1.151 2026/09/16 06:23:16 djm Exp $ */
/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * Copyright 2002 Markus Friedl <markus@openbsd.org>
 * All rights reserved.
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
#ಅನ್ತರ್ಭಾವ <sys/uio.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/dh.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ "dh.h"
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "mac.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "auth-pam.h"
#ಅನ್ತರ್ಭಾವ "monitor.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "monitor_fdpass.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "session.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "srclimit.h"

#ಅನ್ತರ್ಭಾವ "ssherr.h"

/* Imports */
ಬಾಹ್ಯ ರಚನೆ monitor *pmonitor;
ಬಾಹ್ಯ ರಚನೆ sshbuf *loginmsg;
ಬಾಹ್ಯ ServerOptions options;

ಶೂನ್ಯ
mm_log_handler(LogLevel level, ಪೂರ್ಣಾಂಕ forced, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಂದೇಶ, ಶೂನ್ಯ *ctx)
{
	ರಚನೆ sshbuf *log_ಸಂದೇಶ;
	ರಚನೆ monitor *mon = (ರಚನೆ monitor *)ctx;
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t len;

	ಆದರೆ (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	ಆದರೆ ((log_ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	ಆದರೆ ((r = sshbuf_put_u32(log_ಸಂದೇಶ, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_ಸಂದೇಶ, level)) != 0 ||
	    (r = sshbuf_put_u32(log_ಸಂದೇಶ, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_ಸಂದೇಶ, ಸಂದೇಶ)) != 0)
		fatal_fr(r, "assemble");
	ಆದರೆ ((len = sshbuf_len(log_ಸಂದೇಶ)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_ಸಂದೇಶ), len - 4);
	ಆದರೆ (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_ಸಂದೇಶ), len) != len) {
		ಆದರೆ (errno == EPIPE) {
			debug_f("write: %s", strerror(errno));
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
	sshbuf_free(log_ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
mm_reap(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2 = -1;

	ಆದರೆ (!mm_is_monitor())
		ಹಿಂತಿರುಗಿ;
	ಆಗ (waitpid(pmonitor->m_pid, &ಸ್ಥಿತಿ_2, 0) == -1) {
		ಆದರೆ (errno == EINTR)
			ಮುಂದುವರಿ;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ಆದರೆ (WIFEXITED(ಸ್ಥಿತಿ_2)) {
		ಆದರೆ (WEXITSTATUS(ಸ್ಥಿತಿ_2) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(ಸ್ಥಿತಿ_2));
			cleanup_exit(255);
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (WIFSIGNALED(ಸ್ಥಿತಿ_2)) {
		error_f("child terminated by signal %d",
		    WTERMSIG(ಸ್ಥಿತಿ_2));
		cleanup_exit(signal_is_crash(WTERMSIG(ಸ್ಥಿತಿ_2)) ?
		    EXIT_ಮಗು_CRASH : 255);
	} ಇಲ್ಲದಿದ್ದರೆ {
		error_f("child terminated abnormally (status=0x%x)",
		    ಸ್ಥಿತಿ_2);
		cleanup_exit(EXIT_ಮಗು_CRASH);
	}
}

ಶೂನ್ಯ
mm_request_send(ಪೂರ್ಣಾಂಕ sock, ಎಣಿಕೆ monitor_reqtype type, ರಚನೆ sshbuf *m)
{
	ಗಾತ್ರ_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	ಆದರೆ (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	ಆದರೆ (atomicio(vwrite, sock, buf, ಗಾತ್ರ(buf)) != ಗಾತ್ರ(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		ಆದರೆ (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
}

ಶೂನ್ಯ
mm_request_receive(ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	u_char buf[4], *p = ಖಾಲಿ;
	u_int ಸಂದೇಶ_len;
	ಪೂರ್ಣಾಂಕ oerrno, r;

	debug3_f("entering");

	ಆದರೆ (atomicio(ಪಠ, sock, buf, ಗಾತ್ರ(buf)) != ಗಾತ್ರ(buf)) {
		ಆದರೆ (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", strerror(errno));
	}
	ಸಂದೇಶ_len = PEEK_U32(buf);
	ಆದರೆ (ಸಂದೇಶ_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", ಸಂದೇಶ_len);
	sshbuf_reset(m);
	ಆದರೆ ((r = sshbuf_reserve(m, ಸಂದೇಶ_len, &p)) != 0)
		fatal_fr(r, "reserve");
	ಆದರೆ (atomicio(ಪಠ, sock, p, ಸಂದೇಶ_len) != ಸಂದೇಶ_len) {
		oerrno = errno;
		error_f("read: %s", strerror(errno));
		ಆದರೆ (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

ಶೂನ್ಯ
mm_request_receive_expect(ಪೂರ್ಣಾಂಕ sock, ಎಣಿಕೆ monitor_reqtype type, ರಚನೆ sshbuf *m)
{
	u_char rtype;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	ಆದರೆ ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	ಆದರೆ (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
DH *
mm_ಆರಿಸು_dh(ಪೂರ್ಣಾಂಕ min, ಪೂರ್ಣಾಂಕ nbits, ಪೂರ್ಣಾಂಕ max)
{
	BIGNUM *p, *g;
	ಪೂರ್ಣಾಂಕ r;
	u_char success = 0;
	ರಚನೆ sshbuf *m;

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	ಆದರೆ ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ಆದರೆ (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

	ಆದರೆ ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	ಹಿಂತಿರುಗಿ (dh_new_ಗುಂಪು(g, p));
}
#ಆದರೆ_ಅಂತ್ಯ

ಶೂನ್ಯ
mm_sshkey_setcompat(ರಚನೆ ssh *ssh)
{
	ರಚನೆ sshbuf *m;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");
	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

ಪೂರ್ಣಾಂಕ
mm_sshkey_sign(ರಚನೆ ssh *ssh, ರಚನೆ sshkey *ಕೀಲಿ, u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostkey_alg,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin, u_int compat)
{
	ರಚನೆ sshbuf *m;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");
	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshkey_puts(ಕೀಲಿ, m)) != 0 ||
	    (r = sshbuf_put_string(m, ದತ್ತಾಂಶ, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	ಆದರೆ ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	debug3_f("%s signature len=%zu", hostkey_alg ? hostkey_alg : "(null)",
	    *lenp);

	ಹಿಂತಿರುಗಿ (0);
}

ಶೂನ್ಯ
mm_decode_activate_server_options(ರಚನೆ ssh *ssh, ರಚನೆ sshbuf *m)
{
	ರಚನೆ sshbuf *config;
	ಪೂರ್ಣಾಂಕ r;
	u_int i;

	ಆದರೆ ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	ಆದರೆ ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_log_verbose; i++)
		log_verbose_ಕೂಡಿಸು(options.log_verbose[i]);
}

#ವ್ಯಾಖ್ಯಾನಿಸು GETPW(b, id) \
	ಮಾಡು { \
		ಆದರೆ ((r = sshbuf_get_string_ನೇರ(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		ಆದರೆ (len != ಗಾತ್ರ(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		ಸ್ಮರಣೆ_ನಕಲು(&pw->id, p, len); \
	} ಆಗ (0)

ರಚನೆ passwd *
mm_getpwnamallow(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *username)
{
	ರಚನೆ sshbuf *m;
	ರಚನೆ passwd *pw;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r;
	u_char ok;
	ಸ್ಥಿರಾಂಕ u_char *p;

	debug3_f("entering");

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	ಆದರೆ ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	ಆದರೆ (ok == 0) {
		pw = ಖಾಲಿ;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(ಗಾತ್ರ(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ ((r = sshbuf_get_cstring(m, &pw->pw_name, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, ಖಾಲಿ)) != 0 ||
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, ಖಾಲಿ)) != 0 ||
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(m, &pw->pw_class, ಖಾಲಿ)) != 0 ||
#ಆದರೆ_ಅಂತ್ಯ
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse pw");

ಹೊರಹೋಗು:
	/* copy options block as a Match directive may have changed some */
	mm_decode_activate_server_options(ssh, m);
	server_process_permitopen(ssh);
	server_process_channel_timeouts(ssh);
	channel_ಗಣ_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	kex_ಗಣ_server_sig_algs(ssh, options.pubkey_accepted_algos);
	kex_ಗಣ_warn_weak_crypto(ssh, options.warn_weak_crypto);
	ssh_packet_ಗಣ_rekey_limits(ssh, options.rekey_ಎಲ್ಲೆ,
	    options.rekey_interval);
	sshbuf_free(m);

	ಹಿಂತಿರುಗಿ (pw);
}

ಅಕ್ಷರ *
mm_auth2_read_banner(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *m;
	ಅಕ್ಷರ *banner;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	ಆದರೆ ((r = sshbuf_get_cstring(m, &banner, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(banner) == 0) {
		ಬಿಡುಗಡೆ(banner);
		banner = ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ (banner);
}

/* Inform the privileged process about service and style */

ಶೂನ್ಯ
mm_inform_authserv(ಅಕ್ಷರ *service, ಅಕ್ಷರ *style)
{
	ರಚನೆ sshbuf *m;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
ಪೂರ್ಣಾಂಕ
mm_auth_password(ರಚನೆ ssh *ssh, ಅಕ್ಷರ *password)
{
	ರಚನೆ sshbuf *m;
	ಪೂರ್ಣಾಂಕ r, authenticated = 0;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	u_int maxtries = 0;
#ಆದರೆ_ಅಂತ್ಯ

	debug3_f("entering");

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	ಆದರೆ ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	ಆದರೆ ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	ಆದರೆ (maxtries > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		fatal_fr(r, "bad maxtries");
	sshpam_ಗಣ_maxtries_reached(maxtries);
#ಆದರೆ_ಅಂತ್ಯ

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	ಹಿಂತಿರುಗಿ (authenticated);
}

ಪೂರ್ಣಾಂಕ
mm_user_ಕೀಲಿ_allowed(ರಚನೆ ssh *ssh, ರಚನೆ passwd *pw, ರಚನೆ sshkey *ಕೀಲಿ,
    ಪೂರ್ಣಾಂಕ pubkey_auth_attempt, ರಚನೆ sshauthopt **authoptp)
{
	ಹಿಂತಿರುಗಿ (mm_ಕೀಲಿ_allowed(MM_USERKEY, ಖಾಲಿ, ಖಾಲಿ, ಕೀಲಿ,
	    pubkey_auth_attempt, authoptp));
}

ಪೂರ್ಣಾಂಕ
mm_hostbased_ಕೀಲಿ_allowed(ರಚನೆ ssh *ssh, ರಚನೆ passwd *pw,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಹಿಂತಿರುಗಿ (mm_ಕೀಲಿ_allowed(MM_HOSTKEY, user, host, ಕೀಲಿ, 0, ಖಾಲಿ));
}

ಪೂರ್ಣಾಂಕ
mm_ಕೀಲಿ_allowed(ಎಣಿಕೆ mm_keytype type, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host,
    ರಚನೆ sshkey *ಕೀಲಿ, ಪೂರ್ಣಾಂಕ pubkey_auth_attempt, ರಚನೆ sshauthopt **authoptp)
{
	ರಚನೆ sshbuf *m;
	ಪೂರ್ಣಾಂಕ r, allowed = 0;
	ರಚನೆ sshauthopt *opts = ಖಾಲಿ;

	debug3_f("entering");

	ಆದರೆ (authoptp != ಖಾಲಿ)
		*authoptp = ಖಾಲಿ;

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshkey_puts(ಕೀಲಿ, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	ಆದರೆ ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal_fr(r, "parse");
	ಆದರೆ (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	ಆದರೆ (authoptp != ಖಾಲಿ) {
		*authoptp = opts;
		opts = ಖಾಲಿ;
	}
	sshauthopt_free(opts);

	ಹಿಂತಿರುಗಿ allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

ಪೂರ್ಣಾಂಕ
mm_sshkey_verify(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ u_char *sig, ಗಾತ್ರ_t siglen,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sigalg, u_int compat,
    ರಚನೆ sshkey_sig_details **sig_detailsp)
{
	ರಚನೆ sshbuf *m;
	u_int encoded_ret = 0;
	ಪೂರ್ಣಾಂಕ r;
	u_char sig_details_present, flags;
	u_int counter;

	debug3_f("entering");

	ಆದರೆ (sig_detailsp != ಖಾಲಿ)
		*sig_detailsp = ಖಾಲಿ;
	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshkey_puts(ಕೀಲಿ, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, ದತ್ತಾಂಶ, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == ಖಾಲಿ ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	ಆದರೆ ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	ಆದರೆ (sig_details_present && encoded_ret == 0) {
		ಆದರೆ ((r = sshbuf_get_u32(m, &counter)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		ಆದರೆ (sig_detailsp != ಖಾಲಿ) {
			*sig_detailsp = xcalloc(1, ಗಾತ್ರ(**sig_detailsp));
			(*sig_detailsp)->sk_counter = counter;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	ಆದರೆ (encoded_ret != 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_SIGNATURE_INVALID;
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
mm_send_keystate(ರಚನೆ ssh *ssh, ರಚನೆ monitor *monitor)
{
	ರಚನೆ sshbuf *m;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

ಪೂರ್ಣಾಂಕ
mm_pty_allocate(ಪೂರ್ಣಾಂಕ *ptyfd, ಪೂರ್ಣಾಂಕ *ttyfd, ಅಕ್ಷರ *namebuf, ಗಾತ್ರ_t namebuflen)
{
	ರಚನೆ sshbuf *m;
	ಅಕ್ಷರ *p, *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	ಆದರೆ ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		ಆದರೆ (tmp1 >= 0)
			close(tmp1);
		ಹಿಂತಿರುಗಿ 0;
	}
	close(tmp1);
	close(tmp2);

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	ಆದರೆ ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ಆದರೆ (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		ಹಿಂತಿರುಗಿ (0);
	}
	ಆದರೆ ((r = sshbuf_get_cstring(m, &p, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &ಸಂದೇಶ, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	ಬಿಡುಗಡೆ(p);

	ಆದರೆ ((r = sshbuf_put(loginmsg, ಸಂದೇಶ, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಸಂದೇಶ))) != 0)
		fatal_fr(r, "put loginmsg");
	ಬಿಡುಗಡೆ(ಸಂದೇಶ);

	ಆದರೆ ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	ಹಿಂತಿರುಗಿ (1);
}

ಶೂನ್ಯ
mm_session_pty_cleanup2(Session *s)
{
	ರಚನೆ sshbuf *m;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (s->ttyfd == -1)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assmble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	ಆದರೆ (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
ಶೂನ್ಯ
mm_ಆರಂಭ_pam(ರಚನೆ ssh *ssh)
{
	ರಚನೆ sshbuf *m;

	debug3_f("entering");
	ಆದರೆ (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ಆರಂಭ, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *m;
	u_int ret;
	ಅಕ್ಷರ *ಸಂದೇಶ;
	ಗಾತ್ರ_t msglen;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");
	ಆದರೆ (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	ಆದರೆ ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &ಸಂದೇಶ, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, ಸಂದೇಶ, msglen)) != 0)
		fatal_fr(r, "buffer error");

	ಬಿಡುಗಡೆ(ಸಂದೇಶ);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	ಹಿಂತಿರುಗಿ (ret);
}

ಶೂನ್ಯ *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	ರಚನೆ sshbuf *m;
	ಪೂರ್ಣಾಂಕ r, success;

	debug3_f("entering");
	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	ಆದರೆ ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "buffer error");
	ಆದರೆ (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}
	sshbuf_free(m);
	ಹಿಂತಿರುಗಿ (authctxt);
}

ಪೂರ್ಣಾಂಕ
mm_sshpam_query(ಶೂನ್ಯ *ctx, ಅಕ್ಷರ **name, ಅಕ್ಷರ **info,
    u_int *ಅಂಕೆ, ಅಕ್ಷರ ***prompts, u_int **echo_on)
{
	ರಚನೆ sshbuf *m;
	u_int i, n;
	ಪೂರ್ಣಾಂಕ r, ret;

	debug3_f("entering");
	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	ಆದರೆ ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, ಅಂಕೆ)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_ಗಣ_maxtries_reached(n);
	ಆದರೆ (*ಅಂಕೆ > PAM_MAX_ಅಂಕೆ_ಸಂದೇಶ)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *ಅಂಕೆ, PAM_MAX_ಅಂಕೆ_ಸಂದೇಶ);
	*prompts = xcalloc((*ಅಂಕೆ + 1), ಗಾತ್ರ(ಅಕ್ಷರ *));
	*echo_on = xcalloc((*ಅಂಕೆ + 1), ಗಾತ್ರ(u_int));
	ಗಾಗಿ (i = 0; i < *ಅಂಕೆ; ++i) {
		ಆದರೆ ((r = sshbuf_get_cstring(m, &((*prompts)[i]), ಖಾಲಿ)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	ಹಿಂತಿರುಗಿ (ret);
}

ಪೂರ್ಣಾಂಕ
mm_sshpam_respond(ಶೂನ್ಯ *ctx, u_int ಅಂಕೆ, ಅಕ್ಷರ **resp)
{
	ರಚನೆ sshbuf *m;
	u_int n, i;
	ಪೂರ್ಣಾಂಕ r, ret;

	debug3_f("entering");
	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u32(m, ಅಂಕೆ)) != 0)
		fatal_fr(r, "buffer error");
	ಗಾಗಿ (i = 0; i < ಅಂಕೆ; ++i) {
		ಆದರೆ ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	ಆದರೆ ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	ret = (ಪೂರ್ಣಾಂಕ)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	ಹಿಂತಿರುಗಿ (ret);
}

ಶೂನ್ಯ
mm_sshpam_free_ctx(ಶೂನ್ಯ *ctxtp)
{
	ರಚನೆ sshbuf *m;

	debug3_f("entering");
	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_FREE_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_FREE_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_FREE_CTX, m);
	sshbuf_free(m);
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_PAM */

/* Request process termination */

ಶೂನ್ಯ
mm_terminate(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *m;

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_ಪದ, m);
	sshbuf_free(m);
}

/* Request state information */

ಶೂನ್ಯ
mm_get_state(ರಚನೆ ssh *ssh,
    ServerOptions *opts, ರಚನೆ sshbuf **confdatap,
    uint64_t *timing_secretp,
    ರಚನೆ sshbuf **hostkeysp, ರಚನೆ sshbuf **keystatep,
    u_char **pw_namep,
    ರಚನೆ sshbuf **authinfop, ರಚನೆ sshbuf **auth_optsp)
{
	ರಚನೆ sshbuf *m, *config;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ || (config = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	ಆದರೆ ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_ಆವೃತ್ತಿ)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_ಆವೃತ್ತಿ)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	ಆದರೆ (confdatap) {
		ಆದರೆ ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, ಖಾಲಿ)) != 0 ||
		    (r = sshbuf_froms(m, authinfop)) != 0 ||
		    (r = sshbuf_froms(m, auth_optsp)) != 0)
			fatal_fr(r, "parse config postauth");
	}
	ಆದರೆ ((r = deserialise_server_options(config, opts)) != 0)
		fatal_fr(r, "deserialise_server_options");

	sshbuf_free(m);
	sshbuf_free(config);

	debug3_f("done");
}

ಸ್ಥಿರ ಶೂನ್ಯ
mm_chall_ಸಿದ್ಧತೆ(ಅಕ್ಷರ **name, ಅಕ್ಷರ **infotxt, u_int *numprompts,
    ಅಕ್ಷರ ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, ಗಾತ್ರ(ಅಕ್ಷರ *));
	*echo_on = xcalloc(*numprompts, ಗಾತ್ರ(u_int));
	(*echo_on)[0] = 0;
}

ಪೂರ್ಣಾಂಕ
mm_bsdauth_query(ಶೂನ್ಯ *ctx, ಅಕ್ಷರ **name, ಅಕ್ಷರ **infotxt,
   u_int *numprompts, ಅಕ್ಷರ ***prompts, u_int **echo_on)
{
	ರಚನೆ sshbuf *m;
	u_int success;
	ಅಕ್ಷರ *challenge;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	ಆದರೆ ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ಆದರೆ (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		ಹಿಂತಿರುಗಿ (-1);
	}

	/* Get the challenge, and format the response */
	ಆದರೆ ((r = sshbuf_get_cstring(m, &challenge, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_ಸಿದ್ಧತೆ(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
mm_bsdauth_respond(ಶೂನ್ಯ *ctx, u_int numresponses, ಅಕ್ಷರ **responses)
{
	ರಚನೆ sshbuf *m;
	ಪೂರ್ಣಾಂಕ r, authok;

	debug3_f("entering");
	ಆದರೆ (numresponses != 1)
		ಹಿಂತಿರುಗಿ (-1);

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	ಆದರೆ ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	ಹಿಂತಿರುಗಿ ((authok == 0) ? -1 : 0);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_AUDIT_EVENTS
ಶೂನ್ಯ
mm_audit_event(ರಚನೆ ssh *ssh, ssh_audit_event_t event)
{
	ರಚನೆ sshbuf *m;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

ಶೂನ್ಯ
mm_audit_ಸತತ_command(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *command)
{
	ರಚನೆ sshbuf *m;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering command %s", command);

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#ಆದರೆ_ಅಂತ್ಯ /* SSH_AUDIT_EVENTS */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	ರಚನೆ sshbuf *m;
	OM_uint32 major;
	ಪೂರ್ಣಾಂಕ r;

	/* Client doesn't get to see the context */
	*ctx = ಖಾಲಿ;

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_string(m, goid->elements, goid->ಉದ್ದಳತೆ)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	ಆದರೆ ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	ಹಿಂತಿರುಗಿ (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_ಬಫರ್_desc *ಒಳ,
    gss_ಬಫರ್_desc *ಹೊರಹೋಗು, OM_uint32 *flagsp)
{
	ರಚನೆ sshbuf *m;
	OM_uint32 major;
	u_int flags;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_string(m, ಒಳ->ಮೌಲ್ಯ, ಒಳ->ಉದ್ದಳತೆ)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	ಆದರೆ ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_ಬಫರ್_desc(m, ಹೊರಹೋಗು)) != 0)
		fatal_fr(r, "parse");
	ಆದರೆ (flagsp != ಖಾಲಿ) {
		ಆದರೆ ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	ಹಿಂತಿರುಗಿ (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_ಬಫರ್_t gssbuf, gss_ಬಫರ್_t gssmic)
{
	ರಚನೆ sshbuf *m;
	OM_uint32 major;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_string(m, gssbuf->ಮೌಲ್ಯ, gssbuf->ಉದ್ದಳತೆ)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->ಮೌಲ್ಯ, gssmic->ಉದ್ದಳತೆ)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	ಆದರೆ ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	ಹಿಂತಿರುಗಿ(major);
}

ಪೂರ್ಣಾಂಕ
mm_ssh_gssapi_userok(ಅಕ್ಷರ *user)
{
	ರಚನೆ sshbuf *m;
	ಪೂರ್ಣಾಂಕ r, authenticated = 0;

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	ಆದರೆ ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	ಹಿಂತಿರುಗಿ (authenticated);
}
#ಆದರೆ_ಅಂತ್ಯ /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
ಸ್ಥಿರ ಶೂನ್ಯ
server_process_permitopen_list(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ listen,
    ಅಕ್ಷರ **opens, u_int ಅಂಕೆ_opens)
{
	u_int i;
	ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್;
	ಅಕ್ಷರ *host, *arg, *oarg;
	ಪೂರ್ಣಾಂಕ where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	ಆದರೆ (ಅಂಕೆ_opens == 0)
		ಹಿಂತಿರುಗಿ; /* permit any */

	/* handle keywords: "any" / "none" */
	ಆದರೆ (ಅಂಕೆ_opens == 1 && strcmp(opens[0], "any") == 0)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (ಅಂಕೆ_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		ಹಿಂತಿರುಗಿ;
	}
	/* Otherwise treat it as a list of permitted host:port */
	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		ಆದರೆ (host == ಖಾಲಿ)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		ಆದರೆ (arg == ಖಾಲಿ || ((ಪೋರ್ಟ್ = permitopen_ಪೋರ್ಟ್(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_ಕೂಡಿಸು_permission(ssh, FORWARD_ADM,
		    where, host, ಪೋರ್ಟ್);
		ಬಿಡುಗಡೆ(oarg);
	}
}

/*
 * Inform channels layer of permitopen options from configuration.
 */
ಶೂನ್ಯ
server_process_permitopen(ರಚನೆ ssh *ssh)
{
	server_process_permitopen_list(ssh, 0,
	    options.permitted_opens, options.ಅಂಕೆ_permitted_opens);
	server_process_permitopen_list(ssh, 1,
	    options.permitted_listens, options.ಅಂಕೆ_permitted_listens);
}

ಶೂನ್ಯ
server_process_channel_timeouts(ರಚನೆ ssh *ssh)
{
	u_int i;
	ದ್ವಿಗುಣ secs;
	ಅಕ್ಷರ *type;

	debug3_f("setting %u timeouts", options.ಅಂಕೆ_channel_timeouts);
	channel_clear_timeouts(ssh);
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_channel_timeouts; i++) {
		ಆದರೆ (parse_ನಮೂನೆ_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_ಕೂಡಿಸು_timeout(ssh, type, secs);
		ಬಿಡುಗಡೆ(type);
	}
}

ರಚನೆ connection_info *
server_get_connection_info(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ populate, ಪೂರ್ಣಾಂಕ use_dns)
{
	ಸ್ಥಿರ ರಚನೆ connection_info ci;

	ಆದರೆ (ssh == ಖಾಲಿ || !populate)
		ಹಿಂತಿರುಗಿ &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.ವಿಳಾಸ = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_ಪೋರ್ಟ್(ssh);
	ci.rdomain = ssh_packet_rdomain_ಒಳ(ssh);
	ಹಿಂತಿರುಗಿ &ci;
}

