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

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/dh.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#endif

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ "dh.h"
#endif
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
#ifdef GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#endif
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
ಬಾಹ್ಯ ಸಂರಚನಾ monitor *pmonitor;
ಬಾಹ್ಯ ಸಂರಚನಾ sshbuf *loginmsg;
ಬಾಹ್ಯ ServerOptions options;

ಶೂನ್ಯ
mm_log_handler(LogLevel level, ಪೂರ್ಣಾಙ್ಕ forced, ಧ್ರುವ ವರ್ಣ *ಸಂದೇಶ, ಶೂನ್ಯ *ctx)
{
	ಸಂರಚನಾ sshbuf *log_ಸಂದೇಶ;
	ಸಂರಚನಾ monitor *mon = (ಸಂರಚನಾ monitor *)ctx;
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t len;

	ಯದಿ (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	ಯದಿ ((log_ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	ಯದಿ ((r = sshbuf_put_u32(log_ಸಂದೇಶ, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_ಸಂದೇಶ, level)) != 0 ||
	    (r = sshbuf_put_u32(log_ಸಂದೇಶ, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_ಸಂದೇಶ, ಸಂದೇಶ)) != 0)
		fatal_fr(r, "assemble");
	ಯದಿ ((len = sshbuf_len(log_ಸಂದೇಶ)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_ಸಂದೇಶ), len - 4);
	ಯದಿ (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_ಸಂದೇಶ), len) != len) {
		ಯದಿ (errno == EPIPE) {
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
	ಪೂರ್ಣಾಙ್ಕ status = -1;

	ಯದಿ (!mm_is_monitor())
		ಪ್ರತ್ಯಾಗಮ;
	ಯಾವತ್ (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		ಯದಿ (errno == EINTR)
			ಅನುವರ್ತ;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ಯದಿ (WIFEXITED(status)) {
		ಯದಿ (WEXITSTATUS(status) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(status));
			cleanup_exit(255);
		}
	} ಅನ್ಯಥಾ ಯದಿ (WIFSIGNALED(status)) {
		error_f("child terminated by signal %d",
		    WTERMSIG(status));
		cleanup_exit(signal_is_crash(WTERMSIG(status)) ?
		    EXIT_CHILD_CRASH : 255);
	} ಅನ್ಯಥಾ {
		error_f("child terminated abnormally (status=0x%x)",
		    status);
		cleanup_exit(EXIT_CHILD_CRASH);
	}
}

ಶೂನ್ಯ
mm_request_send(ಪೂರ್ಣಾಙ್ಕ sock, ಗಣನಾ monitor_reqtype type, ಸಂರಚನಾ sshbuf *m)
{
	size_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	ಯದಿ (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	ಯದಿ (atomicio(vwrite, sock, buf, ಪರಿಮಾಣ(buf)) != ಪರಿಮಾಣ(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		ಯದಿ (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
}

ಶೂನ್ಯ
mm_request_receive(ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	u_char buf[4], *p = ರಿಕ್ತ;
	u_int ಸಂದೇಶ_len;
	ಪೂರ್ಣಾಙ್ಕ oerrno, r;

	debug3_f("entering");

	ಯದಿ (atomicio(ಪಠ, sock, buf, ಪರಿಮಾಣ(buf)) != ಪರಿಮಾಣ(buf)) {
		ಯದಿ (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", strerror(errno));
	}
	ಸಂದೇಶ_len = PEEK_U32(buf);
	ಯದಿ (ಸಂದೇಶ_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", ಸಂದೇಶ_len);
	sshbuf_reset(m);
	ಯದಿ ((r = sshbuf_reserve(m, ಸಂದೇಶ_len, &p)) != 0)
		fatal_fr(r, "reserve");
	ಯದಿ (atomicio(ಪಠ, sock, p, ಸಂದೇಶ_len) != ಸಂದೇಶ_len) {
		oerrno = errno;
		error_f("read: %s", strerror(errno));
		ಯದಿ (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

ಶೂನ್ಯ
mm_request_receive_expect(ಪೂರ್ಣಾಙ್ಕ sock, ಗಣನಾ monitor_reqtype type, ಸಂರಚನಾ sshbuf *m)
{
	u_char rtype;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	ಯದಿ ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	ಯದಿ (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(ಪೂರ್ಣಾಙ್ಕ min, ಪೂರ್ಣಾಙ್ಕ nbits, ಪೂರ್ಣಾಙ್ಕ max)
{
	BIGNUM *p, *g;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_char success = 0;
	ಸಂರಚನಾ sshbuf *m;

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	ಯದಿ ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ಯದಿ (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

	ಯದಿ ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	ಪ್ರತ್ಯಾಗಮ (dh_new_group(g, p));
}
#endif

ಶೂನ್ಯ
mm_sshkey_setcompat(ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ sshbuf *m;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");
	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

ಪೂರ್ಣಾಙ್ಕ
mm_sshkey_sign(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshkey *ಕೀಲಿ, u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t datalen, ಧ್ರುವ ವರ್ಣ *hostkey_alg,
    ಧ್ರುವ ವರ್ಣ *sk_provider, ಧ್ರುವ ವರ್ಣ *sk_pin, u_int compat)
{
	ಸಂರಚನಾ sshbuf *m;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");
	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshkey_puts(ಕೀಲಿ, m)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	ಯದಿ ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	debug3_f("%s signature len=%zu", hostkey_alg ? hostkey_alg : "(null)",
	    *lenp);

	ಪ್ರತ್ಯಾಗಮ (0);
}

ಶೂನ್ಯ
mm_decode_activate_server_options(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshbuf *m)
{
	ಸಂರಚನಾ sshbuf *config;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i;

	ಯದಿ ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	ಯದಿ ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
}

#define GETPW(b, id) \
	ಕುರು { \
		ಯದಿ ((r = sshbuf_get_string_direct(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		ಯದಿ (len != ಪರಿಮಾಣ(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		memcpy(&pw->id, p, len); \
	} ಯಾವತ್ (0)

ಸಂರಚನಾ passwd *
mm_getpwnamallow(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *username)
{
	ಸಂರಚನಾ sshbuf *m;
	ಸಂರಚನಾ passwd *pw;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_char ok;
	ಧ್ರುವ u_char *p;

	debug3_f("entering");

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	ಯದಿ ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	ಯದಿ (ok == 0) {
		pw = ರಿಕ್ತ;
		ಗಚ್ಛ out;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(ಪರಿಮಾಣ(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#endif
	ಯದಿ ((r = sshbuf_get_cstring(m, &pw->pw_name, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, ರಿಕ್ತ)) != 0 ||
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, ರಿಕ್ತ)) != 0 ||
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(m, &pw->pw_class, ರಿಕ್ತ)) != 0 ||
#endif
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse pw");

out:
	/* copy options block as a Match directive may have changed some */
	mm_decode_activate_server_options(ssh, m);
	server_process_permitopen(ssh);
	server_process_channel_timeouts(ssh);
	channel_set_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	kex_set_server_sig_algs(ssh, options.pubkey_accepted_algos);
	kex_set_warn_weak_crypto(ssh, options.warn_weak_crypto);
	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);
	sshbuf_free(m);

	ಪ್ರತ್ಯಾಗಮ (pw);
}

ವರ್ಣ *
mm_auth2_read_banner(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *m;
	ವರ್ಣ *banner;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	ಯದಿ ((r = sshbuf_get_cstring(m, &banner, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	ಯದಿ (strlen(banner) == 0) {
		ಮುಕ್ತ(banner);
		banner = ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ (banner);
}

/* Inform the privileged process about service and style */

ಶೂನ್ಯ
mm_inform_authserv(ವರ್ಣ *service, ವರ್ಣ *style)
{
	ಸಂರಚನಾ sshbuf *m;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
ಪೂರ್ಣಾಙ್ಕ
mm_auth_password(ಸಂರಚನಾ ssh *ssh, ವರ್ಣ *password)
{
	ಸಂರಚನಾ sshbuf *m;
	ಪೂರ್ಣಾಙ್ಕ r, authenticated = 0;
#ifdef USE_PAM
	u_int maxtries = 0;
#endif

	debug3_f("entering");

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	ಯದಿ ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#ifdef USE_PAM
	ಯದಿ ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	ಯದಿ (maxtries > INT_MAX)
		fatal_fr(r, "bad maxtries");
	sshpam_set_maxtries_reached(maxtries);
#endif

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	ಪ್ರತ್ಯಾಗಮ (authenticated);
}

ಪೂರ್ಣಾಙ್ಕ
mm_user_ಕೀಲಿ_allowed(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ passwd *pw, ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಪೂರ್ಣಾಙ್ಕ pubkey_auth_attempt, ಸಂರಚನಾ sshauthopt **authoptp)
{
	ಪ್ರತ್ಯಾಗಮ (mm_ಕೀಲಿ_allowed(MM_USERKEY, ರಿಕ್ತ, ರಿಕ್ತ, ಕೀಲಿ,
	    pubkey_auth_attempt, authoptp));
}

ಪೂರ್ಣಾಙ್ಕ
mm_hostbased_ಕೀಲಿ_allowed(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ passwd *pw,
    ಧ್ರುವ ವರ್ಣ *user, ಧ್ರುವ ವರ್ಣ *host, ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಪ್ರತ್ಯಾಗಮ (mm_ಕೀಲಿ_allowed(MM_HOSTKEY, user, host, ಕೀಲಿ, 0, ರಿಕ್ತ));
}

ಪೂರ್ಣಾಙ್ಕ
mm_ಕೀಲಿ_allowed(ಗಣನಾ mm_keytype type, ಧ್ರುವ ವರ್ಣ *user, ಧ್ರುವ ವರ್ಣ *host,
    ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಪೂರ್ಣಾಙ್ಕ pubkey_auth_attempt, ಸಂರಚನಾ sshauthopt **authoptp)
{
	ಸಂರಚನಾ sshbuf *m;
	ಪೂರ್ಣಾಙ್ಕ r, allowed = 0;
	ಸಂರಚನಾ sshauthopt *opts = ರಿಕ್ತ;

	debug3_f("entering");

	ಯದಿ (authoptp != ರಿಕ್ತ)
		*authoptp = ರಿಕ್ತ;

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshkey_puts(ಕೀಲಿ, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	ಯದಿ ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal_fr(r, "parse");
	ಯದಿ (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	ಯದಿ (authoptp != ರಿಕ್ತ) {
		*authoptp = opts;
		opts = ರಿಕ್ತ;
	}
	sshauthopt_free(opts);

	ಪ್ರತ್ಯಾಗಮ allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

ಪೂರ್ಣಾಙ್ಕ
mm_sshkey_verify(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ u_char *sig, size_t siglen,
    ಧ್ರುವ u_char *data, size_t datalen, ಧ್ರುವ ವರ್ಣ *sigalg, u_int compat,
    ಸಂರಚನಾ sshkey_sig_details **sig_detailsp)
{
	ಸಂರಚನಾ sshbuf *m;
	u_int encoded_ret = 0;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_char sig_details_present, flags;
	u_int counter;

	debug3_f("entering");

	ಯದಿ (sig_detailsp != ರಿಕ್ತ)
		*sig_detailsp = ರಿಕ್ತ;
	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshkey_puts(ಕೀಲಿ, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == ರಿಕ್ತ ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	ಯದಿ ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	ಯದಿ (sig_details_present && encoded_ret == 0) {
		ಯದಿ ((r = sshbuf_get_u32(m, &counter)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		ಯದಿ (sig_detailsp != ರಿಕ್ತ) {
			*sig_detailsp = xcalloc(1, ಪರಿಮಾಣ(**sig_detailsp));
			(*sig_detailsp)->sk_counter = counter;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	ಯದಿ (encoded_ret != 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SIGNATURE_INVALID;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
mm_send_keystate(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ monitor *monitor)
{
	ಸಂರಚನಾ sshbuf *m;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

ಪೂರ್ಣಾಙ್ಕ
mm_pty_allocate(ಪೂರ್ಣಾಙ್ಕ *ptyfd, ಪೂರ್ಣಾಙ್ಕ *ttyfd, ವರ್ಣ *namebuf, size_t namebuflen)
{
	ಸಂರಚನಾ sshbuf *m;
	ವರ್ಣ *p, *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	ಯದಿ ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		ಯದಿ (tmp1 >= 0)
			close(tmp1);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	close(tmp1);
	close(tmp2);

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	ಯದಿ ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ಯದಿ (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		ಪ್ರತ್ಯಾಗಮ (0);
	}
	ಯದಿ ((r = sshbuf_get_cstring(m, &p, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &ಸಂದೇಶ, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	ಮುಕ್ತ(p);

	ಯದಿ ((r = sshbuf_put(loginmsg, ಸಂದೇಶ, strlen(ಸಂದೇಶ))) != 0)
		fatal_fr(r, "put loginmsg");
	ಮುಕ್ತ(ಸಂದೇಶ);

	ಯದಿ ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	ಪ್ರತ್ಯಾಗಮ (1);
}

ಶೂನ್ಯ
mm_session_pty_cleanup2(Session *s)
{
	ಸಂರಚನಾ sshbuf *m;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (s->ttyfd == -1)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assmble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	ಯದಿ (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#ifdef USE_PAM
ಶೂನ್ಯ
mm_start_pam(ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ sshbuf *m;

	debug3_f("entering");
	ಯದಿ (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_START, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *m;
	u_int ret;
	ವರ್ಣ *ಸಂದೇಶ;
	size_t msglen;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");
	ಯದಿ (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	ಯದಿ ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &ಸಂದೇಶ, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, ಸಂದೇಶ, msglen)) != 0)
		fatal_fr(r, "buffer error");

	ಮುಕ್ತ(ಸಂದೇಶ);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	ಪ್ರತ್ಯಾಗಮ (ret);
}

ಶೂನ್ಯ *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	ಸಂರಚನಾ sshbuf *m;
	ಪೂರ್ಣಾಙ್ಕ r, success;

	debug3_f("entering");
	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	ಯದಿ ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "buffer error");
	ಯದಿ (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}
	sshbuf_free(m);
	ಪ್ರತ್ಯಾಗಮ (authctxt);
}

ಪೂರ್ಣಾಙ್ಕ
mm_sshpam_query(ಶೂನ್ಯ *ctx, ವರ್ಣ **name, ವರ್ಣ **info,
    u_int *ಅಂಕೆ, ವರ್ಣ ***prompts, u_int **echo_on)
{
	ಸಂರಚನಾ sshbuf *m;
	u_int i, n;
	ಪೂರ್ಣಾಙ್ಕ r, ret;

	debug3_f("entering");
	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	ಯದಿ ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, ಅಂಕೆ)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_set_maxtries_reached(n);
	ಯದಿ (*ಅಂಕೆ > PAM_MAX_ಅಂಕೆ_ಸಂದೇಶ)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *ಅಂಕೆ, PAM_MAX_ಅಂಕೆ_ಸಂದೇಶ);
	*prompts = xcalloc((*ಅಂಕೆ + 1), ಪರಿಮಾಣ(ವರ್ಣ *));
	*echo_on = xcalloc((*ಅಂಕೆ + 1), ಪರಿಮಾಣ(u_int));
	ಪ್ರತಿ (i = 0; i < *ಅಂಕೆ; ++i) {
		ಯದಿ ((r = sshbuf_get_cstring(m, &((*prompts)[i]), ರಿಕ್ತ)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	ಪ್ರತ್ಯಾಗಮ (ret);
}

ಪೂರ್ಣಾಙ್ಕ
mm_sshpam_respond(ಶೂನ್ಯ *ctx, u_int ಅಂಕೆ, ವರ್ಣ **resp)
{
	ಸಂರಚನಾ sshbuf *m;
	u_int n, i;
	ಪೂರ್ಣಾಙ್ಕ r, ret;

	debug3_f("entering");
	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u32(m, ಅಂಕೆ)) != 0)
		fatal_fr(r, "buffer error");
	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ; ++i) {
		ಯದಿ ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	ಯದಿ ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	ret = (ಪೂರ್ಣಾಙ್ಕ)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	ಪ್ರತ್ಯಾಗಮ (ret);
}

ಶೂನ್ಯ
mm_sshpam_free_ctx(ಶೂನ್ಯ *ctxtp)
{
	ಸಂರಚನಾ sshbuf *m;

	debug3_f("entering");
	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_FREE_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_FREE_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_FREE_CTX, m);
	sshbuf_free(m);
}
#endif /* USE_PAM */

/* Request process termination */

ಶೂನ್ಯ
mm_terminate(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *m;

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_TERM, m);
	sshbuf_free(m);
}

/* Request state information */

ಶೂನ್ಯ
mm_get_state(ಸಂರಚನಾ ssh *ssh,
    ServerOptions *opts, ಸಂರಚನಾ sshbuf **confdatap,
    uint64_t *timing_secretp,
    ಸಂರಚನಾ sshbuf **hostkeysp, ಸಂರಚನಾ sshbuf **keystatep,
    u_char **pw_namep,
    ಸಂರಚನಾ sshbuf **authinfop, ಸಂರಚನಾ sshbuf **auth_optsp)
{
	ಸಂರಚನಾ sshbuf *m, *config;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ || (config = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	ಯದಿ ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	ಯದಿ (confdatap) {
		ಯದಿ ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, ರಿಕ್ತ)) != 0 ||
		    (r = sshbuf_froms(m, authinfop)) != 0 ||
		    (r = sshbuf_froms(m, auth_optsp)) != 0)
			fatal_fr(r, "parse config postauth");
	}
	ಯದಿ ((r = deserialise_server_options(config, opts)) != 0)
		fatal_fr(r, "deserialise_server_options");

	sshbuf_free(m);
	sshbuf_free(config);

	debug3_f("done");
}

ಸ್ಥಿರ ಶೂನ್ಯ
mm_chall_setup(ವರ್ಣ **name, ವರ್ಣ **infotxt, u_int *numprompts,
    ವರ್ಣ ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, ಪರಿಮಾಣ(ವರ್ಣ *));
	*echo_on = xcalloc(*numprompts, ಪರಿಮಾಣ(u_int));
	(*echo_on)[0] = 0;
}

ಪೂರ್ಣಾಙ್ಕ
mm_bsdauth_query(ಶೂನ್ಯ *ctx, ವರ್ಣ **name, ವರ್ಣ **infotxt,
   u_int *numprompts, ವರ್ಣ ***prompts, u_int **echo_on)
{
	ಸಂರಚನಾ sshbuf *m;
	u_int success;
	ವರ್ಣ *challenge;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	ಯದಿ ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ಯದಿ (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}

	/* Get the challenge, and format the response */
	ಯದಿ ((r = sshbuf_get_cstring(m, &challenge, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_setup(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
mm_bsdauth_respond(ಶೂನ್ಯ *ctx, u_int numresponses, ವರ್ಣ **responses)
{
	ಸಂರಚನಾ sshbuf *m;
	ಪೂರ್ಣಾಙ್ಕ r, authok;

	debug3_f("entering");
	ಯದಿ (numresponses != 1)
		ಪ್ರತ್ಯಾಗಮ (-1);

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	ಯದಿ ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	ಪ್ರತ್ಯಾಗಮ ((authok == 0) ? -1 : 0);
}

#ifdef SSH_AUDIT_EVENTS
ಶೂನ್ಯ
mm_audit_event(ಸಂರಚನಾ ssh *ssh, ssh_audit_event_t event)
{
	ಸಂರಚನಾ sshbuf *m;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

ಶೂನ್ಯ
mm_audit_run_command(ಧ್ರುವ ವರ್ಣ *command)
{
	ಸಂರಚನಾ sshbuf *m;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering command %s", command);

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#endif /* SSH_AUDIT_EVENTS */

#ifdef GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	ಸಂರಚನಾ sshbuf *m;
	OM_uint32 major;
	ಪೂರ್ಣಾಙ್ಕ r;

	/* Client doesn't get to see the context */
	*ctx = ರಿಕ್ತ;

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_string(m, goid->elements, goid->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	ಯದಿ ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	ಪ್ರತ್ಯಾಗಮ (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *in,
    gss_buffer_desc *out, OM_uint32 *flagsp)
{
	ಸಂರಚನಾ sshbuf *m;
	OM_uint32 major;
	u_int flags;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_string(m, in->ಮೌಲ್ಯ, in->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	ಯದಿ ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, out)) != 0)
		fatal_fr(r, "parse");
	ಯದಿ (flagsp != ರಿಕ್ತ) {
		ಯದಿ ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	ಪ್ರತ್ಯಾಗಮ (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	ಸಂರಚನಾ sshbuf *m;
	OM_uint32 major;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_string(m, gssbuf->ಮೌಲ್ಯ, gssbuf->length)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->ಮೌಲ್ಯ, gssmic->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	ಯದಿ ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	ಪ್ರತ್ಯಾಗಮ(major);
}

ಪೂರ್ಣಾಙ್ಕ
mm_ssh_gssapi_userok(ವರ್ಣ *user)
{
	ಸಂರಚನಾ sshbuf *m;
	ಪೂರ್ಣಾಙ್ಕ r, authenticated = 0;

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	ಯದಿ ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	ಪ್ರತ್ಯಾಗಮ (authenticated);
}
#endif /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
ಸ್ಥಿರ ಶೂನ್ಯ
server_process_permitopen_list(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ listen,
    ವರ್ಣ **opens, u_int ಅಂಕೆ_opens)
{
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ port;
	ವರ್ಣ *host, *arg, *oarg;
	ಪೂರ್ಣಾಙ್ಕ where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	ಧ್ರುವ ವರ್ಣ *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	ಯದಿ (ಅಂಕೆ_opens == 0)
		ಪ್ರತ್ಯಾಗಮ; /* permit any */

	/* handle keywords: "any" / "none" */
	ಯದಿ (ಅಂಕೆ_opens == 1 && strcmp(opens[0], "any") == 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (ಅಂಕೆ_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		ಪ್ರತ್ಯಾಗಮ;
	}
	/* Otherwise treat it as a list of permitted host:port */
	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		ಯದಿ (host == ರಿಕ್ತ)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		ಯದಿ (arg == ರಿಕ್ತ || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, host, port);
		ಮುಕ್ತ(oarg);
	}
}

/*
 * Inform channels layer of permitopen options from configuration.
 */
ಶೂನ್ಯ
server_process_permitopen(ಸಂರಚನಾ ssh *ssh)
{
	server_process_permitopen_list(ssh, 0,
	    options.permitted_opens, options.ಅಂಕೆ_permitted_opens);
	server_process_permitopen_list(ssh, 1,
	    options.permitted_listens, options.ಅಂಕೆ_permitted_listens);
}

ಶೂನ್ಯ
server_process_channel_timeouts(ಸಂರಚನಾ ssh *ssh)
{
	u_int i;
	ದ್ವಿಗುಣ secs;
	ವರ್ಣ *type;

	debug3_f("setting %u timeouts", options.ಅಂಕೆ_channel_timeouts);
	channel_clear_timeouts(ssh);
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_channel_timeouts; i++) {
		ಯದಿ (parse_pattern_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_add_timeout(ssh, type, secs);
		ಮುಕ್ತ(type);
	}
}

ಸಂರಚನಾ connection_info *
server_get_connection_info(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ populate, ಪೂರ್ಣಾಙ್ಕ use_dns)
{
	ಸ್ಥಿರ ಸಂರಚನಾ connection_info ci;

	ಯದಿ (ssh == ರಿಕ್ತ || !populate)
		ಪ್ರತ್ಯಾಗಮ &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.address = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_port(ssh);
	ci.rdomain = ssh_packet_rdomain_in(ssh);
	ಪ್ರತ್ಯಾಗಮ &ci;
}

