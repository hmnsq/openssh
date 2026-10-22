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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/uio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/dh.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ "dh.h"
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "mac.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-pam.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_fdpass.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "session.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_wrap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "srclimit.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

/* Imports */
ਬਾਹਰੀ ਬਣਤਰ monitor *pmonitor;
ਬਾਹਰੀ ਬਣਤਰ sshbuf *loginmsg;
ਬਾਹਰੀ ServerOptions options;

ਖਾਲੀ
mm_log_handler(LogLevel level, ਪੂਰਨ forced, ਅਚਲ ਅੱਖਰ *ਸੁਨੇਹਾ, ਖਾਲੀ *ctx)
{
	ਬਣਤਰ sshbuf *log_ਸੁਨੇਹਾ;
	ਬਣਤਰ monitor *mon = (ਬਣਤਰ monitor *)ctx;
	ਪੂਰਨ r;
	ਮਾਪ_t len;

	ਜੇ (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	ਜੇ ((log_ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	ਜੇ ((r = sshbuf_put_u32(log_ਸੁਨੇਹਾ, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_ਸੁਨੇਹਾ, level)) != 0 ||
	    (r = sshbuf_put_u32(log_ਸੁਨੇਹਾ, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_ਸੁਨੇਹਾ, ਸੁਨੇਹਾ)) != 0)
		fatal_fr(r, "assemble");
	ਜੇ ((len = sshbuf_len(log_ਸੁਨੇਹਾ)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_ਸੁਨੇਹਾ), len - 4);
	ਜੇ (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_ਸੁਨੇਹਾ), len) != len) {
		ਜੇ (errno == EPIPE) {
			debug_f("write: %s", strerror(errno));
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
	sshbuf_free(log_ਸੁਨੇਹਾ);
}

ਸਥਿਰ ਖਾਲੀ
mm_reap(ਖਾਲੀ)
{
	ਪੂਰਨ ਸਥਿਤੀ = -1;

	ਜੇ (!mm_is_monitor())
		ਵਾਪਸ;
	ਜਦੋਂ (waitpid(pmonitor->m_pid, &ਸਥਿਤੀ, 0) == -1) {
		ਜੇ (errno == EINTR)
			ਜਾਰੀ;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ਜੇ (WIFEXITED(ਸਥਿਤੀ)) {
		ਜੇ (WEXITSTATUS(ਸਥਿਤੀ) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(ਸਥਿਤੀ));
			cleanup_exit(255);
		}
	} ਨਹੀਂਤਾਂ ਜੇ (WIFSIGNALED(ਸਥਿਤੀ)) {
		error_f("child terminated by signal %d",
		    WTERMSIG(ਸਥਿਤੀ));
		cleanup_exit(signal_is_crash(WTERMSIG(ਸਥਿਤੀ)) ?
		    EXIT_ਬੱਚਾ_CRASH : 255);
	} ਨਹੀਂਤਾਂ {
		error_f("child terminated abnormally (status=0x%x)",
		    ਸਥਿਤੀ);
		cleanup_exit(EXIT_ਬੱਚਾ_CRASH);
	}
}

ਖਾਲੀ
mm_request_send(ਪੂਰਨ sock, ਗਿਣਤੀ monitor_reqtype type, ਬਣਤਰ sshbuf *m)
{
	ਮਾਪ_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	ਜੇ (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	ਜੇ (atomicio(vwrite, sock, buf, ਆਕਾਰ(buf)) != ਆਕਾਰ(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		ਜੇ (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
}

ਖਾਲੀ
mm_request_receive(ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	u_char buf[4], *p = ਨਿਰਾ;
	u_int ਸੁਨੇਹਾ_len;
	ਪੂਰਨ oerrno, r;

	debug3_f("entering");

	ਜੇ (atomicio(ਪਠ, sock, buf, ਆਕਾਰ(buf)) != ਆਕਾਰ(buf)) {
		ਜੇ (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", strerror(errno));
	}
	ਸੁਨੇਹਾ_len = PEEK_U32(buf);
	ਜੇ (ਸੁਨੇਹਾ_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", ਸੁਨੇਹਾ_len);
	sshbuf_reset(m);
	ਜੇ ((r = sshbuf_reserve(m, ਸੁਨੇਹਾ_len, &p)) != 0)
		fatal_fr(r, "reserve");
	ਜੇ (atomicio(ਪਠ, sock, p, ਸੁਨੇਹਾ_len) != ਸੁਨੇਹਾ_len) {
		oerrno = errno;
		error_f("read: %s", strerror(errno));
		ਜੇ (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

ਖਾਲੀ
mm_request_receive_expect(ਪੂਰਨ sock, ਗਿਣਤੀ monitor_reqtype type, ਬਣਤਰ sshbuf *m)
{
	u_char rtype;
	ਪੂਰਨ r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	ਜੇ ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	ਜੇ (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
DH *
mm_ਚੁਣੋ_dh(ਪੂਰਨ min, ਪੂਰਨ nbits, ਪੂਰਨ max)
{
	BIGNUM *p, *g;
	ਪੂਰਨ r;
	u_char success = 0;
	ਬਣਤਰ sshbuf *m;

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	ਜੇ ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ਜੇ (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

	ਜੇ ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	ਵਾਪਸ (dh_new_ਸਮੂਹ(g, p));
}
#ਜੇ_ਅੰਤ

ਖਾਲੀ
mm_sshkey_setcompat(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ sshbuf *m;
	ਪੂਰਨ r;

	debug3_f("entering");
	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

ਪੂਰਨ
mm_sshkey_sign(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshkey *ਕੁੰਜੀ, u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen, ਅਚਲ ਅੱਖਰ *hostkey_alg,
    ਅਚਲ ਅੱਖਰ *sk_provider, ਅਚਲ ਅੱਖਰ *sk_pin, u_int compat)
{
	ਬਣਤਰ sshbuf *m;
	ਪੂਰਨ r;

	debug3_f("entering");
	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshkey_puts(ਕੁੰਜੀ, m)) != 0 ||
	    (r = sshbuf_put_string(m, ਅੰਕੜੇ, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	ਜੇ ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	debug3_f("%s signature len=%zu", hostkey_alg ? hostkey_alg : "(null)",
	    *lenp);

	ਵਾਪਸ (0);
}

ਖਾਲੀ
mm_decode_activate_server_options(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshbuf *m)
{
	ਬਣਤਰ sshbuf *config;
	ਪੂਰਨ r;
	u_int i;

	ਜੇ ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	ਜੇ ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	ਲਈ (i = 0; i < options.ਅੰਕ_log_verbose; i++)
		log_verbose_ਜੋੜੋ(options.log_verbose[i]);
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ GETPW(b, id) \
	ਕਰੋ { \
		ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		ਜੇ (len != ਆਕਾਰ(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(&pw->id, p, len); \
	} ਜਦੋਂ (0)

ਬਣਤਰ passwd *
mm_getpwnamallow(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *username)
{
	ਬਣਤਰ sshbuf *m;
	ਬਣਤਰ passwd *pw;
	ਮਾਪ_t len;
	ਪੂਰਨ r;
	u_char ok;
	ਅਚਲ u_char *p;

	debug3_f("entering");

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	ਜੇ ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	ਜੇ (ok == 0) {
		pw = ਨਿਰਾ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(ਆਕਾਰ(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#ਜੇ_ਅੰਤ
	ਜੇ ((r = sshbuf_get_cstring(m, &pw->pw_name, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, ਨਿਰਾ)) != 0 ||
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, ਨਿਰਾ)) != 0 ||
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(m, &pw->pw_class, ਨਿਰਾ)) != 0 ||
#ਜੇ_ਅੰਤ
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse pw");

ਬਾਹਰਲਾ:
	/* copy options block as a Match directive may have changed some */
	mm_decode_activate_server_options(ssh, m);
	server_process_permitopen(ssh);
	server_process_channel_timeouts(ssh);
	channel_ਸੈੱਟ_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	kex_ਸੈੱਟ_server_sig_algs(ssh, options.pubkey_accepted_algos);
	kex_ਸੈੱਟ_warn_weak_crypto(ssh, options.warn_weak_crypto);
	ssh_packet_ਸੈੱਟ_rekey_limits(ssh, options.rekey_ਹੱਦਬੰਦੀ,
	    options.rekey_interval);
	sshbuf_free(m);

	ਵਾਪਸ (pw);
}

ਅੱਖਰ *
mm_auth2_read_banner(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *m;
	ਅੱਖਰ *banner;
	ਪੂਰਨ r;

	debug3_f("entering");

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	ਜੇ ((r = sshbuf_get_cstring(m, &banner, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	ਜੇ (ਲੜੀ_ਲੰਬਾਈ(banner) == 0) {
		ਮੁਕਤ(banner);
		banner = ਨਿਰਾ;
	}
	ਵਾਪਸ (banner);
}

/* Inform the privileged process about service and style */

ਖਾਲੀ
mm_inform_authserv(ਅੱਖਰ *service, ਅੱਖਰ *style)
{
	ਬਣਤਰ sshbuf *m;
	ਪੂਰਨ r;

	debug3_f("entering");

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
ਪੂਰਨ
mm_auth_password(ਬਣਤਰ ssh *ssh, ਅੱਖਰ *password)
{
	ਬਣਤਰ sshbuf *m;
	ਪੂਰਨ r, authenticated = 0;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	u_int maxtries = 0;
#ਜੇ_ਅੰਤ

	debug3_f("entering");

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	ਜੇ ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	ਜੇ ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	ਜੇ (maxtries > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		fatal_fr(r, "bad maxtries");
	sshpam_ਸੈੱਟ_maxtries_reached(maxtries);
#ਜੇ_ਅੰਤ

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	ਵਾਪਸ (authenticated);
}

ਪੂਰਨ
mm_user_ਕੁੰਜੀ_allowed(ਬਣਤਰ ssh *ssh, ਬਣਤਰ passwd *pw, ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਪੂਰਨ pubkey_auth_attempt, ਬਣਤਰ sshauthopt **authoptp)
{
	ਵਾਪਸ (mm_ਕੁੰਜੀ_allowed(MM_USERKEY, ਨਿਰਾ, ਨਿਰਾ, ਕੁੰਜੀ,
	    pubkey_auth_attempt, authoptp));
}

ਪੂਰਨ
mm_hostbased_ਕੁੰਜੀ_allowed(ਬਣਤਰ ssh *ssh, ਬਣਤਰ passwd *pw,
    ਅਚਲ ਅੱਖਰ *user, ਅਚਲ ਅੱਖਰ *host, ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਵਾਪਸ (mm_ਕੁੰਜੀ_allowed(MM_HOSTKEY, user, host, ਕੁੰਜੀ, 0, ਨਿਰਾ));
}

ਪੂਰਨ
mm_ਕੁੰਜੀ_allowed(ਗਿਣਤੀ mm_keytype type, ਅਚਲ ਅੱਖਰ *user, ਅਚਲ ਅੱਖਰ *host,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਪੂਰਨ pubkey_auth_attempt, ਬਣਤਰ sshauthopt **authoptp)
{
	ਬਣਤਰ sshbuf *m;
	ਪੂਰਨ r, allowed = 0;
	ਬਣਤਰ sshauthopt *opts = ਨਿਰਾ;

	debug3_f("entering");

	ਜੇ (authoptp != ਨਿਰਾ)
		*authoptp = ਨਿਰਾ;

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshkey_puts(ਕੁੰਜੀ, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	ਜੇ ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal_fr(r, "parse");
	ਜੇ (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	ਜੇ (authoptp != ਨਿਰਾ) {
		*authoptp = opts;
		opts = ਨਿਰਾ;
	}
	sshauthopt_free(opts);

	ਵਾਪਸ allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

ਪੂਰਨ
mm_sshkey_verify(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ u_char *sig, ਮਾਪ_t siglen,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen, ਅਚਲ ਅੱਖਰ *sigalg, u_int compat,
    ਬਣਤਰ sshkey_sig_details **sig_detailsp)
{
	ਬਣਤਰ sshbuf *m;
	u_int encoded_ret = 0;
	ਪੂਰਨ r;
	u_char sig_details_present, flags;
	u_int counter;

	debug3_f("entering");

	ਜੇ (sig_detailsp != ਨਿਰਾ)
		*sig_detailsp = ਨਿਰਾ;
	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshkey_puts(ਕੁੰਜੀ, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, ਅੰਕੜੇ, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == ਨਿਰਾ ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	ਜੇ ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	ਜੇ (sig_details_present && encoded_ret == 0) {
		ਜੇ ((r = sshbuf_get_u32(m, &counter)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		ਜੇ (sig_detailsp != ਨਿਰਾ) {
			*sig_detailsp = xcalloc(1, ਆਕਾਰ(**sig_detailsp));
			(*sig_detailsp)->sk_counter = counter;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	ਜੇ (encoded_ret != 0)
		ਵਾਪਸ SSH_ERR_SIGNATURE_INVALID;
	ਵਾਪਸ 0;
}

ਖਾਲੀ
mm_send_keystate(ਬਣਤਰ ssh *ssh, ਬਣਤਰ monitor *monitor)
{
	ਬਣਤਰ sshbuf *m;
	ਪੂਰਨ r;

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

ਪੂਰਨ
mm_pty_allocate(ਪੂਰਨ *ptyfd, ਪੂਰਨ *ttyfd, ਅੱਖਰ *namebuf, ਮਾਪ_t namebuflen)
{
	ਬਣਤਰ sshbuf *m;
	ਅੱਖਰ *p, *ਸੁਨੇਹਾ;
	ਪੂਰਨ success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	ਜੇ ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		ਜੇ (tmp1 >= 0)
			close(tmp1);
		ਵਾਪਸ 0;
	}
	close(tmp1);
	close(tmp2);

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	ਜੇ ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ਜੇ (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		ਵਾਪਸ (0);
	}
	ਜੇ ((r = sshbuf_get_cstring(m, &p, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &ਸੁਨੇਹਾ, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	ਮੁਕਤ(p);

	ਜੇ ((r = sshbuf_put(loginmsg, ਸੁਨੇਹਾ, ਲੜੀ_ਲੰਬਾਈ(ਸੁਨੇਹਾ))) != 0)
		fatal_fr(r, "put loginmsg");
	ਮੁਕਤ(ਸੁਨੇਹਾ);

	ਜੇ ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	ਵਾਪਸ (1);
}

ਖਾਲੀ
mm_session_pty_cleanup2(Session *s)
{
	ਬਣਤਰ sshbuf *m;
	ਪੂਰਨ r;

	ਜੇ (s->ttyfd == -1)
		ਵਾਪਸ;
	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assmble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	ਜੇ (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
ਖਾਲੀ
mm_ਸ਼ੁਰੂ_pam(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ sshbuf *m;

	debug3_f("entering");
	ਜੇ (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ਸ਼ੁਰੂ, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *m;
	u_int ret;
	ਅੱਖਰ *ਸੁਨੇਹਾ;
	ਮਾਪ_t msglen;
	ਪੂਰਨ r;

	debug3_f("entering");
	ਜੇ (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	ਜੇ ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &ਸੁਨੇਹਾ, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, ਸੁਨੇਹਾ, msglen)) != 0)
		fatal_fr(r, "buffer error");

	ਮੁਕਤ(ਸੁਨੇਹਾ);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	ਵਾਪਸ (ret);
}

ਖਾਲੀ *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	ਬਣਤਰ sshbuf *m;
	ਪੂਰਨ r, success;

	debug3_f("entering");
	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	ਜੇ ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "buffer error");
	ਜੇ (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		ਵਾਪਸ (ਨਿਰਾ);
	}
	sshbuf_free(m);
	ਵਾਪਸ (authctxt);
}

ਪੂਰਨ
mm_sshpam_query(ਖਾਲੀ *ctx, ਅੱਖਰ **name, ਅੱਖਰ **info,
    u_int *ਅੰਕ, ਅੱਖਰ ***prompts, u_int **echo_on)
{
	ਬਣਤਰ sshbuf *m;
	u_int i, n;
	ਪੂਰਨ r, ret;

	debug3_f("entering");
	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	ਜੇ ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, ਅੰਕ)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_ਸੈੱਟ_maxtries_reached(n);
	ਜੇ (*ਅੰਕ > PAM_MAX_ਅੰਕ_ਸੁਨੇਹਾ)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *ਅੰਕ, PAM_MAX_ਅੰਕ_ਸੁਨੇਹਾ);
	*prompts = xcalloc((*ਅੰਕ + 1), ਆਕਾਰ(ਅੱਖਰ *));
	*echo_on = xcalloc((*ਅੰਕ + 1), ਆਕਾਰ(u_int));
	ਲਈ (i = 0; i < *ਅੰਕ; ++i) {
		ਜੇ ((r = sshbuf_get_cstring(m, &((*prompts)[i]), ਨਿਰਾ)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	ਵਾਪਸ (ret);
}

ਪੂਰਨ
mm_sshpam_respond(ਖਾਲੀ *ctx, u_int ਅੰਕ, ਅੱਖਰ **resp)
{
	ਬਣਤਰ sshbuf *m;
	u_int n, i;
	ਪੂਰਨ r, ret;

	debug3_f("entering");
	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u32(m, ਅੰਕ)) != 0)
		fatal_fr(r, "buffer error");
	ਲਈ (i = 0; i < ਅੰਕ; ++i) {
		ਜੇ ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	ਜੇ ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	ret = (ਪੂਰਨ)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	ਵਾਪਸ (ret);
}

ਖਾਲੀ
mm_sshpam_free_ctx(ਖਾਲੀ *ctxtp)
{
	ਬਣਤਰ sshbuf *m;

	debug3_f("entering");
	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_FREE_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_FREE_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_FREE_CTX, m);
	sshbuf_free(m);
}
#ਜੇ_ਅੰਤ /* USE_PAM */

/* Request process termination */

ਖਾਲੀ
mm_terminate(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *m;

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_ਪਦ, m);
	sshbuf_free(m);
}

/* Request state information */

ਖਾਲੀ
mm_get_state(ਬਣਤਰ ssh *ssh,
    ServerOptions *opts, ਬਣਤਰ sshbuf **confdatap,
    uint64_t *timing_secretp,
    ਬਣਤਰ sshbuf **hostkeysp, ਬਣਤਰ sshbuf **keystatep,
    u_char **pw_namep,
    ਬਣਤਰ sshbuf **authinfop, ਬਣਤਰ sshbuf **auth_optsp)
{
	ਬਣਤਰ sshbuf *m, *config;
	ਪੂਰਨ r;

	debug3_f("entering");

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ || (config = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	ਜੇ ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_ਸੰਸਕਰਣ)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_ਸੰਸਕਰਣ)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	ਜੇ (confdatap) {
		ਜੇ ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, ਨਿਰਾ)) != 0 ||
		    (r = sshbuf_froms(m, authinfop)) != 0 ||
		    (r = sshbuf_froms(m, auth_optsp)) != 0)
			fatal_fr(r, "parse config postauth");
	}
	ਜੇ ((r = deserialise_server_options(config, opts)) != 0)
		fatal_fr(r, "deserialise_server_options");

	sshbuf_free(m);
	sshbuf_free(config);

	debug3_f("done");
}

ਸਥਿਰ ਖਾਲੀ
mm_chall_ਤਿਆਰੀ(ਅੱਖਰ **name, ਅੱਖਰ **infotxt, u_int *numprompts,
    ਅੱਖਰ ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, ਆਕਾਰ(ਅੱਖਰ *));
	*echo_on = xcalloc(*numprompts, ਆਕਾਰ(u_int));
	(*echo_on)[0] = 0;
}

ਪੂਰਨ
mm_bsdauth_query(ਖਾਲੀ *ctx, ਅੱਖਰ **name, ਅੱਖਰ **infotxt,
   u_int *numprompts, ਅੱਖਰ ***prompts, u_int **echo_on)
{
	ਬਣਤਰ sshbuf *m;
	u_int success;
	ਅੱਖਰ *challenge;
	ਪੂਰਨ r;

	debug3_f("entering");

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	ਜੇ ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ਜੇ (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		ਵਾਪਸ (-1);
	}

	/* Get the challenge, and format the response */
	ਜੇ ((r = sshbuf_get_cstring(m, &challenge, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_ਤਿਆਰੀ(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	ਵਾਪਸ (0);
}

ਪੂਰਨ
mm_bsdauth_respond(ਖਾਲੀ *ctx, u_int numresponses, ਅੱਖਰ **responses)
{
	ਬਣਤਰ sshbuf *m;
	ਪੂਰਨ r, authok;

	debug3_f("entering");
	ਜੇ (numresponses != 1)
		ਵਾਪਸ (-1);

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	ਜੇ ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	ਵਾਪਸ ((authok == 0) ? -1 : 0);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS
ਖਾਲੀ
mm_audit_event(ਬਣਤਰ ssh *ssh, ssh_audit_event_t event)
{
	ਬਣਤਰ sshbuf *m;
	ਪੂਰਨ r;

	debug3_f("entering");

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

ਖਾਲੀ
mm_audit_ਲੜੀਵਾਰ_command(ਅਚਲ ਅੱਖਰ *command)
{
	ਬਣਤਰ sshbuf *m;
	ਪੂਰਨ r;

	debug3_f("entering command %s", command);

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#ਜੇ_ਅੰਤ /* SSH_AUDIT_EVENTS */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	ਬਣਤਰ sshbuf *m;
	OM_uint32 major;
	ਪੂਰਨ r;

	/* Client doesn't get to see the context */
	*ctx = ਨਿਰਾ;

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_string(m, goid->elements, goid->ਲੰਮਾਈ)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	ਜੇ ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	ਵਾਪਸ (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_ਬਫਰ_desc *ਵਿੱਚ,
    gss_ਬਫਰ_desc *ਬਾਹਰਲਾ, OM_uint32 *flagsp)
{
	ਬਣਤਰ sshbuf *m;
	OM_uint32 major;
	u_int flags;
	ਪੂਰਨ r;

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_string(m, ਵਿੱਚ->ਮੁੱਲ, ਵਿੱਚ->ਲੰਮਾਈ)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	ਜੇ ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_ਬਫਰ_desc(m, ਬਾਹਰਲਾ)) != 0)
		fatal_fr(r, "parse");
	ਜੇ (flagsp != ਨਿਰਾ) {
		ਜੇ ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	ਵਾਪਸ (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_ਬਫਰ_t gssbuf, gss_ਬਫਰ_t gssmic)
{
	ਬਣਤਰ sshbuf *m;
	OM_uint32 major;
	ਪੂਰਨ r;

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_string(m, gssbuf->ਮੁੱਲ, gssbuf->ਲੰਮਾਈ)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->ਮੁੱਲ, gssmic->ਲੰਮਾਈ)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	ਜੇ ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	ਵਾਪਸ(major);
}

ਪੂਰਨ
mm_ssh_gssapi_userok(ਅੱਖਰ *user)
{
	ਬਣਤਰ sshbuf *m;
	ਪੂਰਨ r, authenticated = 0;

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	ਜੇ ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	ਵਾਪਸ (authenticated);
}
#ਜੇ_ਅੰਤ /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
ਸਥਿਰ ਖਾਲੀ
server_process_permitopen_list(ਬਣਤਰ ssh *ssh, ਪੂਰਨ listen,
    ਅੱਖਰ **opens, u_int ਅੰਕ_opens)
{
	u_int i;
	ਪੂਰਨ ਪੋਰਟ;
	ਅੱਖਰ *host, *arg, *oarg;
	ਪੂਰਨ where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	ਅਚਲ ਅੱਖਰ *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	ਜੇ (ਅੰਕ_opens == 0)
		ਵਾਪਸ; /* permit any */

	/* handle keywords: "any" / "none" */
	ਜੇ (ਅੰਕ_opens == 1 && strcmp(opens[0], "any") == 0)
		ਵਾਪਸ;
	ਜੇ (ਅੰਕ_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		ਵਾਪਸ;
	}
	/* Otherwise treat it as a list of permitted host:port */
	ਲਈ (i = 0; i < ਅੰਕ_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		ਜੇ (host == ਨਿਰਾ)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		ਜੇ (arg == ਨਿਰਾ || ((ਪੋਰਟ = permitopen_ਪੋਰਟ(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_ਜੋੜੋ_permission(ssh, FORWARD_ADM,
		    where, host, ਪੋਰਟ);
		ਮੁਕਤ(oarg);
	}
}

/*
 * Inform channels layer of permitopen options from configuration.
 */
ਖਾਲੀ
server_process_permitopen(ਬਣਤਰ ssh *ssh)
{
	server_process_permitopen_list(ssh, 0,
	    options.permitted_opens, options.ਅੰਕ_permitted_opens);
	server_process_permitopen_list(ssh, 1,
	    options.permitted_listens, options.ਅੰਕ_permitted_listens);
}

ਖਾਲੀ
server_process_channel_timeouts(ਬਣਤਰ ssh *ssh)
{
	u_int i;
	ਦੁੱਗਣਾ secs;
	ਅੱਖਰ *type;

	debug3_f("setting %u timeouts", options.ਅੰਕ_channel_timeouts);
	channel_clear_timeouts(ssh);
	ਲਈ (i = 0; i < options.ਅੰਕ_channel_timeouts; i++) {
		ਜੇ (parse_ਨਮੂਨਾ_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_ਜੋੜੋ_timeout(ssh, type, secs);
		ਮੁਕਤ(type);
	}
}

ਬਣਤਰ connection_info *
server_get_connection_info(ਬਣਤਰ ssh *ssh, ਪੂਰਨ populate, ਪੂਰਨ use_dns)
{
	ਸਥਿਰ ਬਣਤਰ connection_info ci;

	ਜੇ (ssh == ਨਿਰਾ || !populate)
		ਵਾਪਸ &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.ਪਤਾ = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_ਪੋਰਟ(ssh);
	ci.rdomain = ssh_packet_rdomain_ਵਿੱਚ(ssh);
	ਵਾਪਸ &ci;
}

