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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/uio.h>
#ضمن <sys/queue.h>
#ضمن <sys/wait.h>

#ضمن <errno.h>
#ضمن <pwd.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ifdef WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/dh.h>
#ضمن <openssl/evp.h>
#endif

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ifdef WITH_OPENSSL
#ضمن "dh.h"
#endif
#ضمن "sshbuf.h"
#ضمن "sshkey.h"
#ضمن "cipher.h"
#ضمن "kex.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "auth-options.h"
#ضمن "packet.h"
#ضمن "mac.h"
#ضمن "log.h"
#ضمن "auth-pam.h"
#ضمن "monitor.h"
#ifdef GSSAPI
#ضمن "ssh-gss.h"
#endif
#ضمن "atomicio.h"
#ضمن "monitor_fdpass.h"
#ضمن "misc.h"

#ضمن "channels.h"
#ضمن "session.h"
#ضمن "servconf.h"
#ضمن "monitor_wrap.h"
#ضمن "srclimit.h"

#ضمن "ssherr.h"

/* Imports */
خارجي بنية monitor *pmonitor;
خارجي بنية sshbuf *loginmsg;
خارجي ServerOptions options;

فراغ
mm_log_handler(LogLevel level, صحيح forced, ثابت حرف *سكو, فراغ *ctx)
{
	بنية sshbuf *log_سكو;
	بنية monitor *mon = (بنية monitor *)ctx;
	صحيح r;
	size_t len;

	إذا (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	إذا ((log_سكو = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	إذا ((r = sshbuf_put_u32(log_سكو, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_سكو, level)) != 0 ||
	    (r = sshbuf_put_u32(log_سكو, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_سكو, سكو)) != 0)
		fatal_fr(r, "assemble");
	إذا ((len = sshbuf_len(log_سكو)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_سكو), len - 4);
	إذا (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_سكو), len) != len) {
		إذا (errno == EPIPE) {
			debug_f("write: %s", strerror(errno));
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
	sshbuf_free(log_سكو);
}

ساكن فراغ
mm_reap(فراغ)
{
	صحيح status = -1;

	إذا (!mm_is_monitor())
		أرجع;
	طالما (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		إذا (errno == EINTR)
			استمر;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", strerror(errno));
	}
	إذا (WIFEXITED(status)) {
		إذا (WEXITSTATUS(status) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(status));
			cleanup_exit(255);
		}
	} وإلا إذا (WIFSIGNALED(status)) {
		error_f("child terminated by signal %d",
		    WTERMSIG(status));
		cleanup_exit(signal_is_crash(WTERMSIG(status)) ?
		    EXIT_CHILD_CRASH : 255);
	} وإلا {
		error_f("child terminated abnormally (status=0x%x)",
		    status);
		cleanup_exit(EXIT_CHILD_CRASH);
	}
}

فراغ
mm_request_send(صحيح sock, تعداد monitor_reqtype type, بنية sshbuf *m)
{
	size_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	إذا (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	إذا (atomicio(vwrite, sock, buf, حجم(buf)) != حجم(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		إذا (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
}

فراغ
mm_request_receive(صحيح sock, بنية sshbuf *m)
{
	u_char buf[4], *p = عدم;
	u_int سكو_len;
	صحيح oerrno, r;

	debug3_f("entering");

	إذا (atomicio(اقرأ, sock, buf, حجم(buf)) != حجم(buf)) {
		إذا (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", strerror(errno));
	}
	سكو_len = PEEK_U32(buf);
	إذا (سكو_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", سكو_len);
	sshbuf_reset(m);
	إذا ((r = sshbuf_reserve(m, سكو_len, &p)) != 0)
		fatal_fr(r, "reserve");
	إذا (atomicio(اقرأ, sock, p, سكو_len) != سكو_len) {
		oerrno = errno;
		error_f("read: %s", strerror(errno));
		إذا (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

فراغ
mm_request_receive_expect(صحيح sock, تعداد monitor_reqtype type, بنية sshbuf *m)
{
	u_char rtype;
	صحيح r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	إذا ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	إذا (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(صحيح min, صحيح nbits, صحيح max)
{
	BIGNUM *p, *g;
	صحيح r;
	u_char success = 0;
	بنية sshbuf *m;

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	إذا ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	إذا (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

	إذا ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	أرجع (dh_new_group(g, p));
}
#endif

فراغ
mm_sshkey_setcompat(بنية ssh *ssh)
{
	بنية sshbuf *m;
	صحيح r;

	debug3_f("entering");
	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

صحيح
mm_sshkey_sign(بنية ssh *ssh, بنية sshkey *مبودي, u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen, ثابت حرف *hostkey_alg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	بنية sshbuf *m;
	صحيح r;

	debug3_f("entering");
	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshkey_puts(مبودي, m)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	إذا ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	debug3_f("%s signature len=%zu", hostkey_alg ? hostkey_alg : "(null)",
	    *lenp);

	أرجع (0);
}

فراغ
mm_decode_activate_server_options(بنية ssh *ssh, بنية sshbuf *m)
{
	بنية sshbuf *config;
	صحيح r;
	u_int i;

	إذا ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	إذا ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	لكل (i = 0; i < options.لمب_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
}

#define GETPW(b, id) \
	افعل { \
		إذا ((r = sshbuf_get_string_direct(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		إذا (len != حجم(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		memcpy(&pw->id, p, len); \
	} طالما (0)

بنية passwd *
mm_getpwnamallow(بنية ssh *ssh, ثابت حرف *username)
{
	بنية sshbuf *m;
	بنية passwd *pw;
	size_t len;
	صحيح r;
	u_char ok;
	ثابت u_char *p;

	debug3_f("entering");

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	إذا ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	إذا (ok == 0) {
		pw = عدم;
		اذهب out;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(حجم(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#endif
	إذا ((r = sshbuf_get_cstring(m, &pw->pw_name, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, عدم)) != 0 ||
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, عدم)) != 0 ||
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(m, &pw->pw_class, عدم)) != 0 ||
#endif
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, عدم)) != 0)
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

	أرجع (pw);
}

حرف *
mm_auth2_read_banner(فراغ)
{
	بنية sshbuf *m;
	حرف *banner;
	صحيح r;

	debug3_f("entering");

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	إذا ((r = sshbuf_get_cstring(m, &banner, عدم)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	إذا (strlen(banner) == 0) {
		حرر(banner);
		banner = عدم;
	}
	أرجع (banner);
}

/* Inform the privileged process about service and style */

فراغ
mm_inform_authserv(حرف *service, حرف *style)
{
	بنية sshbuf *m;
	صحيح r;

	debug3_f("entering");

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
صحيح
mm_auth_password(بنية ssh *ssh, حرف *password)
{
	بنية sshbuf *m;
	صحيح r, authenticated = 0;
#ifdef USE_PAM
	u_int maxtries = 0;
#endif

	debug3_f("entering");

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	إذا ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#ifdef USE_PAM
	إذا ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	إذا (maxtries > INT_MAX)
		fatal_fr(r, "bad maxtries");
	sshpam_set_maxtries_reached(maxtries);
#endif

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	أرجع (authenticated);
}

صحيح
mm_user_مبودي_allowed(بنية ssh *ssh, بنية passwd *pw, بنية sshkey *مبودي,
    صحيح pubkey_auth_attempt, بنية sshauthopt **authoptp)
{
	أرجع (mm_مبودي_allowed(MM_USERKEY, عدم, عدم, مبودي,
	    pubkey_auth_attempt, authoptp));
}

صحيح
mm_hostbased_مبودي_allowed(بنية ssh *ssh, بنية passwd *pw,
    ثابت حرف *user, ثابت حرف *host, بنية sshkey *مبودي)
{
	أرجع (mm_مبودي_allowed(MM_HOSTKEY, user, host, مبودي, 0, عدم));
}

صحيح
mm_مبودي_allowed(تعداد mm_keytype type, ثابت حرف *user, ثابت حرف *host,
    بنية sshkey *مبودي, صحيح pubkey_auth_attempt, بنية sshauthopt **authoptp)
{
	بنية sshbuf *m;
	صحيح r, allowed = 0;
	بنية sshauthopt *opts = عدم;

	debug3_f("entering");

	إذا (authoptp != عدم)
		*authoptp = عدم;

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshkey_puts(مبودي, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	إذا ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal_fr(r, "parse");
	إذا (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	إذا (authoptp != عدم) {
		*authoptp = opts;
		opts = عدم;
	}
	sshauthopt_free(opts);

	أرجع allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

صحيح
mm_sshkey_verify(ثابت بنية sshkey *مبودي, ثابت u_char *sig, size_t siglen,
    ثابت u_char *data, size_t datalen, ثابت حرف *sigalg, u_int compat,
    بنية sshkey_sig_details **sig_detailsp)
{
	بنية sshbuf *m;
	u_int encoded_ret = 0;
	صحيح r;
	u_char sig_details_present, flags;
	u_int counter;

	debug3_f("entering");

	إذا (sig_detailsp != عدم)
		*sig_detailsp = عدم;
	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshkey_puts(مبودي, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == عدم ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	إذا ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	إذا (sig_details_present && encoded_ret == 0) {
		إذا ((r = sshbuf_get_u32(m, &counter)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		إذا (sig_detailsp != عدم) {
			*sig_detailsp = xcalloc(1, حجم(**sig_detailsp));
			(*sig_detailsp)->sk_counter = counter;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	إذا (encoded_ret != 0)
		أرجع SSH_ERR_SIGNATURE_INVALID;
	أرجع 0;
}

فراغ
mm_send_keystate(بنية ssh *ssh, بنية monitor *monitor)
{
	بنية sshbuf *m;
	صحيح r;

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

صحيح
mm_pty_allocate(صحيح *ptyfd, صحيح *ttyfd, حرف *namebuf, size_t namebuflen)
{
	بنية sshbuf *m;
	حرف *p, *سكو;
	صحيح success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	إذا ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		إذا (tmp1 >= 0)
			close(tmp1);
		أرجع 0;
	}
	close(tmp1);
	close(tmp2);

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	إذا ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	إذا (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		أرجع (0);
	}
	إذا ((r = sshbuf_get_cstring(m, &p, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(m, &سكو, عدم)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	حرر(p);

	إذا ((r = sshbuf_put(loginmsg, سكو, strlen(سكو))) != 0)
		fatal_fr(r, "put loginmsg");
	حرر(سكو);

	إذا ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	أرجع (1);
}

فراغ
mm_session_pty_cleanup2(Session *s)
{
	بنية sshbuf *m;
	صحيح r;

	إذا (s->ttyfd == -1)
		أرجع;
	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assmble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	إذا (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#ifdef USE_PAM
فراغ
mm_start_pam(بنية ssh *ssh)
{
	بنية sshbuf *m;

	debug3_f("entering");
	إذا (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_START, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(فراغ)
{
	بنية sshbuf *m;
	u_int ret;
	حرف *سكو;
	size_t msglen;
	صحيح r;

	debug3_f("entering");
	إذا (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	إذا ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &سكو, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, سكو, msglen)) != 0)
		fatal_fr(r, "buffer error");

	حرر(سكو);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	أرجع (ret);
}

فراغ *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	بنية sshbuf *m;
	صحيح r, success;

	debug3_f("entering");
	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	إذا ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "buffer error");
	إذا (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		أرجع (عدم);
	}
	sshbuf_free(m);
	أرجع (authctxt);
}

صحيح
mm_sshpam_query(فراغ *ctx, حرف **name, حرف **info,
    u_int *لمب, حرف ***prompts, u_int **echo_on)
{
	بنية sshbuf *m;
	u_int i, n;
	صحيح r, ret;

	debug3_f("entering");
	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	إذا ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, عدم)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, لمب)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_set_maxtries_reached(n);
	إذا (*لمب > PAM_MAX_لمب_سكو)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *لمب, PAM_MAX_لمب_سكو);
	*prompts = xcalloc((*لمب + 1), حجم(حرف *));
	*echo_on = xcalloc((*لمب + 1), حجم(u_int));
	لكل (i = 0; i < *لمب; ++i) {
		إذا ((r = sshbuf_get_cstring(m, &((*prompts)[i]), عدم)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	أرجع (ret);
}

صحيح
mm_sshpam_respond(فراغ *ctx, u_int لمب, حرف **resp)
{
	بنية sshbuf *m;
	u_int n, i;
	صحيح r, ret;

	debug3_f("entering");
	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u32(m, لمب)) != 0)
		fatal_fr(r, "buffer error");
	لكل (i = 0; i < لمب; ++i) {
		إذا ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	إذا ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	ret = (صحيح)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	أرجع (ret);
}

فراغ
mm_sshpam_free_ctx(فراغ *ctxtp)
{
	بنية sshbuf *m;

	debug3_f("entering");
	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_FREE_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_FREE_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_FREE_CTX, m);
	sshbuf_free(m);
}
#endif /* USE_PAM */

/* Request process termination */

فراغ
mm_terminate(فراغ)
{
	بنية sshbuf *m;

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_TERM, m);
	sshbuf_free(m);
}

/* Request state information */

فراغ
mm_get_state(بنية ssh *ssh,
    ServerOptions *opts, بنية sshbuf **confdatap,
    uint64_t *timing_secretp,
    بنية sshbuf **hostkeysp, بنية sshbuf **keystatep,
    u_char **pw_namep,
    بنية sshbuf **authinfop, بنية sshbuf **auth_optsp)
{
	بنية sshbuf *m, *config;
	صحيح r;

	debug3_f("entering");

	إذا ((m = sshbuf_new()) == عدم || (config = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	إذا ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	إذا (confdatap) {
		إذا ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, عدم)) != 0 ||
		    (r = sshbuf_froms(m, authinfop)) != 0 ||
		    (r = sshbuf_froms(m, auth_optsp)) != 0)
			fatal_fr(r, "parse config postauth");
	}
	إذا ((r = deserialise_server_options(config, opts)) != 0)
		fatal_fr(r, "deserialise_server_options");

	sshbuf_free(m);
	sshbuf_free(config);

	debug3_f("done");
}

ساكن فراغ
mm_chall_setup(حرف **name, حرف **infotxt, u_int *numprompts,
    حرف ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, حجم(حرف *));
	*echo_on = xcalloc(*numprompts, حجم(u_int));
	(*echo_on)[0] = 0;
}

صحيح
mm_bsdauth_query(فراغ *ctx, حرف **name, حرف **infotxt,
   u_int *numprompts, حرف ***prompts, u_int **echo_on)
{
	بنية sshbuf *m;
	u_int success;
	حرف *challenge;
	صحيح r;

	debug3_f("entering");

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	إذا ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	إذا (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		أرجع (-1);
	}

	/* Get the challenge, and format the response */
	إذا ((r = sshbuf_get_cstring(m, &challenge, عدم)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_setup(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	أرجع (0);
}

صحيح
mm_bsdauth_respond(فراغ *ctx, u_int numresponses, حرف **responses)
{
	بنية sshbuf *m;
	صحيح r, authok;

	debug3_f("entering");
	إذا (numresponses != 1)
		أرجع (-1);

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	إذا ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	أرجع ((authok == 0) ? -1 : 0);
}

#ifdef SSH_AUDIT_EVENTS
فراغ
mm_audit_event(بنية ssh *ssh, ssh_audit_event_t event)
{
	بنية sshbuf *m;
	صحيح r;

	debug3_f("entering");

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

فراغ
mm_audit_run_command(ثابت حرف *command)
{
	بنية sshbuf *m;
	صحيح r;

	debug3_f("entering command %s", command);

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#endif /* SSH_AUDIT_EVENTS */

#ifdef GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	بنية sshbuf *m;
	OM_uint32 major;
	صحيح r;

	/* Client doesn't get to see the context */
	*ctx = عدم;

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_string(m, goid->elements, goid->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	إذا ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	أرجع (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *in,
    gss_buffer_desc *out, OM_uint32 *flagsp)
{
	بنية sshbuf *m;
	OM_uint32 major;
	u_int flags;
	صحيح r;

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_string(m, in->درج, in->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	إذا ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, out)) != 0)
		fatal_fr(r, "parse");
	إذا (flagsp != عدم) {
		إذا ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	أرجع (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	بنية sshbuf *m;
	OM_uint32 major;
	صحيح r;

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_string(m, gssbuf->درج, gssbuf->length)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->درج, gssmic->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	إذا ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	أرجع(major);
}

صحيح
mm_ssh_gssapi_userok(حرف *user)
{
	بنية sshbuf *m;
	صحيح r, authenticated = 0;

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	إذا ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	أرجع (authenticated);
}
#endif /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
ساكن فراغ
server_process_permitopen_list(بنية ssh *ssh, صحيح listen,
    حرف **opens, u_int لمب_opens)
{
	u_int i;
	صحيح port;
	حرف *host, *arg, *oarg;
	صحيح where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	ثابت حرف *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	إذا (لمب_opens == 0)
		أرجع; /* permit any */

	/* handle keywords: "any" / "none" */
	إذا (لمب_opens == 1 && strcmp(opens[0], "any") == 0)
		أرجع;
	إذا (لمب_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		أرجع;
	}
	/* Otherwise treat it as a list of permitted host:port */
	لكل (i = 0; i < لمب_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		إذا (host == عدم)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		إذا (arg == عدم || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, host, port);
		حرر(oarg);
	}
}

/*
 * Inform channels layer of permitopen options from configuration.
 */
فراغ
server_process_permitopen(بنية ssh *ssh)
{
	server_process_permitopen_list(ssh, 0,
	    options.permitted_opens, options.لمب_permitted_opens);
	server_process_permitopen_list(ssh, 1,
	    options.permitted_listens, options.لمب_permitted_listens);
}

فراغ
server_process_channel_timeouts(بنية ssh *ssh)
{
	u_int i;
	مزدوج secs;
	حرف *type;

	debug3_f("setting %u timeouts", options.لمب_channel_timeouts);
	channel_clear_timeouts(ssh);
	لكل (i = 0; i < options.لمب_channel_timeouts; i++) {
		إذا (parse_pattern_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_add_timeout(ssh, type, secs);
		حرر(type);
	}
}

بنية connection_info *
server_get_connection_info(بنية ssh *ssh, صحيح populate, صحيح use_dns)
{
	ساكن بنية connection_info ci;

	إذا (ssh == عدم || !populate)
		أرجع &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.address = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_port(ssh);
	ci.rdomain = ssh_packet_rdomain_in(ssh);
	أرجع &ci;
}

