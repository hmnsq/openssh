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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/uio.h>
#شامل <sys/queue.h>
#شامل <sys/wait.h>

#شامل <errno.h>
#شامل <pwd.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <unistd.h>

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/dh.h>
#شامل <openssl/evp.h>
#اگر_ختم

#شامل "xmalloc.h"
#شامل "ssh.h"
#اگر_تعریف_شدہ WITH_OPENSSL
#شامل "dh.h"
#اگر_ختم
#شامل "sshbuf.h"
#شامل "sshkey.h"
#شامل "cipher.h"
#شامل "kex.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "auth-options.h"
#شامل "packet.h"
#شامل "mac.h"
#شامل "log.h"
#شامل "auth-pam.h"
#شامل "monitor.h"
#اگر_تعریف_شدہ GSSAPI
#شامل "ssh-gss.h"
#اگر_ختم
#شامل "atomicio.h"
#شامل "monitor_fdpass.h"
#شامل "misc.h"

#شامل "channels.h"
#شامل "session.h"
#شامل "servconf.h"
#شامل "monitor_wrap.h"
#شامل "srclimit.h"

#شامل "ssherr.h"

/* Imports */
خارجی ساخت monitor *pmonitor;
خارجی ساخت sshbuf *loginmsg;
خارجی ServerOptions options;

خالی
mm_log_handler(LogLevel level, صحیح forced, ثابت حرف *پیغام, خالی *ctx)
{
	ساخت sshbuf *log_پیغام;
	ساخت monitor *mon = (ساخت monitor *)ctx;
	صحیح r;
	سائز_t len;

	اگر (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	اگر ((log_پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	اگر ((r = sshbuf_put_u32(log_پیغام, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_پیغام, level)) != 0 ||
	    (r = sshbuf_put_u32(log_پیغام, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_پیغام, پیغام)) != 0)
		fatal_fr(r, "assemble");
	اگر ((len = sshbuf_len(log_پیغام)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_پیغام), len - 4);
	اگر (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_پیغام), len) != len) {
		اگر (errno == EPIPE) {
			debug_f("write: %s", strerror(errno));
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
	sshbuf_free(log_پیغام);
}

ساکن خالی
mm_reap(خالی)
{
	صحیح حالت_2 = -1;

	اگر (!mm_is_monitor())
		واپس;
	جب (waitpid(pmonitor->m_pid, &حالت_2, 0) == -1) {
		اگر (errno == EINTR)
			جاری;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", strerror(errno));
	}
	اگر (WIFEXITED(حالت_2)) {
		اگر (WEXITSTATUS(حالت_2) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(حالت_2));
			cleanup_exit(255);
		}
	} ورنہ اگر (WIFSIGNALED(حالت_2)) {
		error_f("child terminated by signal %d",
		    WTERMSIG(حالت_2));
		cleanup_exit(signal_is_crash(WTERMSIG(حالت_2)) ?
		    EXIT_بچہ_CRASH : 255);
	} ورنہ {
		error_f("child terminated abnormally (status=0x%x)",
		    حالت_2);
		cleanup_exit(EXIT_بچہ_CRASH);
	}
}

خالی
mm_request_send(صحیح sock, شمار monitor_reqtype type, ساخت sshbuf *m)
{
	سائز_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	اگر (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	اگر (atomicio(vwrite, sock, buf, حجم(buf)) != حجم(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		اگر (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
}

خالی
mm_request_receive(صحیح sock, ساخت sshbuf *m)
{
	u_char buf[4], *p = تہی;
	u_int پیغام_len;
	صحیح oerrno, r;

	debug3_f("entering");

	اگر (atomicio(اقرأ, sock, buf, حجم(buf)) != حجم(buf)) {
		اگر (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", strerror(errno));
	}
	پیغام_len = PEEK_U32(buf);
	اگر (پیغام_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", پیغام_len);
	sshbuf_reset(m);
	اگر ((r = sshbuf_reserve(m, پیغام_len, &p)) != 0)
		fatal_fr(r, "reserve");
	اگر (atomicio(اقرأ, sock, p, پیغام_len) != پیغام_len) {
		oerrno = errno;
		error_f("read: %s", strerror(errno));
		اگر (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

خالی
mm_request_receive_expect(صحیح sock, شمار monitor_reqtype type, ساخت sshbuf *m)
{
	u_char rtype;
	صحیح r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	اگر ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	اگر (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#اگر_تعریف_شدہ WITH_OPENSSL
DH *
mm_انتخاب_dh(صحیح min, صحیح nbits, صحیح max)
{
	BIGNUM *p, *g;
	صحیح r;
	u_char success = 0;
	ساخت sshbuf *m;

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	اگر ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	اگر (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

	اگر ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	واپس (dh_new_گروہ(g, p));
}
#اگر_ختم

خالی
mm_sshkey_setcompat(ساخت ssh *ssh)
{
	ساخت sshbuf *m;
	صحیح r;

	debug3_f("entering");
	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

صحیح
mm_sshkey_sign(ساخت ssh *ssh, ساخت sshkey *کلید, u_char **sigp, سائز_t *lenp,
    ثابت u_char *ڈیٹا, سائز_t datalen, ثابت حرف *hostkey_alg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	ساخت sshbuf *m;
	صحیح r;

	debug3_f("entering");
	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_puts(کلید, m)) != 0 ||
	    (r = sshbuf_put_string(m, ڈیٹا, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	اگر ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	debug3_f("%s signature len=%zu", hostkey_alg ? hostkey_alg : "(null)",
	    *lenp);

	واپس (0);
}

خالی
mm_decode_activate_server_options(ساخت ssh *ssh, ساخت sshbuf *m)
{
	ساخت sshbuf *config;
	صحیح r;
	u_int i;

	اگر ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	اگر ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	برائے (i = 0; i < options.عدد_log_verbose; i++)
		log_verbose_جوڑو(options.log_verbose[i]);
}

#تعریف_کرو GETPW(b, id) \
	کرو { \
		اگر ((r = sshbuf_get_string_براہ_راست(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		اگر (len != حجم(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		حافظہ_نقل(&pw->id, p, len); \
	} جب (0)

ساخت passwd *
mm_getpwnamallow(ساخت ssh *ssh, ثابت حرف *username)
{
	ساخت sshbuf *m;
	ساخت passwd *pw;
	سائز_t len;
	صحیح r;
	u_char ok;
	ثابت u_char *p;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	اگر ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	اگر (ok == 0) {
		pw = تہی;
		جاؤ برآمد;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(حجم(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#اگر_تعریف_شدہ HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#اگر_ختم
#اگر_تعریف_شدہ HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#اگر_ختم
	اگر ((r = sshbuf_get_cstring(m, &pw->pw_name, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, تہی)) != 0 ||
#اگر_تعریف_شدہ HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, تہی)) != 0 ||
#اگر_ختم
#اگر_تعریف_شدہ HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(m, &pw->pw_class, تہی)) != 0 ||
#اگر_ختم
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, تہی)) != 0)
		fatal_fr(r, "parse pw");

برآمد:
	/* copy options block as a Match directive may have changed some */
	mm_decode_activate_server_options(ssh, m);
	server_process_permitopen(ssh);
	server_process_channel_timeouts(ssh);
	channel_سیٹ_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	kex_سیٹ_server_sig_algs(ssh, options.pubkey_accepted_algos);
	kex_سیٹ_warn_weak_crypto(ssh, options.warn_weak_crypto);
	ssh_packet_سیٹ_rekey_limits(ssh, options.rekey_حد_بندی,
	    options.rekey_interval);
	sshbuf_free(m);

	واپس (pw);
}

حرف *
mm_auth2_read_banner(خالی)
{
	ساخت sshbuf *m;
	حرف *banner;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	اگر ((r = sshbuf_get_cstring(m, &banner, تہی)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	اگر (لڑی_لمبائی(banner) == 0) {
		آزاد(banner);
		banner = تہی;
	}
	واپس (banner);
}

/* Inform the privileged process about service and style */

خالی
mm_inform_authserv(حرف *service, حرف *style)
{
	ساخت sshbuf *m;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
صحیح
mm_auth_password(ساخت ssh *ssh, حرف *password)
{
	ساخت sshbuf *m;
	صحیح r, authenticated = 0;
#اگر_تعریف_شدہ USE_PAM
	u_int maxtries = 0;
#اگر_ختم

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	اگر ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#اگر_تعریف_شدہ USE_PAM
	اگر ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	اگر (maxtries > زیادہ_سے_زیادہ_عدد)
		fatal_fr(r, "bad maxtries");
	sshpam_سیٹ_maxtries_reached(maxtries);
#اگر_ختم

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	واپس (authenticated);
}

صحیح
mm_user_کلید_allowed(ساخت ssh *ssh, ساخت passwd *pw, ساخت sshkey *کلید,
    صحیح pubkey_auth_attempt, ساخت sshauthopt **authoptp)
{
	واپس (mm_کلید_allowed(MM_USERKEY, تہی, تہی, کلید,
	    pubkey_auth_attempt, authoptp));
}

صحیح
mm_hostbased_کلید_allowed(ساخت ssh *ssh, ساخت passwd *pw,
    ثابت حرف *user, ثابت حرف *host, ساخت sshkey *کلید)
{
	واپس (mm_کلید_allowed(MM_HOSTKEY, user, host, کلید, 0, تہی));
}

صحیح
mm_کلید_allowed(شمار mm_keytype type, ثابت حرف *user, ثابت حرف *host,
    ساخت sshkey *کلید, صحیح pubkey_auth_attempt, ساخت sshauthopt **authoptp)
{
	ساخت sshbuf *m;
	صحیح r, allowed = 0;
	ساخت sshauthopt *opts = تہی;

	debug3_f("entering");

	اگر (authoptp != تہی)
		*authoptp = تہی;

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshkey_puts(کلید, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	اگر ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal_fr(r, "parse");
	اگر (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	اگر (authoptp != تہی) {
		*authoptp = opts;
		opts = تہی;
	}
	sshauthopt_free(opts);

	واپس allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

صحیح
mm_sshkey_verify(ثابت ساخت sshkey *کلید, ثابت u_char *sig, سائز_t siglen,
    ثابت u_char *ڈیٹا, سائز_t datalen, ثابت حرف *sigalg, u_int compat,
    ساخت sshkey_sig_details **sig_detailsp)
{
	ساخت sshbuf *m;
	u_int encoded_ret = 0;
	صحیح r;
	u_char sig_details_present, flags;
	u_int شمار_2;

	debug3_f("entering");

	اگر (sig_detailsp != تہی)
		*sig_detailsp = تہی;
	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_puts(کلید, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, ڈیٹا, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == تہی ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	اگر ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	اگر (sig_details_present && encoded_ret == 0) {
		اگر ((r = sshbuf_get_u32(m, &شمار_2)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		اگر (sig_detailsp != تہی) {
			*sig_detailsp = xcalloc(1, حجم(**sig_detailsp));
			(*sig_detailsp)->sk_شمار = شمار_2;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	اگر (encoded_ret != 0)
		واپس SSH_ERR_SIGNATURE_INVALID;
	واپس 0;
}

خالی
mm_send_keystate(ساخت ssh *ssh, ساخت monitor *monitor)
{
	ساخت sshbuf *m;
	صحیح r;

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

صحیح
mm_pty_allocate(صحیح *ptyfd, صحیح *ttyfd, حرف *namebuf, سائز_t namebuflen)
{
	ساخت sshbuf *m;
	حرف *p, *پیغام;
	صحیح success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	اگر ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		اگر (tmp1 >= 0)
			close(tmp1);
		واپس 0;
	}
	close(tmp1);
	close(tmp2);

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	اگر ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	اگر (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		واپس (0);
	}
	اگر ((r = sshbuf_get_cstring(m, &p, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(m, &پیغام, تہی)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	آزاد(p);

	اگر ((r = sshbuf_put(loginmsg, پیغام, لڑی_لمبائی(پیغام))) != 0)
		fatal_fr(r, "put loginmsg");
	آزاد(پیغام);

	اگر ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	واپس (1);
}

خالی
mm_session_pty_cleanup2(Session *s)
{
	ساخت sshbuf *m;
	صحیح r;

	اگر (s->ttyfd == -1)
		واپس;
	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assmble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	اگر (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#اگر_تعریف_شدہ USE_PAM
خالی
mm_آغاز_pam(ساخت ssh *ssh)
{
	ساخت sshbuf *m;

	debug3_f("entering");
	اگر (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_آغاز, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(خالی)
{
	ساخت sshbuf *m;
	u_int ret;
	حرف *پیغام;
	سائز_t msglen;
	صحیح r;

	debug3_f("entering");
	اگر (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	اگر ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &پیغام, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, پیغام, msglen)) != 0)
		fatal_fr(r, "buffer error");

	آزاد(پیغام);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	واپس (ret);
}

خالی *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	ساخت sshbuf *m;
	صحیح r, success;

	debug3_f("entering");
	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	اگر ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "buffer error");
	اگر (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		واپس (تہی);
	}
	sshbuf_free(m);
	واپس (authctxt);
}

صحیح
mm_sshpam_query(خالی *ctx, حرف **name, حرف **info,
    u_int *عدد, حرف ***prompts, u_int **echo_on)
{
	ساخت sshbuf *m;
	u_int i, n;
	صحیح r, ret;

	debug3_f("entering");
	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	اگر ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, تہی)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, عدد)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_سیٹ_maxtries_reached(n);
	اگر (*عدد > PAM_MAX_عدد_پیغام)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *عدد, PAM_MAX_عدد_پیغام);
	*prompts = xcalloc((*عدد + 1), حجم(حرف *));
	*echo_on = xcalloc((*عدد + 1), حجم(u_int));
	برائے (i = 0; i < *عدد; ++i) {
		اگر ((r = sshbuf_get_cstring(m, &((*prompts)[i]), تہی)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	واپس (ret);
}

صحیح
mm_sshpam_respond(خالی *ctx, u_int عدد, حرف **resp)
{
	ساخت sshbuf *m;
	u_int n, i;
	صحیح r, ret;

	debug3_f("entering");
	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u32(m, عدد)) != 0)
		fatal_fr(r, "buffer error");
	برائے (i = 0; i < عدد; ++i) {
		اگر ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	اگر ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	ret = (صحیح)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	واپس (ret);
}

خالی
mm_sshpam_free_ctx(خالی *ctxtp)
{
	ساخت sshbuf *m;

	debug3_f("entering");
	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_FREE_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_FREE_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_FREE_CTX, m);
	sshbuf_free(m);
}
#اگر_ختم /* USE_PAM */

/* Request process termination */

خالی
mm_terminate(خالی)
{
	ساخت sshbuf *m;

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_رکن, m);
	sshbuf_free(m);
}

/* Request state information */

خالی
mm_get_state(ساخت ssh *ssh,
    ServerOptions *opts, ساخت sshbuf **confdatap,
    uint64_t *timing_secretp,
    ساخت sshbuf **hostkeysp, ساخت sshbuf **keystatep,
    u_char **pw_namep,
    ساخت sshbuf **authinfop, ساخت sshbuf **auth_optsp)
{
	ساخت sshbuf *m, *config;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == تہی || (config = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	اگر ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_نسخہ)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_نسخہ)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	اگر (confdatap) {
		اگر ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, تہی)) != 0 ||
		    (r = sshbuf_froms(m, authinfop)) != 0 ||
		    (r = sshbuf_froms(m, auth_optsp)) != 0)
			fatal_fr(r, "parse config postauth");
	}
	اگر ((r = deserialise_server_options(config, opts)) != 0)
		fatal_fr(r, "deserialise_server_options");

	sshbuf_free(m);
	sshbuf_free(config);

	debug3_f("done");
}

ساکن خالی
mm_chall_تیاری(حرف **name, حرف **infotxt, u_int *numprompts,
    حرف ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, حجم(حرف *));
	*echo_on = xcalloc(*numprompts, حجم(u_int));
	(*echo_on)[0] = 0;
}

صحیح
mm_bsdauth_query(خالی *ctx, حرف **name, حرف **infotxt,
   u_int *numprompts, حرف ***prompts, u_int **echo_on)
{
	ساخت sshbuf *m;
	u_int success;
	حرف *challenge;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	اگر ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	اگر (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		واپس (-1);
	}

	/* Get the challenge, and format the response */
	اگر ((r = sshbuf_get_cstring(m, &challenge, تہی)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_تیاری(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	واپس (0);
}

صحیح
mm_bsdauth_respond(خالی *ctx, u_int numresponses, حرف **responses)
{
	ساخت sshbuf *m;
	صحیح r, authok;

	debug3_f("entering");
	اگر (numresponses != 1)
		واپس (-1);

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	اگر ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	واپس ((authok == 0) ? -1 : 0);
}

#اگر_تعریف_شدہ SSH_AUDIT_EVENTS
خالی
mm_audit_event(ساخت ssh *ssh, ssh_audit_event_t event)
{
	ساخت sshbuf *m;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

خالی
mm_audit_تسلسل_command(ثابت حرف *command)
{
	ساخت sshbuf *m;
	صحیح r;

	debug3_f("entering command %s", command);

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#اگر_ختم /* SSH_AUDIT_EVENTS */

#اگر_تعریف_شدہ GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	ساخت sshbuf *m;
	OM_uint32 major;
	صحیح r;

	/* Client doesn't get to see the context */
	*ctx = تہی;

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_string(m, goid->elements, goid->لمبائی)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	اگر ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	واپس (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_بفر_desc *اندر,
    gss_بفر_desc *برآمد, OM_uint32 *flagsp)
{
	ساخت sshbuf *m;
	OM_uint32 major;
	u_int flags;
	صحیح r;

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_string(m, اندر->قدر, اندر->لمبائی)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	اگر ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_بفر_desc(m, برآمد)) != 0)
		fatal_fr(r, "parse");
	اگر (flagsp != تہی) {
		اگر ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	واپس (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_بفر_t gssbuf, gss_بفر_t gssmic)
{
	ساخت sshbuf *m;
	OM_uint32 major;
	صحیح r;

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_string(m, gssbuf->قدر, gssbuf->لمبائی)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->قدر, gssmic->لمبائی)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	اگر ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	واپس(major);
}

صحیح
mm_ssh_gssapi_userok(حرف *user)
{
	ساخت sshbuf *m;
	صحیح r, authenticated = 0;

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	اگر ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	واپس (authenticated);
}
#اگر_ختم /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
ساکن خالی
server_process_permitopen_list(ساخت ssh *ssh, صحیح listen,
    حرف **opens, u_int عدد_opens)
{
	u_int i;
	صحیح پورٹ;
	حرف *host, *arg, *oarg;
	صحیح where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	ثابت حرف *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	اگر (عدد_opens == 0)
		واپس; /* permit any */

	/* handle keywords: "any" / "none" */
	اگر (عدد_opens == 1 && strcmp(opens[0], "any") == 0)
		واپس;
	اگر (عدد_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		واپس;
	}
	/* Otherwise treat it as a list of permitted host:port */
	برائے (i = 0; i < عدد_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		اگر (host == تہی)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		اگر (arg == تہی || ((پورٹ = permitopen_پورٹ(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_جوڑو_permission(ssh, FORWARD_ADM,
		    where, host, پورٹ);
		آزاد(oarg);
	}
}

/*
 * Inform channels layer of permitopen options from configuration.
 */
خالی
server_process_permitopen(ساخت ssh *ssh)
{
	server_process_permitopen_list(ssh, 0,
	    options.permitted_opens, options.عدد_permitted_opens);
	server_process_permitopen_list(ssh, 1,
	    options.permitted_listens, options.عدد_permitted_listens);
}

خالی
server_process_channel_timeouts(ساخت ssh *ssh)
{
	u_int i;
	دوہرا secs;
	حرف *type;

	debug3_f("setting %u timeouts", options.عدد_channel_timeouts);
	channel_clear_timeouts(ssh);
	برائے (i = 0; i < options.عدد_channel_timeouts; i++) {
		اگر (parse_نمونہ_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_جوڑو_timeout(ssh, type, secs);
		آزاد(type);
	}
}

ساخت connection_info *
server_get_connection_info(ساخت ssh *ssh, صحیح populate, صحیح use_dns)
{
	ساکن ساخت connection_info ci;

	اگر (ssh == تہی || !populate)
		واپس &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.پتہ = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_پورٹ(ssh);
	ci.rdomain = ssh_packet_rdomain_اندر(ssh);
	واپس &ci;
}

