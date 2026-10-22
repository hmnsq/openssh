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

#ifdef WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/dh.h>
#شامل <openssl/evp.h>
#endif

#شامل "xmalloc.h"
#شامل "ssh.h"
#ifdef WITH_OPENSSL
#شامل "dh.h"
#endif
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
#ifdef GSSAPI
#شامل "ssh-gss.h"
#endif
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
بیرونی ساختار monitor *pmonitor;
بیرونی ساختار sshbuf *loginmsg;
بیرونی ServerOptions options;

تهی
mm_log_handler(LogLevel level, صحیح forced, ثابت نویسه *پیام, تهی *ctx)
{
	ساختار sshbuf *log_پیام;
	ساختار monitor *mon = (ساختار monitor *)ctx;
	صحیح r;
	size_t len;

	اگر (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	اگر ((log_پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	اگر ((r = sshbuf_put_u32(log_پیام, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_پیام, level)) != 0 ||
	    (r = sshbuf_put_u32(log_پیام, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_پیام, پیام)) != 0)
		fatal_fr(r, "assemble");
	اگر ((len = sshbuf_len(log_پیام)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_پیام), len - 4);
	اگر (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_پیام), len) != len) {
		اگر (errno == EPIPE) {
			debug_f("write: %s", strerror(errno));
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
	sshbuf_free(log_پیام);
}

ایستا تهی
mm_reap(تهی)
{
	صحیح status = -1;

	اگر (!mm_is_monitor())
		بازگشت;
	وقتی (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		اگر (errno == EINTR)
			ادامه;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", strerror(errno));
	}
	اگر (WIFEXITED(status)) {
		اگر (WEXITSTATUS(status) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(status));
			cleanup_exit(255);
		}
	} وگرنه اگر (WIFSIGNALED(status)) {
		error_f("child terminated by signal %d",
		    WTERMSIG(status));
		cleanup_exit(signal_is_crash(WTERMSIG(status)) ?
		    EXIT_CHILD_CRASH : 255);
	} وگرنه {
		error_f("child terminated abnormally (status=0x%x)",
		    status);
		cleanup_exit(EXIT_CHILD_CRASH);
	}
}

تهی
mm_request_send(صحیح sock, شمارش monitor_reqtype type, ساختار sshbuf *m)
{
	size_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	اگر (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	اگر (atomicio(vwrite, sock, buf, اندازه(buf)) != اندازه(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		اگر (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
}

تهی
mm_request_receive(صحیح sock, ساختار sshbuf *m)
{
	u_char buf[4], *p = پوچ;
	u_int پیام_len;
	صحیح oerrno, r;

	debug3_f("entering");

	اگر (atomicio(اقرأ, sock, buf, اندازه(buf)) != اندازه(buf)) {
		اگر (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", strerror(errno));
	}
	پیام_len = PEEK_U32(buf);
	اگر (پیام_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", پیام_len);
	sshbuf_reset(m);
	اگر ((r = sshbuf_reserve(m, پیام_len, &p)) != 0)
		fatal_fr(r, "reserve");
	اگر (atomicio(اقرأ, sock, p, پیام_len) != پیام_len) {
		oerrno = errno;
		error_f("read: %s", strerror(errno));
		اگر (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

تهی
mm_request_receive_expect(صحیح sock, شمارش monitor_reqtype type, ساختار sshbuf *m)
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

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(صحیح min, صحیح nbits, صحیح max)
{
	BIGNUM *p, *g;
	صحیح r;
	u_char success = 0;
	ساختار sshbuf *m;

	اگر ((m = sshbuf_new()) == پوچ)
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

	بازگشت (dh_new_group(g, p));
}
#endif

تهی
mm_sshkey_setcompat(ساختار ssh *ssh)
{
	ساختار sshbuf *m;
	صحیح r;

	debug3_f("entering");
	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

صحیح
mm_sshkey_sign(ساختار ssh *ssh, ساختار sshkey *کلید, u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen, ثابت نویسه *hostkey_alg,
    ثابت نویسه *sk_provider, ثابت نویسه *sk_pin, u_int compat)
{
	ساختار sshbuf *m;
	صحیح r;

	debug3_f("entering");
	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_puts(کلید, m)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
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

	بازگشت (0);
}

تهی
mm_decode_activate_server_options(ساختار ssh *ssh, ساختار sshbuf *m)
{
	ساختار sshbuf *config;
	صحیح r;
	u_int i;

	اگر ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	اگر ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	برای (i = 0; i < options.رقم_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
}

#define GETPW(b, id) \
	انجامبده { \
		اگر ((r = sshbuf_get_string_direct(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		اگر (len != اندازه(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		memcpy(&pw->id, p, len); \
	} وقتی (0)

ساختار passwd *
mm_getpwnamallow(ساختار ssh *ssh, ثابت نویسه *username)
{
	ساختار sshbuf *m;
	ساختار passwd *pw;
	size_t len;
	صحیح r;
	u_char ok;
	ثابت u_char *p;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	اگر ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	اگر (ok == 0) {
		pw = پوچ;
		برو out;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(اندازه(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#endif
	اگر ((r = sshbuf_get_cstring(m, &pw->pw_name, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, پوچ)) != 0 ||
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, پوچ)) != 0 ||
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(m, &pw->pw_class, پوچ)) != 0 ||
#endif
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, پوچ)) != 0)
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

	بازگشت (pw);
}

نویسه *
mm_auth2_read_banner(تهی)
{
	ساختار sshbuf *m;
	نویسه *banner;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	اگر ((r = sshbuf_get_cstring(m, &banner, پوچ)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	اگر (strlen(banner) == 0) {
		آزاد(banner);
		banner = پوچ;
	}
	بازگشت (banner);
}

/* Inform the privileged process about service and style */

تهی
mm_inform_authserv(نویسه *service, نویسه *style)
{
	ساختار sshbuf *m;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
صحیح
mm_auth_password(ساختار ssh *ssh, نویسه *password)
{
	ساختار sshbuf *m;
	صحیح r, authenticated = 0;
#ifdef USE_PAM
	u_int maxtries = 0;
#endif

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	اگر ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#ifdef USE_PAM
	اگر ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	اگر (maxtries > INT_MAX)
		fatal_fr(r, "bad maxtries");
	sshpam_set_maxtries_reached(maxtries);
#endif

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	بازگشت (authenticated);
}

صحیح
mm_user_کلید_allowed(ساختار ssh *ssh, ساختار passwd *pw, ساختار sshkey *کلید,
    صحیح pubkey_auth_attempt, ساختار sshauthopt **authoptp)
{
	بازگشت (mm_کلید_allowed(MM_USERKEY, پوچ, پوچ, کلید,
	    pubkey_auth_attempt, authoptp));
}

صحیح
mm_hostbased_کلید_allowed(ساختار ssh *ssh, ساختار passwd *pw,
    ثابت نویسه *user, ثابت نویسه *host, ساختار sshkey *کلید)
{
	بازگشت (mm_کلید_allowed(MM_HOSTKEY, user, host, کلید, 0, پوچ));
}

صحیح
mm_کلید_allowed(شمارش mm_keytype type, ثابت نویسه *user, ثابت نویسه *host,
    ساختار sshkey *کلید, صحیح pubkey_auth_attempt, ساختار sshauthopt **authoptp)
{
	ساختار sshbuf *m;
	صحیح r, allowed = 0;
	ساختار sshauthopt *opts = پوچ;

	debug3_f("entering");

	اگر (authoptp != پوچ)
		*authoptp = پوچ;

	اگر ((m = sshbuf_new()) == پوچ)
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

	اگر (authoptp != پوچ) {
		*authoptp = opts;
		opts = پوچ;
	}
	sshauthopt_free(opts);

	بازگشت allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

صحیح
mm_sshkey_verify(ثابت ساختار sshkey *کلید, ثابت u_char *sig, size_t siglen,
    ثابت u_char *data, size_t datalen, ثابت نویسه *sigalg, u_int compat,
    ساختار sshkey_sig_details **sig_detailsp)
{
	ساختار sshbuf *m;
	u_int encoded_ret = 0;
	صحیح r;
	u_char sig_details_present, flags;
	u_int counter;

	debug3_f("entering");

	اگر (sig_detailsp != پوچ)
		*sig_detailsp = پوچ;
	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_puts(کلید, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == پوچ ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	اگر ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	اگر (sig_details_present && encoded_ret == 0) {
		اگر ((r = sshbuf_get_u32(m, &counter)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		اگر (sig_detailsp != پوچ) {
			*sig_detailsp = xcalloc(1, اندازه(**sig_detailsp));
			(*sig_detailsp)->sk_counter = counter;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	اگر (encoded_ret != 0)
		بازگشت SSH_ERR_SIGNATURE_INVALID;
	بازگشت 0;
}

تهی
mm_send_keystate(ساختار ssh *ssh, ساختار monitor *monitor)
{
	ساختار sshbuf *m;
	صحیح r;

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

صحیح
mm_pty_allocate(صحیح *ptyfd, صحیح *ttyfd, نویسه *namebuf, size_t namebuflen)
{
	ساختار sshbuf *m;
	نویسه *p, *پیام;
	صحیح success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	اگر ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		اگر (tmp1 >= 0)
			close(tmp1);
		بازگشت 0;
	}
	close(tmp1);
	close(tmp2);

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	اگر ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	اگر (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		بازگشت (0);
	}
	اگر ((r = sshbuf_get_cstring(m, &p, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &پیام, پوچ)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	آزاد(p);

	اگر ((r = sshbuf_put(loginmsg, پیام, strlen(پیام))) != 0)
		fatal_fr(r, "put loginmsg");
	آزاد(پیام);

	اگر ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	بازگشت (1);
}

تهی
mm_session_pty_cleanup2(Session *s)
{
	ساختار sshbuf *m;
	صحیح r;

	اگر (s->ttyfd == -1)
		بازگشت;
	اگر ((m = sshbuf_new()) == پوچ)
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

#ifdef USE_PAM
تهی
mm_start_pam(ساختار ssh *ssh)
{
	ساختار sshbuf *m;

	debug3_f("entering");
	اگر (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_START, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(تهی)
{
	ساختار sshbuf *m;
	u_int ret;
	نویسه *پیام;
	size_t msglen;
	صحیح r;

	debug3_f("entering");
	اگر (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	اگر ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &پیام, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, پیام, msglen)) != 0)
		fatal_fr(r, "buffer error");

	آزاد(پیام);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	بازگشت (ret);
}

تهی *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	ساختار sshbuf *m;
	صحیح r, success;

	debug3_f("entering");
	اگر ((m = sshbuf_new()) == پوچ)
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
		بازگشت (پوچ);
	}
	sshbuf_free(m);
	بازگشت (authctxt);
}

صحیح
mm_sshpam_query(تهی *ctx, نویسه **name, نویسه **info,
    u_int *رقم, نویسه ***prompts, u_int **echo_on)
{
	ساختار sshbuf *m;
	u_int i, n;
	صحیح r, ret;

	debug3_f("entering");
	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	اگر ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, پوچ)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, رقم)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_set_maxtries_reached(n);
	اگر (*رقم > PAM_MAX_رقم_پیام)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *رقم, PAM_MAX_رقم_پیام);
	*prompts = xcalloc((*رقم + 1), اندازه(نویسه *));
	*echo_on = xcalloc((*رقم + 1), اندازه(u_int));
	برای (i = 0; i < *رقم; ++i) {
		اگر ((r = sshbuf_get_cstring(m, &((*prompts)[i]), پوچ)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	بازگشت (ret);
}

صحیح
mm_sshpam_respond(تهی *ctx, u_int رقم, نویسه **resp)
{
	ساختار sshbuf *m;
	u_int n, i;
	صحیح r, ret;

	debug3_f("entering");
	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u32(m, رقم)) != 0)
		fatal_fr(r, "buffer error");
	برای (i = 0; i < رقم; ++i) {
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
	بازگشت (ret);
}

تهی
mm_sshpam_free_ctx(تهی *ctxtp)
{
	ساختار sshbuf *m;

	debug3_f("entering");
	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_FREE_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_FREE_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_FREE_CTX, m);
	sshbuf_free(m);
}
#endif /* USE_PAM */

/* Request process termination */

تهی
mm_terminate(تهی)
{
	ساختار sshbuf *m;

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_TERM, m);
	sshbuf_free(m);
}

/* Request state information */

تهی
mm_get_state(ساختار ssh *ssh,
    ServerOptions *opts, ساختار sshbuf **confdatap,
    uint64_t *timing_secretp,
    ساختار sshbuf **hostkeysp, ساختار sshbuf **keystatep,
    u_char **pw_namep,
    ساختار sshbuf **authinfop, ساختار sshbuf **auth_optsp)
{
	ساختار sshbuf *m, *config;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == پوچ || (config = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	اگر ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	اگر (confdatap) {
		اگر ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, پوچ)) != 0 ||
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

ایستا تهی
mm_chall_setup(نویسه **name, نویسه **infotxt, u_int *numprompts,
    نویسه ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, اندازه(نویسه *));
	*echo_on = xcalloc(*numprompts, اندازه(u_int));
	(*echo_on)[0] = 0;
}

صحیح
mm_bsdauth_query(تهی *ctx, نویسه **name, نویسه **infotxt,
   u_int *numprompts, نویسه ***prompts, u_int **echo_on)
{
	ساختار sshbuf *m;
	u_int success;
	نویسه *challenge;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	اگر ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	اگر (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		بازگشت (-1);
	}

	/* Get the challenge, and format the response */
	اگر ((r = sshbuf_get_cstring(m, &challenge, پوچ)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_setup(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	بازگشت (0);
}

صحیح
mm_bsdauth_respond(تهی *ctx, u_int numresponses, نویسه **responses)
{
	ساختار sshbuf *m;
	صحیح r, authok;

	debug3_f("entering");
	اگر (numresponses != 1)
		بازگشت (-1);

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	اگر ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	بازگشت ((authok == 0) ? -1 : 0);
}

#ifdef SSH_AUDIT_EVENTS
تهی
mm_audit_event(ساختار ssh *ssh, ssh_audit_event_t event)
{
	ساختار sshbuf *m;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

تهی
mm_audit_run_command(ثابت نویسه *command)
{
	ساختار sshbuf *m;
	صحیح r;

	debug3_f("entering command %s", command);

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#endif /* SSH_AUDIT_EVENTS */

#ifdef GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	ساختار sshbuf *m;
	OM_uint32 major;
	صحیح r;

	/* Client doesn't get to see the context */
	*ctx = پوچ;

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_string(m, goid->elements, goid->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	اگر ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	بازگشت (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *in,
    gss_buffer_desc *out, OM_uint32 *flagsp)
{
	ساختار sshbuf *m;
	OM_uint32 major;
	u_int flags;
	صحیح r;

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_string(m, in->مقدار, in->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	اگر ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, out)) != 0)
		fatal_fr(r, "parse");
	اگر (flagsp != پوچ) {
		اگر ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	بازگشت (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	ساختار sshbuf *m;
	OM_uint32 major;
	صحیح r;

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_string(m, gssbuf->مقدار, gssbuf->length)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->مقدار, gssmic->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	اگر ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	بازگشت(major);
}

صحیح
mm_ssh_gssapi_userok(نویسه *user)
{
	ساختار sshbuf *m;
	صحیح r, authenticated = 0;

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	اگر ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	بازگشت (authenticated);
}
#endif /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
ایستا تهی
server_process_permitopen_list(ساختار ssh *ssh, صحیح listen,
    نویسه **opens, u_int رقم_opens)
{
	u_int i;
	صحیح port;
	نویسه *host, *arg, *oarg;
	صحیح where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	ثابت نویسه *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	اگر (رقم_opens == 0)
		بازگشت; /* permit any */

	/* handle keywords: "any" / "none" */
	اگر (رقم_opens == 1 && strcmp(opens[0], "any") == 0)
		بازگشت;
	اگر (رقم_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		بازگشت;
	}
	/* Otherwise treat it as a list of permitted host:port */
	برای (i = 0; i < رقم_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		اگر (host == پوچ)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		اگر (arg == پوچ || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, host, port);
		آزاد(oarg);
	}
}

/*
 * Inform channels layer of permitopen options from configuration.
 */
تهی
server_process_permitopen(ساختار ssh *ssh)
{
	server_process_permitopen_list(ssh, 0,
	    options.permitted_opens, options.رقم_permitted_opens);
	server_process_permitopen_list(ssh, 1,
	    options.permitted_listens, options.رقم_permitted_listens);
}

تهی
server_process_channel_timeouts(ساختار ssh *ssh)
{
	u_int i;
	دوگانه secs;
	نویسه *type;

	debug3_f("setting %u timeouts", options.رقم_channel_timeouts);
	channel_clear_timeouts(ssh);
	برای (i = 0; i < options.رقم_channel_timeouts; i++) {
		اگر (parse_pattern_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_add_timeout(ssh, type, secs);
		آزاد(type);
	}
}

ساختار connection_info *
server_get_connection_info(ساختار ssh *ssh, صحیح populate, صحیح use_dns)
{
	ایستا ساختار connection_info ci;

	اگر (ssh == پوچ || !populate)
		بازگشت &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.address = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_port(ssh);
	ci.rdomain = ssh_packet_rdomain_in(ssh);
	بازگشت &ci;
}

