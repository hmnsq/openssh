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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/uio.h>
#அந்தர்பாவ <sys/queue.h>
#அந்தர்பாவ <sys/wait.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/dh.h>
#அந்தர்பாவ <openssl/evp.h>
#endif

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#ifdef WITH_OPENSSL
#அந்தர்பாவ "dh.h"
#endif
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "auth-options.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "mac.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "auth-pam.h"
#அந்தர்பாவ "monitor.h"
#ifdef GSSAPI
#அந்தர்பாவ "ssh-gss.h"
#endif
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "monitor_fdpass.h"
#அந்தர்பாவ "misc.h"

#அந்தர்பாவ "channels.h"
#அந்தர்பாவ "session.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "monitor_wrap.h"
#அந்தர்பாவ "srclimit.h"

#அந்தர்பாவ "ssherr.h"

/* Imports */
வெளி கட்டமைப்பு monitor *pmonitor;
வெளி கட்டமைப்பு sshbuf *loginmsg;
வெளி ServerOptions options;

வெறுமை
mm_log_handler(LogLevel level, முழு forced, மாறிலி எழுத்து *செய்தி, வெறுமை *ctx)
{
	கட்டமைப்பு sshbuf *log_செய்தி;
	கட்டமைப்பு monitor *mon = (கட்டமைப்பு monitor *)ctx;
	முழு r;
	size_t len;

	எனில் (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	எனில் ((log_செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	எனில் ((r = sshbuf_put_u32(log_செய்தி, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_செய்தி, level)) != 0 ||
	    (r = sshbuf_put_u32(log_செய்தி, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_செய்தி, செய்தி)) != 0)
		fatal_fr(r, "assemble");
	எனில் ((len = sshbuf_len(log_செய்தி)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_செய்தி), len - 4);
	எனில் (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_செய்தி), len) != len) {
		எனில் (errno == EPIPE) {
			debug_f("write: %s", strerror(errno));
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
	sshbuf_free(log_செய்தி);
}

நிலையான வெறுமை
mm_reap(வெறுமை)
{
	முழு status = -1;

	எனில் (!mm_is_monitor())
		திரும்பு;
	போது (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		எனில் (errno == EINTR)
			தொடர்;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", strerror(errno));
	}
	எனில் (WIFEXITED(status)) {
		எனில் (WEXITSTATUS(status) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(status));
			cleanup_exit(255);
		}
	} இல்லையெனில் எனில் (WIFSIGNALED(status)) {
		error_f("child terminated by signal %d",
		    WTERMSIG(status));
		cleanup_exit(signal_is_crash(WTERMSIG(status)) ?
		    EXIT_CHILD_CRASH : 255);
	} இல்லையெனில் {
		error_f("child terminated abnormally (status=0x%x)",
		    status);
		cleanup_exit(EXIT_CHILD_CRASH);
	}
}

வெறுமை
mm_request_send(முழு sock, எண்ணிக்கை monitor_reqtype type, கட்டமைப்பு sshbuf *m)
{
	size_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	எனில் (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	எனில் (atomicio(vwrite, sock, buf, அளவு(buf)) != அளவு(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		எனில் (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
}

வெறுமை
mm_request_receive(முழு sock, கட்டமைப்பு sshbuf *m)
{
	u_char buf[4], *p = வெற்று;
	u_int செய்தி_len;
	முழு oerrno, r;

	debug3_f("entering");

	எனில் (atomicio(பட, sock, buf, அளவு(buf)) != அளவு(buf)) {
		எனில் (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", strerror(errno));
	}
	செய்தி_len = PEEK_U32(buf);
	எனில் (செய்தி_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", செய்தி_len);
	sshbuf_reset(m);
	எனில் ((r = sshbuf_reserve(m, செய்தி_len, &p)) != 0)
		fatal_fr(r, "reserve");
	எனில் (atomicio(பட, sock, p, செய்தி_len) != செய்தி_len) {
		oerrno = errno;
		error_f("read: %s", strerror(errno));
		எனில் (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

வெறுமை
mm_request_receive_expect(முழு sock, எண்ணிக்கை monitor_reqtype type, கட்டமைப்பு sshbuf *m)
{
	u_char rtype;
	முழு r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	எனில் ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	எனில் (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(முழு min, முழு nbits, முழு max)
{
	BIGNUM *p, *g;
	முழு r;
	u_char success = 0;
	கட்டமைப்பு sshbuf *m;

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	எனில் ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	எனில் (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

	எனில் ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	திரும்பு (dh_new_group(g, p));
}
#endif

வெறுமை
mm_sshkey_setcompat(கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு sshbuf *m;
	முழு r;

	debug3_f("entering");
	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

முழு
mm_sshkey_sign(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshkey *சாவி, u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t datalen, மாறிலி எழுத்து *hostkey_alg,
    மாறிலி எழுத்து *sk_provider, மாறிலி எழுத்து *sk_pin, u_int compat)
{
	கட்டமைப்பு sshbuf *m;
	முழு r;

	debug3_f("entering");
	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshkey_puts(சாவி, m)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	எனில் ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	debug3_f("%s signature len=%zu", hostkey_alg ? hostkey_alg : "(null)",
	    *lenp);

	திரும்பு (0);
}

வெறுமை
mm_decode_activate_server_options(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshbuf *m)
{
	கட்டமைப்பு sshbuf *config;
	முழு r;
	u_int i;

	எனில் ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	எனில் ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	க்கு (i = 0; i < options.இலக்கம்_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
}

#define GETPW(b, id) \
	செய் { \
		எனில் ((r = sshbuf_get_string_direct(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		எனில் (len != அளவு(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		memcpy(&pw->id, p, len); \
	} போது (0)

கட்டமைப்பு passwd *
mm_getpwnamallow(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *username)
{
	கட்டமைப்பு sshbuf *m;
	கட்டமைப்பு passwd *pw;
	size_t len;
	முழு r;
	u_char ok;
	மாறிலி u_char *p;

	debug3_f("entering");

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	எனில் ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	எனில் (ok == 0) {
		pw = வெற்று;
		செல் out;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(அளவு(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#endif
	எனில் ((r = sshbuf_get_cstring(m, &pw->pw_name, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, வெற்று)) != 0 ||
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, வெற்று)) != 0 ||
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(m, &pw->pw_class, வெற்று)) != 0 ||
#endif
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, வெற்று)) != 0)
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

	திரும்பு (pw);
}

எழுத்து *
mm_auth2_read_banner(வெறுமை)
{
	கட்டமைப்பு sshbuf *m;
	எழுத்து *banner;
	முழு r;

	debug3_f("entering");

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	எனில் ((r = sshbuf_get_cstring(m, &banner, வெற்று)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	எனில் (strlen(banner) == 0) {
		விடுவி(banner);
		banner = வெற்று;
	}
	திரும்பு (banner);
}

/* Inform the privileged process about service and style */

வெறுமை
mm_inform_authserv(எழுத்து *service, எழுத்து *style)
{
	கட்டமைப்பு sshbuf *m;
	முழு r;

	debug3_f("entering");

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
முழு
mm_auth_password(கட்டமைப்பு ssh *ssh, எழுத்து *password)
{
	கட்டமைப்பு sshbuf *m;
	முழு r, authenticated = 0;
#ifdef USE_PAM
	u_int maxtries = 0;
#endif

	debug3_f("entering");

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	எனில் ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#ifdef USE_PAM
	எனில் ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	எனில் (maxtries > INT_MAX)
		fatal_fr(r, "bad maxtries");
	sshpam_set_maxtries_reached(maxtries);
#endif

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	திரும்பு (authenticated);
}

முழு
mm_user_சாவி_allowed(கட்டமைப்பு ssh *ssh, கட்டமைப்பு passwd *pw, கட்டமைப்பு sshkey *சாவி,
    முழு pubkey_auth_attempt, கட்டமைப்பு sshauthopt **authoptp)
{
	திரும்பு (mm_சாவி_allowed(MM_USERKEY, வெற்று, வெற்று, சாவி,
	    pubkey_auth_attempt, authoptp));
}

முழு
mm_hostbased_சாவி_allowed(கட்டமைப்பு ssh *ssh, கட்டமைப்பு passwd *pw,
    மாறிலி எழுத்து *user, மாறிலி எழுத்து *host, கட்டமைப்பு sshkey *சாவி)
{
	திரும்பு (mm_சாவி_allowed(MM_HOSTKEY, user, host, சாவி, 0, வெற்று));
}

முழு
mm_சாவி_allowed(எண்ணிக்கை mm_keytype type, மாறிலி எழுத்து *user, மாறிலி எழுத்து *host,
    கட்டமைப்பு sshkey *சாவி, முழு pubkey_auth_attempt, கட்டமைப்பு sshauthopt **authoptp)
{
	கட்டமைப்பு sshbuf *m;
	முழு r, allowed = 0;
	கட்டமைப்பு sshauthopt *opts = வெற்று;

	debug3_f("entering");

	எனில் (authoptp != வெற்று)
		*authoptp = வெற்று;

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshkey_puts(சாவி, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	எனில் ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal_fr(r, "parse");
	எனில் (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	எனில் (authoptp != வெற்று) {
		*authoptp = opts;
		opts = வெற்று;
	}
	sshauthopt_free(opts);

	திரும்பு allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

முழு
mm_sshkey_verify(மாறிலி கட்டமைப்பு sshkey *சாவி, மாறிலி u_char *sig, size_t siglen,
    மாறிலி u_char *data, size_t datalen, மாறிலி எழுத்து *sigalg, u_int compat,
    கட்டமைப்பு sshkey_sig_details **sig_detailsp)
{
	கட்டமைப்பு sshbuf *m;
	u_int encoded_ret = 0;
	முழு r;
	u_char sig_details_present, flags;
	u_int counter;

	debug3_f("entering");

	எனில் (sig_detailsp != வெற்று)
		*sig_detailsp = வெற்று;
	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshkey_puts(சாவி, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == வெற்று ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	எனில் ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	எனில் (sig_details_present && encoded_ret == 0) {
		எனில் ((r = sshbuf_get_u32(m, &counter)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		எனில் (sig_detailsp != வெற்று) {
			*sig_detailsp = xcalloc(1, அளவு(**sig_detailsp));
			(*sig_detailsp)->sk_counter = counter;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	எனில் (encoded_ret != 0)
		திரும்பு SSH_ERR_SIGNATURE_INVALID;
	திரும்பு 0;
}

வெறுமை
mm_send_keystate(கட்டமைப்பு ssh *ssh, கட்டமைப்பு monitor *monitor)
{
	கட்டமைப்பு sshbuf *m;
	முழு r;

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

முழு
mm_pty_allocate(முழு *ptyfd, முழு *ttyfd, எழுத்து *namebuf, size_t namebuflen)
{
	கட்டமைப்பு sshbuf *m;
	எழுத்து *p, *செய்தி;
	முழு success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	எனில் ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		எனில் (tmp1 >= 0)
			close(tmp1);
		திரும்பு 0;
	}
	close(tmp1);
	close(tmp2);

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	எனில் ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	எனில் (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		திரும்பு (0);
	}
	எனில் ((r = sshbuf_get_cstring(m, &p, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(m, &செய்தி, வெற்று)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	விடுவி(p);

	எனில் ((r = sshbuf_put(loginmsg, செய்தி, strlen(செய்தி))) != 0)
		fatal_fr(r, "put loginmsg");
	விடுவி(செய்தி);

	எனில் ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	திரும்பு (1);
}

வெறுமை
mm_session_pty_cleanup2(Session *s)
{
	கட்டமைப்பு sshbuf *m;
	முழு r;

	எனில் (s->ttyfd == -1)
		திரும்பு;
	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assmble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	எனில் (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#ifdef USE_PAM
வெறுமை
mm_start_pam(கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு sshbuf *m;

	debug3_f("entering");
	எனில் (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_START, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(வெறுமை)
{
	கட்டமைப்பு sshbuf *m;
	u_int ret;
	எழுத்து *செய்தி;
	size_t msglen;
	முழு r;

	debug3_f("entering");
	எனில் (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	எனில் ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &செய்தி, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, செய்தி, msglen)) != 0)
		fatal_fr(r, "buffer error");

	விடுவி(செய்தி);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	திரும்பு (ret);
}

வெறுமை *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	கட்டமைப்பு sshbuf *m;
	முழு r, success;

	debug3_f("entering");
	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	எனில் ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "buffer error");
	எனில் (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		திரும்பு (வெற்று);
	}
	sshbuf_free(m);
	திரும்பு (authctxt);
}

முழு
mm_sshpam_query(வெறுமை *ctx, எழுத்து **name, எழுத்து **info,
    u_int *இலக்கம், எழுத்து ***prompts, u_int **echo_on)
{
	கட்டமைப்பு sshbuf *m;
	u_int i, n;
	முழு r, ret;

	debug3_f("entering");
	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	எனில் ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, வெற்று)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, இலக்கம்)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_set_maxtries_reached(n);
	எனில் (*இலக்கம் > PAM_MAX_இலக்கம்_செய்தி)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *இலக்கம், PAM_MAX_இலக்கம்_செய்தி);
	*prompts = xcalloc((*இலக்கம் + 1), அளவு(எழுத்து *));
	*echo_on = xcalloc((*இலக்கம் + 1), அளவு(u_int));
	க்கு (i = 0; i < *இலக்கம்; ++i) {
		எனில் ((r = sshbuf_get_cstring(m, &((*prompts)[i]), வெற்று)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	திரும்பு (ret);
}

முழு
mm_sshpam_respond(வெறுமை *ctx, u_int இலக்கம், எழுத்து **resp)
{
	கட்டமைப்பு sshbuf *m;
	u_int n, i;
	முழு r, ret;

	debug3_f("entering");
	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u32(m, இலக்கம்)) != 0)
		fatal_fr(r, "buffer error");
	க்கு (i = 0; i < இலக்கம்; ++i) {
		எனில் ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	எனில் ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	ret = (முழு)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	திரும்பு (ret);
}

வெறுமை
mm_sshpam_free_ctx(வெறுமை *ctxtp)
{
	கட்டமைப்பு sshbuf *m;

	debug3_f("entering");
	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_FREE_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_FREE_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_FREE_CTX, m);
	sshbuf_free(m);
}
#endif /* USE_PAM */

/* Request process termination */

வெறுமை
mm_terminate(வெறுமை)
{
	கட்டமைப்பு sshbuf *m;

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_TERM, m);
	sshbuf_free(m);
}

/* Request state information */

வெறுமை
mm_get_state(கட்டமைப்பு ssh *ssh,
    ServerOptions *opts, கட்டமைப்பு sshbuf **confdatap,
    uint64_t *timing_secretp,
    கட்டமைப்பு sshbuf **hostkeysp, கட்டமைப்பு sshbuf **keystatep,
    u_char **pw_namep,
    கட்டமைப்பு sshbuf **authinfop, கட்டமைப்பு sshbuf **auth_optsp)
{
	கட்டமைப்பு sshbuf *m, *config;
	முழு r;

	debug3_f("entering");

	எனில் ((m = sshbuf_new()) == வெற்று || (config = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	எனில் ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	எனில் (confdatap) {
		எனில் ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, வெற்று)) != 0 ||
		    (r = sshbuf_froms(m, authinfop)) != 0 ||
		    (r = sshbuf_froms(m, auth_optsp)) != 0)
			fatal_fr(r, "parse config postauth");
	}
	எனில் ((r = deserialise_server_options(config, opts)) != 0)
		fatal_fr(r, "deserialise_server_options");

	sshbuf_free(m);
	sshbuf_free(config);

	debug3_f("done");
}

நிலையான வெறுமை
mm_chall_setup(எழுத்து **name, எழுத்து **infotxt, u_int *numprompts,
    எழுத்து ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, அளவு(எழுத்து *));
	*echo_on = xcalloc(*numprompts, அளவு(u_int));
	(*echo_on)[0] = 0;
}

முழு
mm_bsdauth_query(வெறுமை *ctx, எழுத்து **name, எழுத்து **infotxt,
   u_int *numprompts, எழுத்து ***prompts, u_int **echo_on)
{
	கட்டமைப்பு sshbuf *m;
	u_int success;
	எழுத்து *challenge;
	முழு r;

	debug3_f("entering");

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	எனில் ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	எனில் (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		திரும்பு (-1);
	}

	/* Get the challenge, and format the response */
	எனில் ((r = sshbuf_get_cstring(m, &challenge, வெற்று)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_setup(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	திரும்பு (0);
}

முழு
mm_bsdauth_respond(வெறுமை *ctx, u_int numresponses, எழுத்து **responses)
{
	கட்டமைப்பு sshbuf *m;
	முழு r, authok;

	debug3_f("entering");
	எனில் (numresponses != 1)
		திரும்பு (-1);

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	எனில் ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	திரும்பு ((authok == 0) ? -1 : 0);
}

#ifdef SSH_AUDIT_EVENTS
வெறுமை
mm_audit_event(கட்டமைப்பு ssh *ssh, ssh_audit_event_t event)
{
	கட்டமைப்பு sshbuf *m;
	முழு r;

	debug3_f("entering");

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

வெறுமை
mm_audit_run_command(மாறிலி எழுத்து *command)
{
	கட்டமைப்பு sshbuf *m;
	முழு r;

	debug3_f("entering command %s", command);

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#endif /* SSH_AUDIT_EVENTS */

#ifdef GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	கட்டமைப்பு sshbuf *m;
	OM_uint32 major;
	முழு r;

	/* Client doesn't get to see the context */
	*ctx = வெற்று;

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_string(m, goid->elements, goid->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	எனில் ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	திரும்பு (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *in,
    gss_buffer_desc *out, OM_uint32 *flagsp)
{
	கட்டமைப்பு sshbuf *m;
	OM_uint32 major;
	u_int flags;
	முழு r;

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_string(m, in->மதிப்பு, in->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	எனில் ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, out)) != 0)
		fatal_fr(r, "parse");
	எனில் (flagsp != வெற்று) {
		எனில் ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	திரும்பு (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	கட்டமைப்பு sshbuf *m;
	OM_uint32 major;
	முழு r;

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_string(m, gssbuf->மதிப்பு, gssbuf->length)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->மதிப்பு, gssmic->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	எனில் ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	திரும்பு(major);
}

முழு
mm_ssh_gssapi_userok(எழுத்து *user)
{
	கட்டமைப்பு sshbuf *m;
	முழு r, authenticated = 0;

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	எனில் ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	திரும்பு (authenticated);
}
#endif /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
நிலையான வெறுமை
server_process_permitopen_list(கட்டமைப்பு ssh *ssh, முழு listen,
    எழுத்து **opens, u_int இலக்கம்_opens)
{
	u_int i;
	முழு port;
	எழுத்து *host, *arg, *oarg;
	முழு where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	மாறிலி எழுத்து *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	எனில் (இலக்கம்_opens == 0)
		திரும்பு; /* permit any */

	/* handle keywords: "any" / "none" */
	எனில் (இலக்கம்_opens == 1 && strcmp(opens[0], "any") == 0)
		திரும்பு;
	எனில் (இலக்கம்_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		திரும்பு;
	}
	/* Otherwise treat it as a list of permitted host:port */
	க்கு (i = 0; i < இலக்கம்_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		எனில் (host == வெற்று)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		எனில் (arg == வெற்று || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, host, port);
		விடுவி(oarg);
	}
}

/*
 * Inform channels layer of permitopen options from configuration.
 */
வெறுமை
server_process_permitopen(கட்டமைப்பு ssh *ssh)
{
	server_process_permitopen_list(ssh, 0,
	    options.permitted_opens, options.இலக்கம்_permitted_opens);
	server_process_permitopen_list(ssh, 1,
	    options.permitted_listens, options.இலக்கம்_permitted_listens);
}

வெறுமை
server_process_channel_timeouts(கட்டமைப்பு ssh *ssh)
{
	u_int i;
	இரட்டை secs;
	எழுத்து *type;

	debug3_f("setting %u timeouts", options.இலக்கம்_channel_timeouts);
	channel_clear_timeouts(ssh);
	க்கு (i = 0; i < options.இலக்கம்_channel_timeouts; i++) {
		எனில் (parse_pattern_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_add_timeout(ssh, type, secs);
		விடுவி(type);
	}
}

கட்டமைப்பு connection_info *
server_get_connection_info(கட்டமைப்பு ssh *ssh, முழு populate, முழு use_dns)
{
	நிலையான கட்டமைப்பு connection_info ci;

	எனில் (ssh == வெற்று || !populate)
		திரும்பு &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.address = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_port(ssh);
	ci.rdomain = ssh_packet_rdomain_in(ssh);
	திரும்பு &ci;
}

