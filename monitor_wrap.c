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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/uio.h>
#অন্তর্ভাব <sys/queue.h>
#অন্তর্ভাব <sys/wait.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/dh.h>
#অন্তর্ভাব <openssl/evp.h>
#endif

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh.h"
#ifdef WITH_OPENSSL
#অন্তর্ভাব "dh.h"
#endif
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "auth-options.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "mac.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "auth-pam.h"
#অন্তর্ভাব "monitor.h"
#ifdef GSSAPI
#অন্তর্ভাব "ssh-gss.h"
#endif
#অন্তর্ভাব "atomicio.h"
#অন্তর্ভাব "monitor_fdpass.h"
#অন্তর্ভাব "misc.h"

#অন্তর্ভাব "channels.h"
#অন্তর্ভাব "session.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "monitor_wrap.h"
#অন্তর্ভাব "srclimit.h"

#অন্তর্ভাব "ssherr.h"

/* Imports */
বাহ্য সংরচনা monitor *pmonitor;
বাহ্য সংরচনা sshbuf *loginmsg;
বাহ্য ServerOptions options;

শূন্য
mm_log_handler(LogLevel level, পূর্ণাঙ্ক forced, ধ্রুব বর্ণ *বার্তা, শূন্য *ctx)
{
	সংরচনা sshbuf *log_বার্তা;
	সংরচনা monitor *mon = (সংরচনা monitor *)ctx;
	পূর্ণাঙ্ক r;
	size_t len;

	যদি (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	যদি ((log_বার্তা = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");

	যদি ((r = sshbuf_put_u32(log_বার্তা, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_বার্তা, level)) != 0 ||
	    (r = sshbuf_put_u32(log_বার্তা, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_বার্তা, বার্তা)) != 0)
		fatal_fr(r, "assemble");
	যদি ((len = sshbuf_len(log_বার্তা)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_বার্তা), len - 4);
	যদি (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_বার্তা), len) != len) {
		যদি (errno == EPIPE) {
			debug_f("write: %s", strerror(errno));
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
	sshbuf_free(log_বার্তা);
}

স্থির শূন্য
mm_reap(শূন্য)
{
	পূর্ণাঙ্ক status = -1;

	যদি (!mm_is_monitor())
		প্রত্যাগম;
	যাবত্ (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		যদি (errno == EINTR)
			অনুবর্ত;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", strerror(errno));
	}
	যদি (WIFEXITED(status)) {
		যদি (WEXITSTATUS(status) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(status));
			cleanup_exit(255);
		}
	} অন্যথা যদি (WIFSIGNALED(status)) {
		error_f("child terminated by signal %d",
		    WTERMSIG(status));
		cleanup_exit(signal_is_crash(WTERMSIG(status)) ?
		    EXIT_CHILD_CRASH : 255);
	} অন্যথা {
		error_f("child terminated abnormally (status=0x%x)",
		    status);
		cleanup_exit(EXIT_CHILD_CRASH);
	}
}

শূন্য
mm_request_send(পূর্ণাঙ্ক sock, গণনা monitor_reqtype type, সংরচনা sshbuf *m)
{
	size_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	যদি (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	যদি (atomicio(vwrite, sock, buf, পরিমাণ(buf)) != পরিমাণ(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		যদি (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
}

শূন্য
mm_request_receive(পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	u_char buf[4], *p = রিক্ত;
	u_int বার্তা_len;
	পূর্ণাঙ্ক oerrno, r;

	debug3_f("entering");

	যদি (atomicio(পঠ, sock, buf, পরিমাণ(buf)) != পরিমাণ(buf)) {
		যদি (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", strerror(errno));
	}
	বার্তা_len = PEEK_U32(buf);
	যদি (বার্তা_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", বার্তা_len);
	sshbuf_reset(m);
	যদি ((r = sshbuf_reserve(m, বার্তা_len, &p)) != 0)
		fatal_fr(r, "reserve");
	যদি (atomicio(পঠ, sock, p, বার্তা_len) != বার্তা_len) {
		oerrno = errno;
		error_f("read: %s", strerror(errno));
		যদি (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

শূন্য
mm_request_receive_expect(পূর্ণাঙ্ক sock, গণনা monitor_reqtype type, সংরচনা sshbuf *m)
{
	u_char rtype;
	পূর্ণাঙ্ক r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	যদি ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	যদি (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(পূর্ণাঙ্ক min, পূর্ণাঙ্ক nbits, পূর্ণাঙ্ক max)
{
	BIGNUM *p, *g;
	পূর্ণাঙ্ক r;
	u_char success = 0;
	সংরচনা sshbuf *m;

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	যদি ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	যদি (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

	যদি ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	প্রত্যাগম (dh_new_group(g, p));
}
#endif

শূন্য
mm_sshkey_setcompat(সংরচনা ssh *ssh)
{
	সংরচনা sshbuf *m;
	পূর্ণাঙ্ক r;

	debug3_f("entering");
	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

পূর্ণাঙ্ক
mm_sshkey_sign(সংরচনা ssh *ssh, সংরচনা sshkey *চাবি, u_char **sigp, size_t *lenp,
    ধ্রুব u_char *data, size_t datalen, ধ্রুব বর্ণ *hostkey_alg,
    ধ্রুব বর্ণ *sk_provider, ধ্রুব বর্ণ *sk_pin, u_int compat)
{
	সংরচনা sshbuf *m;
	পূর্ণাঙ্ক r;

	debug3_f("entering");
	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshkey_puts(চাবি, m)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	যদি ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	debug3_f("%s signature len=%zu", hostkey_alg ? hostkey_alg : "(null)",
	    *lenp);

	প্রত্যাগম (0);
}

শূন্য
mm_decode_activate_server_options(সংরচনা ssh *ssh, সংরচনা sshbuf *m)
{
	সংরচনা sshbuf *config;
	পূর্ণাঙ্ক r;
	u_int i;

	যদি ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	যদি ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	প্রতি (i = 0; i < options.অঙ্ক_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
}

#define GETPW(b, id) \
	কুরু { \
		যদি ((r = sshbuf_get_string_direct(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		যদি (len != পরিমাণ(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		memcpy(&pw->id, p, len); \
	} যাবত্ (0)

সংরচনা passwd *
mm_getpwnamallow(সংরচনা ssh *ssh, ধ্রুব বর্ণ *username)
{
	সংরচনা sshbuf *m;
	সংরচনা passwd *pw;
	size_t len;
	পূর্ণাঙ্ক r;
	u_char ok;
	ধ্রুব u_char *p;

	debug3_f("entering");

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	যদি ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	যদি (ok == 0) {
		pw = রিক্ত;
		গচ্ছ out;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(পরিমাণ(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#endif
	যদি ((r = sshbuf_get_cstring(m, &pw->pw_name, রিক্ত)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, রিক্ত)) != 0 ||
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, রিক্ত)) != 0 ||
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(m, &pw->pw_class, রিক্ত)) != 0 ||
#endif
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, রিক্ত)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, রিক্ত)) != 0)
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

	প্রত্যাগম (pw);
}

বর্ণ *
mm_auth2_read_banner(শূন্য)
{
	সংরচনা sshbuf *m;
	বর্ণ *banner;
	পূর্ণাঙ্ক r;

	debug3_f("entering");

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	যদি ((r = sshbuf_get_cstring(m, &banner, রিক্ত)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	যদি (strlen(banner) == 0) {
		মুক্ত(banner);
		banner = রিক্ত;
	}
	প্রত্যাগম (banner);
}

/* Inform the privileged process about service and style */

শূন্য
mm_inform_authserv(বর্ণ *service, বর্ণ *style)
{
	সংরচনা sshbuf *m;
	পূর্ণাঙ্ক r;

	debug3_f("entering");

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
পূর্ণাঙ্ক
mm_auth_password(সংরচনা ssh *ssh, বর্ণ *password)
{
	সংরচনা sshbuf *m;
	পূর্ণাঙ্ক r, authenticated = 0;
#ifdef USE_PAM
	u_int maxtries = 0;
#endif

	debug3_f("entering");

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	যদি ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#ifdef USE_PAM
	যদি ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	যদি (maxtries > INT_MAX)
		fatal_fr(r, "bad maxtries");
	sshpam_set_maxtries_reached(maxtries);
#endif

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	প্রত্যাগম (authenticated);
}

পূর্ণাঙ্ক
mm_user_চাবি_allowed(সংরচনা ssh *ssh, সংরচনা passwd *pw, সংরচনা sshkey *চাবি,
    পূর্ণাঙ্ক pubkey_auth_attempt, সংরচনা sshauthopt **authoptp)
{
	প্রত্যাগম (mm_চাবি_allowed(MM_USERKEY, রিক্ত, রিক্ত, চাবি,
	    pubkey_auth_attempt, authoptp));
}

পূর্ণাঙ্ক
mm_hostbased_চাবি_allowed(সংরচনা ssh *ssh, সংরচনা passwd *pw,
    ধ্রুব বর্ণ *user, ধ্রুব বর্ণ *host, সংরচনা sshkey *চাবি)
{
	প্রত্যাগম (mm_চাবি_allowed(MM_HOSTKEY, user, host, চাবি, 0, রিক্ত));
}

পূর্ণাঙ্ক
mm_চাবি_allowed(গণনা mm_keytype type, ধ্রুব বর্ণ *user, ধ্রুব বর্ণ *host,
    সংরচনা sshkey *চাবি, পূর্ণাঙ্ক pubkey_auth_attempt, সংরচনা sshauthopt **authoptp)
{
	সংরচনা sshbuf *m;
	পূর্ণাঙ্ক r, allowed = 0;
	সংরচনা sshauthopt *opts = রিক্ত;

	debug3_f("entering");

	যদি (authoptp != রিক্ত)
		*authoptp = রিক্ত;

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshkey_puts(চাবি, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	যদি ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal_fr(r, "parse");
	যদি (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	যদি (authoptp != রিক্ত) {
		*authoptp = opts;
		opts = রিক্ত;
	}
	sshauthopt_free(opts);

	প্রত্যাগম allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

পূর্ণাঙ্ক
mm_sshkey_verify(ধ্রুব সংরচনা sshkey *চাবি, ধ্রুব u_char *sig, size_t siglen,
    ধ্রুব u_char *data, size_t datalen, ধ্রুব বর্ণ *sigalg, u_int compat,
    সংরচনা sshkey_sig_details **sig_detailsp)
{
	সংরচনা sshbuf *m;
	u_int encoded_ret = 0;
	পূর্ণাঙ্ক r;
	u_char sig_details_present, flags;
	u_int counter;

	debug3_f("entering");

	যদি (sig_detailsp != রিক্ত)
		*sig_detailsp = রিক্ত;
	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshkey_puts(চাবি, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == রিক্ত ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	যদি ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	যদি (sig_details_present && encoded_ret == 0) {
		যদি ((r = sshbuf_get_u32(m, &counter)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		যদি (sig_detailsp != রিক্ত) {
			*sig_detailsp = xcalloc(1, পরিমাণ(**sig_detailsp));
			(*sig_detailsp)->sk_counter = counter;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	যদি (encoded_ret != 0)
		প্রত্যাগম SSH_ERR_SIGNATURE_INVALID;
	প্রত্যাগম 0;
}

শূন্য
mm_send_keystate(সংরচনা ssh *ssh, সংরচনা monitor *monitor)
{
	সংরচনা sshbuf *m;
	পূর্ণাঙ্ক r;

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

পূর্ণাঙ্ক
mm_pty_allocate(পূর্ণাঙ্ক *ptyfd, পূর্ণাঙ্ক *ttyfd, বর্ণ *namebuf, size_t namebuflen)
{
	সংরচনা sshbuf *m;
	বর্ণ *p, *বার্তা;
	পূর্ণাঙ্ক success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	যদি ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		যদি (tmp1 >= 0)
			close(tmp1);
		প্রত্যাগম 0;
	}
	close(tmp1);
	close(tmp2);

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	যদি ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	যদি (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		প্রত্যাগম (0);
	}
	যদি ((r = sshbuf_get_cstring(m, &p, রিক্ত)) != 0 ||
	    (r = sshbuf_get_cstring(m, &বার্তা, রিক্ত)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	মুক্ত(p);

	যদি ((r = sshbuf_put(loginmsg, বার্তা, strlen(বার্তা))) != 0)
		fatal_fr(r, "put loginmsg");
	মুক্ত(বার্তা);

	যদি ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	প্রত্যাগম (1);
}

শূন্য
mm_session_pty_cleanup2(Session *s)
{
	সংরচনা sshbuf *m;
	পূর্ণাঙ্ক r;

	যদি (s->ttyfd == -1)
		প্রত্যাগম;
	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assmble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	যদি (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#ifdef USE_PAM
শূন্য
mm_start_pam(সংরচনা ssh *ssh)
{
	সংরচনা sshbuf *m;

	debug3_f("entering");
	যদি (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_START, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(শূন্য)
{
	সংরচনা sshbuf *m;
	u_int ret;
	বর্ণ *বার্তা;
	size_t msglen;
	পূর্ণাঙ্ক r;

	debug3_f("entering");
	যদি (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	যদি ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &বার্তা, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, বার্তা, msglen)) != 0)
		fatal_fr(r, "buffer error");

	মুক্ত(বার্তা);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	প্রত্যাগম (ret);
}

শূন্য *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	সংরচনা sshbuf *m;
	পূর্ণাঙ্ক r, success;

	debug3_f("entering");
	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	যদি ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "buffer error");
	যদি (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		প্রত্যাগম (রিক্ত);
	}
	sshbuf_free(m);
	প্রত্যাগম (authctxt);
}

পূর্ণাঙ্ক
mm_sshpam_query(শূন্য *ctx, বর্ণ **name, বর্ণ **info,
    u_int *অঙ্ক, বর্ণ ***prompts, u_int **echo_on)
{
	সংরচনা sshbuf *m;
	u_int i, n;
	পূর্ণাঙ্ক r, ret;

	debug3_f("entering");
	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	যদি ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, রিক্ত)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, রিক্ত)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, অঙ্ক)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_set_maxtries_reached(n);
	যদি (*অঙ্ক > PAM_MAX_অঙ্ক_বার্তা)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *অঙ্ক, PAM_MAX_অঙ্ক_বার্তা);
	*prompts = xcalloc((*অঙ্ক + 1), পরিমাণ(বর্ণ *));
	*echo_on = xcalloc((*অঙ্ক + 1), পরিমাণ(u_int));
	প্রতি (i = 0; i < *অঙ্ক; ++i) {
		যদি ((r = sshbuf_get_cstring(m, &((*prompts)[i]), রিক্ত)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	প্রত্যাগম (ret);
}

পূর্ণাঙ্ক
mm_sshpam_respond(শূন্য *ctx, u_int অঙ্ক, বর্ণ **resp)
{
	সংরচনা sshbuf *m;
	u_int n, i;
	পূর্ণাঙ্ক r, ret;

	debug3_f("entering");
	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u32(m, অঙ্ক)) != 0)
		fatal_fr(r, "buffer error");
	প্রতি (i = 0; i < অঙ্ক; ++i) {
		যদি ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	যদি ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	ret = (পূর্ণাঙ্ক)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	প্রত্যাগম (ret);
}

শূন্য
mm_sshpam_free_ctx(শূন্য *ctxtp)
{
	সংরচনা sshbuf *m;

	debug3_f("entering");
	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_FREE_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_FREE_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_FREE_CTX, m);
	sshbuf_free(m);
}
#endif /* USE_PAM */

/* Request process termination */

শূন্য
mm_terminate(শূন্য)
{
	সংরচনা sshbuf *m;

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_TERM, m);
	sshbuf_free(m);
}

/* Request state information */

শূন্য
mm_get_state(সংরচনা ssh *ssh,
    ServerOptions *opts, সংরচনা sshbuf **confdatap,
    uint64_t *timing_secretp,
    সংরচনা sshbuf **hostkeysp, সংরচনা sshbuf **keystatep,
    u_char **pw_namep,
    সংরচনা sshbuf **authinfop, সংরচনা sshbuf **auth_optsp)
{
	সংরচনা sshbuf *m, *config;
	পূর্ণাঙ্ক r;

	debug3_f("entering");

	যদি ((m = sshbuf_new()) == রিক্ত || (config = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	যদি ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	যদি (confdatap) {
		যদি ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, রিক্ত)) != 0 ||
		    (r = sshbuf_froms(m, authinfop)) != 0 ||
		    (r = sshbuf_froms(m, auth_optsp)) != 0)
			fatal_fr(r, "parse config postauth");
	}
	যদি ((r = deserialise_server_options(config, opts)) != 0)
		fatal_fr(r, "deserialise_server_options");

	sshbuf_free(m);
	sshbuf_free(config);

	debug3_f("done");
}

স্থির শূন্য
mm_chall_setup(বর্ণ **name, বর্ণ **infotxt, u_int *numprompts,
    বর্ণ ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, পরিমাণ(বর্ণ *));
	*echo_on = xcalloc(*numprompts, পরিমাণ(u_int));
	(*echo_on)[0] = 0;
}

পূর্ণাঙ্ক
mm_bsdauth_query(শূন্য *ctx, বর্ণ **name, বর্ণ **infotxt,
   u_int *numprompts, বর্ণ ***prompts, u_int **echo_on)
{
	সংরচনা sshbuf *m;
	u_int success;
	বর্ণ *challenge;
	পূর্ণাঙ্ক r;

	debug3_f("entering");

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	যদি ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	যদি (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		প্রত্যাগম (-1);
	}

	/* Get the challenge, and format the response */
	যদি ((r = sshbuf_get_cstring(m, &challenge, রিক্ত)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_setup(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
mm_bsdauth_respond(শূন্য *ctx, u_int numresponses, বর্ণ **responses)
{
	সংরচনা sshbuf *m;
	পূর্ণাঙ্ক r, authok;

	debug3_f("entering");
	যদি (numresponses != 1)
		প্রত্যাগম (-1);

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	যদি ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	প্রত্যাগম ((authok == 0) ? -1 : 0);
}

#ifdef SSH_AUDIT_EVENTS
শূন্য
mm_audit_event(সংরচনা ssh *ssh, ssh_audit_event_t event)
{
	সংরচনা sshbuf *m;
	পূর্ণাঙ্ক r;

	debug3_f("entering");

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

শূন্য
mm_audit_run_command(ধ্রুব বর্ণ *command)
{
	সংরচনা sshbuf *m;
	পূর্ণাঙ্ক r;

	debug3_f("entering command %s", command);

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#endif /* SSH_AUDIT_EVENTS */

#ifdef GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	সংরচনা sshbuf *m;
	OM_uint32 major;
	পূর্ণাঙ্ক r;

	/* Client doesn't get to see the context */
	*ctx = রিক্ত;

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_string(m, goid->elements, goid->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	যদি ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	প্রত্যাগম (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *in,
    gss_buffer_desc *out, OM_uint32 *flagsp)
{
	সংরচনা sshbuf *m;
	OM_uint32 major;
	u_int flags;
	পূর্ণাঙ্ক r;

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_string(m, in->মান, in->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	যদি ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, out)) != 0)
		fatal_fr(r, "parse");
	যদি (flagsp != রিক্ত) {
		যদি ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	প্রত্যাগম (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	সংরচনা sshbuf *m;
	OM_uint32 major;
	পূর্ণাঙ্ক r;

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_string(m, gssbuf->মান, gssbuf->length)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->মান, gssmic->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	যদি ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	প্রত্যাগম(major);
}

পূর্ণাঙ্ক
mm_ssh_gssapi_userok(বর্ণ *user)
{
	সংরচনা sshbuf *m;
	পূর্ণাঙ্ক r, authenticated = 0;

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	যদি ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	প্রত্যাগম (authenticated);
}
#endif /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
স্থির শূন্য
server_process_permitopen_list(সংরচনা ssh *ssh, পূর্ণাঙ্ক listen,
    বর্ণ **opens, u_int অঙ্ক_opens)
{
	u_int i;
	পূর্ণাঙ্ক port;
	বর্ণ *host, *arg, *oarg;
	পূর্ণাঙ্ক where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	ধ্রুব বর্ণ *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	যদি (অঙ্ক_opens == 0)
		প্রত্যাগম; /* permit any */

	/* handle keywords: "any" / "none" */
	যদি (অঙ্ক_opens == 1 && strcmp(opens[0], "any") == 0)
		প্রত্যাগম;
	যদি (অঙ্ক_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		প্রত্যাগম;
	}
	/* Otherwise treat it as a list of permitted host:port */
	প্রতি (i = 0; i < অঙ্ক_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		যদি (host == রিক্ত)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		যদি (arg == রিক্ত || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, host, port);
		মুক্ত(oarg);
	}
}

/*
 * Inform channels layer of permitopen options from configuration.
 */
শূন্য
server_process_permitopen(সংরচনা ssh *ssh)
{
	server_process_permitopen_list(ssh, 0,
	    options.permitted_opens, options.অঙ্ক_permitted_opens);
	server_process_permitopen_list(ssh, 1,
	    options.permitted_listens, options.অঙ্ক_permitted_listens);
}

শূন্য
server_process_channel_timeouts(সংরচনা ssh *ssh)
{
	u_int i;
	দ্বিগুণ secs;
	বর্ণ *type;

	debug3_f("setting %u timeouts", options.অঙ্ক_channel_timeouts);
	channel_clear_timeouts(ssh);
	প্রতি (i = 0; i < options.অঙ্ক_channel_timeouts; i++) {
		যদি (parse_pattern_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_add_timeout(ssh, type, secs);
		মুক্ত(type);
	}
}

সংরচনা connection_info *
server_get_connection_info(সংরচনা ssh *ssh, পূর্ণাঙ্ক populate, পূর্ণাঙ্ক use_dns)
{
	স্থির সংরচনা connection_info ci;

	যদি (ssh == রিক্ত || !populate)
		প্রত্যাগম &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.address = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_port(ssh);
	ci.rdomain = ssh_packet_rdomain_in(ssh);
	প্রত্যাগম &ci;
}

