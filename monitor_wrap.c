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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/uio.h>
#अन्तर्भाव <sys/queue.h>
#अन्तर्भाव <sys/wait.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/dh.h>
#अन्तर्भाव <openssl/evp.h>
#endif

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#ifdef WITH_OPENSSL
#अन्तर्भाव "dh.h"
#endif
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "auth-options.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "mac.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "auth-pam.h"
#अन्तर्भाव "monitor.h"
#ifdef GSSAPI
#अन्तर्भाव "ssh-gss.h"
#endif
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "monitor_fdpass.h"
#अन्तर्भाव "misc.h"

#अन्तर्भाव "channels.h"
#अन्तर्भाव "session.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "monitor_wrap.h"
#अन्तर्भाव "srclimit.h"

#अन्तर्भाव "ssherr.h"

/* Imports */
बाह्य संरचना monitor *pmonitor;
बाह्य संरचना sshbuf *loginmsg;
बाह्य ServerOptions options;

शून्य
mm_log_handler(LogLevel level, पूर्णाङ्क forced, ध्रुव वर्ण *संदेश, शून्य *ctx)
{
	संरचना sshbuf *log_संदेश;
	संरचना monitor *mon = (संरचना monitor *)ctx;
	पूर्णाङ्क r;
	size_t len;

	यदि (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	यदि ((log_संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	यदि ((r = sshbuf_put_u32(log_संदेश, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_संदेश, level)) != 0 ||
	    (r = sshbuf_put_u32(log_संदेश, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_संदेश, संदेश)) != 0)
		fatal_fr(r, "assemble");
	यदि ((len = sshbuf_len(log_संदेश)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_संदेश), len - 4);
	यदि (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_संदेश), len) != len) {
		यदि (errno == EPIPE) {
			debug_f("write: %s", strerror(errno));
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
	sshbuf_free(log_संदेश);
}

स्थिर शून्य
mm_reap(शून्य)
{
	पूर्णाङ्क status = -1;

	यदि (!mm_is_monitor())
		प्रत्यागम;
	यावत् (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		यदि (errno == EINTR)
			अनुवर्त;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", strerror(errno));
	}
	यदि (WIFEXITED(status)) {
		यदि (WEXITSTATUS(status) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(status));
			cleanup_exit(255);
		}
	} अन्यथा यदि (WIFSIGNALED(status)) {
		error_f("child terminated by signal %d",
		    WTERMSIG(status));
		cleanup_exit(signal_is_crash(WTERMSIG(status)) ?
		    EXIT_CHILD_CRASH : 255);
	} अन्यथा {
		error_f("child terminated abnormally (status=0x%x)",
		    status);
		cleanup_exit(EXIT_CHILD_CRASH);
	}
}

शून्य
mm_request_send(पूर्णाङ्क sock, गणना monitor_reqtype type, संरचना sshbuf *m)
{
	size_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	यदि (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	यदि (atomicio(vwrite, sock, buf, परिमाण(buf)) != परिमाण(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		यदि (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
}

शून्य
mm_request_receive(पूर्णाङ्क sock, संरचना sshbuf *m)
{
	u_char buf[4], *p = रिक्त;
	u_int संदेश_len;
	पूर्णाङ्क oerrno, r;

	debug3_f("entering");

	यदि (atomicio(पठ, sock, buf, परिमाण(buf)) != परिमाण(buf)) {
		यदि (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", strerror(errno));
	}
	संदेश_len = PEEK_U32(buf);
	यदि (संदेश_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", संदेश_len);
	sshbuf_reset(m);
	यदि ((r = sshbuf_reserve(m, संदेश_len, &p)) != 0)
		fatal_fr(r, "reserve");
	यदि (atomicio(पठ, sock, p, संदेश_len) != संदेश_len) {
		oerrno = errno;
		error_f("read: %s", strerror(errno));
		यदि (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

शून्य
mm_request_receive_expect(पूर्णाङ्क sock, गणना monitor_reqtype type, संरचना sshbuf *m)
{
	u_char rtype;
	पूर्णाङ्क r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	यदि ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	यदि (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(पूर्णाङ्क min, पूर्णाङ्क nbits, पूर्णाङ्क max)
{
	BIGNUM *p, *g;
	पूर्णाङ्क r;
	u_char success = 0;
	संरचना sshbuf *m;

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	यदि ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	यदि (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

	यदि ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	प्रत्यागम (dh_new_group(g, p));
}
#endif

शून्य
mm_sshkey_setcompat(संरचना ssh *ssh)
{
	संरचना sshbuf *m;
	पूर्णाङ्क r;

	debug3_f("entering");
	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

पूर्णाङ्क
mm_sshkey_sign(संरचना ssh *ssh, संरचना sshkey *कुंजी, u_char **sigp, size_t *lenp,
    ध्रुव u_char *data, size_t datalen, ध्रुव वर्ण *hostkey_alg,
    ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin, u_int compat)
{
	संरचना sshbuf *m;
	पूर्णाङ्क r;

	debug3_f("entering");
	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshkey_puts(कुंजी, m)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	यदि ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	debug3_f("%s signature len=%zu", hostkey_alg ? hostkey_alg : "(null)",
	    *lenp);

	प्रत्यागम (0);
}

शून्य
mm_decode_activate_server_options(संरचना ssh *ssh, संरचना sshbuf *m)
{
	संरचना sshbuf *config;
	पूर्णाङ्क r;
	u_int i;

	यदि ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	यदि ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	प्रति (i = 0; i < options.अंक_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
}

#define GETPW(b, id) \
	कुरु { \
		यदि ((r = sshbuf_get_string_direct(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		यदि (len != परिमाण(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		memcpy(&pw->id, p, len); \
	} यावत् (0)

संरचना passwd *
mm_getpwnamallow(संरचना ssh *ssh, ध्रुव वर्ण *username)
{
	संरचना sshbuf *m;
	संरचना passwd *pw;
	size_t len;
	पूर्णाङ्क r;
	u_char ok;
	ध्रुव u_char *p;

	debug3_f("entering");

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	यदि ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	यदि (ok == 0) {
		pw = रिक्त;
		गच्छ out;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(परिमाण(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#endif
	यदि ((r = sshbuf_get_cstring(m, &pw->pw_name, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, रिक्त)) != 0 ||
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, रिक्त)) != 0 ||
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(m, &pw->pw_class, रिक्त)) != 0 ||
#endif
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, रिक्त)) != 0)
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

	प्रत्यागम (pw);
}

वर्ण *
mm_auth2_read_banner(शून्य)
{
	संरचना sshbuf *m;
	वर्ण *banner;
	पूर्णाङ्क r;

	debug3_f("entering");

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	यदि ((r = sshbuf_get_cstring(m, &banner, रिक्त)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	यदि (strlen(banner) == 0) {
		मुक्त(banner);
		banner = रिक्त;
	}
	प्रत्यागम (banner);
}

/* Inform the privileged process about service and style */

शून्य
mm_inform_authserv(वर्ण *service, वर्ण *style)
{
	संरचना sshbuf *m;
	पूर्णाङ्क r;

	debug3_f("entering");

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
पूर्णाङ्क
mm_auth_password(संरचना ssh *ssh, वर्ण *password)
{
	संरचना sshbuf *m;
	पूर्णाङ्क r, authenticated = 0;
#ifdef USE_PAM
	u_int maxtries = 0;
#endif

	debug3_f("entering");

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	यदि ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#ifdef USE_PAM
	यदि ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	यदि (maxtries > INT_MAX)
		fatal_fr(r, "bad maxtries");
	sshpam_set_maxtries_reached(maxtries);
#endif

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	प्रत्यागम (authenticated);
}

पूर्णाङ्क
mm_user_कुंजी_allowed(संरचना ssh *ssh, संरचना passwd *pw, संरचना sshkey *कुंजी,
    पूर्णाङ्क pubkey_auth_attempt, संरचना sshauthopt **authoptp)
{
	प्रत्यागम (mm_कुंजी_allowed(MM_USERKEY, रिक्त, रिक्त, कुंजी,
	    pubkey_auth_attempt, authoptp));
}

पूर्णाङ्क
mm_hostbased_कुंजी_allowed(संरचना ssh *ssh, संरचना passwd *pw,
    ध्रुव वर्ण *user, ध्रुव वर्ण *host, संरचना sshkey *कुंजी)
{
	प्रत्यागम (mm_कुंजी_allowed(MM_HOSTKEY, user, host, कुंजी, 0, रिक्त));
}

पूर्णाङ्क
mm_कुंजी_allowed(गणना mm_keytype type, ध्रुव वर्ण *user, ध्रुव वर्ण *host,
    संरचना sshkey *कुंजी, पूर्णाङ्क pubkey_auth_attempt, संरचना sshauthopt **authoptp)
{
	संरचना sshbuf *m;
	पूर्णाङ्क r, allowed = 0;
	संरचना sshauthopt *opts = रिक्त;

	debug3_f("entering");

	यदि (authoptp != रिक्त)
		*authoptp = रिक्त;

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshkey_puts(कुंजी, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	यदि ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal_fr(r, "parse");
	यदि (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	यदि (authoptp != रिक्त) {
		*authoptp = opts;
		opts = रिक्त;
	}
	sshauthopt_free(opts);

	प्रत्यागम allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

पूर्णाङ्क
mm_sshkey_verify(ध्रुव संरचना sshkey *कुंजी, ध्रुव u_char *sig, size_t siglen,
    ध्रुव u_char *data, size_t datalen, ध्रुव वर्ण *sigalg, u_int compat,
    संरचना sshkey_sig_details **sig_detailsp)
{
	संरचना sshbuf *m;
	u_int encoded_ret = 0;
	पूर्णाङ्क r;
	u_char sig_details_present, flags;
	u_int counter;

	debug3_f("entering");

	यदि (sig_detailsp != रिक्त)
		*sig_detailsp = रिक्त;
	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshkey_puts(कुंजी, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == रिक्त ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	यदि ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	यदि (sig_details_present && encoded_ret == 0) {
		यदि ((r = sshbuf_get_u32(m, &counter)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		यदि (sig_detailsp != रिक्त) {
			*sig_detailsp = xcalloc(1, परिमाण(**sig_detailsp));
			(*sig_detailsp)->sk_counter = counter;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	यदि (encoded_ret != 0)
		प्रत्यागम SSH_ERR_SIGNATURE_INVALID;
	प्रत्यागम 0;
}

शून्य
mm_send_keystate(संरचना ssh *ssh, संरचना monitor *monitor)
{
	संरचना sshbuf *m;
	पूर्णाङ्क r;

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

पूर्णाङ्क
mm_pty_allocate(पूर्णाङ्क *ptyfd, पूर्णाङ्क *ttyfd, वर्ण *namebuf, size_t namebuflen)
{
	संरचना sshbuf *m;
	वर्ण *p, *संदेश;
	पूर्णाङ्क success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	यदि ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		यदि (tmp1 >= 0)
			close(tmp1);
		प्रत्यागम 0;
	}
	close(tmp1);
	close(tmp2);

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	यदि ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	यदि (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		प्रत्यागम (0);
	}
	यदि ((r = sshbuf_get_cstring(m, &p, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(m, &संदेश, रिक्त)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	मुक्त(p);

	यदि ((r = sshbuf_put(loginmsg, संदेश, strlen(संदेश))) != 0)
		fatal_fr(r, "put loginmsg");
	मुक्त(संदेश);

	यदि ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	प्रत्यागम (1);
}

शून्य
mm_session_pty_cleanup2(Session *s)
{
	संरचना sshbuf *m;
	पूर्णाङ्क r;

	यदि (s->ttyfd == -1)
		प्रत्यागम;
	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assmble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	यदि (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#ifdef USE_PAM
शून्य
mm_start_pam(संरचना ssh *ssh)
{
	संरचना sshbuf *m;

	debug3_f("entering");
	यदि (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_START, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(शून्य)
{
	संरचना sshbuf *m;
	u_int ret;
	वर्ण *संदेश;
	size_t msglen;
	पूर्णाङ्क r;

	debug3_f("entering");
	यदि (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	यदि ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &संदेश, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, संदेश, msglen)) != 0)
		fatal_fr(r, "buffer error");

	मुक्त(संदेश);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	प्रत्यागम (ret);
}

शून्य *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	संरचना sshbuf *m;
	पूर्णाङ्क r, success;

	debug3_f("entering");
	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	यदि ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "buffer error");
	यदि (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		प्रत्यागम (रिक्त);
	}
	sshbuf_free(m);
	प्रत्यागम (authctxt);
}

पूर्णाङ्क
mm_sshpam_query(शून्य *ctx, वर्ण **name, वर्ण **info,
    u_int *अंक, वर्ण ***prompts, u_int **echo_on)
{
	संरचना sshbuf *m;
	u_int i, n;
	पूर्णाङ्क r, ret;

	debug3_f("entering");
	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	यदि ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, अंक)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_set_maxtries_reached(n);
	यदि (*अंक > PAM_MAX_अंक_संदेश)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *अंक, PAM_MAX_अंक_संदेश);
	*prompts = xcalloc((*अंक + 1), परिमाण(वर्ण *));
	*echo_on = xcalloc((*अंक + 1), परिमाण(u_int));
	प्रति (i = 0; i < *अंक; ++i) {
		यदि ((r = sshbuf_get_cstring(m, &((*prompts)[i]), रिक्त)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	प्रत्यागम (ret);
}

पूर्णाङ्क
mm_sshpam_respond(शून्य *ctx, u_int अंक, वर्ण **resp)
{
	संरचना sshbuf *m;
	u_int n, i;
	पूर्णाङ्क r, ret;

	debug3_f("entering");
	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u32(m, अंक)) != 0)
		fatal_fr(r, "buffer error");
	प्रति (i = 0; i < अंक; ++i) {
		यदि ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	यदि ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	ret = (पूर्णाङ्क)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	प्रत्यागम (ret);
}

शून्य
mm_sshpam_free_ctx(शून्य *ctxtp)
{
	संरचना sshbuf *m;

	debug3_f("entering");
	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_FREE_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_FREE_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_FREE_CTX, m);
	sshbuf_free(m);
}
#endif /* USE_PAM */

/* Request process termination */

शून्य
mm_terminate(शून्य)
{
	संरचना sshbuf *m;

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_TERM, m);
	sshbuf_free(m);
}

/* Request state information */

शून्य
mm_get_state(संरचना ssh *ssh,
    ServerOptions *opts, संरचना sshbuf **confdatap,
    uint64_t *timing_secretp,
    संरचना sshbuf **hostkeysp, संरचना sshbuf **keystatep,
    u_char **pw_namep,
    संरचना sshbuf **authinfop, संरचना sshbuf **auth_optsp)
{
	संरचना sshbuf *m, *config;
	पूर्णाङ्क r;

	debug3_f("entering");

	यदि ((m = sshbuf_new()) == रिक्त || (config = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	यदि ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	यदि (confdatap) {
		यदि ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, रिक्त)) != 0 ||
		    (r = sshbuf_froms(m, authinfop)) != 0 ||
		    (r = sshbuf_froms(m, auth_optsp)) != 0)
			fatal_fr(r, "parse config postauth");
	}
	यदि ((r = deserialise_server_options(config, opts)) != 0)
		fatal_fr(r, "deserialise_server_options");

	sshbuf_free(m);
	sshbuf_free(config);

	debug3_f("done");
}

स्थिर शून्य
mm_chall_setup(वर्ण **name, वर्ण **infotxt, u_int *numprompts,
    वर्ण ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, परिमाण(वर्ण *));
	*echo_on = xcalloc(*numprompts, परिमाण(u_int));
	(*echo_on)[0] = 0;
}

पूर्णाङ्क
mm_bsdauth_query(शून्य *ctx, वर्ण **name, वर्ण **infotxt,
   u_int *numprompts, वर्ण ***prompts, u_int **echo_on)
{
	संरचना sshbuf *m;
	u_int success;
	वर्ण *challenge;
	पूर्णाङ्क r;

	debug3_f("entering");

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	यदि ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	यदि (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		प्रत्यागम (-1);
	}

	/* Get the challenge, and format the response */
	यदि ((r = sshbuf_get_cstring(m, &challenge, रिक्त)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_setup(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	प्रत्यागम (0);
}

पूर्णाङ्क
mm_bsdauth_respond(शून्य *ctx, u_int numresponses, वर्ण **responses)
{
	संरचना sshbuf *m;
	पूर्णाङ्क r, authok;

	debug3_f("entering");
	यदि (numresponses != 1)
		प्रत्यागम (-1);

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	यदि ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	प्रत्यागम ((authok == 0) ? -1 : 0);
}

#ifdef SSH_AUDIT_EVENTS
शून्य
mm_audit_event(संरचना ssh *ssh, ssh_audit_event_t event)
{
	संरचना sshbuf *m;
	पूर्णाङ्क r;

	debug3_f("entering");

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

शून्य
mm_audit_run_command(ध्रुव वर्ण *command)
{
	संरचना sshbuf *m;
	पूर्णाङ्क r;

	debug3_f("entering command %s", command);

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#endif /* SSH_AUDIT_EVENTS */

#ifdef GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	संरचना sshbuf *m;
	OM_uint32 major;
	पूर्णाङ्क r;

	/* Client doesn't get to see the context */
	*ctx = रिक्त;

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_string(m, goid->elements, goid->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	यदि ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	प्रत्यागम (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *in,
    gss_buffer_desc *out, OM_uint32 *flagsp)
{
	संरचना sshbuf *m;
	OM_uint32 major;
	u_int flags;
	पूर्णाङ्क r;

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_string(m, in->मूल्य, in->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	यदि ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, out)) != 0)
		fatal_fr(r, "parse");
	यदि (flagsp != रिक्त) {
		यदि ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	प्रत्यागम (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	संरचना sshbuf *m;
	OM_uint32 major;
	पूर्णाङ्क r;

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_string(m, gssbuf->मूल्य, gssbuf->length)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->मूल्य, gssmic->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	यदि ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	प्रत्यागम(major);
}

पूर्णाङ्क
mm_ssh_gssapi_userok(वर्ण *user)
{
	संरचना sshbuf *m;
	पूर्णाङ्क r, authenticated = 0;

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	यदि ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	प्रत्यागम (authenticated);
}
#endif /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
स्थिर शून्य
server_process_permitopen_list(संरचना ssh *ssh, पूर्णाङ्क listen,
    वर्ण **opens, u_int अंक_opens)
{
	u_int i;
	पूर्णाङ्क port;
	वर्ण *host, *arg, *oarg;
	पूर्णाङ्क where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	ध्रुव वर्ण *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	यदि (अंक_opens == 0)
		प्रत्यागम; /* permit any */

	/* handle keywords: "any" / "none" */
	यदि (अंक_opens == 1 && strcmp(opens[0], "any") == 0)
		प्रत्यागम;
	यदि (अंक_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		प्रत्यागम;
	}
	/* Otherwise treat it as a list of permitted host:port */
	प्रति (i = 0; i < अंक_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		यदि (host == रिक्त)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		यदि (arg == रिक्त || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, host, port);
		मुक्त(oarg);
	}
}

/*
 * Inform channels layer of permitopen options from configuration.
 */
शून्य
server_process_permitopen(संरचना ssh *ssh)
{
	server_process_permitopen_list(ssh, 0,
	    options.permitted_opens, options.अंक_permitted_opens);
	server_process_permitopen_list(ssh, 1,
	    options.permitted_listens, options.अंक_permitted_listens);
}

शून्य
server_process_channel_timeouts(संरचना ssh *ssh)
{
	u_int i;
	द्विगुण secs;
	वर्ण *type;

	debug3_f("setting %u timeouts", options.अंक_channel_timeouts);
	channel_clear_timeouts(ssh);
	प्रति (i = 0; i < options.अंक_channel_timeouts; i++) {
		यदि (parse_pattern_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_add_timeout(ssh, type, secs);
		मुक्त(type);
	}
}

संरचना connection_info *
server_get_connection_info(संरचना ssh *ssh, पूर्णाङ्क populate, पूर्णाङ्क use_dns)
{
	स्थिर संरचना connection_info ci;

	यदि (ssh == रिक्त || !populate)
		प्रत्यागम &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.address = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_port(ssh);
	ci.rdomain = ssh_packet_rdomain_in(ssh);
	प्रत्यागम &ci;
}

