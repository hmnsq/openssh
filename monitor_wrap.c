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
mm_log_handler(LogLevel level, पूर्णांक forced, स्थिरांक अक्षर *संदेश, शून्य *ctx)
{
	संरचना sshbuf *log_संदेश;
	संरचना monitor *mon = (संरचना monitor *)ctx;
	पूर्णांक r;
	माप_प्रकार len;

	जर (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	जर ((log_संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	जर ((r = sshbuf_put_u32(log_संदेश, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_संदेश, level)) != 0 ||
	    (r = sshbuf_put_u32(log_संदेश, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_संदेश, संदेश)) != 0)
		fatal_fr(r, "assemble");
	जर ((len = sshbuf_len(log_संदेश)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_संदेश), len - 4);
	जर (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_संदेश), len) != len) {
		जर (त्रुटि_सं == EPIPE) {
			debug_f("write: %s", म_त्रुटि(त्रुटि_सं));
			cleanup_exit(255);
		}
		fatal_f("write: %s", म_त्रुटि(त्रुटि_सं));
	}
	sshbuf_free(log_संदेश);
}

स्थिर शून्य
mm_reap(शून्य)
{
	पूर्णांक status = -1;

	जर (!mm_is_monitor())
		परत;
	पर्यंत (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		जर (त्रुटि_सं == EINTR)
			सुरूठेवा;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", म_त्रुटि(त्रुटि_सं));
	}
	जर (WIFEXITED(status)) {
		जर (WEXITSTATUS(status) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(status));
			cleanup_exit(255);
		}
	} अन्यथा जर (WIFSIGNALED(status)) {
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
mm_request_send(पूर्णांक sock, गणना monitor_reqtype type, संरचना sshbuf *m)
{
	माप_प्रकार mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	जर (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	जर (atomicio(vwrite, sock, buf, आकार(buf)) != आकार(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		जर (त्रुटि_सं == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", म_त्रुटि(त्रुटि_सं));
	}
}

शून्य
mm_request_receive(पूर्णांक sock, संरचना sshbuf *m)
{
	u_char buf[4], *p = रिक्त;
	u_int संदेश_len;
	पूर्णांक oerrno, r;

	debug3_f("entering");

	जर (atomicio(पठ, sock, buf, आकार(buf)) != आकार(buf)) {
		जर (त्रुटि_सं == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", म_त्रुटि(त्रुटि_सं));
	}
	संदेश_len = PEEK_U32(buf);
	जर (संदेश_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", संदेश_len);
	sshbuf_reset(m);
	जर ((r = sshbuf_reserve(m, संदेश_len, &p)) != 0)
		fatal_fr(r, "reserve");
	जर (atomicio(पठ, sock, p, संदेश_len) != संदेश_len) {
		oerrno = त्रुटि_सं;
		error_f("read: %s", म_त्रुटि(त्रुटि_सं));
		जर (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

शून्य
mm_request_receive_expect(पूर्णांक sock, गणना monitor_reqtype type, संरचना sshbuf *m)
{
	u_char rtype;
	पूर्णांक r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	जर ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	जर (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(पूर्णांक min, पूर्णांक nbits, पूर्णांक max)
{
	BIGNUM *p, *g;
	पूर्णांक r;
	u_char success = 0;
	संरचना sshbuf *m;

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	जर ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	जर (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

	जर ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	परत (dh_new_group(g, p));
}
#endif

शून्य
mm_sshkey_setcompat(संरचना ssh *ssh)
{
	संरचना sshbuf *m;
	पूर्णांक r;

	debug3_f("entering");
	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

पूर्णांक
mm_sshkey_sign(संरचना ssh *ssh, संरचना sshkey *किल्ली, u_char **sigp, माप_प्रकार *lenp,
    स्थिरांक u_char *data, माप_प्रकार datalen, स्थिरांक अक्षर *hostkey_alg,
    स्थिरांक अक्षर *sk_provider, स्थिरांक अक्षर *sk_pin, u_int compat)
{
	संरचना sshbuf *m;
	पूर्णांक r;

	debug3_f("entering");
	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshkey_puts(किल्ली, m)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	जर ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	debug3_f("%s signature len=%zu", hostkey_alg ? hostkey_alg : "(null)",
	    *lenp);

	परत (0);
}

शून्य
mm_decode_activate_server_options(संरचना ssh *ssh, संरचना sshbuf *m)
{
	संरचना sshbuf *config;
	पूर्णांक r;
	u_int i;

	जर ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	जर ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	साठी (i = 0; i < options.अंक_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
}

#define GETPW(b, id) \
	करा { \
		जर ((r = sshbuf_get_string_direct(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		जर (len != आकार(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		स_नकल(&pw->id, p, len); \
	} पर्यंत (0)

संरचना passwd *
mm_getpwnamallow(संरचना ssh *ssh, स्थिरांक अक्षर *username)
{
	संरचना sshbuf *m;
	संरचना passwd *pw;
	माप_प्रकार len;
	पूर्णांक r;
	u_char ok;
	स्थिरांक u_char *p;

	debug3_f("entering");

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	जर ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	जर (ok == 0) {
		pw = रिक्त;
		जा out;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(आकार(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#endif
	जर ((r = sshbuf_get_cstring(m, &pw->pw_name, रिक्त)) != 0 ||
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

	परत (pw);
}

अक्षर *
mm_auth2_read_banner(शून्य)
{
	संरचना sshbuf *m;
	अक्षर *banner;
	पूर्णांक r;

	debug3_f("entering");

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	जर ((r = sshbuf_get_cstring(m, &banner, रिक्त)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	जर (म_माप(banner) == 0) {
		मुक्त(banner);
		banner = रिक्त;
	}
	परत (banner);
}

/* Inform the privileged process about service and style */

शून्य
mm_inform_authserv(अक्षर *service, अक्षर *style)
{
	संरचना sshbuf *m;
	पूर्णांक r;

	debug3_f("entering");

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
पूर्णांक
mm_auth_password(संरचना ssh *ssh, अक्षर *password)
{
	संरचना sshbuf *m;
	पूर्णांक r, authenticated = 0;
#ifdef USE_PAM
	u_int maxtries = 0;
#endif

	debug3_f("entering");

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	जर ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#ifdef USE_PAM
	जर ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	जर (maxtries > पूर्णांक_उच्च)
		fatal_fr(r, "bad maxtries");
	sshpam_set_maxtries_reached(maxtries);
#endif

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	परत (authenticated);
}

पूर्णांक
mm_user_किल्ली_allowed(संरचना ssh *ssh, संरचना passwd *pw, संरचना sshkey *किल्ली,
    पूर्णांक pubkey_auth_attempt, संरचना sshauthopt **authoptp)
{
	परत (mm_किल्ली_allowed(MM_USERKEY, रिक्त, रिक्त, किल्ली,
	    pubkey_auth_attempt, authoptp));
}

पूर्णांक
mm_hostbased_किल्ली_allowed(संरचना ssh *ssh, संरचना passwd *pw,
    स्थिरांक अक्षर *user, स्थिरांक अक्षर *host, संरचना sshkey *किल्ली)
{
	परत (mm_किल्ली_allowed(MM_HOSTKEY, user, host, किल्ली, 0, रिक्त));
}

पूर्णांक
mm_किल्ली_allowed(गणना mm_keytype type, स्थिरांक अक्षर *user, स्थिरांक अक्षर *host,
    संरचना sshkey *किल्ली, पूर्णांक pubkey_auth_attempt, संरचना sshauthopt **authoptp)
{
	संरचना sshbuf *m;
	पूर्णांक r, allowed = 0;
	संरचना sshauthopt *opts = रिक्त;

	debug3_f("entering");

	जर (authoptp != रिक्त)
		*authoptp = रिक्त;

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshkey_puts(किल्ली, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	जर ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal_fr(r, "parse");
	जर (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	जर (authoptp != रिक्त) {
		*authoptp = opts;
		opts = रिक्त;
	}
	sshauthopt_free(opts);

	परत allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

पूर्णांक
mm_sshkey_verify(स्थिरांक संरचना sshkey *किल्ली, स्थिरांक u_char *sig, माप_प्रकार siglen,
    स्थिरांक u_char *data, माप_प्रकार datalen, स्थिरांक अक्षर *sigalg, u_int compat,
    संरचना sshkey_sig_details **sig_detailsp)
{
	संरचना sshbuf *m;
	u_int encoded_ret = 0;
	पूर्णांक r;
	u_char sig_details_present, flags;
	u_int counter;

	debug3_f("entering");

	जर (sig_detailsp != रिक्त)
		*sig_detailsp = रिक्त;
	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshkey_puts(किल्ली, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == रिक्त ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	जर ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	जर (sig_details_present && encoded_ret == 0) {
		जर ((r = sshbuf_get_u32(m, &counter)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		जर (sig_detailsp != रिक्त) {
			*sig_detailsp = xcalloc(1, आकार(**sig_detailsp));
			(*sig_detailsp)->sk_counter = counter;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	जर (encoded_ret != 0)
		परत SSH_ERR_SIGNATURE_INVALID;
	परत 0;
}

शून्य
mm_send_keystate(संरचना ssh *ssh, संरचना monitor *monitor)
{
	संरचना sshbuf *m;
	पूर्णांक r;

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

पूर्णांक
mm_pty_allocate(पूर्णांक *ptyfd, पूर्णांक *ttyfd, अक्षर *namebuf, माप_प्रकार namebuflen)
{
	संरचना sshbuf *m;
	अक्षर *p, *संदेश;
	पूर्णांक success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	जर ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		जर (tmp1 >= 0)
			बंद(tmp1);
		परत 0;
	}
	बंद(tmp1);
	बंद(tmp2);

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	जर ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	जर (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		परत (0);
	}
	जर ((r = sshbuf_get_cstring(m, &p, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(m, &संदेश, रिक्त)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	मुक्त(p);

	जर ((r = sshbuf_put(loginmsg, संदेश, म_माप(संदेश))) != 0)
		fatal_fr(r, "put loginmsg");
	मुक्त(संदेश);

	जर ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	परत (1);
}

शून्य
mm_session_pty_cleanup2(Session *s)
{
	संरचना sshbuf *m;
	पूर्णांक r;

	जर (s->ttyfd == -1)
		परत;
	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assmble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	जर (s->ptymaster != -1 && बंद(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, म_त्रुटि(त्रुटि_सं));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#ifdef USE_PAM
शून्य
mm_start_pam(संरचना ssh *ssh)
{
	संरचना sshbuf *m;

	debug3_f("entering");
	जर (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_START, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(शून्य)
{
	संरचना sshbuf *m;
	u_int ret;
	अक्षर *संदेश;
	माप_प्रकार msglen;
	पूर्णांक r;

	debug3_f("entering");
	जर (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	जर ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &संदेश, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, संदेश, msglen)) != 0)
		fatal_fr(r, "buffer error");

	मुक्त(संदेश);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	परत (ret);
}

शून्य *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	संरचना sshbuf *m;
	पूर्णांक r, success;

	debug3_f("entering");
	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	जर ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "buffer error");
	जर (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		परत (रिक्त);
	}
	sshbuf_free(m);
	परत (authctxt);
}

पूर्णांक
mm_sshpam_query(शून्य *ctx, अक्षर **name, अक्षर **info,
    u_int *अंक, अक्षर ***prompts, u_int **echo_on)
{
	संरचना sshbuf *m;
	u_int i, n;
	पूर्णांक r, ret;

	debug3_f("entering");
	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	जर ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, अंक)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_set_maxtries_reached(n);
	जर (*अंक > PAM_MAX_अंक_संदेश)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *अंक, PAM_MAX_अंक_संदेश);
	*prompts = xcalloc((*अंक + 1), आकार(अक्षर *));
	*echo_on = xcalloc((*अंक + 1), आकार(u_int));
	साठी (i = 0; i < *अंक; ++i) {
		जर ((r = sshbuf_get_cstring(m, &((*prompts)[i]), रिक्त)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	परत (ret);
}

पूर्णांक
mm_sshpam_respond(शून्य *ctx, u_int अंक, अक्षर **resp)
{
	संरचना sshbuf *m;
	u_int n, i;
	पूर्णांक r, ret;

	debug3_f("entering");
	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_u32(m, अंक)) != 0)
		fatal_fr(r, "buffer error");
	साठी (i = 0; i < अंक; ++i) {
		जर ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	जर ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	ret = (पूर्णांक)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	परत (ret);
}

शून्य
mm_sshpam_free_ctx(शून्य *ctxtp)
{
	संरचना sshbuf *m;

	debug3_f("entering");
	जर ((m = sshbuf_new()) == रिक्त)
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

	जर ((m = sshbuf_new()) == रिक्त)
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
	पूर्णांक r;

	debug3_f("entering");

	जर ((m = sshbuf_new()) == रिक्त || (config = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	जर ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	जर (confdatap) {
		जर ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, रिक्त)) != 0 ||
		    (r = sshbuf_froms(m, authinfop)) != 0 ||
		    (r = sshbuf_froms(m, auth_optsp)) != 0)
			fatal_fr(r, "parse config postauth");
	}
	जर ((r = deserialise_server_options(config, opts)) != 0)
		fatal_fr(r, "deserialise_server_options");

	sshbuf_free(m);
	sshbuf_free(config);

	debug3_f("done");
}

स्थिर शून्य
mm_chall_setup(अक्षर **name, अक्षर **infotxt, u_int *numprompts,
    अक्षर ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, आकार(अक्षर *));
	*echo_on = xcalloc(*numprompts, आकार(u_int));
	(*echo_on)[0] = 0;
}

पूर्णांक
mm_bsdauth_query(शून्य *ctx, अक्षर **name, अक्षर **infotxt,
   u_int *numprompts, अक्षर ***prompts, u_int **echo_on)
{
	संरचना sshbuf *m;
	u_int success;
	अक्षर *challenge;
	पूर्णांक r;

	debug3_f("entering");

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	जर ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	जर (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		परत (-1);
	}

	/* Get the challenge, and format the response */
	जर ((r = sshbuf_get_cstring(m, &challenge, रिक्त)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_setup(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	परत (0);
}

पूर्णांक
mm_bsdauth_respond(शून्य *ctx, u_int numresponses, अक्षर **responses)
{
	संरचना sshbuf *m;
	पूर्णांक r, authok;

	debug3_f("entering");
	जर (numresponses != 1)
		परत (-1);

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	जर ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	परत ((authok == 0) ? -1 : 0);
}

#ifdef SSH_AUDIT_EVENTS
शून्य
mm_audit_event(संरचना ssh *ssh, ssh_audit_event_t event)
{
	संरचना sshbuf *m;
	पूर्णांक r;

	debug3_f("entering");

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

शून्य
mm_audit_run_command(स्थिरांक अक्षर *command)
{
	संरचना sshbuf *m;
	पूर्णांक r;

	debug3_f("entering command %s", command);

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_cstring(m, command)) != 0)
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
	पूर्णांक r;

	/* Client doesn't get to see the context */
	*ctx = रिक्त;

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_string(m, goid->elements, goid->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	जर ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	परत (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *in,
    gss_buffer_desc *out, OM_uint32 *flagsp)
{
	संरचना sshbuf *m;
	OM_uint32 major;
	u_int flags;
	पूर्णांक r;

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_string(m, in->मूल्य, in->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	जर ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, out)) != 0)
		fatal_fr(r, "parse");
	जर (flagsp != रिक्त) {
		जर ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	परत (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	संरचना sshbuf *m;
	OM_uint32 major;
	पूर्णांक r;

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_string(m, gssbuf->मूल्य, gssbuf->length)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->मूल्य, gssmic->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	जर ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	परत(major);
}

पूर्णांक
mm_ssh_gssapi_userok(अक्षर *user)
{
	संरचना sshbuf *m;
	पूर्णांक r, authenticated = 0;

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	जर ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	परत (authenticated);
}
#endif /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
स्थिर शून्य
server_process_permitopen_list(संरचना ssh *ssh, पूर्णांक listen,
    अक्षर **opens, u_int अंक_opens)
{
	u_int i;
	पूर्णांक port;
	अक्षर *host, *arg, *oarg;
	पूर्णांक where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	स्थिरांक अक्षर *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	जर (अंक_opens == 0)
		परत; /* permit any */

	/* handle keywords: "any" / "none" */
	जर (अंक_opens == 1 && म_भेद(opens[0], "any") == 0)
		परत;
	जर (अंक_opens == 1 && म_भेद(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		परत;
	}
	/* Otherwise treat it as a list of permitted host:port */
	साठी (i = 0; i < अंक_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		जर (host == रिक्त)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		जर (arg == रिक्त || ((port = permitopen_port(arg)) < 0))
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
	अक्षर *type;

	debug3_f("setting %u timeouts", options.अंक_channel_timeouts);
	channel_clear_timeouts(ssh);
	साठी (i = 0; i < options.अंक_channel_timeouts; i++) {
		जर (parse_pattern_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_add_timeout(ssh, type, secs);
		मुक्त(type);
	}
}

संरचना connection_info *
server_get_connection_info(संरचना ssh *ssh, पूर्णांक populate, पूर्णांक use_dns)
{
	स्थिर संरचना connection_info ci;

	जर (ssh == रिक्त || !populate)
		परत &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.address = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_port(ssh);
	ci.rdomain = ssh_packet_rdomain_in(ssh);
	परत &ci;
}

