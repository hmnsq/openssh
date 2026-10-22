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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/uio.h>
#समावेश <sys/queue.h>
#समावेश <sys/wait.h>

#समावेश <errno.h>
#समावेश <pwd.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <unistd.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/bn.h>
#समावेश <openssl/dh.h>
#समावेश <openssl/evp.h>
#पूर्ण_अगर

#समावेश "xmalloc.h"
#समावेश "ssh.h"
#अगर_घोषित WITH_OPENSSL
#समावेश "dh.h"
#पूर्ण_अगर
#समावेश "sshbuf.h"
#समावेश "sshkey.h"
#समावेश "cipher.h"
#समावेश "kex.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "auth-options.h"
#समावेश "packet.h"
#समावेश "mac.h"
#समावेश "log.h"
#समावेश "auth-pam.h"
#समावेश "monitor.h"
#अगर_घोषित GSSAPI
#समावेश "ssh-gss.h"
#पूर्ण_अगर
#समावेश "atomicio.h"
#समावेश "monitor_fdpass.h"
#समावेश "misc.h"

#समावेश "channels.h"
#समावेश "session.h"
#समावेश "servconf.h"
#समावेश "monitor_wrap.h"
#समावेश "srclimit.h"

#समावेश "ssherr.h"

/* Imports */
बाह्य काष्ठा monitor *pmonitor;
बाह्य काष्ठा sshbuf *loginmsg;
बाह्य ServerOptions options;

व्योम
mm_log_handler(LogLevel level, पूर्णांक forced, स्थिर अक्षर *संदेश, व्योम *ctx)
{
	काष्ठा sshbuf *log_संदेश;
	काष्ठा monitor *mon = (काष्ठा monitor *)ctx;
	पूर्णांक r;
	माप_प्रकार len;

	अगर (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	अगर ((log_संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	अगर ((r = sshbuf_put_u32(log_संदेश, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_संदेश, level)) != 0 ||
	    (r = sshbuf_put_u32(log_संदेश, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_संदेश, संदेश)) != 0)
		fatal_fr(r, "assemble");
	अगर ((len = sshbuf_len(log_संदेश)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_संदेश), len - 4);
	अगर (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_संदेश), len) != len) {
		अगर (त्रुटि_सं == EPIPE) {
			debug_f("write: %s", म_त्रुटि(त्रुटि_सं));
			cleanup_exit(255);
		}
		fatal_f("write: %s", म_त्रुटि(त्रुटि_सं));
	}
	sshbuf_free(log_संदेश);
}

अटल व्योम
mm_reap(व्योम)
{
	पूर्णांक status = -1;

	अगर (!mm_is_monitor())
		वापस;
	जबतक (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		अगर (त्रुटि_सं == EINTR)
			जारी;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", म_त्रुटि(त्रुटि_सं));
	}
	अगर (WIFEXITED(status)) {
		अगर (WEXITSTATUS(status) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(status));
			cleanup_exit(255);
		}
	} अन्यथा अगर (WIFSIGNALED(status)) {
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

व्योम
mm_request_send(पूर्णांक sock, क्रमागत monitor_reqtype type, काष्ठा sshbuf *m)
{
	माप_प्रकार mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	अगर (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	अगर (atomicio(vwrite, sock, buf, माप(buf)) != माप(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		अगर (त्रुटि_सं == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", म_त्रुटि(त्रुटि_सं));
	}
}

व्योम
mm_request_receive(पूर्णांक sock, काष्ठा sshbuf *m)
{
	u_char buf[4], *p = शून्य;
	u_int संदेश_len;
	पूर्णांक oerrno, r;

	debug3_f("entering");

	अगर (atomicio(पढ़ो, sock, buf, माप(buf)) != माप(buf)) {
		अगर (त्रुटि_सं == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", म_त्रुटि(त्रुटि_सं));
	}
	संदेश_len = PEEK_U32(buf);
	अगर (संदेश_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", संदेश_len);
	sshbuf_reset(m);
	अगर ((r = sshbuf_reserve(m, संदेश_len, &p)) != 0)
		fatal_fr(r, "reserve");
	अगर (atomicio(पढ़ो, sock, p, संदेश_len) != संदेश_len) {
		oerrno = त्रुटि_सं;
		error_f("read: %s", म_त्रुटि(त्रुटि_सं));
		अगर (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

व्योम
mm_request_receive_expect(पूर्णांक sock, क्रमागत monitor_reqtype type, काष्ठा sshbuf *m)
{
	u_char rtype;
	पूर्णांक r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	अगर ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	अगर (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#अगर_घोषित WITH_OPENSSL
DH *
mm_choose_dh(पूर्णांक min, पूर्णांक nbits, पूर्णांक max)
{
	BIGNUM *p, *g;
	पूर्णांक r;
	u_char success = 0;
	काष्ठा sshbuf *m;

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	अगर ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	अगर (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

	अगर ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	वापस (dh_new_group(g, p));
}
#पूर्ण_अगर

व्योम
mm_sshkey_setcompat(काष्ठा ssh *ssh)
{
	काष्ठा sshbuf *m;
	पूर्णांक r;

	debug3_f("entering");
	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

पूर्णांक
mm_sshkey_sign(काष्ठा ssh *ssh, काष्ठा sshkey *कुंजी, u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार datalen, स्थिर अक्षर *hostkey_alg,
    स्थिर अक्षर *sk_provider, स्थिर अक्षर *sk_pin, u_int compat)
{
	काष्ठा sshbuf *m;
	पूर्णांक r;

	debug3_f("entering");
	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshkey_puts(कुंजी, m)) != 0 ||
	    (r = sshbuf_put_string(m, तथ्य, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	अगर ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	debug3_f("%s signature len=%zu", hostkey_alg ? hostkey_alg : "(null)",
	    *lenp);

	वापस (0);
}

व्योम
mm_decode_activate_server_options(काष्ठा ssh *ssh, काष्ठा sshbuf *m)
{
	काष्ठा sshbuf *config;
	पूर्णांक r;
	u_int i;

	अगर ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	अगर ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	क्रम (i = 0; i < options.अंक_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
}

#घोषणा GETPW(b, id) \
	करो { \
		अगर ((r = sshbuf_get_string_direct(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		अगर (len != माप(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		स_नकल(&pw->id, p, len); \
	} जबतक (0)

काष्ठा passwd *
mm_getpwnamallow(काष्ठा ssh *ssh, स्थिर अक्षर *username)
{
	काष्ठा sshbuf *m;
	काष्ठा passwd *pw;
	माप_प्रकार len;
	पूर्णांक r;
	u_char ok;
	स्थिर u_char *p;

	debug3_f("entering");

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	अगर ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	अगर (ok == 0) {
		pw = शून्य;
		जाओ out;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(माप(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#अगर_घोषित HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#पूर्ण_अगर
#अगर_घोषित HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#पूर्ण_अगर
	अगर ((r = sshbuf_get_cstring(m, &pw->pw_name, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, शून्य)) != 0 ||
#अगर_घोषित HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, शून्य)) != 0 ||
#पूर्ण_अगर
#अगर_घोषित HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(m, &pw->pw_class, शून्य)) != 0 ||
#पूर्ण_अगर
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, शून्य)) != 0)
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

	वापस (pw);
}

अक्षर *
mm_auth2_read_banner(व्योम)
{
	काष्ठा sshbuf *m;
	अक्षर *banner;
	पूर्णांक r;

	debug3_f("entering");

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	अगर ((r = sshbuf_get_cstring(m, &banner, शून्य)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	अगर (म_माप(banner) == 0) {
		मुक्त(banner);
		banner = शून्य;
	}
	वापस (banner);
}

/* Inform the privileged process about service and style */

व्योम
mm_inform_authserv(अक्षर *service, अक्षर *style)
{
	काष्ठा sshbuf *m;
	पूर्णांक r;

	debug3_f("entering");

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
पूर्णांक
mm_auth_password(काष्ठा ssh *ssh, अक्षर *password)
{
	काष्ठा sshbuf *m;
	पूर्णांक r, authenticated = 0;
#अगर_घोषित USE_PAM
	u_int maxtries = 0;
#पूर्ण_अगर

	debug3_f("entering");

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	अगर ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#अगर_घोषित USE_PAM
	अगर ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	अगर (maxtries > पूर्णांक_उच्च)
		fatal_fr(r, "bad maxtries");
	sshpam_set_maxtries_reached(maxtries);
#पूर्ण_अगर

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	वापस (authenticated);
}

पूर्णांक
mm_user_कुंजी_allowed(काष्ठा ssh *ssh, काष्ठा passwd *pw, काष्ठा sshkey *कुंजी,
    पूर्णांक pubkey_auth_attempt, काष्ठा sshauthopt **authoptp)
{
	वापस (mm_कुंजी_allowed(MM_USERKEY, शून्य, शून्य, कुंजी,
	    pubkey_auth_attempt, authoptp));
}

पूर्णांक
mm_hostbased_कुंजी_allowed(काष्ठा ssh *ssh, काष्ठा passwd *pw,
    स्थिर अक्षर *user, स्थिर अक्षर *host, काष्ठा sshkey *कुंजी)
{
	वापस (mm_कुंजी_allowed(MM_HOSTKEY, user, host, कुंजी, 0, शून्य));
}

पूर्णांक
mm_कुंजी_allowed(क्रमागत mm_keytype type, स्थिर अक्षर *user, स्थिर अक्षर *host,
    काष्ठा sshkey *कुंजी, पूर्णांक pubkey_auth_attempt, काष्ठा sshauthopt **authoptp)
{
	काष्ठा sshbuf *m;
	पूर्णांक r, allowed = 0;
	काष्ठा sshauthopt *opts = शून्य;

	debug3_f("entering");

	अगर (authoptp != शून्य)
		*authoptp = शून्य;

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshkey_puts(कुंजी, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	अगर ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal_fr(r, "parse");
	अगर (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	अगर (authoptp != शून्य) {
		*authoptp = opts;
		opts = शून्य;
	}
	sshauthopt_free(opts);

	वापस allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

पूर्णांक
mm_sshkey_verify(स्थिर काष्ठा sshkey *कुंजी, स्थिर u_char *sig, माप_प्रकार siglen,
    स्थिर u_char *तथ्य, माप_प्रकार datalen, स्थिर अक्षर *sigalg, u_int compat,
    काष्ठा sshkey_sig_details **sig_detailsp)
{
	काष्ठा sshbuf *m;
	u_int encoded_ret = 0;
	पूर्णांक r;
	u_char sig_details_present, flags;
	u_int गणक;

	debug3_f("entering");

	अगर (sig_detailsp != शून्य)
		*sig_detailsp = शून्य;
	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshkey_puts(कुंजी, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, तथ्य, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == शून्य ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	अगर ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	अगर (sig_details_present && encoded_ret == 0) {
		अगर ((r = sshbuf_get_u32(m, &गणक)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		अगर (sig_detailsp != शून्य) {
			*sig_detailsp = xcalloc(1, माप(**sig_detailsp));
			(*sig_detailsp)->sk_गणक = गणक;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	अगर (encoded_ret != 0)
		वापस SSH_ERR_SIGNATURE_INVALID;
	वापस 0;
}

व्योम
mm_send_keystate(काष्ठा ssh *ssh, काष्ठा monitor *monitor)
{
	काष्ठा sshbuf *m;
	पूर्णांक r;

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

पूर्णांक
mm_pty_allocate(पूर्णांक *ptyfd, पूर्णांक *ttyfd, अक्षर *namebuf, माप_प्रकार namebuflen)
{
	काष्ठा sshbuf *m;
	अक्षर *p, *संदेश;
	पूर्णांक success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	अगर ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		अगर (tmp1 >= 0)
			बंद(tmp1);
		वापस 0;
	}
	बंद(tmp1);
	बंद(tmp2);

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	अगर ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	अगर (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		वापस (0);
	}
	अगर ((r = sshbuf_get_cstring(m, &p, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(m, &संदेश, शून्य)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	मुक्त(p);

	अगर ((r = sshbuf_put(loginmsg, संदेश, म_माप(संदेश))) != 0)
		fatal_fr(r, "put loginmsg");
	मुक्त(संदेश);

	अगर ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	वापस (1);
}

व्योम
mm_session_pty_cleanup2(Session *s)
{
	काष्ठा sshbuf *m;
	पूर्णांक r;

	अगर (s->ttyfd == -1)
		वापस;
	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assmble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	अगर (s->ptymaster != -1 && बंद(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, म_त्रुटि(त्रुटि_सं));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#अगर_घोषित USE_PAM
व्योम
mm_start_pam(काष्ठा ssh *ssh)
{
	काष्ठा sshbuf *m;

	debug3_f("entering");
	अगर (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_START, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(व्योम)
{
	काष्ठा sshbuf *m;
	u_int ret;
	अक्षर *संदेश;
	माप_प्रकार msglen;
	पूर्णांक r;

	debug3_f("entering");
	अगर (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	अगर ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &संदेश, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, संदेश, msglen)) != 0)
		fatal_fr(r, "buffer error");

	मुक्त(संदेश);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	वापस (ret);
}

व्योम *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	काष्ठा sshbuf *m;
	पूर्णांक r, success;

	debug3_f("entering");
	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	अगर ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "buffer error");
	अगर (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		वापस (शून्य);
	}
	sshbuf_free(m);
	वापस (authctxt);
}

पूर्णांक
mm_sshpam_query(व्योम *ctx, अक्षर **name, अक्षर **info,
    u_int *अंक, अक्षर ***prompts, u_int **echo_on)
{
	काष्ठा sshbuf *m;
	u_int i, n;
	पूर्णांक r, ret;

	debug3_f("entering");
	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	अगर ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, शून्य)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, अंक)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_set_maxtries_reached(n);
	अगर (*अंक > PAM_MAX_अंक_संदेश)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *अंक, PAM_MAX_अंक_संदेश);
	*prompts = xcalloc((*अंक + 1), माप(अक्षर *));
	*echo_on = xcalloc((*अंक + 1), माप(u_int));
	क्रम (i = 0; i < *अंक; ++i) {
		अगर ((r = sshbuf_get_cstring(m, &((*prompts)[i]), शून्य)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	वापस (ret);
}

पूर्णांक
mm_sshpam_respond(व्योम *ctx, u_int अंक, अक्षर **resp)
{
	काष्ठा sshbuf *m;
	u_int n, i;
	पूर्णांक r, ret;

	debug3_f("entering");
	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u32(m, अंक)) != 0)
		fatal_fr(r, "buffer error");
	क्रम (i = 0; i < अंक; ++i) {
		अगर ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	अगर ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	ret = (पूर्णांक)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	वापस (ret);
}

व्योम
mm_sshpam_free_ctx(व्योम *ctxtp)
{
	काष्ठा sshbuf *m;

	debug3_f("entering");
	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_FREE_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_FREE_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_FREE_CTX, m);
	sshbuf_free(m);
}
#पूर्ण_अगर /* USE_PAM */

/* Request process termination */

व्योम
mm_terminate(व्योम)
{
	काष्ठा sshbuf *m;

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_TERM, m);
	sshbuf_free(m);
}

/* Request state information */

व्योम
mm_get_state(काष्ठा ssh *ssh,
    ServerOptions *opts, काष्ठा sshbuf **confdatap,
    uint64_t *timing_secretp,
    काष्ठा sshbuf **hostkeysp, काष्ठा sshbuf **keystatep,
    u_char **pw_namep,
    काष्ठा sshbuf **authinfop, काष्ठा sshbuf **auth_optsp)
{
	काष्ठा sshbuf *m, *config;
	पूर्णांक r;

	debug3_f("entering");

	अगर ((m = sshbuf_new()) == शून्य || (config = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	अगर ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	अगर (confdatap) {
		अगर ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, शून्य)) != 0 ||
		    (r = sshbuf_froms(m, authinfop)) != 0 ||
		    (r = sshbuf_froms(m, auth_optsp)) != 0)
			fatal_fr(r, "parse config postauth");
	}
	अगर ((r = deserialise_server_options(config, opts)) != 0)
		fatal_fr(r, "deserialise_server_options");

	sshbuf_free(m);
	sshbuf_free(config);

	debug3_f("done");
}

अटल व्योम
mm_chall_setup(अक्षर **name, अक्षर **infotxt, u_int *numprompts,
    अक्षर ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, माप(अक्षर *));
	*echo_on = xcalloc(*numprompts, माप(u_int));
	(*echo_on)[0] = 0;
}

पूर्णांक
mm_bsdauth_query(व्योम *ctx, अक्षर **name, अक्षर **infotxt,
   u_int *numprompts, अक्षर ***prompts, u_int **echo_on)
{
	काष्ठा sshbuf *m;
	u_int success;
	अक्षर *challenge;
	पूर्णांक r;

	debug3_f("entering");

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	अगर ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	अगर (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		वापस (-1);
	}

	/* Get the challenge, and format the response */
	अगर ((r = sshbuf_get_cstring(m, &challenge, शून्य)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_setup(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	वापस (0);
}

पूर्णांक
mm_bsdauth_respond(व्योम *ctx, u_int numresponses, अक्षर **responses)
{
	काष्ठा sshbuf *m;
	पूर्णांक r, authok;

	debug3_f("entering");
	अगर (numresponses != 1)
		वापस (-1);

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	अगर ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	वापस ((authok == 0) ? -1 : 0);
}

#अगर_घोषित SSH_AUDIT_EVENTS
व्योम
mm_audit_event(काष्ठा ssh *ssh, ssh_audit_event_t event)
{
	काष्ठा sshbuf *m;
	पूर्णांक r;

	debug3_f("entering");

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

व्योम
mm_audit_run_command(स्थिर अक्षर *command)
{
	काष्ठा sshbuf *m;
	पूर्णांक r;

	debug3_f("entering command %s", command);

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#पूर्ण_अगर /* SSH_AUDIT_EVENTS */

#अगर_घोषित GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	काष्ठा sshbuf *m;
	OM_uint32 major;
	पूर्णांक r;

	/* Client doesn't get to see the context */
	*ctx = शून्य;

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_string(m, goid->elements, goid->लंबाई)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	अगर ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	वापस (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_बफर_desc *in,
    gss_बफर_desc *out, OM_uint32 *flagsp)
{
	काष्ठा sshbuf *m;
	OM_uint32 major;
	u_int flags;
	पूर्णांक r;

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_string(m, in->मूल्य, in->लंबाई)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	अगर ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_बफर_desc(m, out)) != 0)
		fatal_fr(r, "parse");
	अगर (flagsp != शून्य) {
		अगर ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	वापस (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_बफर_t gssbuf, gss_बफर_t gssmic)
{
	काष्ठा sshbuf *m;
	OM_uint32 major;
	पूर्णांक r;

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_string(m, gssbuf->मूल्य, gssbuf->लंबाई)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->मूल्य, gssmic->लंबाई)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	अगर ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	वापस(major);
}

पूर्णांक
mm_ssh_gssapi_userok(अक्षर *user)
{
	काष्ठा sshbuf *m;
	पूर्णांक r, authenticated = 0;

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	अगर ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	वापस (authenticated);
}
#पूर्ण_अगर /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
अटल व्योम
server_process_permitopen_list(काष्ठा ssh *ssh, पूर्णांक listen,
    अक्षर **opens, u_int अंक_opens)
{
	u_int i;
	पूर्णांक port;
	अक्षर *host, *arg, *oarg;
	पूर्णांक where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	स्थिर अक्षर *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	अगर (अंक_opens == 0)
		वापस; /* permit any */

	/* handle keywords: "any" / "none" */
	अगर (अंक_opens == 1 && म_भेद(opens[0], "any") == 0)
		वापस;
	अगर (अंक_opens == 1 && म_भेद(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		वापस;
	}
	/* Otherwise treat it as a list of permitted host:port */
	क्रम (i = 0; i < अंक_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		अगर (host == शून्य)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		अगर (arg == शून्य || ((port = permitopen_port(arg)) < 0))
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
व्योम
server_process_permitopen(काष्ठा ssh *ssh)
{
	server_process_permitopen_list(ssh, 0,
	    options.permitted_opens, options.अंक_permitted_opens);
	server_process_permitopen_list(ssh, 1,
	    options.permitted_listens, options.अंक_permitted_listens);
}

व्योम
server_process_channel_timeouts(काष्ठा ssh *ssh)
{
	u_int i;
	द्विगुन secs;
	अक्षर *type;

	debug3_f("setting %u timeouts", options.अंक_channel_timeouts);
	channel_clear_timeouts(ssh);
	क्रम (i = 0; i < options.अंक_channel_timeouts; i++) {
		अगर (parse_pattern_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_add_timeout(ssh, type, secs);
		मुक्त(type);
	}
}

काष्ठा connection_info *
server_get_connection_info(काष्ठा ssh *ssh, पूर्णांक populate, पूर्णांक use_dns)
{
	अटल काष्ठा connection_info ci;

	अगर (ssh == शून्य || !populate)
		वापस &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.address = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_port(ssh);
	ci.rdomain = ssh_packet_rdomain_in(ssh);
	वापस &ci;
}

