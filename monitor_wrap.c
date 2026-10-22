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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/uio.h>
#ଅନ୍ତର୍ଭାଵ <sys/queue.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/dh.h>
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
#endif

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ "dh.h"
#endif
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "cipher.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "auth-options.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "mac.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "auth-pam.h"
#ଅନ୍ତର୍ଭାଵ "monitor.h"
#ifdef GSSAPI
#ଅନ୍ତର୍ଭାଵ "ssh-gss.h"
#endif
#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "monitor_fdpass.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"

#ଅନ୍ତର୍ଭାଵ "channels.h"
#ଅନ୍ତର୍ଭାଵ "session.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "monitor_wrap.h"
#ଅନ୍ତର୍ଭାଵ "srclimit.h"

#ଅନ୍ତର୍ଭାଵ "ssherr.h"

/* Imports */
ବାହ୍ୟ ସଂରଚନା monitor *pmonitor;
ବାହ୍ୟ ସଂରଚନା sshbuf *loginmsg;
ବାହ୍ୟ ServerOptions options;

ଶୂନ୍ୟ
mm_log_handler(LogLevel level, ପୂର୍ଣ୍ଣସଂଖ୍ୟା forced, ଅଚଳ ଅକ୍ଷର *ସନ୍ଦେଶ, ଶୂନ୍ୟ *ctx)
{
	ସଂରଚନା sshbuf *log_ସନ୍ଦେଶ;
	ସଂରଚନା monitor *mon = (ସଂରଚନା monitor *)ctx;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	size_t len;

	ଯଦି (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	ଯଦି ((log_ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	ଯଦି ((r = sshbuf_put_u32(log_ସନ୍ଦେଶ, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_ସନ୍ଦେଶ, level)) != 0 ||
	    (r = sshbuf_put_u32(log_ସନ୍ଦେଶ, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_ସନ୍ଦେଶ, ସନ୍ଦେଶ)) != 0)
		fatal_fr(r, "assemble");
	ଯଦି ((len = sshbuf_len(log_ସନ୍ଦେଶ)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_ସନ୍ଦେଶ), len - 4);
	ଯଦି (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_ସନ୍ଦେଶ), len) != len) {
		ଯଦି (errno == EPIPE) {
			debug_f("write: %s", strerror(errno));
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
	sshbuf_free(log_ସନ୍ଦେଶ);
}

ସ୍ଥିର ଶୂନ୍ୟ
mm_reap(ଶୂନ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status = -1;

	ଯଦି (!mm_is_monitor())
		ଫେରନ୍ତୁ;
	ଯେତେବେଳେ (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		ଯଦି (errno == EINTR)
			ଜାରି;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ଯଦି (WIFEXITED(status)) {
		ଯଦି (WEXITSTATUS(status) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(status));
			cleanup_exit(255);
		}
	} ଅନ୍ୟଥା ଯଦି (WIFSIGNALED(status)) {
		error_f("child terminated by signal %d",
		    WTERMSIG(status));
		cleanup_exit(signal_is_crash(WTERMSIG(status)) ?
		    EXIT_CHILD_CRASH : 255);
	} ଅନ୍ୟଥା {
		error_f("child terminated abnormally (status=0x%x)",
		    status);
		cleanup_exit(EXIT_CHILD_CRASH);
	}
}

ଶୂନ୍ୟ
mm_request_send(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ଗଣନା monitor_reqtype type, ସଂରଚନା sshbuf *m)
{
	size_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	ଯଦି (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	ଯଦି (atomicio(vwrite, sock, buf, ଆକାର(buf)) != ଆକାର(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		ଯଦି (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
}

ଶୂନ୍ୟ
mm_request_receive(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	u_char buf[4], *p = ଖାଲି;
	u_int ସନ୍ଦେଶ_len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା oerrno, r;

	debug3_f("entering");

	ଯଦି (atomicio(ପଠ, sock, buf, ଆକାର(buf)) != ଆକାର(buf)) {
		ଯଦି (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", strerror(errno));
	}
	ସନ୍ଦେଶ_len = PEEK_U32(buf);
	ଯଦି (ସନ୍ଦେଶ_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", ସନ୍ଦେଶ_len);
	sshbuf_reset(m);
	ଯଦି ((r = sshbuf_reserve(m, ସନ୍ଦେଶ_len, &p)) != 0)
		fatal_fr(r, "reserve");
	ଯଦି (atomicio(ପଠ, sock, p, ସନ୍ଦେଶ_len) != ସନ୍ଦେଶ_len) {
		oerrno = errno;
		error_f("read: %s", strerror(errno));
		ଯଦି (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

ଶୂନ୍ୟ
mm_request_receive_expect(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ଗଣନା monitor_reqtype type, ସଂରଚନା sshbuf *m)
{
	u_char rtype;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	ଯଦି ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	ଯଦି (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(ପୂର୍ଣ୍ଣସଂଖ୍ୟା min, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nbits, ପୂର୍ଣ୍ଣସଂଖ୍ୟା max)
{
	BIGNUM *p, *g;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char success = 0;
	ସଂରଚନା sshbuf *m;

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	ଯଦି ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ଯଦି (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

	ଯଦି ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	ଫେରନ୍ତୁ (dh_new_group(g, p));
}
#endif

ଶୂନ୍ୟ
mm_sshkey_setcompat(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା sshbuf *m;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");
	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_sshkey_sign(ସଂରଚନା ssh *ssh, ସଂରଚନା sshkey *ଚାବି, u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t datalen, ଅଚଳ ଅକ୍ଷର *hostkey_alg,
    ଅଚଳ ଅକ୍ଷର *sk_provider, ଅଚଳ ଅକ୍ଷର *sk_pin, u_int compat)
{
	ସଂରଚନା sshbuf *m;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");
	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshkey_puts(ଚାବି, m)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	ଯଦି ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	debug3_f("%s signature len=%zu", hostkey_alg ? hostkey_alg : "(null)",
	    *lenp);

	ଫେରନ୍ତୁ (0);
}

ଶୂନ୍ୟ
mm_decode_activate_server_options(ସଂରଚନା ssh *ssh, ସଂରଚନା sshbuf *m)
{
	ସଂରଚନା sshbuf *config;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i;

	ଯଦି ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	ଯଦି ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
}

#define GETPW(b, id) \
	କର { \
		ଯଦି ((r = sshbuf_get_string_direct(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		ଯଦି (len != ଆକାର(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		memcpy(&pw->id, p, len); \
	} ଯେତେବେଳେ (0)

ସଂରଚନା passwd *
mm_getpwnamallow(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *username)
{
	ସଂରଚନା sshbuf *m;
	ସଂରଚନା passwd *pw;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char ok;
	ଅଚଳ u_char *p;

	debug3_f("entering");

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	ଯଦି ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	ଯଦି (ok == 0) {
		pw = ଖାଲି;
		ଯାଅ out;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(ଆକାର(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#endif
	ଯଦି ((r = sshbuf_get_cstring(m, &pw->pw_name, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, ଖାଲି)) != 0 ||
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, ଖାଲି)) != 0 ||
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(m, &pw->pw_class, ଖାଲି)) != 0 ||
#endif
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, ଖାଲି)) != 0)
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

	ଫେରନ୍ତୁ (pw);
}

ଅକ୍ଷର *
mm_auth2_read_banner(ଶୂନ୍ୟ)
{
	ସଂରଚନା sshbuf *m;
	ଅକ୍ଷର *banner;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	ଯଦି ((r = sshbuf_get_cstring(m, &banner, ଖାଲି)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	ଯଦି (strlen(banner) == 0) {
		ମୁକ୍ତ(banner);
		banner = ଖାଲି;
	}
	ଫେରନ୍ତୁ (banner);
}

/* Inform the privileged process about service and style */

ଶୂନ୍ୟ
mm_inform_authserv(ଅକ୍ଷର *service, ଅକ୍ଷର *style)
{
	ସଂରଚନା sshbuf *m;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_auth_password(ସଂରଚନା ssh *ssh, ଅକ୍ଷର *password)
{
	ସଂରଚନା sshbuf *m;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, authenticated = 0;
#ifdef USE_PAM
	u_int maxtries = 0;
#endif

	debug3_f("entering");

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	ଯଦି ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#ifdef USE_PAM
	ଯଦି ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	ଯଦି (maxtries > INT_MAX)
		fatal_fr(r, "bad maxtries");
	sshpam_set_maxtries_reached(maxtries);
#endif

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	ଫେରନ୍ତୁ (authenticated);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_user_ଚାବି_allowed(ସଂରଚନା ssh *ssh, ସଂରଚନା passwd *pw, ସଂରଚନା sshkey *ଚାବି,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା pubkey_auth_attempt, ସଂରଚନା sshauthopt **authoptp)
{
	ଫେରନ୍ତୁ (mm_ଚାବି_allowed(MM_USERKEY, ଖାଲି, ଖାଲି, ଚାବି,
	    pubkey_auth_attempt, authoptp));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_hostbased_ଚାବି_allowed(ସଂରଚନା ssh *ssh, ସଂରଚନା passwd *pw,
    ଅଚଳ ଅକ୍ଷର *user, ଅଚଳ ଅକ୍ଷର *host, ସଂରଚନା sshkey *ଚାବି)
{
	ଫେରନ୍ତୁ (mm_ଚାବି_allowed(MM_HOSTKEY, user, host, ଚାବି, 0, ଖାଲି));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_ଚାବି_allowed(ଗଣନା mm_keytype type, ଅଚଳ ଅକ୍ଷର *user, ଅଚଳ ଅକ୍ଷର *host,
    ସଂରଚନା sshkey *ଚାବି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା pubkey_auth_attempt, ସଂରଚନା sshauthopt **authoptp)
{
	ସଂରଚନା sshbuf *m;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, allowed = 0;
	ସଂରଚନା sshauthopt *opts = ଖାଲି;

	debug3_f("entering");

	ଯଦି (authoptp != ଖାଲି)
		*authoptp = ଖାଲି;

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshkey_puts(ଚାବି, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	ଯଦି ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal_fr(r, "parse");
	ଯଦି (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	ଯଦି (authoptp != ଖାଲି) {
		*authoptp = opts;
		opts = ଖାଲି;
	}
	sshauthopt_free(opts);

	ଫେରନ୍ତୁ allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_sshkey_verify(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ଅଚଳ u_char *sig, size_t siglen,
    ଅଚଳ u_char *data, size_t datalen, ଅଚଳ ଅକ୍ଷର *sigalg, u_int compat,
    ସଂରଚନା sshkey_sig_details **sig_detailsp)
{
	ସଂରଚନା sshbuf *m;
	u_int encoded_ret = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char sig_details_present, flags;
	u_int counter;

	debug3_f("entering");

	ଯଦି (sig_detailsp != ଖାଲି)
		*sig_detailsp = ଖାଲି;
	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshkey_puts(ଚାବି, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == ଖାଲି ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	ଯଦି ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	ଯଦି (sig_details_present && encoded_ret == 0) {
		ଯଦି ((r = sshbuf_get_u32(m, &counter)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		ଯଦି (sig_detailsp != ଖାଲି) {
			*sig_detailsp = xcalloc(1, ଆକାର(**sig_detailsp));
			(*sig_detailsp)->sk_counter = counter;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	ଯଦି (encoded_ret != 0)
		ଫେରନ୍ତୁ SSH_ERR_SIGNATURE_INVALID;
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
mm_send_keystate(ସଂରଚନା ssh *ssh, ସଂରଚନା monitor *monitor)
{
	ସଂରଚନା sshbuf *m;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_pty_allocate(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ptyfd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ttyfd, ଅକ୍ଷର *namebuf, size_t namebuflen)
{
	ସଂରଚନା sshbuf *m;
	ଅକ୍ଷର *p, *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	ଯଦି ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		ଯଦି (tmp1 >= 0)
			close(tmp1);
		ଫେରନ୍ତୁ 0;
	}
	close(tmp1);
	close(tmp2);

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	ଯଦି ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ଯଦି (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		ଫେରନ୍ତୁ (0);
	}
	ଯଦି ((r = sshbuf_get_cstring(m, &p, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(m, &ସନ୍ଦେଶ, ଖାଲି)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	ମୁକ୍ତ(p);

	ଯଦି ((r = sshbuf_put(loginmsg, ସନ୍ଦେଶ, strlen(ସନ୍ଦେଶ))) != 0)
		fatal_fr(r, "put loginmsg");
	ମୁକ୍ତ(ସନ୍ଦେଶ);

	ଯଦି ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	ଫେରନ୍ତୁ (1);
}

ଶୂନ୍ୟ
mm_session_pty_cleanup2(Session *s)
{
	ସଂରଚନା sshbuf *m;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (s->ttyfd == -1)
		ଫେରନ୍ତୁ;
	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assmble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	ଯଦି (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#ifdef USE_PAM
ଶୂନ୍ୟ
mm_start_pam(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା sshbuf *m;

	debug3_f("entering");
	ଯଦି (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_START, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(ଶୂନ୍ୟ)
{
	ସଂରଚନା sshbuf *m;
	u_int ret;
	ଅକ୍ଷର *ସନ୍ଦେଶ;
	size_t msglen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");
	ଯଦି (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	ଯଦି ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &ସନ୍ଦେଶ, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, ସନ୍ଦେଶ, msglen)) != 0)
		fatal_fr(r, "buffer error");

	ମୁକ୍ତ(ସନ୍ଦେଶ);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	ଫେରନ୍ତୁ (ret);
}

ଶୂନ୍ୟ *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	ସଂରଚନା sshbuf *m;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, success;

	debug3_f("entering");
	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	ଯଦି ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "buffer error");
	ଯଦି (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		ଫେରନ୍ତୁ (ଖାଲି);
	}
	sshbuf_free(m);
	ଫେରନ୍ତୁ (authctxt);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_sshpam_query(ଶୂନ୍ୟ *ctx, ଅକ୍ଷର **name, ଅକ୍ଷର **info,
    u_int *ଅଙ୍କ, ଅକ୍ଷର ***prompts, u_int **echo_on)
{
	ସଂରଚନା sshbuf *m;
	u_int i, n;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret;

	debug3_f("entering");
	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	ଯଦି ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, ଅଙ୍କ)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_set_maxtries_reached(n);
	ଯଦି (*ଅଙ୍କ > PAM_MAX_ଅଙ୍କ_ସନ୍ଦେଶ)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *ଅଙ୍କ, PAM_MAX_ଅଙ୍କ_ସନ୍ଦେଶ);
	*prompts = xcalloc((*ଅଙ୍କ + 1), ଆକାର(ଅକ୍ଷର *));
	*echo_on = xcalloc((*ଅଙ୍କ + 1), ଆକାର(u_int));
	ପାଇଁ (i = 0; i < *ଅଙ୍କ; ++i) {
		ଯଦି ((r = sshbuf_get_cstring(m, &((*prompts)[i]), ଖାଲି)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	ଫେରନ୍ତୁ (ret);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_sshpam_respond(ଶୂନ୍ୟ *ctx, u_int ଅଙ୍କ, ଅକ୍ଷର **resp)
{
	ସଂରଚନା sshbuf *m;
	u_int n, i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret;

	debug3_f("entering");
	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u32(m, ଅଙ୍କ)) != 0)
		fatal_fr(r, "buffer error");
	ପାଇଁ (i = 0; i < ଅଙ୍କ; ++i) {
		ଯଦି ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	ଯଦି ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	ret = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	ଫେରନ୍ତୁ (ret);
}

ଶୂନ୍ୟ
mm_sshpam_free_ctx(ଶୂନ୍ୟ *ctxtp)
{
	ସଂରଚନା sshbuf *m;

	debug3_f("entering");
	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_FREE_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_FREE_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_FREE_CTX, m);
	sshbuf_free(m);
}
#endif /* USE_PAM */

/* Request process termination */

ଶୂନ୍ୟ
mm_terminate(ଶୂନ୍ୟ)
{
	ସଂରଚନା sshbuf *m;

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_TERM, m);
	sshbuf_free(m);
}

/* Request state information */

ଶୂନ୍ୟ
mm_get_state(ସଂରଚନା ssh *ssh,
    ServerOptions *opts, ସଂରଚନା sshbuf **confdatap,
    uint64_t *timing_secretp,
    ସଂରଚନା sshbuf **hostkeysp, ସଂରଚନା sshbuf **keystatep,
    u_char **pw_namep,
    ସଂରଚନା sshbuf **authinfop, ସଂରଚନା sshbuf **auth_optsp)
{
	ସଂରଚନା sshbuf *m, *config;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");

	ଯଦି ((m = sshbuf_new()) == ଖାଲି || (config = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	ଯଦି ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	ଯଦି (confdatap) {
		ଯଦି ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, ଖାଲି)) != 0 ||
		    (r = sshbuf_froms(m, authinfop)) != 0 ||
		    (r = sshbuf_froms(m, auth_optsp)) != 0)
			fatal_fr(r, "parse config postauth");
	}
	ଯଦି ((r = deserialise_server_options(config, opts)) != 0)
		fatal_fr(r, "deserialise_server_options");

	sshbuf_free(m);
	sshbuf_free(config);

	debug3_f("done");
}

ସ୍ଥିର ଶୂନ୍ୟ
mm_chall_setup(ଅକ୍ଷର **name, ଅକ୍ଷର **infotxt, u_int *numprompts,
    ଅକ୍ଷର ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, ଆକାର(ଅକ୍ଷର *));
	*echo_on = xcalloc(*numprompts, ଆକାର(u_int));
	(*echo_on)[0] = 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_bsdauth_query(ଶୂନ୍ୟ *ctx, ଅକ୍ଷର **name, ଅକ୍ଷର **infotxt,
   u_int *numprompts, ଅକ୍ଷର ***prompts, u_int **echo_on)
{
	ସଂରଚନା sshbuf *m;
	u_int success;
	ଅକ୍ଷର *challenge;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	ଯଦି ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ଯଦି (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		ଫେରନ୍ତୁ (-1);
	}

	/* Get the challenge, and format the response */
	ଯଦି ((r = sshbuf_get_cstring(m, &challenge, ଖାଲି)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_setup(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_bsdauth_respond(ଶୂନ୍ୟ *ctx, u_int numresponses, ଅକ୍ଷର **responses)
{
	ସଂରଚନା sshbuf *m;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, authok;

	debug3_f("entering");
	ଯଦି (numresponses != 1)
		ଫେରନ୍ତୁ (-1);

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	ଯଦି ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	ଫେରନ୍ତୁ ((authok == 0) ? -1 : 0);
}

#ifdef SSH_AUDIT_EVENTS
ଶୂନ୍ୟ
mm_audit_event(ସଂରଚନା ssh *ssh, ssh_audit_event_t event)
{
	ସଂରଚନା sshbuf *m;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

ଶୂନ୍ୟ
mm_audit_run_command(ଅଚଳ ଅକ୍ଷର *command)
{
	ସଂରଚନା sshbuf *m;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering command %s", command);

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#endif /* SSH_AUDIT_EVENTS */

#ifdef GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	ସଂରଚନା sshbuf *m;
	OM_uint32 major;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/* Client doesn't get to see the context */
	*ctx = ଖାଲି;

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_string(m, goid->elements, goid->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	ଯଦି ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	ଫେରନ୍ତୁ (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *in,
    gss_buffer_desc *out, OM_uint32 *flagsp)
{
	ସଂରଚନା sshbuf *m;
	OM_uint32 major;
	u_int flags;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_string(m, in->ମୂଲ୍ୟ, in->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	ଯଦି ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, out)) != 0)
		fatal_fr(r, "parse");
	ଯଦି (flagsp != ଖାଲି) {
		ଯଦି ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	ଫେରନ୍ତୁ (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	ସଂରଚନା sshbuf *m;
	OM_uint32 major;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_string(m, gssbuf->ମୂଲ୍ୟ, gssbuf->length)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->ମୂଲ୍ୟ, gssmic->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	ଯଦି ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	ଫେରନ୍ତୁ(major);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_ssh_gssapi_userok(ଅକ୍ଷର *user)
{
	ସଂରଚନା sshbuf *m;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, authenticated = 0;

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	ଯଦି ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	ଫେରନ୍ତୁ (authenticated);
}
#endif /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
ସ୍ଥିର ଶୂନ୍ୟ
server_process_permitopen_list(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା listen,
    ଅକ୍ଷର **opens, u_int ଅଙ୍କ_opens)
{
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା port;
	ଅକ୍ଷର *host, *arg, *oarg;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	ଅଚଳ ଅକ୍ଷର *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	ଯଦି (ଅଙ୍କ_opens == 0)
		ଫେରନ୍ତୁ; /* permit any */

	/* handle keywords: "any" / "none" */
	ଯଦି (ଅଙ୍କ_opens == 1 && strcmp(opens[0], "any") == 0)
		ଫେରନ୍ତୁ;
	ଯଦି (ଅଙ୍କ_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		ଫେରନ୍ତୁ;
	}
	/* Otherwise treat it as a list of permitted host:port */
	ପାଇଁ (i = 0; i < ଅଙ୍କ_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		ଯଦି (host == ଖାଲି)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		ଯଦି (arg == ଖାଲି || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, host, port);
		ମୁକ୍ତ(oarg);
	}
}

/*
 * Inform channels layer of permitopen options from configuration.
 */
ଶୂନ୍ୟ
server_process_permitopen(ସଂରଚନା ssh *ssh)
{
	server_process_permitopen_list(ssh, 0,
	    options.permitted_opens, options.ଅଙ୍କ_permitted_opens);
	server_process_permitopen_list(ssh, 1,
	    options.permitted_listens, options.ଅଙ୍କ_permitted_listens);
}

ଶୂନ୍ୟ
server_process_channel_timeouts(ସଂରଚନା ssh *ssh)
{
	u_int i;
	ଦ୍ୱିଗୁଣ secs;
	ଅକ୍ଷର *type;

	debug3_f("setting %u timeouts", options.ଅଙ୍କ_channel_timeouts);
	channel_clear_timeouts(ssh);
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_channel_timeouts; i++) {
		ଯଦି (parse_pattern_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_add_timeout(ssh, type, secs);
		ମୁକ୍ତ(type);
	}
}

ସଂରଚନା connection_info *
server_get_connection_info(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା populate, ପୂର୍ଣ୍ଣସଂଖ୍ୟା use_dns)
{
	ସ୍ଥିର ସଂରଚନା connection_info ci;

	ଯଦି (ssh == ଖାଲି || !populate)
		ଫେରନ୍ତୁ &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.address = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_port(ssh);
	ci.rdomain = ssh_packet_rdomain_in(ssh);
	ଫେରନ୍ତୁ &ci;
}

