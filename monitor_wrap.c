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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/uio.h>
#અન્તર્ભાવ <sys/queue.h>
#અન્તર્ભાવ <sys/wait.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/dh.h>
#અન્તર્ભાવ <openssl/evp.h>
#endif

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#ifdef WITH_OPENSSL
#અન્તર્ભાવ "dh.h"
#endif
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "auth-options.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "mac.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "auth-pam.h"
#અન્તર્ભાવ "monitor.h"
#ifdef GSSAPI
#અન્તર્ભાવ "ssh-gss.h"
#endif
#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "monitor_fdpass.h"
#અન્તર્ભાવ "misc.h"

#અન્તર્ભાવ "channels.h"
#અન્તર્ભાવ "session.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "monitor_wrap.h"
#અન્તર્ભાવ "srclimit.h"

#અન્તર્ભાવ "ssherr.h"

/* Imports */
બાહ્ય સંરચના monitor *pmonitor;
બાહ્ય સંરચના sshbuf *loginmsg;
બાહ્ય ServerOptions options;

શૂન્ય
mm_log_handler(LogLevel level, પૂર્ણાંક forced, અચલ અક્ષર *સંદેશ, શૂન્ય *ctx)
{
	સંરચના sshbuf *log_સંદેશ;
	સંરચના monitor *mon = (સંરચના monitor *)ctx;
	પૂર્ણાંક r;
	size_t len;

	જો (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	જો ((log_સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	જો ((r = sshbuf_put_u32(log_સંદેશ, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_સંદેશ, level)) != 0 ||
	    (r = sshbuf_put_u32(log_સંદેશ, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_સંદેશ, સંદેશ)) != 0)
		fatal_fr(r, "assemble");
	જો ((len = sshbuf_len(log_સંદેશ)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_સંદેશ), len - 4);
	જો (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_સંદેશ), len) != len) {
		જો (errno == EPIPE) {
			debug_f("write: %s", strerror(errno));
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
	sshbuf_free(log_સંદેશ);
}

સ્થિર શૂન્ય
mm_reap(શૂન્ય)
{
	પૂર્ણાંક status = -1;

	જો (!mm_is_monitor())
		પાછા;
	જ્યારે (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		જો (errno == EINTR)
			ચાલુ;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", strerror(errno));
	}
	જો (WIFEXITED(status)) {
		જો (WEXITSTATUS(status) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(status));
			cleanup_exit(255);
		}
	} નહીંતર જો (WIFSIGNALED(status)) {
		error_f("child terminated by signal %d",
		    WTERMSIG(status));
		cleanup_exit(signal_is_crash(WTERMSIG(status)) ?
		    EXIT_CHILD_CRASH : 255);
	} નહીંતર {
		error_f("child terminated abnormally (status=0x%x)",
		    status);
		cleanup_exit(EXIT_CHILD_CRASH);
	}
}

શૂન્ય
mm_request_send(પૂર્ણાંક sock, ગણના monitor_reqtype type, સંરચના sshbuf *m)
{
	size_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	જો (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	જો (atomicio(vwrite, sock, buf, કદ(buf)) != કદ(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		જો (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
}

શૂન્ય
mm_request_receive(પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	u_char buf[4], *p = ખાલી;
	u_int સંદેશ_len;
	પૂર્ણાંક oerrno, r;

	debug3_f("entering");

	જો (atomicio(પઠ, sock, buf, કદ(buf)) != કદ(buf)) {
		જો (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", strerror(errno));
	}
	સંદેશ_len = PEEK_U32(buf);
	જો (સંદેશ_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", સંદેશ_len);
	sshbuf_reset(m);
	જો ((r = sshbuf_reserve(m, સંદેશ_len, &p)) != 0)
		fatal_fr(r, "reserve");
	જો (atomicio(પઠ, sock, p, સંદેશ_len) != સંદેશ_len) {
		oerrno = errno;
		error_f("read: %s", strerror(errno));
		જો (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

શૂન્ય
mm_request_receive_expect(પૂર્ણાંક sock, ગણના monitor_reqtype type, સંરચના sshbuf *m)
{
	u_char rtype;
	પૂર્ણાંક r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	જો ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	જો (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(પૂર્ણાંક min, પૂર્ણાંક nbits, પૂર્ણાંક max)
{
	BIGNUM *p, *g;
	પૂર્ણાંક r;
	u_char success = 0;
	સંરચના sshbuf *m;

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	જો ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	જો (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

	જો ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	પાછા (dh_new_group(g, p));
}
#endif

શૂન્ય
mm_sshkey_setcompat(સંરચના ssh *ssh)
{
	સંરચના sshbuf *m;
	પૂર્ણાંક r;

	debug3_f("entering");
	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

પૂર્ણાંક
mm_sshkey_sign(સંરચના ssh *ssh, સંરચના sshkey *ચાવી, u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t datalen, અચલ અક્ષર *hostkey_alg,
    અચલ અક્ષર *sk_provider, અચલ અક્ષર *sk_pin, u_int compat)
{
	સંરચના sshbuf *m;
	પૂર્ણાંક r;

	debug3_f("entering");
	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshkey_puts(ચાવી, m)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	જો ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	debug3_f("%s signature len=%zu", hostkey_alg ? hostkey_alg : "(null)",
	    *lenp);

	પાછા (0);
}

શૂન્ય
mm_decode_activate_server_options(સંરચના ssh *ssh, સંરચના sshbuf *m)
{
	સંરચના sshbuf *config;
	પૂર્ણાંક r;
	u_int i;

	જો ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	જો ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	માટે (i = 0; i < options.અંક_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
}

#define GETPW(b, id) \
	કરો { \
		જો ((r = sshbuf_get_string_direct(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		જો (len != કદ(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		memcpy(&pw->id, p, len); \
	} જ્યારે (0)

સંરચના passwd *
mm_getpwnamallow(સંરચના ssh *ssh, અચલ અક્ષર *username)
{
	સંરચના sshbuf *m;
	સંરચના passwd *pw;
	size_t len;
	પૂર્ણાંક r;
	u_char ok;
	અચલ u_char *p;

	debug3_f("entering");

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	જો ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	જો (ok == 0) {
		pw = ખાલી;
		જાઓ out;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(કદ(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#endif
	જો ((r = sshbuf_get_cstring(m, &pw->pw_name, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, ખાલી)) != 0 ||
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, ખાલી)) != 0 ||
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(m, &pw->pw_class, ખાલી)) != 0 ||
#endif
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, ખાલી)) != 0)
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

	પાછા (pw);
}

અક્ષર *
mm_auth2_read_banner(શૂન્ય)
{
	સંરચના sshbuf *m;
	અક્ષર *banner;
	પૂર્ણાંક r;

	debug3_f("entering");

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	જો ((r = sshbuf_get_cstring(m, &banner, ખાલી)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	જો (strlen(banner) == 0) {
		મુક્ત(banner);
		banner = ખાલી;
	}
	પાછા (banner);
}

/* Inform the privileged process about service and style */

શૂન્ય
mm_inform_authserv(અક્ષર *service, અક્ષર *style)
{
	સંરચના sshbuf *m;
	પૂર્ણાંક r;

	debug3_f("entering");

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
પૂર્ણાંક
mm_auth_password(સંરચના ssh *ssh, અક્ષર *password)
{
	સંરચના sshbuf *m;
	પૂર્ણાંક r, authenticated = 0;
#ifdef USE_PAM
	u_int maxtries = 0;
#endif

	debug3_f("entering");

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	જો ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#ifdef USE_PAM
	જો ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	જો (maxtries > INT_MAX)
		fatal_fr(r, "bad maxtries");
	sshpam_set_maxtries_reached(maxtries);
#endif

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	પાછા (authenticated);
}

પૂર્ણાંક
mm_user_ચાવી_allowed(સંરચના ssh *ssh, સંરચના passwd *pw, સંરચના sshkey *ચાવી,
    પૂર્ણાંક pubkey_auth_attempt, સંરચના sshauthopt **authoptp)
{
	પાછા (mm_ચાવી_allowed(MM_USERKEY, ખાલી, ખાલી, ચાવી,
	    pubkey_auth_attempt, authoptp));
}

પૂર્ણાંક
mm_hostbased_ચાવી_allowed(સંરચના ssh *ssh, સંરચના passwd *pw,
    અચલ અક્ષર *user, અચલ અક્ષર *host, સંરચના sshkey *ચાવી)
{
	પાછા (mm_ચાવી_allowed(MM_HOSTKEY, user, host, ચાવી, 0, ખાલી));
}

પૂર્ણાંક
mm_ચાવી_allowed(ગણના mm_keytype type, અચલ અક્ષર *user, અચલ અક્ષર *host,
    સંરચના sshkey *ચાવી, પૂર્ણાંક pubkey_auth_attempt, સંરચના sshauthopt **authoptp)
{
	સંરચના sshbuf *m;
	પૂર્ણાંક r, allowed = 0;
	સંરચના sshauthopt *opts = ખાલી;

	debug3_f("entering");

	જો (authoptp != ખાલી)
		*authoptp = ખાલી;

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshkey_puts(ચાવી, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	જો ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal_fr(r, "parse");
	જો (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	જો (authoptp != ખાલી) {
		*authoptp = opts;
		opts = ખાલી;
	}
	sshauthopt_free(opts);

	પાછા allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

પૂર્ણાંક
mm_sshkey_verify(અચલ સંરચના sshkey *ચાવી, અચલ u_char *sig, size_t siglen,
    અચલ u_char *data, size_t datalen, અચલ અક્ષર *sigalg, u_int compat,
    સંરચના sshkey_sig_details **sig_detailsp)
{
	સંરચના sshbuf *m;
	u_int encoded_ret = 0;
	પૂર્ણાંક r;
	u_char sig_details_present, flags;
	u_int counter;

	debug3_f("entering");

	જો (sig_detailsp != ખાલી)
		*sig_detailsp = ખાલી;
	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshkey_puts(ચાવી, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == ખાલી ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	જો ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	જો (sig_details_present && encoded_ret == 0) {
		જો ((r = sshbuf_get_u32(m, &counter)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		જો (sig_detailsp != ખાલી) {
			*sig_detailsp = xcalloc(1, કદ(**sig_detailsp));
			(*sig_detailsp)->sk_counter = counter;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	જો (encoded_ret != 0)
		પાછા SSH_ERR_SIGNATURE_INVALID;
	પાછા 0;
}

શૂન્ય
mm_send_keystate(સંરચના ssh *ssh, સંરચના monitor *monitor)
{
	સંરચના sshbuf *m;
	પૂર્ણાંક r;

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

પૂર્ણાંક
mm_pty_allocate(પૂર્ણાંક *ptyfd, પૂર્ણાંક *ttyfd, અક્ષર *namebuf, size_t namebuflen)
{
	સંરચના sshbuf *m;
	અક્ષર *p, *સંદેશ;
	પૂર્ણાંક success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	જો ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		જો (tmp1 >= 0)
			close(tmp1);
		પાછા 0;
	}
	close(tmp1);
	close(tmp2);

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	જો ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	જો (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		પાછા (0);
	}
	જો ((r = sshbuf_get_cstring(m, &p, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(m, &સંદેશ, ખાલી)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	મુક્ત(p);

	જો ((r = sshbuf_put(loginmsg, સંદેશ, strlen(સંદેશ))) != 0)
		fatal_fr(r, "put loginmsg");
	મુક્ત(સંદેશ);

	જો ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	પાછા (1);
}

શૂન્ય
mm_session_pty_cleanup2(Session *s)
{
	સંરચના sshbuf *m;
	પૂર્ણાંક r;

	જો (s->ttyfd == -1)
		પાછા;
	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assmble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	જો (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#ifdef USE_PAM
શૂન્ય
mm_start_pam(સંરચના ssh *ssh)
{
	સંરચના sshbuf *m;

	debug3_f("entering");
	જો (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_START, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(શૂન્ય)
{
	સંરચના sshbuf *m;
	u_int ret;
	અક્ષર *સંદેશ;
	size_t msglen;
	પૂર્ણાંક r;

	debug3_f("entering");
	જો (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	જો ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &સંદેશ, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, સંદેશ, msglen)) != 0)
		fatal_fr(r, "buffer error");

	મુક્ત(સંદેશ);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	પાછા (ret);
}

શૂન્ય *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	સંરચના sshbuf *m;
	પૂર્ણાંક r, success;

	debug3_f("entering");
	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	જો ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "buffer error");
	જો (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		પાછા (ખાલી);
	}
	sshbuf_free(m);
	પાછા (authctxt);
}

પૂર્ણાંક
mm_sshpam_query(શૂન્ય *ctx, અક્ષર **name, અક્ષર **info,
    u_int *અંક, અક્ષર ***prompts, u_int **echo_on)
{
	સંરચના sshbuf *m;
	u_int i, n;
	પૂર્ણાંક r, ret;

	debug3_f("entering");
	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	જો ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, ખાલી)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, અંક)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_set_maxtries_reached(n);
	જો (*અંક > PAM_MAX_અંક_સંદેશ)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *અંક, PAM_MAX_અંક_સંદેશ);
	*prompts = xcalloc((*અંક + 1), કદ(અક્ષર *));
	*echo_on = xcalloc((*અંક + 1), કદ(u_int));
	માટે (i = 0; i < *અંક; ++i) {
		જો ((r = sshbuf_get_cstring(m, &((*prompts)[i]), ખાલી)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	પાછા (ret);
}

પૂર્ણાંક
mm_sshpam_respond(શૂન્ય *ctx, u_int અંક, અક્ષર **resp)
{
	સંરચના sshbuf *m;
	u_int n, i;
	પૂર્ણાંક r, ret;

	debug3_f("entering");
	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u32(m, અંક)) != 0)
		fatal_fr(r, "buffer error");
	માટે (i = 0; i < અંક; ++i) {
		જો ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	જો ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	ret = (પૂર્ણાંક)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	પાછા (ret);
}

શૂન્ય
mm_sshpam_free_ctx(શૂન્ય *ctxtp)
{
	સંરચના sshbuf *m;

	debug3_f("entering");
	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_FREE_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_FREE_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_FREE_CTX, m);
	sshbuf_free(m);
}
#endif /* USE_PAM */

/* Request process termination */

શૂન્ય
mm_terminate(શૂન્ય)
{
	સંરચના sshbuf *m;

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_TERM, m);
	sshbuf_free(m);
}

/* Request state information */

શૂન્ય
mm_get_state(સંરચના ssh *ssh,
    ServerOptions *opts, સંરચના sshbuf **confdatap,
    uint64_t *timing_secretp,
    સંરચના sshbuf **hostkeysp, સંરચના sshbuf **keystatep,
    u_char **pw_namep,
    સંરચના sshbuf **authinfop, સંરચના sshbuf **auth_optsp)
{
	સંરચના sshbuf *m, *config;
	પૂર્ણાંક r;

	debug3_f("entering");

	જો ((m = sshbuf_new()) == ખાલી || (config = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	જો ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	જો (confdatap) {
		જો ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, ખાલી)) != 0 ||
		    (r = sshbuf_froms(m, authinfop)) != 0 ||
		    (r = sshbuf_froms(m, auth_optsp)) != 0)
			fatal_fr(r, "parse config postauth");
	}
	જો ((r = deserialise_server_options(config, opts)) != 0)
		fatal_fr(r, "deserialise_server_options");

	sshbuf_free(m);
	sshbuf_free(config);

	debug3_f("done");
}

સ્થિર શૂન્ય
mm_chall_setup(અક્ષર **name, અક્ષર **infotxt, u_int *numprompts,
    અક્ષર ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, કદ(અક્ષર *));
	*echo_on = xcalloc(*numprompts, કદ(u_int));
	(*echo_on)[0] = 0;
}

પૂર્ણાંક
mm_bsdauth_query(શૂન્ય *ctx, અક્ષર **name, અક્ષર **infotxt,
   u_int *numprompts, અક્ષર ***prompts, u_int **echo_on)
{
	સંરચના sshbuf *m;
	u_int success;
	અક્ષર *challenge;
	પૂર્ણાંક r;

	debug3_f("entering");

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	જો ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	જો (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		પાછા (-1);
	}

	/* Get the challenge, and format the response */
	જો ((r = sshbuf_get_cstring(m, &challenge, ખાલી)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_setup(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	પાછા (0);
}

પૂર્ણાંક
mm_bsdauth_respond(શૂન્ય *ctx, u_int numresponses, અક્ષર **responses)
{
	સંરચના sshbuf *m;
	પૂર્ણાંક r, authok;

	debug3_f("entering");
	જો (numresponses != 1)
		પાછા (-1);

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	જો ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	પાછા ((authok == 0) ? -1 : 0);
}

#ifdef SSH_AUDIT_EVENTS
શૂન્ય
mm_audit_event(સંરચના ssh *ssh, ssh_audit_event_t event)
{
	સંરચના sshbuf *m;
	પૂર્ણાંક r;

	debug3_f("entering");

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

શૂન્ય
mm_audit_run_command(અચલ અક્ષર *command)
{
	સંરચના sshbuf *m;
	પૂર્ણાંક r;

	debug3_f("entering command %s", command);

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#endif /* SSH_AUDIT_EVENTS */

#ifdef GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	સંરચના sshbuf *m;
	OM_uint32 major;
	પૂર્ણાંક r;

	/* Client doesn't get to see the context */
	*ctx = ખાલી;

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_string(m, goid->elements, goid->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	જો ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	પાછા (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *in,
    gss_buffer_desc *out, OM_uint32 *flagsp)
{
	સંરચના sshbuf *m;
	OM_uint32 major;
	u_int flags;
	પૂર્ણાંક r;

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_string(m, in->કિંમત, in->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	જો ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, out)) != 0)
		fatal_fr(r, "parse");
	જો (flagsp != ખાલી) {
		જો ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	પાછા (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	સંરચના sshbuf *m;
	OM_uint32 major;
	પૂર્ણાંક r;

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_string(m, gssbuf->કિંમત, gssbuf->length)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->કિંમત, gssmic->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	જો ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	પાછા(major);
}

પૂર્ણાંક
mm_ssh_gssapi_userok(અક્ષર *user)
{
	સંરચના sshbuf *m;
	પૂર્ણાંક r, authenticated = 0;

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	જો ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	પાછા (authenticated);
}
#endif /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
સ્થિર શૂન્ય
server_process_permitopen_list(સંરચના ssh *ssh, પૂર્ણાંક listen,
    અક્ષર **opens, u_int અંક_opens)
{
	u_int i;
	પૂર્ણાંક port;
	અક્ષર *host, *arg, *oarg;
	પૂર્ણાંક where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	અચલ અક્ષર *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	જો (અંક_opens == 0)
		પાછા; /* permit any */

	/* handle keywords: "any" / "none" */
	જો (અંક_opens == 1 && strcmp(opens[0], "any") == 0)
		પાછા;
	જો (અંક_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		પાછા;
	}
	/* Otherwise treat it as a list of permitted host:port */
	માટે (i = 0; i < અંક_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		જો (host == ખાલી)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		જો (arg == ખાલી || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, host, port);
		મુક્ત(oarg);
	}
}

/*
 * Inform channels layer of permitopen options from configuration.
 */
શૂન્ય
server_process_permitopen(સંરચના ssh *ssh)
{
	server_process_permitopen_list(ssh, 0,
	    options.permitted_opens, options.અંક_permitted_opens);
	server_process_permitopen_list(ssh, 1,
	    options.permitted_listens, options.અંક_permitted_listens);
}

શૂન્ય
server_process_channel_timeouts(સંરચના ssh *ssh)
{
	u_int i;
	દ્વિગુણ secs;
	અક્ષર *type;

	debug3_f("setting %u timeouts", options.અંક_channel_timeouts);
	channel_clear_timeouts(ssh);
	માટે (i = 0; i < options.અંક_channel_timeouts; i++) {
		જો (parse_pattern_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_add_timeout(ssh, type, secs);
		મુક્ત(type);
	}
}

સંરચના connection_info *
server_get_connection_info(સંરચના ssh *ssh, પૂર્ણાંક populate, પૂર્ણાંક use_dns)
{
	સ્થિર સંરચના connection_info ci;

	જો (ssh == ખાલી || !populate)
		પાછા &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.address = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_port(ssh);
	ci.rdomain = ssh_packet_rdomain_in(ssh);
	પાછા &ci;
}

