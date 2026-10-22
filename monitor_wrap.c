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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/uio.h>
#അന്തര്ഭാവ <sys/queue.h>
#അന്തര്ഭാവ <sys/wait.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/dh.h>
#അന്തര്ഭാവ <openssl/evp.h>
#endif

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#ifdef WITH_OPENSSL
#അന്തര്ഭാവ "dh.h"
#endif
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "cipher.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "auth-options.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "mac.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "auth-pam.h"
#അന്തര്ഭാവ "monitor.h"
#ifdef GSSAPI
#അന്തര്ഭാവ "ssh-gss.h"
#endif
#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "monitor_fdpass.h"
#അന്തര്ഭാവ "misc.h"

#അന്തര്ഭാവ "channels.h"
#അന്തര്ഭാവ "session.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "monitor_wrap.h"
#അന്തര്ഭാവ "srclimit.h"

#അന്തര്ഭാവ "ssherr.h"

/* Imports */
ബാഹ്യ ഘടന monitor *pmonitor;
ബാഹ്യ ഘടന sshbuf *loginmsg;
ബാഹ്യ ServerOptions options;

ശൂന്യം
mm_log_handler(LogLevel level, പൂർണ്ണസംഖ്യ forced, സ്ഥിരം അക്ഷരം *സന്ദേശം, ശൂന്യം *ctx)
{
	ഘടന sshbuf *log_സന്ദേശം;
	ഘടന monitor *mon = (ഘടന monitor *)ctx;
	പൂർണ്ണസംഖ്യ r;
	size_t len;

	എങ്കിൽ (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	എങ്കിൽ ((log_സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	എങ്കിൽ ((r = sshbuf_put_u32(log_സന്ദേശം, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_സന്ദേശം, level)) != 0 ||
	    (r = sshbuf_put_u32(log_സന്ദേശം, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_സന്ദേശം, സന്ദേശം)) != 0)
		fatal_fr(r, "assemble");
	എങ്കിൽ ((len = sshbuf_len(log_സന്ദേശം)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_സന്ദേശം), len - 4);
	എങ്കിൽ (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_സന്ദേശം), len) != len) {
		എങ്കിൽ (errno == EPIPE) {
			debug_f("write: %s", strerror(errno));
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
	sshbuf_free(log_സന്ദേശം);
}

സ്ഥിതം ശൂന്യം
mm_reap(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ status = -1;

	എങ്കിൽ (!mm_is_monitor())
		തിരികെ;
	ആകുമ്പോൾ (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		എങ്കിൽ (errno == EINTR)
			തുടരുക;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", strerror(errno));
	}
	എങ്കിൽ (WIFEXITED(status)) {
		എങ്കിൽ (WEXITSTATUS(status) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(status));
			cleanup_exit(255);
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (WIFSIGNALED(status)) {
		error_f("child terminated by signal %d",
		    WTERMSIG(status));
		cleanup_exit(signal_is_crash(WTERMSIG(status)) ?
		    EXIT_CHILD_CRASH : 255);
	} അല്ലെങ്കിൽ {
		error_f("child terminated abnormally (status=0x%x)",
		    status);
		cleanup_exit(EXIT_CHILD_CRASH);
	}
}

ശൂന്യം
mm_request_send(പൂർണ്ണസംഖ്യ sock, എണ്ണൽ monitor_reqtype type, ഘടന sshbuf *m)
{
	size_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	എങ്കിൽ (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	എങ്കിൽ (atomicio(vwrite, sock, buf, വലുപ്പം(buf)) != വലുപ്പം(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		എങ്കിൽ (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
}

ശൂന്യം
mm_request_receive(പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	u_char buf[4], *p = ശൂന്യ;
	u_int സന്ദേശം_len;
	പൂർണ്ണസംഖ്യ oerrno, r;

	debug3_f("entering");

	എങ്കിൽ (atomicio(പഠ, sock, buf, വലുപ്പം(buf)) != വലുപ്പം(buf)) {
		എങ്കിൽ (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", strerror(errno));
	}
	സന്ദേശം_len = PEEK_U32(buf);
	എങ്കിൽ (സന്ദേശം_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", സന്ദേശം_len);
	sshbuf_reset(m);
	എങ്കിൽ ((r = sshbuf_reserve(m, സന്ദേശം_len, &p)) != 0)
		fatal_fr(r, "reserve");
	എങ്കിൽ (atomicio(പഠ, sock, p, സന്ദേശം_len) != സന്ദേശം_len) {
		oerrno = errno;
		error_f("read: %s", strerror(errno));
		എങ്കിൽ (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

ശൂന്യം
mm_request_receive_expect(പൂർണ്ണസംഖ്യ sock, എണ്ണൽ monitor_reqtype type, ഘടന sshbuf *m)
{
	u_char rtype;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	എങ്കിൽ ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	എങ്കിൽ (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(പൂർണ്ണസംഖ്യ min, പൂർണ്ണസംഖ്യ nbits, പൂർണ്ണസംഖ്യ max)
{
	BIGNUM *p, *g;
	പൂർണ്ണസംഖ്യ r;
	u_char success = 0;
	ഘടന sshbuf *m;

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	എങ്കിൽ ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	എങ്കിൽ (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

	എങ്കിൽ ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	തിരികെ (dh_new_group(g, p));
}
#endif

ശൂന്യം
mm_sshkey_setcompat(ഘടന ssh *ssh)
{
	ഘടന sshbuf *m;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");
	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

പൂർണ്ണസംഖ്യ
mm_sshkey_sign(ഘടന ssh *ssh, ഘടന sshkey *താക്കോൽ, u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t datalen, സ്ഥിരം അക്ഷരം *hostkey_alg,
    സ്ഥിരം അക്ഷരം *sk_provider, സ്ഥിരം അക്ഷരം *sk_pin, u_int compat)
{
	ഘടന sshbuf *m;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");
	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshkey_puts(താക്കോൽ, m)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	എങ്കിൽ ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	debug3_f("%s signature len=%zu", hostkey_alg ? hostkey_alg : "(null)",
	    *lenp);

	തിരികെ (0);
}

ശൂന്യം
mm_decode_activate_server_options(ഘടന ssh *ssh, ഘടന sshbuf *m)
{
	ഘടന sshbuf *config;
	പൂർണ്ണസംഖ്യ r;
	u_int i;

	എങ്കിൽ ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	എങ്കിൽ ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	വേണ്ടി (i = 0; i < options.അക്കം_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
}

#define GETPW(b, id) \
	ചെയ്യുക { \
		എങ്കിൽ ((r = sshbuf_get_string_direct(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		എങ്കിൽ (len != വലുപ്പം(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		memcpy(&pw->id, p, len); \
	} ആകുമ്പോൾ (0)

ഘടന passwd *
mm_getpwnamallow(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *username)
{
	ഘടന sshbuf *m;
	ഘടന passwd *pw;
	size_t len;
	പൂർണ്ണസംഖ്യ r;
	u_char ok;
	സ്ഥിരം u_char *p;

	debug3_f("entering");

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	എങ്കിൽ ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	എങ്കിൽ (ok == 0) {
		pw = ശൂന്യ;
		പോകുക out;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(വലുപ്പം(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#endif
	എങ്കിൽ ((r = sshbuf_get_cstring(m, &pw->pw_name, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, ശൂന്യ)) != 0 ||
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, ശൂന്യ)) != 0 ||
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(m, &pw->pw_class, ശൂന്യ)) != 0 ||
#endif
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, ശൂന്യ)) != 0)
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

	തിരികെ (pw);
}

അക്ഷരം *
mm_auth2_read_banner(ശൂന്യം)
{
	ഘടന sshbuf *m;
	അക്ഷരം *banner;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	എങ്കിൽ ((r = sshbuf_get_cstring(m, &banner, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	എങ്കിൽ (strlen(banner) == 0) {
		സ്വതന്ത്രം(banner);
		banner = ശൂന്യ;
	}
	തിരികെ (banner);
}

/* Inform the privileged process about service and style */

ശൂന്യം
mm_inform_authserv(അക്ഷരം *service, അക്ഷരം *style)
{
	ഘടന sshbuf *m;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
പൂർണ്ണസംഖ്യ
mm_auth_password(ഘടന ssh *ssh, അക്ഷരം *password)
{
	ഘടന sshbuf *m;
	പൂർണ്ണസംഖ്യ r, authenticated = 0;
#ifdef USE_PAM
	u_int maxtries = 0;
#endif

	debug3_f("entering");

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	എങ്കിൽ ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#ifdef USE_PAM
	എങ്കിൽ ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	എങ്കിൽ (maxtries > INT_MAX)
		fatal_fr(r, "bad maxtries");
	sshpam_set_maxtries_reached(maxtries);
#endif

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	തിരികെ (authenticated);
}

പൂർണ്ണസംഖ്യ
mm_user_താക്കോൽ_allowed(ഘടന ssh *ssh, ഘടന passwd *pw, ഘടന sshkey *താക്കോൽ,
    പൂർണ്ണസംഖ്യ pubkey_auth_attempt, ഘടന sshauthopt **authoptp)
{
	തിരികെ (mm_താക്കോൽ_allowed(MM_USERKEY, ശൂന്യ, ശൂന്യ, താക്കോൽ,
	    pubkey_auth_attempt, authoptp));
}

പൂർണ്ണസംഖ്യ
mm_hostbased_താക്കോൽ_allowed(ഘടന ssh *ssh, ഘടന passwd *pw,
    സ്ഥിരം അക്ഷരം *user, സ്ഥിരം അക്ഷരം *host, ഘടന sshkey *താക്കോൽ)
{
	തിരികെ (mm_താക്കോൽ_allowed(MM_HOSTKEY, user, host, താക്കോൽ, 0, ശൂന്യ));
}

പൂർണ്ണസംഖ്യ
mm_താക്കോൽ_allowed(എണ്ണൽ mm_keytype type, സ്ഥിരം അക്ഷരം *user, സ്ഥിരം അക്ഷരം *host,
    ഘടന sshkey *താക്കോൽ, പൂർണ്ണസംഖ്യ pubkey_auth_attempt, ഘടന sshauthopt **authoptp)
{
	ഘടന sshbuf *m;
	പൂർണ്ണസംഖ്യ r, allowed = 0;
	ഘടന sshauthopt *opts = ശൂന്യ;

	debug3_f("entering");

	എങ്കിൽ (authoptp != ശൂന്യ)
		*authoptp = ശൂന്യ;

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshkey_puts(താക്കോൽ, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	എങ്കിൽ ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal_fr(r, "parse");
	എങ്കിൽ (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	എങ്കിൽ (authoptp != ശൂന്യ) {
		*authoptp = opts;
		opts = ശൂന്യ;
	}
	sshauthopt_free(opts);

	തിരികെ allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

പൂർണ്ണസംഖ്യ
mm_sshkey_verify(സ്ഥിരം ഘടന sshkey *താക്കോൽ, സ്ഥിരം u_char *sig, size_t siglen,
    സ്ഥിരം u_char *data, size_t datalen, സ്ഥിരം അക്ഷരം *sigalg, u_int compat,
    ഘടന sshkey_sig_details **sig_detailsp)
{
	ഘടന sshbuf *m;
	u_int encoded_ret = 0;
	പൂർണ്ണസംഖ്യ r;
	u_char sig_details_present, flags;
	u_int counter;

	debug3_f("entering");

	എങ്കിൽ (sig_detailsp != ശൂന്യ)
		*sig_detailsp = ശൂന്യ;
	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshkey_puts(താക്കോൽ, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == ശൂന്യ ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	എങ്കിൽ ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	എങ്കിൽ (sig_details_present && encoded_ret == 0) {
		എങ്കിൽ ((r = sshbuf_get_u32(m, &counter)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		എങ്കിൽ (sig_detailsp != ശൂന്യ) {
			*sig_detailsp = xcalloc(1, വലുപ്പം(**sig_detailsp));
			(*sig_detailsp)->sk_counter = counter;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	എങ്കിൽ (encoded_ret != 0)
		തിരികെ SSH_ERR_SIGNATURE_INVALID;
	തിരികെ 0;
}

ശൂന്യം
mm_send_keystate(ഘടന ssh *ssh, ഘടന monitor *monitor)
{
	ഘടന sshbuf *m;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

പൂർണ്ണസംഖ്യ
mm_pty_allocate(പൂർണ്ണസംഖ്യ *ptyfd, പൂർണ്ണസംഖ്യ *ttyfd, അക്ഷരം *namebuf, size_t namebuflen)
{
	ഘടന sshbuf *m;
	അക്ഷരം *p, *സന്ദേശം;
	പൂർണ്ണസംഖ്യ success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	എങ്കിൽ ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		എങ്കിൽ (tmp1 >= 0)
			close(tmp1);
		തിരികെ 0;
	}
	close(tmp1);
	close(tmp2);

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	എങ്കിൽ ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	എങ്കിൽ (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		തിരികെ (0);
	}
	എങ്കിൽ ((r = sshbuf_get_cstring(m, &p, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &സന്ദേശം, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	സ്വതന്ത്രം(p);

	എങ്കിൽ ((r = sshbuf_put(loginmsg, സന്ദേശം, strlen(സന്ദേശം))) != 0)
		fatal_fr(r, "put loginmsg");
	സ്വതന്ത്രം(സന്ദേശം);

	എങ്കിൽ ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	തിരികെ (1);
}

ശൂന്യം
mm_session_pty_cleanup2(Session *s)
{
	ഘടന sshbuf *m;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (s->ttyfd == -1)
		തിരികെ;
	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assmble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	എങ്കിൽ (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#ifdef USE_PAM
ശൂന്യം
mm_start_pam(ഘടന ssh *ssh)
{
	ഘടന sshbuf *m;

	debug3_f("entering");
	എങ്കിൽ (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_START, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(ശൂന്യം)
{
	ഘടന sshbuf *m;
	u_int ret;
	അക്ഷരം *സന്ദേശം;
	size_t msglen;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");
	എങ്കിൽ (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	എങ്കിൽ ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &സന്ദേശം, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, സന്ദേശം, msglen)) != 0)
		fatal_fr(r, "buffer error");

	സ്വതന്ത്രം(സന്ദേശം);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	തിരികെ (ret);
}

ശൂന്യം *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	ഘടന sshbuf *m;
	പൂർണ്ണസംഖ്യ r, success;

	debug3_f("entering");
	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	എങ്കിൽ ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "buffer error");
	എങ്കിൽ (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		തിരികെ (ശൂന്യ);
	}
	sshbuf_free(m);
	തിരികെ (authctxt);
}

പൂർണ്ണസംഖ്യ
mm_sshpam_query(ശൂന്യം *ctx, അക്ഷരം **name, അക്ഷരം **info,
    u_int *അക്കം, അക്ഷരം ***prompts, u_int **echo_on)
{
	ഘടന sshbuf *m;
	u_int i, n;
	പൂർണ്ണസംഖ്യ r, ret;

	debug3_f("entering");
	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	എങ്കിൽ ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, അക്കം)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_set_maxtries_reached(n);
	എങ്കിൽ (*അക്കം > PAM_MAX_അക്കം_സന്ദേശം)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *അക്കം, PAM_MAX_അക്കം_സന്ദേശം);
	*prompts = xcalloc((*അക്കം + 1), വലുപ്പം(അക്ഷരം *));
	*echo_on = xcalloc((*അക്കം + 1), വലുപ്പം(u_int));
	വേണ്ടി (i = 0; i < *അക്കം; ++i) {
		എങ്കിൽ ((r = sshbuf_get_cstring(m, &((*prompts)[i]), ശൂന്യ)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	തിരികെ (ret);
}

പൂർണ്ണസംഖ്യ
mm_sshpam_respond(ശൂന്യം *ctx, u_int അക്കം, അക്ഷരം **resp)
{
	ഘടന sshbuf *m;
	u_int n, i;
	പൂർണ്ണസംഖ്യ r, ret;

	debug3_f("entering");
	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u32(m, അക്കം)) != 0)
		fatal_fr(r, "buffer error");
	വേണ്ടി (i = 0; i < അക്കം; ++i) {
		എങ്കിൽ ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	എങ്കിൽ ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	ret = (പൂർണ്ണസംഖ്യ)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	തിരികെ (ret);
}

ശൂന്യം
mm_sshpam_free_ctx(ശൂന്യം *ctxtp)
{
	ഘടന sshbuf *m;

	debug3_f("entering");
	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_FREE_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_FREE_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_FREE_CTX, m);
	sshbuf_free(m);
}
#endif /* USE_PAM */

/* Request process termination */

ശൂന്യം
mm_terminate(ശൂന്യം)
{
	ഘടന sshbuf *m;

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_TERM, m);
	sshbuf_free(m);
}

/* Request state information */

ശൂന്യം
mm_get_state(ഘടന ssh *ssh,
    ServerOptions *opts, ഘടന sshbuf **confdatap,
    uint64_t *timing_secretp,
    ഘടന sshbuf **hostkeysp, ഘടന sshbuf **keystatep,
    u_char **pw_namep,
    ഘടന sshbuf **authinfop, ഘടന sshbuf **auth_optsp)
{
	ഘടന sshbuf *m, *config;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ || (config = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	എങ്കിൽ ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	എങ്കിൽ (confdatap) {
		എങ്കിൽ ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, ശൂന്യ)) != 0 ||
		    (r = sshbuf_froms(m, authinfop)) != 0 ||
		    (r = sshbuf_froms(m, auth_optsp)) != 0)
			fatal_fr(r, "parse config postauth");
	}
	എങ്കിൽ ((r = deserialise_server_options(config, opts)) != 0)
		fatal_fr(r, "deserialise_server_options");

	sshbuf_free(m);
	sshbuf_free(config);

	debug3_f("done");
}

സ്ഥിതം ശൂന്യം
mm_chall_setup(അക്ഷരം **name, അക്ഷരം **infotxt, u_int *numprompts,
    അക്ഷരം ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, വലുപ്പം(അക്ഷരം *));
	*echo_on = xcalloc(*numprompts, വലുപ്പം(u_int));
	(*echo_on)[0] = 0;
}

പൂർണ്ണസംഖ്യ
mm_bsdauth_query(ശൂന്യം *ctx, അക്ഷരം **name, അക്ഷരം **infotxt,
   u_int *numprompts, അക്ഷരം ***prompts, u_int **echo_on)
{
	ഘടന sshbuf *m;
	u_int success;
	അക്ഷരം *challenge;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	എങ്കിൽ ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	എങ്കിൽ (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		തിരികെ (-1);
	}

	/* Get the challenge, and format the response */
	എങ്കിൽ ((r = sshbuf_get_cstring(m, &challenge, ശൂന്യ)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_setup(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
mm_bsdauth_respond(ശൂന്യം *ctx, u_int numresponses, അക്ഷരം **responses)
{
	ഘടന sshbuf *m;
	പൂർണ്ണസംഖ്യ r, authok;

	debug3_f("entering");
	എങ്കിൽ (numresponses != 1)
		തിരികെ (-1);

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	എങ്കിൽ ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	തിരികെ ((authok == 0) ? -1 : 0);
}

#ifdef SSH_AUDIT_EVENTS
ശൂന്യം
mm_audit_event(ഘടന ssh *ssh, ssh_audit_event_t event)
{
	ഘടന sshbuf *m;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

ശൂന്യം
mm_audit_run_command(സ്ഥിരം അക്ഷരം *command)
{
	ഘടന sshbuf *m;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering command %s", command);

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#endif /* SSH_AUDIT_EVENTS */

#ifdef GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	ഘടന sshbuf *m;
	OM_uint32 major;
	പൂർണ്ണസംഖ്യ r;

	/* Client doesn't get to see the context */
	*ctx = ശൂന്യ;

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_string(m, goid->elements, goid->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	എങ്കിൽ ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	തിരികെ (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *in,
    gss_buffer_desc *out, OM_uint32 *flagsp)
{
	ഘടന sshbuf *m;
	OM_uint32 major;
	u_int flags;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_string(m, in->മൂല്യം, in->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	എങ്കിൽ ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, out)) != 0)
		fatal_fr(r, "parse");
	എങ്കിൽ (flagsp != ശൂന്യ) {
		എങ്കിൽ ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	തിരികെ (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	ഘടന sshbuf *m;
	OM_uint32 major;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_string(m, gssbuf->മൂല്യം, gssbuf->length)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->മൂല്യം, gssmic->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	എങ്കിൽ ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	തിരികെ(major);
}

പൂർണ്ണസംഖ്യ
mm_ssh_gssapi_userok(അക്ഷരം *user)
{
	ഘടന sshbuf *m;
	പൂർണ്ണസംഖ്യ r, authenticated = 0;

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	എങ്കിൽ ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	തിരികെ (authenticated);
}
#endif /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
സ്ഥിതം ശൂന്യം
server_process_permitopen_list(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ listen,
    അക്ഷരം **opens, u_int അക്കം_opens)
{
	u_int i;
	പൂർണ്ണസംഖ്യ port;
	അക്ഷരം *host, *arg, *oarg;
	പൂർണ്ണസംഖ്യ where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	സ്ഥിരം അക്ഷരം *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	എങ്കിൽ (അക്കം_opens == 0)
		തിരികെ; /* permit any */

	/* handle keywords: "any" / "none" */
	എങ്കിൽ (അക്കം_opens == 1 && strcmp(opens[0], "any") == 0)
		തിരികെ;
	എങ്കിൽ (അക്കം_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		തിരികെ;
	}
	/* Otherwise treat it as a list of permitted host:port */
	വേണ്ടി (i = 0; i < അക്കം_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		എങ്കിൽ (host == ശൂന്യ)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		എങ്കിൽ (arg == ശൂന്യ || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, host, port);
		സ്വതന്ത്രം(oarg);
	}
}

/*
 * Inform channels layer of permitopen options from configuration.
 */
ശൂന്യം
server_process_permitopen(ഘടന ssh *ssh)
{
	server_process_permitopen_list(ssh, 0,
	    options.permitted_opens, options.അക്കം_permitted_opens);
	server_process_permitopen_list(ssh, 1,
	    options.permitted_listens, options.അക്കം_permitted_listens);
}

ശൂന്യം
server_process_channel_timeouts(ഘടന ssh *ssh)
{
	u_int i;
	ഇരട്ട secs;
	അക്ഷരം *type;

	debug3_f("setting %u timeouts", options.അക്കം_channel_timeouts);
	channel_clear_timeouts(ssh);
	വേണ്ടി (i = 0; i < options.അക്കം_channel_timeouts; i++) {
		എങ്കിൽ (parse_pattern_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_add_timeout(ssh, type, secs);
		സ്വതന്ത്രം(type);
	}
}

ഘടന connection_info *
server_get_connection_info(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ populate, പൂർണ്ണസംഖ്യ use_dns)
{
	സ്ഥിതം ഘടന connection_info ci;

	എങ്കിൽ (ssh == ശൂന്യ || !populate)
		തിരികെ &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.address = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_port(ssh);
	ci.rdomain = ssh_packet_rdomain_in(ssh);
	തിരികെ &ci;
}

