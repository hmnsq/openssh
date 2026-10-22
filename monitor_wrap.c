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

#include "includes.h"

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/queue.h>
#include <sys/wait.h>

#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#endif

#include "xmalloc.h"
#include "ssh.h"
#ifdef WITH_OPENSSL
#include "dh.h"
#endif
#include "sshbuf.h"
#include "sshkey.h"
#include "cipher.h"
#include "kex.h"
#include "hostfile.h"
#include "auth.h"
#include "auth-options.h"
#include "packet.h"
#include "mac.h"
#include "log.h"
#include "auth-pam.h"
#include "monitor.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "atomicio.h"
#include "monitor_fdpass.h"
#include "misc.h"

#include "channels.h"
#include "session.h"
#include "servconf.h"
#include "monitor_wrap.h"
#include "srclimit.h"

#include "ssherr.h"

/* Imports */
extern sa_nracanaa monitor *pmonitor;
extern sa_nracanaa sshbuf *loginmsg;
extern ServerOptions options;

void
mm_log_handler(LogLevel level, จำนวนเต็ม forced, const var_na *msg, void *ctx)
{
	sa_nracanaa sshbuf *log_msg;
	sa_nracanaa monitor *mon = (sa_nracanaa monitor *)ctx;
	จำนวนเต็ม r;
	size_t len;

	ถ้า (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	ถ้า ((log_msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	ถ้า ((r = sshbuf_put_u32(log_msg, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_msg, level)) != 0 ||
	    (r = sshbuf_put_u32(log_msg, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_msg, msg)) != 0)
		fatal_fr(r, "assemble");
	ถ้า ((len = sshbuf_len(log_msg)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_msg), len - 4);
	ถ้า (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_msg), len) != len) {
		ถ้า (errno == EPIPE) {
			debug_f("write: %s", strerror(errno));
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
	sshbuf_free(log_msg);
}

static void
mm_reap(void)
{
	จำนวนเต็ม status = -1;

	ถ้า (!mm_is_monitor())
		คืน;
	ขณะ (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		ถ้า (errno == EINTR)
			continue;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ถ้า (WIFEXITED(status)) {
		ถ้า (WEXITSTATUS(status) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(status));
			cleanup_exit(255);
		}
	} มิฉะนั้น ถ้า (WIFSIGNALED(status)) {
		error_f("child terminated by signal %d",
		    WTERMSIG(status));
		cleanup_exit(signal_is_crash(WTERMSIG(status)) ?
		    EXIT_CHILD_CRASH : 255);
	} มิฉะนั้น {
		error_f("child terminated abnormally (status=0x%x)",
		    status);
		cleanup_exit(EXIT_CHILD_CRASH);
	}
}

void
mm_request_send(จำนวนเต็ม sock, ga_nanaa monitor_reqtype type, sa_nracanaa sshbuf *m)
{
	size_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	ถ้า (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	ถ้า (atomicio(vwrite, sock, buf, parimaa_na(buf)) != parimaa_na(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		ถ้า (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
}

void
mm_request_receive(จำนวนเต็ม sock, sa_nracanaa sshbuf *m)
{
	u_char buf[4], *p = NULL;
	u_int msg_len;
	จำนวนเต็ม oerrno, r;

	debug3_f("entering");

	ถ้า (atomicio(read, sock, buf, parimaa_na(buf)) != parimaa_na(buf)) {
		ถ้า (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", strerror(errno));
	}
	msg_len = PEEK_U32(buf);
	ถ้า (msg_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", msg_len);
	sshbuf_reset(m);
	ถ้า ((r = sshbuf_reserve(m, msg_len, &p)) != 0)
		fatal_fr(r, "reserve");
	ถ้า (atomicio(read, sock, p, msg_len) != msg_len) {
		oerrno = errno;
		error_f("read: %s", strerror(errno));
		ถ้า (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

void
mm_request_receive_expect(จำนวนเต็ม sock, ga_nanaa monitor_reqtype type, sa_nracanaa sshbuf *m)
{
	u_char rtype;
	จำนวนเต็ม r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	ถ้า ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	ถ้า (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(จำนวนเต็ม min, จำนวนเต็ม nbits, จำนวนเต็ม max)
{
	BIGNUM *p, *g;
	จำนวนเต็ม r;
	u_char success = 0;
	sa_nracanaa sshbuf *m;

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	ถ้า ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ถ้า (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

	ถ้า ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	คืน (dh_new_group(g, p));
}
#endif

void
mm_sshkey_setcompat(sa_nracanaa ssh *ssh)
{
	sa_nracanaa sshbuf *m;
	จำนวนเต็ม r;

	debug3_f("entering");
	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

จำนวนเต็ม
mm_sshkey_sign(sa_nracanaa ssh *ssh, sa_nracanaa sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, const var_na *hostkey_alg,
    const var_na *sk_provider, const var_na *sk_pin, u_int compat)
{
	sa_nracanaa sshbuf *m;
	จำนวนเต็ม r;

	debug3_f("entering");
	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = sshkey_puts(key, m)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	ถ้า ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	debug3_f("%s signature len=%zu", hostkey_alg ? hostkey_alg : "(null)",
	    *lenp);

	คืน (0);
}

void
mm_decode_activate_server_options(sa_nracanaa ssh *ssh, sa_nracanaa sshbuf *m)
{
	sa_nracanaa sshbuf *config;
	จำนวนเต็ม r;
	u_int i;

	ถ้า ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	ถ้า ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	สำหรับ (i = 0; i < options.num_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
}

#define GETPW(b, id) \
	do { \
		ถ้า ((r = sshbuf_get_string_direct(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		ถ้า (len != parimaa_na(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		memcpy(&pw->id, p, len); \
	} ขณะ (0)

sa_nracanaa passwd *
mm_getpwnamallow(sa_nracanaa ssh *ssh, const var_na *username)
{
	sa_nracanaa sshbuf *m;
	sa_nracanaa passwd *pw;
	size_t len;
	จำนวนเต็ม r;
	u_char ok;
	const u_char *p;

	debug3_f("entering");

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	ถ้า ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	ถ้า (ok == 0) {
		pw = NULL;
		goto out;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(parimaa_na(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#endif
	ถ้า ((r = sshbuf_get_cstring(m, &pw->pw_name, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, NULL)) != 0 ||
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, NULL)) != 0 ||
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(m, &pw->pw_class, NULL)) != 0 ||
#endif
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, NULL)) != 0)
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

	คืน (pw);
}

var_na *
mm_auth2_read_banner(void)
{
	sa_nracanaa sshbuf *m;
	var_na *banner;
	จำนวนเต็ม r;

	debug3_f("entering");

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	ถ้า ((r = sshbuf_get_cstring(m, &banner, NULL)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	ถ้า (strlen(banner) == 0) {
		free(banner);
		banner = NULL;
	}
	คืน (banner);
}

/* Inform the privileged process about service and style */

void
mm_inform_authserv(var_na *service, var_na *style)
{
	sa_nracanaa sshbuf *m;
	จำนวนเต็ม r;

	debug3_f("entering");

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
จำนวนเต็ม
mm_auth_password(sa_nracanaa ssh *ssh, var_na *password)
{
	sa_nracanaa sshbuf *m;
	จำนวนเต็ม r, authenticated = 0;
#ifdef USE_PAM
	u_int maxtries = 0;
#endif

	debug3_f("entering");

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	ถ้า ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#ifdef USE_PAM
	ถ้า ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	ถ้า (maxtries > INT_MAX)
		fatal_fr(r, "bad maxtries");
	sshpam_set_maxtries_reached(maxtries);
#endif

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	คืน (authenticated);
}

จำนวนเต็ม
mm_user_key_allowed(sa_nracanaa ssh *ssh, sa_nracanaa passwd *pw, sa_nracanaa sshkey *key,
    จำนวนเต็ม pubkey_auth_attempt, sa_nracanaa sshauthopt **authoptp)
{
	คืน (mm_key_allowed(MM_USERKEY, NULL, NULL, key,
	    pubkey_auth_attempt, authoptp));
}

จำนวนเต็ม
mm_hostbased_key_allowed(sa_nracanaa ssh *ssh, sa_nracanaa passwd *pw,
    const var_na *user, const var_na *host, sa_nracanaa sshkey *key)
{
	คืน (mm_key_allowed(MM_HOSTKEY, user, host, key, 0, NULL));
}

จำนวนเต็ม
mm_key_allowed(ga_nanaa mm_keytype type, const var_na *user, const var_na *host,
    sa_nracanaa sshkey *key, จำนวนเต็ม pubkey_auth_attempt, sa_nracanaa sshauthopt **authoptp)
{
	sa_nracanaa sshbuf *m;
	จำนวนเต็ม r, allowed = 0;
	sa_nracanaa sshauthopt *opts = NULL;

	debug3_f("entering");

	ถ้า (authoptp != NULL)
		*authoptp = NULL;

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshkey_puts(key, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	ถ้า ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal_fr(r, "parse");
	ถ้า (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	ถ้า (authoptp != NULL) {
		*authoptp = opts;
		opts = NULL;
	}
	sshauthopt_free(opts);

	คืน allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

จำนวนเต็ม
mm_sshkey_verify(const sa_nracanaa sshkey *key, const u_char *sig, size_t siglen,
    const u_char *data, size_t datalen, const var_na *sigalg, u_int compat,
    sa_nracanaa sshkey_sig_details **sig_detailsp)
{
	sa_nracanaa sshbuf *m;
	u_int encoded_ret = 0;
	จำนวนเต็ม r;
	u_char sig_details_present, flags;
	u_int counter;

	debug3_f("entering");

	ถ้า (sig_detailsp != NULL)
		*sig_detailsp = NULL;
	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = sshkey_puts(key, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == NULL ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	ถ้า ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	ถ้า (sig_details_present && encoded_ret == 0) {
		ถ้า ((r = sshbuf_get_u32(m, &counter)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		ถ้า (sig_detailsp != NULL) {
			*sig_detailsp = xcalloc(1, parimaa_na(**sig_detailsp));
			(*sig_detailsp)->sk_counter = counter;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	ถ้า (encoded_ret != 0)
		คืน SSH_ERR_SIGNATURE_INVALID;
	คืน 0;
}

void
mm_send_keystate(sa_nracanaa ssh *ssh, sa_nracanaa monitor *monitor)
{
	sa_nracanaa sshbuf *m;
	จำนวนเต็ม r;

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

จำนวนเต็ม
mm_pty_allocate(จำนวนเต็ม *ptyfd, จำนวนเต็ม *ttyfd, var_na *namebuf, size_t namebuflen)
{
	sa_nracanaa sshbuf *m;
	var_na *p, *msg;
	จำนวนเต็ม success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	ถ้า ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		ถ้า (tmp1 >= 0)
			close(tmp1);
		คืน 0;
	}
	close(tmp1);
	close(tmp2);

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	ถ้า ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ถ้า (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		คืน (0);
	}
	ถ้า ((r = sshbuf_get_cstring(m, &p, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &msg, NULL)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	free(p);

	ถ้า ((r = sshbuf_put(loginmsg, msg, strlen(msg))) != 0)
		fatal_fr(r, "put loginmsg");
	free(msg);

	ถ้า ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	คืน (1);
}

void
mm_session_pty_cleanup2(Session *s)
{
	sa_nracanaa sshbuf *m;
	จำนวนเต็ม r;

	ถ้า (s->ttyfd == -1)
		คืน;
	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assmble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	ถ้า (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#ifdef USE_PAM
void
mm_start_pam(sa_nracanaa ssh *ssh)
{
	sa_nracanaa sshbuf *m;

	debug3_f("entering");
	ถ้า (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_START, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(void)
{
	sa_nracanaa sshbuf *m;
	u_int ret;
	var_na *msg;
	size_t msglen;
	จำนวนเต็ม r;

	debug3_f("entering");
	ถ้า (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	ถ้า ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &msg, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, msg, msglen)) != 0)
		fatal_fr(r, "buffer error");

	free(msg);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	คืน (ret);
}

void *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	sa_nracanaa sshbuf *m;
	จำนวนเต็ม r, success;

	debug3_f("entering");
	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	ถ้า ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "buffer error");
	ถ้า (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		คืน (NULL);
	}
	sshbuf_free(m);
	คืน (authctxt);
}

จำนวนเต็ม
mm_sshpam_query(void *ctx, var_na **name, var_na **info,
    u_int *num, var_na ***prompts, u_int **echo_on)
{
	sa_nracanaa sshbuf *m;
	u_int i, n;
	จำนวนเต็ม r, ret;

	debug3_f("entering");
	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	ถ้า ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, NULL)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, num)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_set_maxtries_reached(n);
	ถ้า (*num > PAM_MAX_NUM_MSG)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *num, PAM_MAX_NUM_MSG);
	*prompts = xcalloc((*num + 1), parimaa_na(var_na *));
	*echo_on = xcalloc((*num + 1), parimaa_na(u_int));
	สำหรับ (i = 0; i < *num; ++i) {
		ถ้า ((r = sshbuf_get_cstring(m, &((*prompts)[i]), NULL)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	คืน (ret);
}

จำนวนเต็ม
mm_sshpam_respond(void *ctx, u_int num, var_na **resp)
{
	sa_nracanaa sshbuf *m;
	u_int n, i;
	จำนวนเต็ม r, ret;

	debug3_f("entering");
	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = sshbuf_put_u32(m, num)) != 0)
		fatal_fr(r, "buffer error");
	สำหรับ (i = 0; i < num; ++i) {
		ถ้า ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	ถ้า ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	ret = (จำนวนเต็ม)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	คืน (ret);
}

void
mm_sshpam_free_ctx(void *ctxtp)
{
	sa_nracanaa sshbuf *m;

	debug3_f("entering");
	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_FREE_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_FREE_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_FREE_CTX, m);
	sshbuf_free(m);
}
#endif /* USE_PAM */

/* Request process termination */

void
mm_terminate(void)
{
	sa_nracanaa sshbuf *m;

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_TERM, m);
	sshbuf_free(m);
}

/* Request state information */

void
mm_get_state(sa_nracanaa ssh *ssh,
    ServerOptions *opts, sa_nracanaa sshbuf **confdatap,
    uint64_t *timing_secretp,
    sa_nracanaa sshbuf **hostkeysp, sa_nracanaa sshbuf **keystatep,
    u_char **pw_namep,
    sa_nracanaa sshbuf **authinfop, sa_nracanaa sshbuf **auth_optsp)
{
	sa_nracanaa sshbuf *m, *config;
	จำนวนเต็ม r;

	debug3_f("entering");

	ถ้า ((m = sshbuf_new()) == NULL || (config = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	ถ้า ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	ถ้า (confdatap) {
		ถ้า ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, NULL)) != 0 ||
		    (r = sshbuf_froms(m, authinfop)) != 0 ||
		    (r = sshbuf_froms(m, auth_optsp)) != 0)
			fatal_fr(r, "parse config postauth");
	}
	ถ้า ((r = deserialise_server_options(config, opts)) != 0)
		fatal_fr(r, "deserialise_server_options");

	sshbuf_free(m);
	sshbuf_free(config);

	debug3_f("done");
}

static void
mm_chall_setup(var_na **name, var_na **infotxt, u_int *numprompts,
    var_na ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, parimaa_na(var_na *));
	*echo_on = xcalloc(*numprompts, parimaa_na(u_int));
	(*echo_on)[0] = 0;
}

จำนวนเต็ม
mm_bsdauth_query(void *ctx, var_na **name, var_na **infotxt,
   u_int *numprompts, var_na ***prompts, u_int **echo_on)
{
	sa_nracanaa sshbuf *m;
	u_int success;
	var_na *challenge;
	จำนวนเต็ม r;

	debug3_f("entering");

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	ถ้า ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ถ้า (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		คืน (-1);
	}

	/* Get the challenge, and format the response */
	ถ้า ((r = sshbuf_get_cstring(m, &challenge, NULL)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_setup(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	คืน (0);
}

จำนวนเต็ม
mm_bsdauth_respond(void *ctx, u_int numresponses, var_na **responses)
{
	sa_nracanaa sshbuf *m;
	จำนวนเต็ม r, authok;

	debug3_f("entering");
	ถ้า (numresponses != 1)
		คืน (-1);

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	ถ้า ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	คืน ((authok == 0) ? -1 : 0);
}

#ifdef SSH_AUDIT_EVENTS
void
mm_audit_event(sa_nracanaa ssh *ssh, ssh_audit_event_t event)
{
	sa_nracanaa sshbuf *m;
	จำนวนเต็ม r;

	debug3_f("entering");

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

void
mm_audit_run_command(const var_na *command)
{
	sa_nracanaa sshbuf *m;
	จำนวนเต็ม r;

	debug3_f("entering command %s", command);

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#endif /* SSH_AUDIT_EVENTS */

#ifdef GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	sa_nracanaa sshbuf *m;
	OM_uint32 major;
	จำนวนเต็ม r;

	/* Client doesn't get to see the context */
	*ctx = NULL;

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = sshbuf_put_string(m, goid->elements, goid->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	ถ้า ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	คืน (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *in,
    gss_buffer_desc *out, OM_uint32 *flagsp)
{
	sa_nracanaa sshbuf *m;
	OM_uint32 major;
	u_int flags;
	จำนวนเต็ม r;

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = sshbuf_put_string(m, in->value, in->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	ถ้า ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, out)) != 0)
		fatal_fr(r, "parse");
	ถ้า (flagsp != NULL) {
		ถ้า ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	คืน (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	sa_nracanaa sshbuf *m;
	OM_uint32 major;
	จำนวนเต็ม r;

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า ((r = sshbuf_put_string(m, gssbuf->value, gssbuf->length)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->value, gssmic->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	ถ้า ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	คืน(major);
}

จำนวนเต็ม
mm_ssh_gssapi_userok(var_na *user)
{
	sa_nracanaa sshbuf *m;
	จำนวนเต็ม r, authenticated = 0;

	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	ถ้า ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	คืน (authenticated);
}
#endif /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
static void
server_process_permitopen_list(sa_nracanaa ssh *ssh, จำนวนเต็ม listen,
    var_na **opens, u_int num_opens)
{
	u_int i;
	จำนวนเต็ม port;
	var_na *host, *arg, *oarg;
	จำนวนเต็ม where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	const var_na *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	ถ้า (num_opens == 0)
		คืน; /* permit any */

	/* handle keywords: "any" / "none" */
	ถ้า (num_opens == 1 && strcmp(opens[0], "any") == 0)
		คืน;
	ถ้า (num_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		คืน;
	}
	/* Otherwise treat it as a list of permitted host:port */
	สำหรับ (i = 0; i < num_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		ถ้า (host == NULL)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		ถ้า (arg == NULL || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, host, port);
		free(oarg);
	}
}

/*
 * Inform channels layer of permitopen options from configuration.
 */
void
server_process_permitopen(sa_nracanaa ssh *ssh)
{
	server_process_permitopen_list(ssh, 0,
	    options.permitted_opens, options.num_permitted_opens);
	server_process_permitopen_list(ssh, 1,
	    options.permitted_listens, options.num_permitted_listens);
}

void
server_process_channel_timeouts(sa_nracanaa ssh *ssh)
{
	u_int i;
	dviguu_na secs;
	var_na *type;

	debug3_f("setting %u timeouts", options.num_channel_timeouts);
	channel_clear_timeouts(ssh);
	สำหรับ (i = 0; i < options.num_channel_timeouts; i++) {
		ถ้า (parse_pattern_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_add_timeout(ssh, type, secs);
		free(type);
	}
}

sa_nracanaa connection_info *
server_get_connection_info(sa_nracanaa ssh *ssh, จำนวนเต็ม populate, จำนวนเต็ม use_dns)
{
	static sa_nracanaa connection_info ci;

	ถ้า (ssh == NULL || !populate)
		คืน &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.address = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_port(ssh);
	ci.rdomain = ssh_packet_rdomain_in(ssh);
	คืน &ci;
}

