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
extern struct monitor *pmonitor;
extern struct sshbuf *loginmsg;
extern ServerOptions options;

void
mm_log_handler(LogLevel level, ціле forced, const char *msg, void *ctx)
{
	struct sshbuf *log_msg;
	struct monitor *mon = (struct monitor *)ctx;
	ціле r;
	size_t len;

	якщо (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	якщо ((log_msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	якщо ((r = sshbuf_put_u32(log_msg, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_msg, level)) != 0 ||
	    (r = sshbuf_put_u32(log_msg, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_msg, msg)) != 0)
		fatal_fr(r, "assemble");
	якщо ((len = sshbuf_len(log_msg)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_msg), len - 4);
	якщо (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_msg), len) != len) {
		якщо (errno == EPIPE) {
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
	ціле status = -1;

	якщо (!mm_is_monitor())
		повернути;
	поки (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		якщо (errno == EINTR)
			continue;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", strerror(errno));
	}
	якщо (WIFEXITED(status)) {
		якщо (WEXITSTATUS(status) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(status));
			cleanup_exit(255);
		}
	} інакше якщо (WIFSIGNALED(status)) {
		error_f("child terminated by signal %d",
		    WTERMSIG(status));
		cleanup_exit(signal_is_crash(WTERMSIG(status)) ?
		    EXIT_CHILD_CRASH : 255);
	} інакше {
		error_f("child terminated abnormally (status=0x%x)",
		    status);
		cleanup_exit(EXIT_CHILD_CRASH);
	}
}

void
mm_request_send(ціле sock, enum monitor_reqtype type, struct sshbuf *m)
{
	size_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	якщо (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	якщо (atomicio(vwrite, sock, buf, sizeof(buf)) != sizeof(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		якщо (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
}

void
mm_request_receive(ціле sock, struct sshbuf *m)
{
	u_char buf[4], *p = NULL;
	u_int msg_len;
	ціле oerrno, r;

	debug3_f("entering");

	якщо (atomicio(read, sock, buf, sizeof(buf)) != sizeof(buf)) {
		якщо (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", strerror(errno));
	}
	msg_len = PEEK_U32(buf);
	якщо (msg_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", msg_len);
	sshbuf_reset(m);
	якщо ((r = sshbuf_reserve(m, msg_len, &p)) != 0)
		fatal_fr(r, "reserve");
	якщо (atomicio(read, sock, p, msg_len) != msg_len) {
		oerrno = errno;
		error_f("read: %s", strerror(errno));
		якщо (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

void
mm_request_receive_expect(ціле sock, enum monitor_reqtype type, struct sshbuf *m)
{
	u_char rtype;
	ціле r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	якщо ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	якщо (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(ціле min, ціле nbits, ціле max)
{
	BIGNUM *p, *g;
	ціле r;
	u_char success = 0;
	struct sshbuf *m;

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	якщо ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	якщо (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

	якщо ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	повернути (dh_new_group(g, p));
}
#endif

void
mm_sshkey_setcompat(struct ssh *ssh)
{
	struct sshbuf *m;
	ціле r;

	debug3_f("entering");
	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

ціле
mm_sshkey_sign(struct ssh *ssh, struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, const char *hostkey_alg,
    const char *sk_provider, const char *sk_pin, u_int compat)
{
	struct sshbuf *m;
	ціле r;

	debug3_f("entering");
	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshkey_puts(key, m)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	якщо ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	debug3_f("%s signature len=%zu", hostkey_alg ? hostkey_alg : "(null)",
	    *lenp);

	повернути (0);
}

void
mm_decode_activate_server_options(struct ssh *ssh, struct sshbuf *m)
{
	struct sshbuf *config;
	ціле r;
	u_int i;

	якщо ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	якщо ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	для (i = 0; i < options.num_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
}

#define GETPW(b, id) \
	do { \
		якщо ((r = sshbuf_get_string_direct(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		якщо (len != sizeof(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		memcpy(&pw->id, p, len); \
	} поки (0)

struct passwd *
mm_getpwnamallow(struct ssh *ssh, const char *username)
{
	struct sshbuf *m;
	struct passwd *pw;
	size_t len;
	ціле r;
	u_char ok;
	const u_char *p;

	debug3_f("entering");

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	якщо ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	якщо (ok == 0) {
		pw = NULL;
		goto out;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(sizeof(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#endif
	якщо ((r = sshbuf_get_cstring(m, &pw->pw_name, NULL)) != 0 ||
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

	повернути (pw);
}

char *
mm_auth2_read_banner(void)
{
	struct sshbuf *m;
	char *banner;
	ціле r;

	debug3_f("entering");

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	якщо ((r = sshbuf_get_cstring(m, &banner, NULL)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	якщо (strlen(banner) == 0) {
		free(banner);
		banner = NULL;
	}
	повернути (banner);
}

/* Inform the privileged process about service and style */

void
mm_inform_authserv(char *service, char *style)
{
	struct sshbuf *m;
	ціле r;

	debug3_f("entering");

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
ціле
mm_auth_password(struct ssh *ssh, char *password)
{
	struct sshbuf *m;
	ціле r, authenticated = 0;
#ifdef USE_PAM
	u_int maxtries = 0;
#endif

	debug3_f("entering");

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	якщо ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#ifdef USE_PAM
	якщо ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	якщо (maxtries > INT_MAX)
		fatal_fr(r, "bad maxtries");
	sshpam_set_maxtries_reached(maxtries);
#endif

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	повернути (authenticated);
}

ціле
mm_user_key_allowed(struct ssh *ssh, struct passwd *pw, struct sshkey *key,
    ціле pubkey_auth_attempt, struct sshauthopt **authoptp)
{
	повернути (mm_key_allowed(MM_USERKEY, NULL, NULL, key,
	    pubkey_auth_attempt, authoptp));
}

ціле
mm_hostbased_key_allowed(struct ssh *ssh, struct passwd *pw,
    const char *user, const char *host, struct sshkey *key)
{
	повернути (mm_key_allowed(MM_HOSTKEY, user, host, key, 0, NULL));
}

ціле
mm_key_allowed(enum mm_keytype type, const char *user, const char *host,
    struct sshkey *key, ціле pubkey_auth_attempt, struct sshauthopt **authoptp)
{
	struct sshbuf *m;
	ціле r, allowed = 0;
	struct sshauthopt *opts = NULL;

	debug3_f("entering");

	якщо (authoptp != NULL)
		*authoptp = NULL;

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshkey_puts(key, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	якщо ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal_fr(r, "parse");
	якщо (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	якщо (authoptp != NULL) {
		*authoptp = opts;
		opts = NULL;
	}
	sshauthopt_free(opts);

	повернути allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

ціле
mm_sshkey_verify(const struct sshkey *key, const u_char *sig, size_t siglen,
    const u_char *data, size_t datalen, const char *sigalg, u_int compat,
    struct sshkey_sig_details **sig_detailsp)
{
	struct sshbuf *m;
	u_int encoded_ret = 0;
	ціле r;
	u_char sig_details_present, flags;
	u_int counter;

	debug3_f("entering");

	якщо (sig_detailsp != NULL)
		*sig_detailsp = NULL;
	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshkey_puts(key, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == NULL ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	якщо ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	якщо (sig_details_present && encoded_ret == 0) {
		якщо ((r = sshbuf_get_u32(m, &counter)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		якщо (sig_detailsp != NULL) {
			*sig_detailsp = xcalloc(1, sizeof(**sig_detailsp));
			(*sig_detailsp)->sk_counter = counter;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	якщо (encoded_ret != 0)
		повернути SSH_ERR_SIGNATURE_INVALID;
	повернути 0;
}

void
mm_send_keystate(struct ssh *ssh, struct monitor *monitor)
{
	struct sshbuf *m;
	ціле r;

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

ціле
mm_pty_allocate(ціле *ptyfd, ціле *ttyfd, char *namebuf, size_t namebuflen)
{
	struct sshbuf *m;
	char *p, *msg;
	ціле success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	якщо ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		якщо (tmp1 >= 0)
			close(tmp1);
		повернути 0;
	}
	close(tmp1);
	close(tmp2);

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	якщо ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	якщо (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		повернути (0);
	}
	якщо ((r = sshbuf_get_cstring(m, &p, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &msg, NULL)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	free(p);

	якщо ((r = sshbuf_put(loginmsg, msg, strlen(msg))) != 0)
		fatal_fr(r, "put loginmsg");
	free(msg);

	якщо ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	повернути (1);
}

void
mm_session_pty_cleanup2(Session *s)
{
	struct sshbuf *m;
	ціле r;

	якщо (s->ttyfd == -1)
		повернути;
	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assmble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	якщо (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#ifdef USE_PAM
void
mm_start_pam(struct ssh *ssh)
{
	struct sshbuf *m;

	debug3_f("entering");
	якщо (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_START, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(void)
{
	struct sshbuf *m;
	u_int ret;
	char *msg;
	size_t msglen;
	ціле r;

	debug3_f("entering");
	якщо (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	якщо ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &msg, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, msg, msglen)) != 0)
		fatal_fr(r, "buffer error");

	free(msg);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	повернути (ret);
}

void *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	struct sshbuf *m;
	ціле r, success;

	debug3_f("entering");
	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	якщо ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "buffer error");
	якщо (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		повернути (NULL);
	}
	sshbuf_free(m);
	повернути (authctxt);
}

ціле
mm_sshpam_query(void *ctx, char **name, char **info,
    u_int *num, char ***prompts, u_int **echo_on)
{
	struct sshbuf *m;
	u_int i, n;
	ціле r, ret;

	debug3_f("entering");
	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	якщо ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, NULL)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, num)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_set_maxtries_reached(n);
	якщо (*num > PAM_MAX_NUM_MSG)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *num, PAM_MAX_NUM_MSG);
	*prompts = xcalloc((*num + 1), sizeof(char *));
	*echo_on = xcalloc((*num + 1), sizeof(u_int));
	для (i = 0; i < *num; ++i) {
		якщо ((r = sshbuf_get_cstring(m, &((*prompts)[i]), NULL)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	повернути (ret);
}

ціле
mm_sshpam_respond(void *ctx, u_int num, char **resp)
{
	struct sshbuf *m;
	u_int n, i;
	ціле r, ret;

	debug3_f("entering");
	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshbuf_put_u32(m, num)) != 0)
		fatal_fr(r, "buffer error");
	для (i = 0; i < num; ++i) {
		якщо ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	якщо ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	ret = (ціле)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	повернути (ret);
}

void
mm_sshpam_free_ctx(void *ctxtp)
{
	struct sshbuf *m;

	debug3_f("entering");
	якщо ((m = sshbuf_new()) == NULL)
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
	struct sshbuf *m;

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_TERM, m);
	sshbuf_free(m);
}

/* Request state information */

void
mm_get_state(struct ssh *ssh,
    ServerOptions *opts, struct sshbuf **confdatap,
    uint64_t *timing_secretp,
    struct sshbuf **hostkeysp, struct sshbuf **keystatep,
    u_char **pw_namep,
    struct sshbuf **authinfop, struct sshbuf **auth_optsp)
{
	struct sshbuf *m, *config;
	ціле r;

	debug3_f("entering");

	якщо ((m = sshbuf_new()) == NULL || (config = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	якщо ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	якщо (confdatap) {
		якщо ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, NULL)) != 0 ||
		    (r = sshbuf_froms(m, authinfop)) != 0 ||
		    (r = sshbuf_froms(m, auth_optsp)) != 0)
			fatal_fr(r, "parse config postauth");
	}
	якщо ((r = deserialise_server_options(config, opts)) != 0)
		fatal_fr(r, "deserialise_server_options");

	sshbuf_free(m);
	sshbuf_free(config);

	debug3_f("done");
}

static void
mm_chall_setup(char **name, char **infotxt, u_int *numprompts,
    char ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, sizeof(char *));
	*echo_on = xcalloc(*numprompts, sizeof(u_int));
	(*echo_on)[0] = 0;
}

ціле
mm_bsdauth_query(void *ctx, char **name, char **infotxt,
   u_int *numprompts, char ***prompts, u_int **echo_on)
{
	struct sshbuf *m;
	u_int success;
	char *challenge;
	ціле r;

	debug3_f("entering");

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	якщо ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	якщо (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		повернути (-1);
	}

	/* Get the challenge, and format the response */
	якщо ((r = sshbuf_get_cstring(m, &challenge, NULL)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_setup(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	повернути (0);
}

ціле
mm_bsdauth_respond(void *ctx, u_int numresponses, char **responses)
{
	struct sshbuf *m;
	ціле r, authok;

	debug3_f("entering");
	якщо (numresponses != 1)
		повернути (-1);

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	якщо ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	повернути ((authok == 0) ? -1 : 0);
}

#ifdef SSH_AUDIT_EVENTS
void
mm_audit_event(struct ssh *ssh, ssh_audit_event_t event)
{
	struct sshbuf *m;
	ціле r;

	debug3_f("entering");

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

void
mm_audit_run_command(const char *command)
{
	struct sshbuf *m;
	ціле r;

	debug3_f("entering command %s", command);

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#endif /* SSH_AUDIT_EVENTS */

#ifdef GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	struct sshbuf *m;
	OM_uint32 major;
	ціле r;

	/* Client doesn't get to see the context */
	*ctx = NULL;

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshbuf_put_string(m, goid->elements, goid->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	якщо ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	повернути (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *in,
    gss_buffer_desc *out, OM_uint32 *flagsp)
{
	struct sshbuf *m;
	OM_uint32 major;
	u_int flags;
	ціле r;

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshbuf_put_string(m, in->value, in->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	якщо ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, out)) != 0)
		fatal_fr(r, "parse");
	якщо (flagsp != NULL) {
		якщо ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	повернути (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	struct sshbuf *m;
	OM_uint32 major;
	ціле r;

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshbuf_put_string(m, gssbuf->value, gssbuf->length)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->value, gssmic->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	якщо ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	повернути(major);
}

ціле
mm_ssh_gssapi_userok(char *user)
{
	struct sshbuf *m;
	ціле r, authenticated = 0;

	якщо ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	якщо ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	повернути (authenticated);
}
#endif /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
static void
server_process_permitopen_list(struct ssh *ssh, ціле listen,
    char **opens, u_int num_opens)
{
	u_int i;
	ціле port;
	char *host, *arg, *oarg;
	ціле where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	const char *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	якщо (num_opens == 0)
		повернути; /* permit any */

	/* handle keywords: "any" / "none" */
	якщо (num_opens == 1 && strcmp(opens[0], "any") == 0)
		повернути;
	якщо (num_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		повернути;
	}
	/* Otherwise treat it as a list of permitted host:port */
	для (i = 0; i < num_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		якщо (host == NULL)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		якщо (arg == NULL || ((port = permitopen_port(arg)) < 0))
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
server_process_permitopen(struct ssh *ssh)
{
	server_process_permitopen_list(ssh, 0,
	    options.permitted_opens, options.num_permitted_opens);
	server_process_permitopen_list(ssh, 1,
	    options.permitted_listens, options.num_permitted_listens);
}

void
server_process_channel_timeouts(struct ssh *ssh)
{
	u_int i;
	double secs;
	char *type;

	debug3_f("setting %u timeouts", options.num_channel_timeouts);
	channel_clear_timeouts(ssh);
	для (i = 0; i < options.num_channel_timeouts; i++) {
		якщо (parse_pattern_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_add_timeout(ssh, type, secs);
		free(type);
	}
}

struct connection_info *
server_get_connection_info(struct ssh *ssh, ціле populate, ціле use_dns)
{
	static struct connection_info ci;

	якщо (ssh == NULL || !populate)
		повернути &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.address = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_port(ssh);
	ci.rdomain = ssh_packet_rdomain_in(ssh);
	повернути &ci;
}

