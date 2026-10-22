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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/uio.h>
#అన్తర్భావ <sys/queue.h>
#అన్తర్భావ <sys/wait.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/dh.h>
#అన్తర్భావ <openssl/evp.h>
#అయితే_ముగింపు

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ "dh.h"
#అయితే_ముగింపు
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "cipher.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "auth-options.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "mac.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "auth-pam.h"
#అన్తర్భావ "monitor.h"
#నిర్వచితమైతే GSSAPI
#అన్తర్భావ "ssh-gss.h"
#అయితే_ముగింపు
#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "monitor_fdpass.h"
#అన్తర్భావ "misc.h"

#అన్తర్భావ "channels.h"
#అన్తర్భావ "session.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "monitor_wrap.h"
#అన్తర్భావ "srclimit.h"

#అన్తర్భావ "ssherr.h"

/* Imports */
బాహ్య నిర్మాణం monitor *pmonitor;
బాహ్య నిర్మాణం sshbuf *loginmsg;
బాహ్య ServerOptions options;

శూన్య
mm_log_handler(LogLevel level, పూర్ణాంకం forced, స్థిరరాశి అక్షరం *సందేశం, శూన్య *ctx)
{
	నిర్మాణం sshbuf *log_సందేశం;
	నిర్మాణం monitor *mon = (నిర్మాణం monitor *)ctx;
	పూర్ణాంకం r;
	కొలత_t len;

	ఒకవేళ (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	ఒకవేళ ((log_సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	ఒకవేళ ((r = sshbuf_put_u32(log_సందేశం, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_సందేశం, level)) != 0 ||
	    (r = sshbuf_put_u32(log_సందేశం, forced)) != 0 ||
	    (r = sshbuf_put_cstring(log_సందేశం, సందేశం)) != 0)
		fatal_fr(r, "assemble");
	ఒకవేళ ((len = sshbuf_len(log_సందేశం)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_సందేశం), len - 4);
	ఒకవేళ (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_సందేశం), len) != len) {
		ఒకవేళ (errno == EPIPE) {
			debug_f("write: %s", strerror(errno));
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
	sshbuf_free(log_సందేశం);
}

స్థిర శూన్య
mm_reap(శూన్య)
{
	పూర్ణాంకం స్థితి_2 = -1;

	ఒకవేళ (!mm_is_monitor())
		తిరిగి;
	అయితే (waitpid(pmonitor->m_pid, &స్థితి_2, 0) == -1) {
		ఒకవేళ (errno == EINTR)
			కొనసాగు;
		pmonitor->m_pid = -1;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ఒకవేళ (WIFEXITED(స్థితి_2)) {
		ఒకవేళ (WEXITSTATUS(స్థితి_2) != 0) {
			debug_f("child exited with status %d",
			    WEXITSTATUS(స్థితి_2));
			cleanup_exit(255);
		}
	} లేకపోతే ఒకవేళ (WIFSIGNALED(స్థితి_2)) {
		error_f("child terminated by signal %d",
		    WTERMSIG(స్థితి_2));
		cleanup_exit(signal_is_crash(WTERMSIG(స్థితి_2)) ?
		    EXIT_బిడ్డ_CRASH : 255);
	} లేకపోతే {
		error_f("child terminated abnormally (status=0x%x)",
		    స్థితి_2);
		cleanup_exit(EXIT_బిడ్డ_CRASH);
	}
}

శూన్య
mm_request_send(పూర్ణాంకం sock, గణన monitor_reqtype type, నిర్మాణం sshbuf *m)
{
	కొలత_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	ఒకవేళ (mlen >= MONITOR_MAX_MSGLEN)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	ఒకవేళ (atomicio(vwrite, sock, buf, పరిమాణం(buf)) != పరిమాణం(buf) ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen) {
		ఒకవేళ (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("write: %s", strerror(errno));
	}
}

శూన్య
mm_request_receive(పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	u_char buf[4], *p = ఖాళీ;
	u_int సందేశం_len;
	పూర్ణాంకం oerrno, r;

	debug3_f("entering");

	ఒకవేళ (atomicio(పఠ, sock, buf, పరిమాణం(buf)) != పరిమాణం(buf)) {
		ఒకవేళ (errno == EPIPE) {
			debug3_f("monitor fd closed");
			mm_reap();
			cleanup_exit(255);
		}
		fatal_f("read: %s", strerror(errno));
	}
	సందేశం_len = PEEK_U32(buf);
	ఒకవేళ (సందేశం_len > MONITOR_MAX_MSGLEN)
		fatal_f("read: bad msg_len %d", సందేశం_len);
	sshbuf_reset(m);
	ఒకవేళ ((r = sshbuf_reserve(m, సందేశం_len, &p)) != 0)
		fatal_fr(r, "reserve");
	ఒకవేళ (atomicio(పఠ, sock, p, సందేశం_len) != సందేశం_len) {
		oerrno = errno;
		error_f("read: %s", strerror(errno));
		ఒకవేళ (oerrno == EPIPE)
			mm_reap();
		cleanup_exit(255);
	}
}

శూన్య
mm_request_receive_expect(పూర్ణాంకం sock, గణన monitor_reqtype type, నిర్మాణం sshbuf *m)
{
	u_char rtype;
	పూర్ణాంకం r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	ఒకవేళ ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	ఒకవేళ (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#నిర్వచితమైతే WITH_OPENSSL
DH *
mm_ఎంచుకో_dh(పూర్ణాంకం min, పూర్ణాంకం nbits, పూర్ణాంకం max)
{
	BIGNUM *p, *g;
	పూర్ణాంకం r;
	u_char success = 0;
	నిర్మాణం sshbuf *m;

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	ఒకవేళ ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ఒకవేళ (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

	ఒకవేళ ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	తిరిగి (dh_new_సమూహం(g, p));
}
#అయితే_ముగింపు

శూన్య
mm_sshkey_setcompat(నిర్మాణం ssh *ssh)
{
	నిర్మాణం sshbuf *m;
	పూర్ణాంకం r;

	debug3_f("entering");
	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u32(m, ssh->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SETCOMPAT, m);
}

పూర్ణాంకం
mm_sshkey_sign(నిర్మాణం ssh *ssh, నిర్మాణం sshkey *కీలకం, u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen, స్థిరరాశి అక్షరం *hostkey_alg,
    స్థిరరాశి అక్షరం *sk_provider, స్థిరరాశి అక్షరం *sk_pin, u_int compat)
{
	నిర్మాణం sshbuf *m;
	పూర్ణాంకం r;

	debug3_f("entering");
	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshkey_puts(కీలకం, m)) != 0 ||
	    (r = sshbuf_put_string(m, దత్తాంశం, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	ఒకవేళ ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	debug3_f("%s signature len=%zu", hostkey_alg ? hostkey_alg : "(null)",
	    *lenp);

	తిరిగి (0);
}

శూన్య
mm_decode_activate_server_options(నిర్మాణం ssh *ssh, నిర్మాణం sshbuf *m)
{
	నిర్మాణం sshbuf *config;
	పూర్ణాంకం r;
	u_int i;

	ఒకవేళ ((r = sshbuf_froms(m, &config)) != 0)
		fatal_fr(r, "parse opts");
	ఒకవేళ ((r = deserialise_server_options(config, &options)) != 0)
		fatal_fr(r, "deserialise_server_options");
	sshbuf_free(config);

	log_change_level(options.log_level);
	log_verbose_reset();
	కొరకు (i = 0; i < options.అంకె_log_verbose; i++)
		log_verbose_కూడు(options.log_verbose[i]);
}

#నిర్వచించు GETPW(b, id) \
	చేయి { \
		ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		ఒకవేళ (len != పరిమాణం(pw->id)) \
			fatal_fr(r, "bad length for %s", #id); \
		జ్ఞాపకం_నకలు(&pw->id, p, len); \
	} అయితే (0)

నిర్మాణం passwd *
mm_getpwnamallow(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *username)
{
	నిర్మాణం sshbuf *m;
	నిర్మాణం passwd *pw;
	కొలత_t len;
	పూర్ణాంకం r;
	u_char ok;
	స్థిరరాశి u_char *p;

	debug3_f("entering");

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	ఒకవేళ ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	ఒకవేళ (ok == 0) {
		pw = ఖాళీ;
		వెళ్ళు బహిర్గతం;
	}

	/* XXX don't like passing struct passwd like this */
	pw = xcalloc(పరిమాణం(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#నిర్వచితమైతే HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#అయితే_ముగింపు
	ఒకవేళ ((r = sshbuf_get_cstring(m, &pw->pw_name, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, ఖాళీ)) != 0 ||
#నిర్వచితమైతే HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, ఖాళీ)) != 0 ||
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(m, &pw->pw_class, ఖాళీ)) != 0 ||
#అయితే_ముగింపు
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, ఖాళీ)) != 0)
		fatal_fr(r, "parse pw");

బహిర్గతం:
	/* copy options block as a Match directive may have changed some */
	mm_decode_activate_server_options(ssh, m);
	server_process_permitopen(ssh);
	server_process_channel_timeouts(ssh);
	channel_సమితి_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);
	kex_సమితి_server_sig_algs(ssh, options.pubkey_accepted_algos);
	kex_సమితి_warn_weak_crypto(ssh, options.warn_weak_crypto);
	ssh_packet_సమితి_rekey_limits(ssh, options.rekey_హద్దు,
	    options.rekey_interval);
	sshbuf_free(m);

	తిరిగి (pw);
}

అక్షరం *
mm_auth2_read_banner(శూన్య)
{
	నిర్మాణం sshbuf *m;
	అక్షరం *banner;
	పూర్ణాంకం r;

	debug3_f("entering");

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	ఒకవేళ ((r = sshbuf_get_cstring(m, &banner, ఖాళీ)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	ఒకవేళ (అక్షరశ్రేణి_పొడవు(banner) == 0) {
		విడుదల(banner);
		banner = ఖాళీ;
	}
	తిరిగి (banner);
}

/* Inform the privileged process about service and style */

శూన్య
mm_inform_authserv(అక్షరం *service, అక్షరం *style)
{
	నిర్మాణం sshbuf *m;
	పూర్ణాంకం r;

	debug3_f("entering");

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
పూర్ణాంకం
mm_auth_password(నిర్మాణం ssh *ssh, అక్షరం *password)
{
	నిర్మాణం sshbuf *m;
	పూర్ణాంకం r, authenticated = 0;
#నిర్వచితమైతే USE_PAM
	u_int maxtries = 0;
#అయితే_ముగింపు

	debug3_f("entering");

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	ఒకవేళ ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");
#నిర్వచితమైతే USE_PAM
	ఒకవేళ ((r = sshbuf_get_u32(m, &maxtries)) != 0)
		fatal_fr(r, "parse PAM");
	ఒకవేళ (maxtries > గరిష్ఠ_పూర్ణాంకం)
		fatal_fr(r, "bad maxtries");
	sshpam_సమితి_maxtries_reached(maxtries);
#అయితే_ముగింపు

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	తిరిగి (authenticated);
}

పూర్ణాంకం
mm_user_కీలకం_allowed(నిర్మాణం ssh *ssh, నిర్మాణం passwd *pw, నిర్మాణం sshkey *కీలకం,
    పూర్ణాంకం pubkey_auth_attempt, నిర్మాణం sshauthopt **authoptp)
{
	తిరిగి (mm_కీలకం_allowed(MM_USERKEY, ఖాళీ, ఖాళీ, కీలకం,
	    pubkey_auth_attempt, authoptp));
}

పూర్ణాంకం
mm_hostbased_కీలకం_allowed(నిర్మాణం ssh *ssh, నిర్మాణం passwd *pw,
    స్థిరరాశి అక్షరం *user, స్థిరరాశి అక్షరం *host, నిర్మాణం sshkey *కీలకం)
{
	తిరిగి (mm_కీలకం_allowed(MM_HOSTKEY, user, host, కీలకం, 0, ఖాళీ));
}

పూర్ణాంకం
mm_కీలకం_allowed(గణన mm_keytype type, స్థిరరాశి అక్షరం *user, స్థిరరాశి అక్షరం *host,
    నిర్మాణం sshkey *కీలకం, పూర్ణాంకం pubkey_auth_attempt, నిర్మాణం sshauthopt **authoptp)
{
	నిర్మాణం sshbuf *m;
	పూర్ణాంకం r, allowed = 0;
	నిర్మాణం sshauthopt *opts = ఖాళీ;

	debug3_f("entering");

	ఒకవేళ (authoptp != ఖాళీ)
		*authoptp = ఖాళీ;

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshkey_puts(కీలకం, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	ఒకవేళ ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal_fr(r, "parse");
	ఒకవేళ (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	ఒకవేళ (authoptp != ఖాళీ) {
		*authoptp = opts;
		opts = ఖాళీ;
	}
	sshauthopt_free(opts);

	తిరిగి allowed;
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

పూర్ణాంకం
mm_sshkey_verify(స్థిరరాశి నిర్మాణం sshkey *కీలకం, స్థిరరాశి u_char *sig, కొలత_t siglen,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen, స్థిరరాశి అక్షరం *sigalg, u_int compat,
    నిర్మాణం sshkey_sig_details **sig_detailsp)
{
	నిర్మాణం sshbuf *m;
	u_int encoded_ret = 0;
	పూర్ణాంకం r;
	u_char sig_details_present, flags;
	u_int counter;

	debug3_f("entering");

	ఒకవేళ (sig_detailsp != ఖాళీ)
		*sig_detailsp = ఖాళీ;
	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshkey_puts(కీలకం, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, దత్తాంశం, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, sigalg == ఖాళీ ? "" : sigalg)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	ఒకవేళ ((r = sshbuf_get_u32(m, &encoded_ret)) != 0 ||
	    (r = sshbuf_get_u8(m, &sig_details_present)) != 0)
		fatal_fr(r, "parse");
	ఒకవేళ (sig_details_present && encoded_ret == 0) {
		ఒకవేళ ((r = sshbuf_get_u32(m, &counter)) != 0 ||
		    (r = sshbuf_get_u8(m, &flags)) != 0)
			fatal_fr(r, "parse sig_details");
		ఒకవేళ (sig_detailsp != ఖాళీ) {
			*sig_detailsp = xcalloc(1, పరిమాణం(**sig_detailsp));
			(*sig_detailsp)->sk_counter = counter;
			(*sig_detailsp)->sk_flags = flags;
		}
	}

	sshbuf_free(m);

	ఒకవేళ (encoded_ret != 0)
		తిరిగి SSH_ERR_SIGNATURE_INVALID;
	తిరిగి 0;
}

శూన్య
mm_send_keystate(నిర్మాణం ssh *ssh, నిర్మాణం monitor *monitor)
{
	నిర్మాణం sshbuf *m;
	పూర్ణాంకం r;

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("Finished sending state");
	sshbuf_free(m);
}

పూర్ణాంకం
mm_pty_allocate(పూర్ణాంకం *ptyfd, పూర్ణాంకం *ttyfd, అక్షరం *namebuf, కొలత_t namebuflen)
{
	నిర్మాణం sshbuf *m;
	అక్షరం *p, *సందేశం;
	పూర్ణాంకం success = 0, tmp1 = -1, tmp2 = -1, r;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	ఒకవేళ ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		ఒకవేళ (tmp1 >= 0)
			close(tmp1);
		తిరిగి 0;
	}
	close(tmp1);
	close(tmp2);

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	ఒకవేళ ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ఒకవేళ (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		తిరిగి (0);
	}
	ఒకవేళ ((r = sshbuf_get_cstring(m, &p, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &సందేశం, ఖాళీ)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	విడుదల(p);

	ఒకవేళ ((r = sshbuf_put(loginmsg, సందేశం, అక్షరశ్రేణి_పొడవు(సందేశం))) != 0)
		fatal_fr(r, "put loginmsg");
	విడుదల(సందేశం);

	ఒకవేళ ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	తిరిగి (1);
}

శూన్య
mm_session_pty_cleanup2(Session *s)
{
	నిర్మాణం sshbuf *m;
	పూర్ణాంకం r;

	ఒకవేళ (s->ttyfd == -1)
		తిరిగి;
	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assmble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	ఒకవేళ (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#నిర్వచితమైతే USE_PAM
శూన్య
mm_ప్రారంభం_pam(నిర్మాణం ssh *ssh)
{
	నిర్మాణం sshbuf *m;

	debug3_f("entering");
	ఒకవేళ (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);
	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ప్రారంభం, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(శూన్య)
{
	నిర్మాణం sshbuf *m;
	u_int ret;
	అక్షరం *సందేశం;
	కొలత_t msglen;
	పూర్ణాంకం r;

	debug3_f("entering");
	ఒకవేళ (!options.use_pam)
		fatal_f("UsePAM=no, but ended up in %s anyway", __func__);

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	ఒకవేళ ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &సందేశం, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, సందేశం, msglen)) != 0)
		fatal_fr(r, "buffer error");

	విడుదల(సందేశం);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	తిరిగి (ret);
}

శూన్య *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	నిర్మాణం sshbuf *m;
	పూర్ణాంకం r, success;

	debug3_f("entering");
	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	ఒకవేళ ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "buffer error");
	ఒకవేళ (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		తిరిగి (ఖాళీ);
	}
	sshbuf_free(m);
	తిరిగి (authctxt);
}

పూర్ణాంకం
mm_sshpam_query(శూన్య *ctx, అక్షరం **name, అక్షరం **info,
    u_int *అంకె, అక్షరం ***prompts, u_int **echo_on)
{
	నిర్మాణం sshbuf *m;
	u_int i, n;
	పూర్ణాంకం r, ret;

	debug3_f("entering");
	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	ఒకవేళ ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, అంకె)) != 0)
		fatal_fr(r, "buffer error");
	debug3_f("pam_query returned %d", ret);
	sshpam_సమితి_maxtries_reached(n);
	ఒకవేళ (*అంకె > PAM_MAX_అంకె_సందేశం)
		fatal("%s: received %u PAM messages, expected <= %u",
		    __func__, *అంకె, PAM_MAX_అంకె_సందేశం);
	*prompts = xcalloc((*అంకె + 1), పరిమాణం(అక్షరం *));
	*echo_on = xcalloc((*అంకె + 1), పరిమాణం(u_int));
	కొరకు (i = 0; i < *అంకె; ++i) {
		ఒకవేళ ((r = sshbuf_get_cstring(m, &((*prompts)[i]), ఖాళీ)) != 0 ||
		    (r = sshbuf_get_u32(m, &((*echo_on)[i]))) != 0)
			fatal_fr(r, "buffer error");
	}
	sshbuf_free(m);
	తిరిగి (ret);
}

పూర్ణాంకం
mm_sshpam_respond(శూన్య *ctx, u_int అంకె, అక్షరం **resp)
{
	నిర్మాణం sshbuf *m;
	u_int n, i;
	పూర్ణాంకం r, ret;

	debug3_f("entering");
	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u32(m, అంకె)) != 0)
		fatal_fr(r, "buffer error");
	కొరకు (i = 0; i < అంకె; ++i) {
		ఒకవేళ ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	ఒకవేళ ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	ret = (పూర్ణాంకం)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	తిరిగి (ret);
}

శూన్య
mm_sshpam_free_ctx(శూన్య *ctxtp)
{
	నిర్మాణం sshbuf *m;

	debug3_f("entering");
	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_FREE_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_FREE_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_FREE_CTX, m);
	sshbuf_free(m);
}
#అయితే_ముగింపు /* USE_PAM */

/* Request process termination */

శూన్య
mm_terminate(శూన్య)
{
	నిర్మాణం sshbuf *m;

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_పదం, m);
	sshbuf_free(m);
}

/* Request state information */

శూన్య
mm_get_state(నిర్మాణం ssh *ssh,
    ServerOptions *opts, నిర్మాణం sshbuf **confdatap,
    uint64_t *timing_secretp,
    నిర్మాణం sshbuf **hostkeysp, నిర్మాణం sshbuf **keystatep,
    u_char **pw_namep,
    నిర్మాణం sshbuf **authinfop, నిర్మాణం sshbuf **auth_optsp)
{
	నిర్మాణం sshbuf *m, *config;
	పూర్ణాంకం r;

	debug3_f("entering");

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ || (config = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_STATE, m);

	debug3_f("waiting for MONITOR_ANS_STATE");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_STATE, m);

	ఒకవేళ ((r = sshbuf_froms(m, &config)) != 0 ||
	    (r = sshbuf_get_u64(m, timing_secretp)) != 0 ||
	    (r = sshbuf_froms(m, hostkeysp)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->server_సంస్కరణ)) != 0 ||
	    (r = sshbuf_get_stringb(m, ssh->kex->client_సంస్కరణ)) != 0)
		fatal_fr(r, "parse config");

	/* postauth */
	ఒకవేళ (confdatap) {
		ఒకవేళ ((r = sshbuf_froms(m, confdatap)) != 0 ||
		    (r = sshbuf_froms(m, keystatep)) != 0 ||
		    (r = sshbuf_get_string(m, pw_namep, ఖాళీ)) != 0 ||
		    (r = sshbuf_froms(m, authinfop)) != 0 ||
		    (r = sshbuf_froms(m, auth_optsp)) != 0)
			fatal_fr(r, "parse config postauth");
	}
	ఒకవేళ ((r = deserialise_server_options(config, opts)) != 0)
		fatal_fr(r, "deserialise_server_options");

	sshbuf_free(m);
	sshbuf_free(config);

	debug3_f("done");
}

స్థిర శూన్య
mm_chall_అమరిక(అక్షరం **name, అక్షరం **infotxt, u_int *numprompts,
    అక్షరం ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, పరిమాణం(అక్షరం *));
	*echo_on = xcalloc(*numprompts, పరిమాణం(u_int));
	(*echo_on)[0] = 0;
}

పూర్ణాంకం
mm_bsdauth_query(శూన్య *ctx, అక్షరం **name, అక్షరం **infotxt,
   u_int *numprompts, అక్షరం ***prompts, u_int **echo_on)
{
	నిర్మాణం sshbuf *m;
	u_int success;
	అక్షరం *challenge;
	పూర్ణాంకం r;

	debug3_f("entering");

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	ఒకవేళ ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	ఒకవేళ (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		తిరిగి (-1);
	}

	/* Get the challenge, and format the response */
	ఒకవేళ ((r = sshbuf_get_cstring(m, &challenge, ఖాళీ)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_అమరిక(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	తిరిగి (0);
}

పూర్ణాంకం
mm_bsdauth_respond(శూన్య *ctx, u_int numresponses, అక్షరం **responses)
{
	నిర్మాణం sshbuf *m;
	పూర్ణాంకం r, authok;

	debug3_f("entering");
	ఒకవేళ (numresponses != 1)
		తిరిగి (-1);

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	ఒకవేళ ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	తిరిగి ((authok == 0) ? -1 : 0);
}

#నిర్వచితమైతే SSH_AUDIT_EVENTS
శూన్య
mm_audit_event(నిర్మాణం ssh *ssh, ssh_audit_event_t event)
{
	నిర్మాణం sshbuf *m;
	పూర్ణాంకం r;

	debug3_f("entering");

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

శూన్య
mm_audit_నిరంతరం_command(స్థిరరాశి అక్షరం *command)
{
	నిర్మాణం sshbuf *m;
	పూర్ణాంకం r;

	debug3_f("entering command %s", command);

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "buffer error");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#అయితే_ముగింపు /* SSH_AUDIT_EVENTS */

#నిర్వచితమైతే GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	నిర్మాణం sshbuf *m;
	OM_uint32 major;
	పూర్ణాంకం r;

	/* Client doesn't get to see the context */
	*ctx = ఖాళీ;

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_string(m, goid->elements, goid->నిడివి)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	ఒకవేళ ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	తిరిగి (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_బఫరు_desc *లోపల,
    gss_బఫరు_desc *బహిర్గతం, OM_uint32 *flagsp)
{
	నిర్మాణం sshbuf *m;
	OM_uint32 major;
	u_int flags;
	పూర్ణాంకం r;

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_string(m, లోపల->విలువ, లోపల->నిడివి)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	ఒకవేళ ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_బఫరు_desc(m, బహిర్గతం)) != 0)
		fatal_fr(r, "parse");
	ఒకవేళ (flagsp != ఖాళీ) {
		ఒకవేళ ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	తిరిగి (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_బఫరు_t gssbuf, gss_బఫరు_t gssmic)
{
	నిర్మాణం sshbuf *m;
	OM_uint32 major;
	పూర్ణాంకం r;

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_string(m, gssbuf->విలువ, gssbuf->నిడివి)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->విలువ, gssmic->నిడివి)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	ఒకవేళ ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	తిరిగి(major);
}

పూర్ణాంకం
mm_ssh_gssapi_userok(అక్షరం *user)
{
	నిర్మాణం sshbuf *m;
	పూర్ణాంకం r, authenticated = 0;

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	ఒకవేళ ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	తిరిగి (authenticated);
}
#అయితే_ముగింపు /* GSSAPI */

/*
 * Inform channels layer of permitopen options for a single forwarding
 * direction (local/remote).
 */
స్థిర శూన్య
server_process_permitopen_list(నిర్మాణం ssh *ssh, పూర్ణాంకం listen,
    అక్షరం **opens, u_int అంకె_opens)
{
	u_int i;
	పూర్ణాంకం పోర్టు;
	అక్షరం *host, *arg, *oarg;
	పూర్ణాంకం where = listen ? FORWARD_REMOTE : FORWARD_LOCAL;
	స్థిరరాశి అక్షరం *what = listen ? "permitlisten" : "permitopen";

	channel_clear_permission(ssh, FORWARD_ADM, where);
	ఒకవేళ (అంకె_opens == 0)
		తిరిగి; /* permit any */

	/* handle keywords: "any" / "none" */
	ఒకవేళ (అంకె_opens == 1 && strcmp(opens[0], "any") == 0)
		తిరిగి;
	ఒకవేళ (అంకె_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		తిరిగి;
	}
	/* Otherwise treat it as a list of permitted host:port */
	కొరకు (i = 0; i < అంకె_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		host = hpdelim(&arg);
		ఒకవేళ (host == ఖాళీ)
			fatal_f("missing host in %s", what);
		host = cleanhostname(host);
		ఒకవేళ (arg == ఖాళీ || ((పోర్టు = permitopen_పోర్టు(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_కూడు_permission(ssh, FORWARD_ADM,
		    where, host, పోర్టు);
		విడుదల(oarg);
	}
}

/*
 * Inform channels layer of permitopen options from configuration.
 */
శూన్య
server_process_permitopen(నిర్మాణం ssh *ssh)
{
	server_process_permitopen_list(ssh, 0,
	    options.permitted_opens, options.అంకె_permitted_opens);
	server_process_permitopen_list(ssh, 1,
	    options.permitted_listens, options.అంకె_permitted_listens);
}

శూన్య
server_process_channel_timeouts(నిర్మాణం ssh *ssh)
{
	u_int i;
	ద్విగుణ secs;
	అక్షరం *type;

	debug3_f("setting %u timeouts", options.అంకె_channel_timeouts);
	channel_clear_timeouts(ssh);
	కొరకు (i = 0; i < options.అంకె_channel_timeouts; i++) {
		ఒకవేళ (parse_నమూనా_interval(options.channel_timeouts[i],
		    &type, &secs) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[i]);
		}
		channel_కూడు_timeout(ssh, type, secs);
		విడుదల(type);
	}
}

నిర్మాణం connection_info *
server_get_connection_info(నిర్మాణం ssh *ssh, పూర్ణాంకం populate, పూర్ణాంకం use_dns)
{
	స్థిర నిర్మాణం connection_info ci;

	ఒకవేళ (ssh == ఖాళీ || !populate)
		తిరిగి &ci;
	ci.host = use_dns ? ssh_remote_hostname(ssh) : ssh_remote_ipaddr(ssh);
	ci.చిరునామా = ssh_remote_ipaddr(ssh);
	ci.laddress = ssh_local_ipaddr(ssh);
	ci.lport = ssh_local_పోర్టు(ssh);
	ci.rdomain = ssh_packet_rdomain_లోపల(ssh);
	తిరిగి &ci;
}

