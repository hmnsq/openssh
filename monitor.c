/* $OpenBSD: monitor.c,v 1.260 2026/10/11 20:41:20 dtucker Exp $ */
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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/tree.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/dh.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-pam.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshpty.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "session.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshlogin.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_wrap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_fdpass.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sk-api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "srclimit.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
ਸਥਿਰ Gssctxt *gsscontext = ਨਿਰਾ;
#ਜੇ_ਅੰਤ

/* Imports */
ਬਾਹਰੀ ServerOptions options;
ਬਾਹਰੀ u_int utmp_len;
ਬਾਹਰੀ ਬਣਤਰ sshbuf *cfg;
ਬਾਹਰੀ ਬਣਤਰ sshbuf *loginmsg;
ਬਾਹਰੀ ਬਣਤਰ include_list includes;
ਬਾਹਰੀ ਬਣਤਰ sshauthopt *auth_opts; /* XXX move to permanent ssh->authctxt? */

/* State exported from the child */
ਸਥਿਰ ਬਣਤਰ sshbuf *ਬੱਚਾ_state;

/* Functions on the monitor that answer unprivileged requests */

ਪੂਰਨ mm_answer_moduli(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_setcompat(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_sign(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_pwnamallow(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_auth2_read_banner(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_authserv(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_authpassword(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_bsdauthquery(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_bsdauthrespond(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_keyallowed(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_keyverify(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_pty(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_pty_cleanup(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_ਪਦ(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_state(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
ਪੂਰਨ mm_answer_pam_ਸ਼ੁਰੂ(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_pam_account(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_pam_init_ctx(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_pam_query(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_pam_respond(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_pam_free_ctx(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
ਪੂਰਨ mm_answer_gss_ਤਿਆਰੀ_ctx(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_gss_accept_ctx(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_gss_userok(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_gss_checkmic(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS
ਪੂਰਨ mm_answer_audit_event(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
ਪੂਰਨ mm_answer_audit_command(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
#ਜੇ_ਅੰਤ

ਸਥਿਰ Authctxt *authctxt;

/* local state for key verify */
ਸਥਿਰ u_char *ਕੁੰਜੀ_blob = ਨਿਰਾ;
ਸਥਿਰ ਮਾਪ_t ਕੁੰਜੀ_bloblen = 0;
ਸਥਿਰ u_int ਕੁੰਜੀ_blobtype = MM_NOKEY;
ਸਥਿਰ ਬਣਤਰ sshauthopt *ਕੁੰਜੀ_opts = ਨਿਰਾ;
ਸਥਿਰ ਅੱਖਰ *hostbased_cuser = ਨਿਰਾ;
ਸਥਿਰ ਅੱਖਰ *hostbased_chost = ਨਿਰਾ;
ਸਥਿਰ ਅੱਖਰ *auth_ਵਿਧੀ = "unknown";
ਸਥਿਰ ਅੱਖਰ *auth_submethod = ਨਿਰਾ;
ਸਥਿਰ u_int session_id2_len = 0;
ਸਥਿਰ u_char *session_id2 = ਨਿਰਾ;
ਸਥਿਰ pid_t monitor_ਬੱਚਾ_pid;
ਸਥਿਰ ਪੂਰਨ auth_attempted = 0;
ਸਥਿਰ ਪੂਰਨ invalid_user = 0;
ਸਥਿਰ ਪੂਰਨ compat_ਸੈੱਟ = 0;

ਬਣਤਰ mon_ਸਾਰਣੀ {
	ਗਿਣਤੀ monitor_reqtype type;
	ਪੂਰਨ flags;
	ਪੂਰਨ (*f)(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ sshbuf *);
};

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MON_ISAUTH	0x0004	/* Required for Authentication */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MON_ONCE	0x0010	/* Disable after calling */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MON_PERMIT	0x1000	/* Request is permitted */

ਸਥਿਰ ਪੂਰਨ monitor_read(ਬਣਤਰ ssh *, ਬਣਤਰ monitor *, ਬਣਤਰ mon_ਸਾਰਣੀ *,
    ਬਣਤਰ mon_ਸਾਰਣੀ **);
ਸਥਿਰ ਪੂਰਨ monitor_read_log(ਬਣਤਰ monitor *);

ਬਣਤਰ mon_ਸਾਰਣੀ mon_dispatch_proto20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
    {MONITOR_REQ_MODULI, MON_ONCE, mm_answer_moduli},
#ਜੇ_ਅੰਤ
    {MONITOR_REQ_SETCOMPAT, MON_ONCE, mm_answer_setcompat},
    {MONITOR_REQ_SIGN, MON_ONCE, mm_answer_sign},
    {MONITOR_REQ_PWNAM, MON_ONCE, mm_answer_pwnamallow},
    {MONITOR_REQ_AUTHSERV, MON_ONCE, mm_answer_authserv},
    {MONITOR_REQ_AUTH2_READ_BANNER, MON_ONCE, mm_answer_auth2_read_banner},
    {MONITOR_REQ_AUTHPASSWORD, MON_AUTH, mm_answer_authpassword},
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
    {MONITOR_REQ_PAM_ਸ਼ੁਰੂ, MON_ONCE, mm_answer_pam_ਸ਼ੁਰੂ},
    {MONITOR_REQ_PAM_ACCOUNT, 0, mm_answer_pam_account},
    {MONITOR_REQ_PAM_INIT_CTX, MON_ONCE, mm_answer_pam_init_ctx},
    {MONITOR_REQ_PAM_QUERY, 0, mm_answer_pam_query},
    {MONITOR_REQ_PAM_RESPOND, MON_ONCE, mm_answer_pam_respond},
    {MONITOR_REQ_PAM_FREE_CTX, MON_ONCE|MON_AUTHDECIDE, mm_answer_pam_free_ctx},
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BSD_AUTH
    {MONITOR_REQ_BSDAUTHQUERY, MON_ISAUTH, mm_answer_bsdauthquery},
    {MONITOR_REQ_BSDAUTHRESPOND, MON_AUTH, mm_answer_bsdauthrespond},
#ਜੇ_ਅੰਤ
    {MONITOR_REQ_KEYALLOWED, MON_ISAUTH, mm_answer_keyallowed},
    {MONITOR_REQ_KEYVERIFY, MON_AUTH, mm_answer_keyverify},
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
    {MONITOR_REQ_GSSSETUP, MON_ISAUTH, mm_answer_gss_ਤਿਆਰੀ_ctx},
    {MONITOR_REQ_GSSSTEP, 0, mm_answer_gss_accept_ctx},
    {MONITOR_REQ_GSSUSEROK, MON_ONCE|MON_AUTHDECIDE, mm_answer_gss_userok},
    {MONITOR_REQ_GSSCHECKMIC, MON_ONCE, mm_answer_gss_checkmic},
#ਜੇ_ਅੰਤ
    {0, 0, ਨਿਰਾ}
};

ਬਣਤਰ mon_ਸਾਰਣੀ mon_dispatch_postauth20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
    {MONITOR_REQ_MODULI, 0, mm_answer_moduli},
#ਜੇ_ਅੰਤ
    {MONITOR_REQ_SIGN, 0, mm_answer_sign},
    {MONITOR_REQ_PTY, 0, mm_answer_pty},
    {MONITOR_REQ_PTYCLEANUP, 0, mm_answer_pty_cleanup},
    {MONITOR_REQ_ਪਦ, 0, mm_answer_ਪਦ},
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
    {MONITOR_REQ_AUDIT_COMMAND, MON_PERMIT, mm_answer_audit_command},
#ਜੇ_ਅੰਤ
    {0, 0, ਨਿਰਾ}
};

ਬਣਤਰ mon_ਸਾਰਣੀ *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
ਸਥਿਰ ਖਾਲੀ
monitor_permit(ਬਣਤਰ mon_ਸਾਰਣੀ *ent, ਗਿਣਤੀ monitor_reqtype type, ਪੂਰਨ permit)
{
	ਜਦੋਂ (ent->f != ਨਿਰਾ) {
		ਜੇ (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			ਵਾਪਸ;
		}
		ent++;
	}
}

ਸਥਿਰ ਖਾਲੀ
monitor_permit_authentications(ਪੂਰਨ permit)
{
	ਬਣਤਰ mon_ਸਾਰਣੀ *ent = mon_dispatch;

	ਜਦੋਂ (ent->f != ਨਿਰਾ) {
		ਜੇ (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

ਖਾਲੀ
monitor_ਬੱਚਾ_preauth(ਬਣਤਰ ssh *ssh, ਬਣਤਰ monitor *pmonitor)
{
	ਬਣਤਰ mon_ਸਾਰਣੀ *ent;
	ਪੂਰਨ ਸਥਿਤੀ, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	ਜੇ (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	ਜੇ (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = (Authctxt *)ssh->authctxt;
	memset(authctxt, 0, ਆਕਾਰ(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	mon_dispatch = mon_dispatch_proto20;
	/* Permit requests for state, moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SETCOMPAT, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);

	/* The first few requests do not require asynchronous access */
	ਜਦੋਂ (!authenticated) {
		partial = 0;
		auth_ਵਿਧੀ = "unknown";
		auth_submethod = ਨਿਰਾ;
		auth2_authctxt_reset_info(authctxt);

		authenticated = (monitor_read(ssh, pmonitor,
		    mon_dispatch, &ent) == 1);

		/* Record that auth was attempted to set exit status later */
		ਜੇ ((ent->flags & MON_AUTH) != 0)
			auth_attempted = 1;

		/* Special handling for multiple required authentications */
		ਜੇ (options.ਅੰਕ_auth_methods != 0) {
			ਜੇ (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_ਵਿਧੀ, auth_submethod)) {
				debug3_f("method %s: partial", auth_ਵਿਧੀ);
				authenticated = 0;
				partial = 1;
			}
		}

		ਜੇ (authenticated) {
			ਜੇ (!(ent->flags & MON_AUTHDECIDE))
				fatal_f("unexpected authentication from %d",
				    ent->type);
			ਜੇ (authctxt->pw->pw_uid == 0 &&
			    !auth_ਜੜ੍ਹ_allowed(ssh, auth_ਵਿਧੀ))
				authenticated = 0;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
			/* PAM needs to perform account checks after auth */
			ਜੇ (options.use_pam && authenticated) {
				ਬਣਤਰ sshbuf *m;

				ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
					fatal("%s: sshbuf_new failed",
					    __func__);
				mm_request_receive_expect(pmonitor->m_sendfd,
				    MONITOR_REQ_PAM_ACCOUNT, m);
				authenticated = mm_answer_pam_account(
				    ssh, pmonitor->m_sendfd, m);
				sshbuf_free(m);
			}
#ਜੇ_ਅੰਤ
		}
		ਜੇ (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(ssh, authenticated, partial,
			    auth_ਵਿਧੀ, auth_submethod);
			ਜੇ (!partial && !authenticated)
				authctxt->failures++;
			ਜੇ (authenticated || partial) {
				auth2_update_session_info(authctxt,
				    auth_ਵਿਧੀ, auth_submethod);
			}
		}
		ਜੇ (authctxt->failures > options.max_authtries) {
			/* Shouldn't happen */
			fatal_f("privsep child made too many authentication "
			    "attempts");
		}
	}

	ਜੇ (!authctxt->valid)
		fatal_f("authenticated invalid user");
	ਜੇ (strcmp(auth_ਵਿਧੀ, "unknown") == 0)
		fatal_f("authentication method name unknown");

	debug_f("user %s authenticated by privileged process", authctxt->user);
	auth_attempted = 0;
	ssh->authctxt = ਨਿਰਾ;
	ssh_packet_ਸੈੱਟ_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	ਜਦੋਂ (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	ਜਦੋਂ (waitpid(pmonitor->m_pid, &ਸਥਿਤੀ, 0) == -1) {
		ਜੇ (errno == EINTR)
			ਜਾਰੀ;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ਜੇ (WIFEXITED(ਸਥਿਤੀ)) {
		ਜੇ (WEXITSTATUS(ਸਥਿਤੀ) != 0)
			fatal_f("preauth child %ld exited with status %d",
			    (ਲੰਮਾ)pmonitor->m_pid, WEXITSTATUS(ਸਥਿਤੀ));
	} ਨਹੀਂਤਾਂ ਜੇ (WIFSIGNALED(ਸਥਿਤੀ)) {
		fatal_f("preauth child %ld terminated by signal %d",
		    (ਲੰਮਾ)pmonitor->m_pid, WTERMSIG(ਸਥਿਤੀ));
	}
	debug3_f("preauth child %ld terminated successfully",
	    (ਲੰਮਾ)pmonitor->m_pid);

	ਜੇ (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	ਜੇ (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_pid = -1;
}

ਸਥਿਰ ਖਾਲੀ
monitor_ਸੈੱਟ_ਬੱਚਾ_handler(pid_t pid)
{
	monitor_ਬੱਚਾ_pid = pid;
}

ਸਥਿਰ ਖਾਲੀ
monitor_ਬੱਚਾ_handler(ਪੂਰਨ sig)
{
	kill(monitor_ਬੱਚਾ_pid, sig);
}

ਖਾਲੀ
monitor_ਬੱਚਾ_postauth(ਬਣਤਰ ssh *ssh, ਬਣਤਰ monitor *pmonitor)
{
	close(pmonitor->m_recvfd);
	pmonitor->m_recvfd = -1;

	monitor_ਸੈੱਟ_ਬੱਚਾ_handler(pmonitor->m_pid);
	ssh_signal(SIGHUP, &monitor_ਬੱਚਾ_handler);
	ssh_signal(SIGTERM, &monitor_ਬੱਚਾ_handler);
	ssh_signal(SIGINT, &monitor_ਬੱਚਾ_handler);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SIGXFSZ
	ssh_signal(SIGXFSZ, SIG_IGN);
#ਜੇ_ਅੰਤ

	mon_dispatch = mon_dispatch_postauth20;

	/* Permit requests for moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_ਪਦ, 1);

	ਜੇ (auth_opts->permit_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	ਲਈ (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, ਨਿਰਾ);
}

ਸਥਿਰ ਪੂਰਨ
monitor_read_log(ਬਣਤਰ monitor *pmonitor)
{
	ਬਣਤਰ sshbuf *logmsg;
	u_int len, level, forced;
	ਅੱਖਰ *ਸੁਨੇਹਾ;
	u_char *p;
	ਪੂਰਨ r;

	ਜੇ ((logmsg = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");

	/* Read length */
	ਜੇ ((r = sshbuf_reserve(logmsg, 4, &p)) != 0)
		fatal_fr(r, "reserve len");
	ਜੇ (atomicio(ਪਠ, pmonitor->m_log_recvfd, p, 4) != 4) {
		ਜੇ (errno == EPIPE) {
			sshbuf_free(logmsg);
			debug_f("child log fd closed");
			close(pmonitor->m_log_recvfd);
			pmonitor->m_log_recvfd = -1;
			ਵਾਪਸ -1;
		}
		fatal_f("log fd read: %s", strerror(errno));
	}
	ਜੇ ((r = sshbuf_get_u32(logmsg, &len)) != 0)
		fatal_fr(r, "parse len");
	ਜੇ (len <= 4 || len > 8192)
		fatal_f("invalid log message length %u", len);

	/* Read severity, message */
	sshbuf_reset(logmsg);
	ਜੇ ((r = sshbuf_reserve(logmsg, len, &p)) != 0)
		fatal_fr(r, "reserve msg");
	ਜੇ (atomicio(ਪਠ, pmonitor->m_log_recvfd, p, len) != len)
		fatal_f("log fd read: %s", strerror(errno));
	ਜੇ ((r = sshbuf_get_u32(logmsg, &level)) != 0 ||
	    (r = sshbuf_get_u32(logmsg, &forced)) != 0 ||
	    (r = sshbuf_get_cstring(logmsg, &ਸੁਨੇਹਾ, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	ਜੇ (log_level_name(level) == ਨਿਰਾ)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", ਸੁਨੇਹਾ,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	ਮੁਕਤ(ਸੁਨੇਹਾ);

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
monitor_read(ਬਣਤਰ ssh *ssh, ਬਣਤਰ monitor *pmonitor, ਬਣਤਰ mon_ਸਾਰਣੀ *ent,
    ਬਣਤਰ mon_ਸਾਰਣੀ **pent)
{
	ਬਣਤਰ sshbuf *m;
	ਪੂਰਨ r, ret;
	u_char type;
	ਬਣਤਰ pollfd pfd[2];

	ਲਈ (;;) {
		memset(&pfd, 0, ਆਕਾਰ(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		ਜੇ (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			ਜੇ (errno == EINTR || errno == EAGAIN)
				ਜਾਰੀ;
			fatal_f("poll: %s", strerror(errno));
		}
		ਜੇ (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			ਜਾਰੀ;
		}
		ਜੇ (pfd[0].revents)
			ਰੋਕੋ;  /* Continues below */
	}

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	ਜੇ ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	ਜਦੋਂ (ent->f != ਨਿਰਾ) {
		ਜੇ (ent->type == type)
			ਰੋਕੋ;
		ent++;
	}

	ਜੇ (ent->f != ਨਿਰਾ) {
		ਜੇ (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		ਜੇ (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		ਜੇ (pent != ਨਿਰਾ)
			*pent = ent;

		ਵਾਪਸ ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	ਵਾਪਸ (-1);
}

/* allowed key state */
ਸਥਿਰ ਪੂਰਨ
monitor_allowed_ਕੁੰਜੀ(ਅਚਲ u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	ਜੇ (ਕੁੰਜੀ_blob == ਨਿਰਾ || ਕੁੰਜੀ_bloblen != bloblen ||
	    timingsafe_bcmp(ਕੁੰਜੀ_blob, blob, ਕੁੰਜੀ_bloblen))
		ਵਾਪਸ (0);
	ਵਾਪਸ (1);
}

ਸਥਿਰ ਖਾਲੀ
monitor_reset_ਕੁੰਜੀ_state(ਖਾਲੀ)
{
	/* reset state */
	ਮੁਕਤ(ਕੁੰਜੀ_blob);
	ਮੁਕਤ(hostbased_cuser);
	ਮੁਕਤ(hostbased_chost);
	sshauthopt_free(ਕੁੰਜੀ_opts);
	ਕੁੰਜੀ_blob = ਨਿਰਾ;
	ਕੁੰਜੀ_bloblen = 0;
	ਕੁੰਜੀ_blobtype = MM_NOKEY;
	ਕੁੰਜੀ_opts = ਨਿਰਾ;
	hostbased_cuser = ਨਿਰਾ;
	hostbased_chost = ਨਿਰਾ;
}

ਪੂਰਨ
mm_answer_state(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *ਅਣਵਰਤਿਆ)
{
	ਬਣਤਰ sshbuf *m = ਨਿਰਾ, *config = ਨਿਰਾ, *hostkeys = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *opts = ਨਿਰਾ, *confdata = ਨਿਰਾ;
	ਪੂਰਨ postauth;
	ਪੂਰਨ r;

	debug_f("config len %zu", sshbuf_len(cfg));

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ ||
	    (config = sshbuf_new()) == ਨਿਰਾ ||
	    (opts = sshbuf_new()) == ਨਿਰਾ ||
	    (confdata = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	hostkeys = pack_hostkeys();
	ਜੇ ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");

	/*
	 * Protocol from monitor to unpriv privsep process:
	 *	string	configuration_blob
	 *	uint64	timing_secret	XXX move delays to monitor and remove
	 *	string	host_keys[] {
	 *		string public_key
	 *		string certificate
	 *	}
	 *	string  server_banner
	 *	string  client_banner
	 *	string	configuration_data (postauth)
	 *	string  keystate (postauth)
	 *	string  authenticated_user (postauth)
	 *	string  session_info (postauth)
	 *	string  authopts (postauth)
	 */
	ਜੇ ((r = sshbuf_put_stringb(m, config)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->server_ਸੰਸਕਰਣ)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->client_ਸੰਸਕਰਣ)) != 0)
		fatal_fr(r, "compose config");

	postauth = (authctxt && authctxt->pw && authctxt->authenticated);
	ਜੇ (postauth) {
		/* XXX shouldn't be reachable */
		fatal_f("internal error: called in postauth");
	}

	sshbuf_free(config);
	sshbuf_free(opts);
	sshbuf_free(confdata);
	sshbuf_free(hostkeys);

	mm_request_send(sock, MONITOR_ANS_STATE, m);
	sshbuf_free(m);
	debug3_f("done");

	ਵਾਪਸ (0);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਪੂਰਨ
mm_answer_moduli(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	DH *dh;
	ਅਚਲ BIGNUM *dh_p, *dh_g;
	ਪੂਰਨ r;
	u_int min, want, max;

	ਜੇ ((r = sshbuf_get_u32(m, &min)) != 0 ||
	    (r = sshbuf_get_u32(m, &want)) != 0 ||
	    (r = sshbuf_get_u32(m, &max)) != 0)
		fatal_fr(r, "parse");

	debug3_f("got parameters: %d %d %d", min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	ਜੇ (max < min || want < min || max < want)
		fatal_f("bad parameters: %d %d %d", min, want, max);

	sshbuf_reset(m);

	dh = ਚੁਣੋ_dh(min, want, max);
	ਜੇ (dh == ਨਿਰਾ) {
		ਜੇ ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} ਨਹੀਂਤਾਂ {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, ਨਿਰਾ, &dh_g);
		ਜੇ ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	ਵਾਪਸ (0);
}
#ਜੇ_ਅੰਤ

ਪੂਰਨ
mm_answer_setcompat(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	ਪੂਰਨ r;

	debug3_f("entering");

	ਜੇ ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_ਸੈੱਟ = 1;

	ਵਾਪਸ (0);
}

ਪੂਰਨ
mm_answer_sign(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	ਬਾਹਰੀ ਪੂਰਨ auth_sock;			/* XXX move to state struct? */
	ਬਣਤਰ sshkey *pubkey, *ਕੁੰਜੀ;
	ਬਣਤਰ sshbuf *sigbuf = ਨਿਰਾ;
	u_char *p = ਨਿਰਾ, *signature = ਨਿਰਾ;
	ਅੱਖਰ *alg = ਨਿਰਾ;
	ਮਾਪ_t datlen, siglen;
	ਪੂਰਨ r, is_proof = 0, keyid;
	u_int compat;
	ਅਚਲ ਅੱਖਰ proof_req[] = "hostkeys-prove-00@openssh.com";
	ਸਥਿਰ ਪੂਰਨ nhostkey_proofs_ਪੂਰਾ, *hostkey_proofs_ਪੂਰਾ;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	ਜੇ (!compat_ਸੈੱਟ)
		fatal_f("state error: setcompat never called");

	ਜੇ ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	ਜੇ ((keyid = get_hostkey_ਸੂਚਕਾਂਕ(pubkey, 1, ssh)) == -1)
		fatal_f("unknown hostkey");
	debug_f("hostkey %s index %d", sshkey_ssh_name(pubkey), keyid);
	sshkey_free(pubkey);

	/*
	 * Supported KEX types use SHA1 (20 bytes), SHA256 (32 bytes),
	 * SHA384 (48 bytes) and SHA512 (64 bytes).
	 *
	 * Otherwise, verify the signature request is for a hostkey
	 * proof.
	 *
	 * XXX perform similar check for KEX signature requests too?
	 * it's not trivial, since what is signed is the hash, rather
	 * than the full kex structure...
	 */
	ਜੇ (datlen != 20 && datlen != 32 && datlen != 48 && datlen != 64) {
		/*
		 * Construct expected hostkey proof and compare it to what
		 * the client sent us.
		 */
		ਜੇ (session_id2_len == 0) /* hostkeys is never first */
			fatal_f("bad data length: %zu", datlen);
		ਜੇ ((ਕੁੰਜੀ = get_hostkey_ਜਨਤਕ_by_ਸੂਚਕਾਂਕ(keyid, ssh)) == ਨਿਰਾ)
			fatal_f("no hostkey for index %d", keyid);
		ਜੇ (keyid >= nhostkey_proofs_ਪੂਰਾ) {
			hostkey_proofs_ਪੂਰਾ = xrecallocarray(
			    hostkey_proofs_ਪੂਰਾ, nhostkey_proofs_ਪੂਰਾ,
			    keyid + 1, ਆਕਾਰ(*hostkey_proofs_ਪੂਰਾ));
			nhostkey_proofs_ਪੂਰਾ = keyid + 1;
		}
		ਜੇ (hostkey_proofs_ਪੂਰਾ[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(ਕੁੰਜੀ), keyid);
		}
		hostkey_proofs_ਪੂਰਾ[keyid] = 1;
		ਜੇ ((sigbuf = sshbuf_new()) == ਨਿਰਾ)
			fatal_f("sshbuf_new");
		ਜੇ ((r = sshbuf_put_cstring(sigbuf, proof_req)) != 0 ||
		    (r = sshbuf_put_string(sigbuf, session_id2,
		    session_id2_len)) != 0 ||
		    (r = sshkey_puts(ਕੁੰਜੀ, sigbuf)) != 0)
			fatal_fr(r, "assemble private key proof");
		ਜੇ (datlen != sshbuf_len(sigbuf) ||
		    memcmp(p, sshbuf_ptr(sigbuf), sshbuf_len(sigbuf)) != 0)
			fatal_f("bad data length: %zu, hostkey proof len %zu",
			    datlen, sshbuf_len(sigbuf));
		sshbuf_free(sigbuf);
		is_proof = 1;
	}

	/* save session id, it will be passed on the first call */
	ਜੇ (session_id2_len == 0) {
		session_id2_len = datlen;
		session_id2 = xmalloc(session_id2_len);
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(session_id2, p, session_id2_len);
	}

	ਜੇ ((ਕੁੰਜੀ = get_hostkey_by_ਸੂਚਕਾਂਕ(keyid)) != ਨਿਰਾ) {
		ਜੇ ((r = sshkey_sign(ਕੁੰਜੀ, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, ਨਿਰਾ, compat)) != 0)
			fatal_fr(r, "sign");
	} ਨਹੀਂਤਾਂ ਜੇ ((ਕੁੰਜੀ = get_hostkey_ਜਨਤਕ_by_ਸੂਚਕਾਂਕ(keyid, ssh)) != ਨਿਰਾ &&
	    auth_sock > 0) {
		ਜੇ ((r = ssh_agent_sign(auth_sock, ਕੁੰਜੀ, &signature, &siglen,
		    p, datlen, alg, compat)) != 0)
			fatal_fr(r, "agent sign");
	} ਨਹੀਂਤਾਂ
		fatal_f("no hostkey from index %d", keyid);

	debug3_f("%s %s signature len=%zu", alg,
	    is_proof ? "hostkey proof" : "KEX", siglen);

	sshbuf_reset(m);
	ਜੇ ((r = sshbuf_put_string(m, signature, siglen)) != 0)
		fatal_fr(r, "assemble");

	ਮੁਕਤ(alg);
	ਮੁਕਤ(p);
	ਮੁਕਤ(signature);

	mm_request_send(sock, MONITOR_ANS_SIGN, m);

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	ਵਾਪਸ (0);
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PUTPW(b, id) \
	ਕਰੋ { \
		ਜੇ ((r = sshbuf_put_string(b, \
		    &pwent->id, ਆਕਾਰ(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} ਜਦੋਂ (0)

ਖਾਲੀ
mm_encode_server_options(ਬਣਤਰ sshbuf *m)
{
	ਪੂਰਨ r;
	ਬਣਤਰ sshbuf *config;

	ਜੇ ((config = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	ਜੇ ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
ਪੂਰਨ
mm_answer_pwnamallow(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	ਬਣਤਰ passwd *pwent;
	ਪੂਰਨ r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	ਜੇ (!compat_ਸੈੱਟ)
		fatal_f("state error: setcompat never called");

	ਜੇ (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	ਜੇ ((r = sshbuf_get_cstring(m, &authctxt->user, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	ਜੇ (pwent == ਨਿਰਾ) {
		invalid_user = 1;
		ਜੇ ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	/* XXX send fake class/dir/shell, etc. */
	ਜੇ ((r = sshbuf_put_u8(m, 1)) != 0)
		fatal_fr(r, "assemble ok");
	PUTPW(m, pw_uid);
	PUTPW(m, pw_gid);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(m, pw_change);
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(m, pw_expire);
#ਜੇ_ਅੰਤ
	ਜੇ ((r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
	    (r = sshbuf_put_cstring(m, "*")) != 0 ||
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_put_cstring(m, pwent->pw_gecos)) != 0 ||
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_put_cstring(m, pwent->pw_class)) != 0 ||
#ਜੇ_ਅੰਤ
	    (r = sshbuf_put_cstring(m, pwent->pw_dir)) != 0 ||
	    (r = sshbuf_put_cstring(m, pwent->pw_shell)) != 0)
		fatal_fr(r, "assemble pw");

 ਬਾਹਰਲਾ:
	ssh_packet_ਸੈੱਟ_log_preamble(ssh, "%suser %s",
	    authctxt->valid ? "authenticating" : "invalid ", authctxt->user);

	ਜੇ (options.refuse_connection) {
		logit("administratively prohibited connection for "
		    "%s%s from %.128s port %d",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user, ssh_remote_ipaddr(ssh),
		    ssh_remote_ਪੋਰਟ(ssh));
		cleanup_exit(EXIT_CONFIG_REFUSED);
	}

	/* Send active options to unpriv */
	mm_encode_server_options(m);

	/* Create valid auth method lists */
	ਜੇ (auth2_ਤਿਆਰੀ_methods_lists(authctxt) != 0) {
		/*
		 * The monitor will continue long enough to let the child
		 * run to its packet_disconnect(), but it must not allow any
		 * authentication to succeed.
		 */
		debug_f("no valid authentication method lists");
	}

	debug3_f("sending MONITOR_ANS_PWNAM: %d", allowed);
	mm_request_send(sock, MONITOR_ANS_PWNAM, m);

	/* Allow service/style information on the auth context */
	monitor_permit(mon_dispatch, MONITOR_REQ_AUTHSERV, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_AUTH2_READ_BANNER, 1);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	ਜੇ (options.use_pam)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ਸ਼ੁਰੂ, 1);
#ਜੇ_ਅੰਤ

	ਵਾਪਸ (0);
}

ਪੂਰਨ mm_answer_auth2_read_banner(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	ਅੱਖਰ *banner;
	ਪੂਰਨ r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	ਜੇ ((r = sshbuf_put_cstring(m, banner != ਨਿਰਾ ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	ਮੁਕਤ(banner);

	ਵਾਪਸ (0);
}

ਪੂਰਨ
mm_answer_authserv(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	ਪੂਰਨ r;

	monitor_permit_authentications(1);

	ਜੇ ((r = sshbuf_get_cstring(m, &authctxt->service, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	ਜੇ (ਲੜੀ_ਲੰਬਾਈ(authctxt->style) == 0) {
		ਮੁਕਤ(authctxt->style);
		authctxt->style = ਨਿਰਾ;
	}

	ਵਾਪਸ (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
ਸਥਿਰ ਪੂਰਨ
ਕੁੰਜੀ_ਅਧਾਰ_type_ਮੇਲ(ਅਚਲ ਅੱਖਰ *ਵਿਧੀ, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ ਅੱਖਰ *list)
{
	ਅੱਖਰ *s, *l, *ol = xstrdup(list);
	ਪੂਰਨ ਮਿਲਿਆ = 0;

	l = ol;
	ਲਈ ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		ਜੇ (sshkey_type_from_name(s) == ਕੁੰਜੀ->type) {
			ਮਿਲਿਆ = 1;
			ਰੋਕੋ;
		}
	}
	ਜੇ (!ਮਿਲਿਆ) {
		error("%s key type %s is not in permitted list %s", ਵਿਧੀ,
		    sshkey_ssh_name(ਕੁੰਜੀ), list);
	}

	ਮੁਕਤ(ol);
	ਵਾਪਸ ਮਿਲਿਆ;
}

ਪੂਰਨ
mm_answer_authpassword(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	ਸਥਿਰ ਪੂਰਨ call_ਗਿਣਤੀ;
	ਅੱਖਰ *passwd;
	ਪੂਰਨ r, authenticated;
	ਮਾਪ_t plen;

	ਜੇ (!options.password_authentication)
		fatal_f("password authentication not enabled");
	ਜੇ ((r = sshbuf_get_cstring(m, &passwd, &plen)) != 0)
		fatal_fr(r, "parse");
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(ssh, passwd);
	freezero(passwd, plen);

	sshbuf_reset(m);
	ਜੇ ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	ਜੇ ((r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0)
		fatal_fr(r, "assemble PAM");
#ਜੇ_ਅੰਤ

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_ਗਿਣਤੀ++;
	ਜੇ (plen == 0 && call_ਗਿਣਤੀ == 1)
		auth_ਵਿਧੀ = "none";
	ਨਹੀਂਤਾਂ
		auth_ਵਿਧੀ = "password";

	/* Causes monitor loop to terminate if authenticated */
	ਵਾਪਸ (authenticated);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BSD_AUTH
ਪੂਰਨ
mm_answer_bsdauthquery(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	ਅੱਖਰ *name, *infotxt;
	u_int numprompts, *echo_on, success;
	ਅੱਖਰ **prompts;
	ਪੂਰਨ r;

	ਜੇ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	success = bsdauth_query(authctxt, &name, &infotxt, &numprompts,
	    &prompts, &echo_on) < 0 ? 0 : 1;

	sshbuf_reset(m);
	ਜੇ ((r = sshbuf_put_u32(m, success)) != 0)
		fatal_fr(r, "assemble");
	ਜੇ (success) {
		ਜੇ ((r = sshbuf_put_cstring(m, prompts[0])) != 0)
			fatal_fr(r, "assemble prompt");
	}

	debug3_f("sending challenge success: %u", success);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHQUERY, m);

	ਜੇ (success) {
		ਮੁਕਤ(name);
		ਮੁਕਤ(infotxt);
		ਮੁਕਤ(prompts);
		ਮੁਕਤ(echo_on);
	}

	ਵਾਪਸ (0);
}

ਪੂਰਨ
mm_answer_bsdauthrespond(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	ਅੱਖਰ *response;
	ਪੂਰਨ r, authok;

	ਜੇ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	ਜੇ (authctxt->as == ਨਿਰਾ)
		fatal_f("no bsd auth session");

	ਜੇ ((r = sshbuf_get_cstring(m, &response, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = ਨਿਰਾ;
	debug3_f("<%s> = <%d>", response, authok);
	ਮੁਕਤ(response);

	sshbuf_reset(m);
	ਜੇ ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_ਵਿਧੀ = "keyboard-interactive";
	auth_submethod = "bsdauth";

	ਵਾਪਸ (authok != 0);
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
ਪੂਰਨ
mm_answer_pam_ਸ਼ੁਰੂ(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	ਜੇ (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	ਸ਼ੁਰੂ_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	ਜੇ (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	ਵਾਪਸ (0);
}

ਪੂਰਨ
mm_answer_pam_account(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	u_int ret;
	ਪੂਰਨ r;

	ਜੇ (!options.use_pam)
		fatal_f("PAM not enabled");

	ret = do_pam_account();

	ਜੇ ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "buffer error");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	ਵਾਪਸ (ret);
}

ਸਥਿਰ ਖਾਲੀ *sshpam_ctxt, *sshpam_authok;
ਬਾਹਰੀ KbdintDevice sshpam_device;

ਪੂਰਨ
mm_answer_pam_init_ctx(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	u_int ok = 0;
	ਪੂਰਨ r;

	debug3_f("entering");
	ਜੇ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	ਜੇ (sshpam_ctxt != ਨਿਰਾ)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = ਨਿਰਾ;
	sshbuf_reset(m);
	ਜੇ (sshpam_ctxt != ਨਿਰਾ) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	ਜੇ ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	ਵਾਪਸ (0);
}

ਪੂਰਨ
mm_answer_pam_query(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	ਅੱਖਰ *name = ਨਿਰਾ, *info = ਨਿਰਾ, **prompts = ਨਿਰਾ;
	u_int i, ਅੰਕ = 0, *echo_on = 0;
	ਪੂਰਨ r, ret;

	debug3_f("entering");
	sshpam_authok = ਨਿਰਾ;
	ਜੇ (sshpam_ctxt == ਨਿਰਾ)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &ਅੰਕ, &prompts, &echo_on);
	ਜੇ (ret == 0 && ਅੰਕ == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	ਜੇ (ਅੰਕ > 1 || name == ਨਿਰਾ || info == ਨਿਰਾ)
		fatal("sshpam_device.query failed");
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_RESPOND, 1);
	sshbuf_reset(m);
	ਜੇ ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0 ||
	    (r = sshbuf_put_cstring(m, info)) != 0 ||
	    (r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0 ||
	    (r = sshbuf_put_u32(m, ਅੰਕ)) != 0)
		fatal_fr(r, "buffer error");
	ਮੁਕਤ(name);
	ਮੁਕਤ(info);
	ਲਈ (i = 0; i < ਅੰਕ; ++i) {
		ਜੇ ((r = sshbuf_put_cstring(m, prompts[i])) != 0 ||
		    (r = sshbuf_put_u32(m, echo_on[i])) != 0)
			fatal_fr(r, "buffer error");
		ਮੁਕਤ(prompts[i]);
	}
	ਮੁਕਤ(prompts);
	ਮੁਕਤ(echo_on);
	auth_ਵਿਧੀ = "keyboard-interactive";
	auth_submethod = "pam";
	mm_request_send(sock, MONITOR_ANS_PAM_QUERY, m);
	ਵਾਪਸ (0);
}

ਪੂਰਨ
mm_answer_pam_respond(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	ਅੱਖਰ **resp;
	u_int i, ਅੰਕ;
	ਪੂਰਨ r, ret;

	debug3_f("entering");
	ਜੇ (sshpam_ctxt == ਨਿਰਾ)
		fatal_f("no context");
	sshpam_authok = ਨਿਰਾ;
	ਜੇ ((r = sshbuf_get_u32(m, &ਅੰਕ)) != 0)
		fatal_fr(r, "buffer error");
	ਜੇ (ਅੰਕ > PAM_MAX_ਅੰਕ_ਸੁਨੇਹਾ) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    ਅੰਕ, (ਬਿਨਾਨਿਸ਼ਾਨੀ)PAM_MAX_ਅੰਕ_ਸੁਨੇਹਾ);
	}
	ਜੇ (ਅੰਕ > 0) {
		resp = xcalloc(ਅੰਕ, ਆਕਾਰ(ਅੱਖਰ *));
		ਲਈ (i = 0; i < ਅੰਕ; ++i) {
			ਜੇ ((r = sshbuf_get_cstring(m, &(resp[i]), ਨਿਰਾ)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, ਅੰਕ, resp);
		ਲਈ (i = 0; i < ਅੰਕ; ++i)
			ਮੁਕਤ(resp[i]);
		ਮੁਕਤ(resp);
	} ਨਹੀਂਤਾਂ {
		ret = (sshpam_device.respond)(sshpam_ctxt, ਅੰਕ, ਨਿਰਾ);
	}
	sshbuf_reset(m);
	ਜੇ ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_ਵਿਧੀ = "keyboard-interactive";
	auth_submethod = "pam";
	ਜੇ (ret == 0)
		sshpam_authok = sshpam_ctxt;
	ਵਾਪਸ (0);
}

ਪੂਰਨ
mm_answer_pam_free_ctx(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	ਪੂਰਨ r = sshpam_authok != ਨਿਰਾ && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	ਜੇ (sshpam_ctxt == ਨਿਰਾ)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = ਨਿਰਾ;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_ਵਿਧੀ = "keyboard-interactive";
	auth_submethod = "pam";
	ਵਾਪਸ r;
}
#ਜੇ_ਅੰਤ

ਪੂਰਨ
mm_answer_keyallowed(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਅੱਖਰ *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	ਪੂਰਨ r, allowed = 0;
	ਬਣਤਰ sshauthopt *opts = ਨਿਰਾ;

	debug3_f("entering");
	ਜੇ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, ਨਿਰਾ)) != 0 ||
	    (r = sshkey_froms(m, &ਕੁੰਜੀ)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	ਜੇ (ਕੁੰਜੀ != ਨਿਰਾ && authctxt->valid) {
		ਚੋਣ (type) {
		ਹਾਲਤ MM_USERKEY:
			auth_ਵਿਧੀ = "publickey";
			ਜੇ (!options.pubkey_authentication)
				ਰੋਕੋ;
			ਜੇ (auth2_ਕੁੰਜੀ_already_ਵਰਤਿਆ(authctxt, ਕੁੰਜੀ))
				ਰੋਕੋ;
			ਜੇ (!ਕੁੰਜੀ_ਅਧਾਰ_type_ਮੇਲ(auth_ਵਿਧੀ, ਕੁੰਜੀ,
			    options.pubkey_accepted_algos))
				ਰੋਕੋ;
			allowed = user_ਕੁੰਜੀ_allowed(ssh, authctxt->pw, ਕੁੰਜੀ,
			    pubkey_auth_attempt, &opts);
			ਰੋਕੋ;
		ਹਾਲਤ MM_HOSTKEY:
			auth_ਵਿਧੀ = "hostbased";
			ਜੇ (!options.hostbased_authentication)
				ਰੋਕੋ;
			ਜੇ (auth2_ਕੁੰਜੀ_already_ਵਰਤਿਆ(authctxt, ਕੁੰਜੀ))
				ਰੋਕੋ;
			ਜੇ (!ਕੁੰਜੀ_ਅਧਾਰ_type_ਮੇਲ(auth_ਵਿਧੀ, ਕੁੰਜੀ,
			    options.hostbased_accepted_algos))
				ਰੋਕੋ;
			allowed = hostbased_ਕੁੰਜੀ_allowed(ssh, authctxt->pw,
			    cuser, chost, ਕੁੰਜੀ);
			auth2_ਰਿਕਾਰਡ_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			ਰੋਕੋ;
		ਮੂਲ:
			fatal_f("unknown key type %u", type);
			ਰੋਕੋ;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_ਵਿਧੀ,
	    pubkey_auth_attempt ? "" : " test",
	    (ਕੁੰਜੀ == ਨਿਰਾ || !authctxt->valid) ? "invalid" : sshkey_type(ਕੁੰਜੀ),
	    allowed ? "allowed" : "not allowed");

	auth2_ਰਿਕਾਰਡ_ਕੁੰਜੀ(authctxt, 0, ਕੁੰਜੀ);

	/* clear temporarily storage (used by verify) */
	monitor_reset_ਕੁੰਜੀ_state();

	ਜੇ (allowed) {
		/* Save temporarily for comparison in verify */
		ਜੇ ((r = sshkey_ਮੰਜ਼ਿਲ_blob(ਕੁੰਜੀ, &ਕੁੰਜੀ_blob, &ਕੁੰਜੀ_bloblen)) != 0)
			fatal_fr(r, "sshkey_to_blob");
		ਕੁੰਜੀ_blobtype = type;
		ਕੁੰਜੀ_opts = opts;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} ਨਹੀਂਤਾਂ {
		/* Log failed attempt */
		auth_log(ssh, 0, 0, auth_ਵਿਧੀ, ਨਿਰਾ);
		ਮੁਕਤ(cuser);
		ਮੁਕਤ(chost);
	}
	sshkey_free(ਕੁੰਜੀ);

	sshbuf_reset(m);
	ਜੇ ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	ਜੇ (opts != ਨਿਰਾ && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	ਜੇ (!allowed)
		sshauthopt_free(opts);

	ਵਾਪਸ (0);
}

ਸਥਿਰ ਪੂਰਨ
monitor_valid_userblob(ਬਣਤਰ ssh *ssh, ਅਚਲ u_char *ਅੰਕੜੇ, u_int datalen)
{
	ਬਣਤਰ sshbuf *b;
	ਬਣਤਰ sshkey *hostkey = ਨਿਰਾ;
	ਅਚਲ u_char *p;
	ਅੱਖਰ *userstyle, *cp;
	ਮਾਪ_t len;
	u_char type;
	ਪੂਰਨ hostbound = 0, r, fail = 0;

	ਜੇ ((b = sshbuf_from(ਅੰਕੜੇ, datalen)) == ਨਿਰਾ)
		fatal_f("sshbuf_from");

	ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	ਜੇ ((session_id2 == ਨਿਰਾ) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	ਜੇ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ਜੇ (type != SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST)
		fail++;
	ਜੇ ((r = sshbuf_get_cstring(b, &cp, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	ਜੇ (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	ਮੁਕਤ(userstyle);
	ਮੁਕਤ(cp);
	ਜੇ ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse method");
	ਜੇ (strcmp("publickey", cp) != 0) {
		ਜੇ (strcmp("publickey-hostbound-v00@openssh.com", cp) == 0)
			hostbound = 1;
		ਨਹੀਂਤਾਂ
			fail++;
	}
	ਮੁਕਤ(cp);
	ਜੇ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse pktype");
	ਜੇ (type == 0)
		fail++;
	ਜੇ ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0 ||	/* pkblob */
	    (hostbound && (r = sshkey_froms(b, &hostkey)) != 0))
		fatal_fr(r, "parse pk");
	ਜੇ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	ਜੇ (hostkey != ਨਿਰਾ) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		ਜੇ (get_hostkey_ਸੂਚਕਾਂਕ(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	ਵਾਪਸ (fail == 0);
}

ਸਥਿਰ ਪੂਰਨ
monitor_valid_hostbasedblob(ਅਚਲ u_char *ਅੰਕੜੇ, u_int datalen,
    ਅਚਲ ਅੱਖਰ *cuser, ਅਚਲ ਅੱਖਰ *chost)
{
	ਬਣਤਰ sshbuf *b;
	ਅਚਲ u_char *p;
	ਅੱਖਰ *cp, *userstyle;
	ਮਾਪ_t len;
	ਪੂਰਨ r, fail = 0;
	u_char type;

	ਜੇ ((b = sshbuf_from(ਅੰਕੜੇ, datalen)) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	ਜੇ ((session_id2 == ਨਿਰਾ) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	ਜੇ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ਜੇ (type != SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST)
		fail++;
	ਜੇ ((r = sshbuf_get_cstring(b, &cp, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	ਜੇ (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	ਮੁਕਤ(userstyle);
	ਮੁਕਤ(cp);
	ਜੇ ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse method");
	ਜੇ (strcmp(cp, "hostbased") != 0)
		fail++;
	ਮੁਕਤ(cp);
	ਜੇ ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	ਜੇ ((r = sshbuf_get_cstring(b, &cp, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse host");
	ਜੇ (((len = ਲੜੀ_ਲੰਬਾਈ(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	ਜੇ (strcmp(cp, chost) != 0)
		fail++;
	ਮੁਕਤ(cp);

	/* verify client user */
	ਜੇ ((r = sshbuf_get_cstring(b, &cp, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse ruser");
	ਜੇ (strcmp(cp, cuser) != 0)
		fail++;
	ਮੁਕਤ(cp);

	ਜੇ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	ਵਾਪਸ (fail == 0);
}

ਪੂਰਨ
mm_answer_keyverify(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	ਬਣਤਰ sshkey *ਕੁੰਜੀ;
	ਅਚਲ u_char *signature, *ਅੰਕੜੇ, *blob;
	ਅੱਖਰ *sigalg = ਨਿਰਾ, *fp = ਨਿਰਾ;
	ਮਾਪ_t signaturelen, datalen, bloblen;
	ਪੂਰਨ r, ret, req_presence = 0, req_verify = 0, valid_ਅੰਕੜੇ = 0;
	ਪੂਰਨ encoded_ret;
	ਬਣਤਰ sshkey_sig_details *sig_details = ਨਿਰਾ;

	ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_ਸਿੱਧਾ(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_ਸਿੱਧਾ(m, &ਅੰਕੜੇ, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");

	ਜੇ (hostbased_cuser == ਨਿਰਾ || hostbased_chost == ਨਿਰਾ ||
	  !monitor_allowed_ਕੁੰਜੀ(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	ਜੇ (*sigalg == '\0') {
		ਮੁਕਤ(sigalg);
		sigalg = ਨਿਰਾ;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	ਜੇ ((r = sshkey_from_blob(blob, bloblen, &ਕੁੰਜੀ)) != 0)
		fatal_fr(r, "parse key");

	ਚੋਣ (ਕੁੰਜੀ_blobtype) {
	ਹਾਲਤ MM_USERKEY:
		valid_ਅੰਕੜੇ = monitor_valid_userblob(ssh, ਅੰਕੜੇ, datalen);
		auth_ਵਿਧੀ = "publickey";
		ਰੋਕੋ;
	ਹਾਲਤ MM_HOSTKEY:
		valid_ਅੰਕੜੇ = monitor_valid_hostbasedblob(ਅੰਕੜੇ, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_ਵਿਧੀ = "hostbased";
		ਰੋਕੋ;
	ਮੂਲ:
		valid_ਅੰਕੜੇ = 0;
		ਰੋਕੋ;
	}
	ਜੇ (!valid_ਅੰਕੜੇ)
		fatal_f("bad %s signature data blob",
		    ਕੁੰਜੀ_blobtype == MM_USERKEY ? "userkey" :
		    (ਕੁੰਜੀ_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	ਜੇ ((fp = sshkey_fingerprint(ਕੁੰਜੀ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ਨਿਰਾ)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(ਕੁੰਜੀ, signature, signaturelen, ਅੰਕੜੇ, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_ਵਿਧੀ,
	    sshkey_type(ਕੁੰਜੀ), sigalg == ਨਿਰਾ ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	ਜੇ (ret == 0 && ਕੁੰਜੀ_blobtype == MM_USERKEY && sig_details != ਨਿਰਾ) {
		req_presence = (options.pubkey_auth_options &
		    PUBKEYAUTH_TOUCH_REQUIRED) ||
		    !ਕੁੰਜੀ_opts->no_require_user_presence;
		ਜੇ (req_presence &&
		    (sig_details->sk_flags & SSH_SK_USER_PRESENCE_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user presence "
			    "(authenticator touch) requirement not met ",
			    sshkey_type(ਕੁੰਜੀ), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_ਪੋਰਟ(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
		req_verify = (options.pubkey_auth_options &
		    PUBKEYAUTH_VERIFY_REQUIRED) || ਕੁੰਜੀ_opts->require_verify;
		ਜੇ (req_verify &&
		    (sig_details->sk_flags & SSH_SK_USER_VERIFICATION_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user verification requirement "
			    "not met ", sshkey_type(ਕੁੰਜੀ), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_ਪੋਰਟ(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
	}
	auth2_ਰਿਕਾਰਡ_ਕੁੰਜੀ(authctxt, ret == 0, ਕੁੰਜੀ);

	ਜੇ (ਕੁੰਜੀ_blobtype == MM_USERKEY && ret == 0)
		auth_activate_options(ssh, ਕੁੰਜੀ_opts);
	monitor_reset_ਕੁੰਜੀ_state();

	sshbuf_reset(m);

	/* encode ret != 0 as positive integer, since we're sending u32 */
	encoded_ret = (ret != 0);
	ਜੇ ((r = sshbuf_put_u32(m, encoded_ret)) != 0 ||
	    (r = sshbuf_put_u8(m, sig_details != ਨਿਰਾ)) != 0)
		fatal_fr(r, "assemble");
	ਜੇ (sig_details != ਨਿਰਾ) {
		ਜੇ ((r = sshbuf_put_u32(m, sig_details->sk_counter)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	ਮੁਕਤ(sigalg);
	ਮੁਕਤ(fp);
	sshkey_free(ਕੁੰਜੀ);

	ਵਾਪਸ ret == 0;
}

ਸਥਿਰ ਖਾਲੀ
mm_ਰਿਕਾਰਡ_login(ਬਣਤਰ ssh *ssh, Session *s, ਬਣਤਰ passwd *pw)
{
	socklen_t fromlen;
	ਬਣਤਰ sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, ਆਕਾਰ(from));
	fromlen = ਆਕਾਰ(from);
	ਜੇ (ssh_packet_connection_is_on_socket(ssh)) {
		ਜੇ (getpeername(ssh_packet_get_connection_ਵਿੱਚ(ssh),
		    (ਬਣਤਰ sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	ਰਿਕਾਰਡ_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (ਬਣਤਰ sockaddr *)&from, fromlen);
}

ਸਥਿਰ ਖਾਲੀ
mm_session_close(Session *s)
{
	debug3_f("session %d pid %ld", s->self, (ਲੰਮਾ)s->pid);
	ਜੇ (s->ttyfd != -1) {
		debug3_f("tty %s ptyfd %d", s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_ਅਣਵਰਤਿਆ(s->self);
}

ਪੂਰਨ
mm_answer_pty(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	ਬਾਹਰੀ ਬਣਤਰ monitor *pmonitor;
	Session *s;
	ਪੂਰਨ r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	ਜੇ (s == ਨਿਰਾ)
		ਜਾਓ error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, ਆਕਾਰ(s->tty));
	ਜੇ (res == 0)
		ਜਾਓ error;
	pty_setowner(authctxt->pw, s->tty);

	ਜੇ ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");

	/* We need to trick ttyslot */
	ਜੇ (dup2(s->ttyfd, 0) == -1)
		fatal_f("dup2");

	mm_ਰਿਕਾਰਡ_login(ssh, s, authctxt->pw);

	/* Now we can close the file descriptor again */
	close(0);

	/* send messages generated by record_login */
	ਜੇ ((r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "assemble loginmsg");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PTY, m);

	ਜੇ (mm_send_fd(sock, s->ptyfd) == -1 ||
	    mm_send_fd(sock, s->ttyfd) == -1)
		fatal_f("send fds failed");

	/* make sure nothing uses fd 0 */
	ਜੇ ((fd0 = open(_PATH_DEVNULL, O_RDONLY)) == -1)
		fatal_f("open(/dev/null): %s", strerror(errno));
	ਜੇ (fd0 != 0)
		error_f("fd0 %d != 0", fd0);

	/* slave side of pty is not needed */
	close(s->ttyfd);
	s->ttyfd = s->ptyfd;
	/* no need to dup() because nobody closes ptyfd */
	s->ptymaster = s->ptyfd;

	debug3_f("tty %s ptyfd %d", s->tty, s->ttyfd);

	ਵਾਪਸ (0);

 error:
	ਜੇ (s != ਨਿਰਾ)
		mm_session_close(s);
	ਜੇ ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	ਵਾਪਸ (0);
}

ਪੂਰਨ
mm_answer_pty_cleanup(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	Session *s;
	ਅੱਖਰ *tty;
	ਪੂਰਨ r;

	debug3_f("entering");

	ਜੇ ((r = sshbuf_get_cstring(m, &tty, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse tty");
	ਜੇ ((s = session_by_tty(tty)) != ਨਿਰਾ)
		mm_session_close(s);
	sshbuf_reset(m);
	ਮੁਕਤ(tty);
	ਵਾਪਸ (0);
}

ਪੂਰਨ
mm_answer_ਪਦ(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *req)
{
	ਬਾਹਰੀ ਬਣਤਰ monitor *pmonitor;
	ਪੂਰਨ res, ਸਥਿਤੀ;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	ਜੇ (options.use_pam)
		sshpam_cleanup();
#ਜੇ_ਅੰਤ

	ਜਦੋਂ (waitpid(pmonitor->m_pid, &ਸਥਿਤੀ, 0) == -1)
		ਜੇ (errno != EINTR)
			ਬਾਹਰ_ਨਿਕਲੋ(1);

	res = WIFEXITED(ਸਥਿਤੀ) ? WEXITSTATUS(ਸਥਿਤੀ) : 1;

	/* Terminate process */
	ਬਾਹਰ_ਨਿਕਲੋ(res);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
ਪੂਰਨ
mm_answer_audit_event(ਬਣਤਰ ssh *ssh, ਪੂਰਨ socket, ਬਣਤਰ sshbuf *m)
{
	u_int n;
	ssh_audit_event_t event;
	ਪੂਰਨ r;

	debug3_f("entering");

	ਜੇ ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	event = (ssh_audit_event_t)n;
	ਚੋਣ (event) {
	ਹਾਲਤ SSH_AUTH_FAIL_PUBKEY:
	ਹਾਲਤ SSH_AUTH_FAIL_HOSTBASED:
	ਹਾਲਤ SSH_AUTH_FAIL_GSSAPI:
	ਹਾਲਤ SSH_LOGIN_EXCEED_MAXTRIES:
	ਹਾਲਤ SSH_LOGIN_ਜੜ੍ਹ_DENIED:
	ਹਾਲਤ SSH_CONNECTION_CLOSE:
	ਹਾਲਤ SSH_INVALID_USER:
		audit_event(ssh, event);
		ਰੋਕੋ;
	ਮੂਲ:
		fatal("Audit event type %d not permitted", event);
	}

	ਵਾਪਸ (0);
}

ਪੂਰਨ
mm_answer_audit_command(ਬਣਤਰ ssh *ssh, ਪੂਰਨ socket, ਬਣਤਰ sshbuf *m)
{
	ਅੱਖਰ *cmd;
	ਪੂਰਨ r;

	debug3_f("entering");
	ਜੇ ((r = sshbuf_get_cstring(m, &cmd, ਨਿਰਾ)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_ਲੜੀਵਾਰ_command(cmd);
	ਮੁਕਤ(cmd);
	ਵਾਪਸ (0);
}
#ਜੇ_ਅੰਤ /* SSH_AUDIT_EVENTS */

ਖਾਲੀ
monitor_clear_keystate(ਬਣਤਰ ssh *ssh, ਬਣਤਰ monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, ਬਹੁਲਕ_ਵਿੱਚ);
	ssh_clear_newkeys(ssh, ਬਹੁਲਕ_ਬਾਹਰਲਾ);
	sshbuf_free(ਬੱਚਾ_state);
	ਬੱਚਾ_state = ਨਿਰਾ;
}

ਖਾਲੀ
monitor_apply_keystate(ਬਣਤਰ ssh *ssh, ਬਣਤਰ monitor *pmonitor)
{
	ਬਣਤਰ kex *kex;
	ਪੂਰਨ r;

	debug3_f("packet_set_state");
	ਜੇ ((r = ssh_packet_ਸੈੱਟ_state(ssh, ਬੱਚਾ_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(ਬੱਚਾ_state);
	ਬੱਚਾ_state = ਨਿਰਾ;
	ਜੇ ((kex = ssh->kex) == ਨਿਰਾ)
		fatal_f("internal error: ssh->kex == NULL");
	ਜੇ (session_id2_len != sshbuf_len(ssh->kex->session_id)) {
		fatal_f("incorrect session id length %zu (expected %u)",
		    sshbuf_len(ssh->kex->session_id), session_id2_len);
	}
	ਜੇ (memcmp(sshbuf_ptr(ssh->kex->session_id), session_id2,
	    session_id2_len) != 0)
		fatal_f("session ID mismatch");
	/* XXX set callbacks */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#ਜੇ_ਅੰਤ
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->ਲੱਦੋ_host_ਜਨਤਕ_ਕੁੰਜੀ=&get_hostkey_ਜਨਤਕ_by_type;
	kex->ਲੱਦੋ_host_ਨਿੱਜੀ_ਕੁੰਜੀ=&get_hostkey_ਨਿੱਜੀ_by_type;
	kex->host_ਕੁੰਜੀ_ਸੂਚਕਾਂਕ=&get_hostkey_ਸੂਚਕਾਂਕ;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

ਖਾਲੀ
mm_get_keystate(ਬਣਤਰ ssh *ssh, ਬਣਤਰ monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	ਜੇ ((ਬੱਚਾ_state = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    ਬੱਚਾ_state);
	debug3_f("GOT new keys");
}


/* XXX */

ਸਥਿਰ ਖਾਲੀ
monitor_openfds(ਬਣਤਰ monitor *mon, ਪੂਰਨ do_logfds)
{
	ਪੂਰਨ pair[2];
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SO_ZEROIZE
	ਪੂਰਨ on = 1;
#ਜੇ_ਅੰਤ

	ਜੇ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", strerror(errno));
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SO_ZEROIZE
	ਜੇ (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, ਆਕਾਰ(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", strerror(errno));
	ਜੇ (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, ਆਕਾਰ(on)) == -1)
		error("setsockopt SO_ZEROIZE(1): %.100s", strerror(errno));
#ਜੇ_ਅੰਤ
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
	mon->m_recvfd = pair[0];
	mon->m_sendfd = pair[1];

	ਜੇ (do_logfds) {
		ਜੇ (pipe(pair) == -1)
			fatal_f("pipe: %s", strerror(errno));
		FD_CLOSEONEXEC(pair[0]);
		FD_CLOSEONEXEC(pair[1]);
		mon->m_log_recvfd = pair[0];
		mon->m_log_sendfd = pair[1];
	} ਨਹੀਂਤਾਂ
		mon->m_log_recvfd = mon->m_log_sendfd = -1;
}

ਬਣਤਰ monitor *
monitor_init(ਖਾਲੀ)
{
	ਬਣਤਰ monitor *mon;

	mon = xcalloc(1, ਆਕਾਰ(*mon));
	monitor_openfds(mon, 1);

	ਵਾਪਸ mon;
}

ਖਾਲੀ
monitor_reinit(ਬਣਤਰ monitor *mon)
{
	monitor_openfds(mon, 0);
}

ਪੂਰਨ
monitor_auth_attempted(ਖਾਲੀ)
{
	ਵਾਪਸ auth_attempted;
}

ਪੂਰਨ
monitor_invalid_user(ਖਾਲੀ)
{
	ਵਾਪਸ invalid_user;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
ਪੂਰਨ
mm_answer_gss_ਤਿਆਰੀ_ctx(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	ਮਾਪ_t len;
	u_char *p;
	ਪੂਰਨ r;

	ਜੇ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	ਜੇ ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.ਲੰਮਾਈ = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	ਮੁਕਤ(goid.elements);

	sshbuf_reset(m);
	ਜੇ ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	ਵਾਪਸ (0);
}

ਪੂਰਨ
mm_answer_gss_accept_ctx(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	gss_ਬਫਰ_desc ਵਿੱਚ;
	gss_ਬਫਰ_desc ਬਾਹਰਲਾ = GSS_C_ਖਾਲੀ_ਥਾਵਾਂ_ਬਫਰ;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	ਪੂਰਨ r;

	ਜੇ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ਜੇ ((r = ssh_gssapi_get_ਬਫਰ_desc(m, &ਵਿੱਚ)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &ਵਿੱਚ, &ਬਾਹਰਲਾ, &flags);
	ਮੁਕਤ(ਵਿੱਚ.ਮੁੱਲ);

	sshbuf_reset(m);
	ਜੇ ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, ਬਾਹਰਲਾ.ਮੁੱਲ, ਬਾਹਰਲਾ.ਲੰਮਾਈ)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_ਬਫਰ(&minor, &ਬਾਹਰਲਾ);

	ਜੇ (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	ਵਾਪਸ (0);
}

ਪੂਰਨ
mm_answer_gss_checkmic(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	gss_ਬਫਰ_desc gssbuf, mic;
	OM_uint32 ret;
	ਪੂਰਨ r;

	ਜੇ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ਜੇ ((r = ssh_gssapi_get_ਬਫਰ_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_ਬਫਰ_desc(m, &mic)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	ਮੁਕਤ(gssbuf.ਮੁੱਲ);
	ਮੁਕਤ(mic.ਮੁੱਲ);

	sshbuf_reset(m);
	ਜੇ ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	ਜੇ (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	ਵਾਪਸ (0);
}

ਪੂਰਨ
mm_answer_gss_userok(ਬਣਤਰ ssh *ssh, ਪੂਰਨ sock, ਬਣਤਰ sshbuf *m)
{
	ਪੂਰਨ r, authenticated;
	ਅਚਲ ਅੱਖਰ *displayname;

	ਜੇ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	ਜੇ ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_ਵਿਧੀ = "gssapi-with-mic";

	ਜੇ ((displayname = ssh_gssapi_displayname()) != ਨਿਰਾ)
		auth2_ਰਿਕਾਰਡ_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	ਵਾਪਸ (authenticated);
}
#ਜੇ_ਅੰਤ /* GSSAPI */

