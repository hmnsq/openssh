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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/tree.h>
#ଅନ୍ତର୍ଭାଵ <sys/queue.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <paths.h>
#ଅନ୍ତର୍ଭାଵ <poll.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/dh.h>
#endif

#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"

#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "cipher.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "dh.h"
#ଅନ୍ତର୍ଭାଵ "auth-pam.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "auth-options.h"
#ଅନ୍ତର୍ଭାଵ "sshpty.h"
#ଅନ୍ତର୍ଭାଵ "channels.h"
#ଅନ୍ତର୍ଭାଵ "session.h"
#ଅନ୍ତର୍ଭାଵ "sshlogin.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "monitor.h"
#ifdef GSSAPI
#ଅନ୍ତର୍ଭାଵ "ssh-gss.h"
#endif
#ଅନ୍ତର୍ଭାଵ "monitor_wrap.h"
#ଅନ୍ତର୍ଭାଵ "monitor_fdpass.h"
#ଅନ୍ତର୍ଭାଵ "compat.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "authfd.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sk-api.h"
#ଅନ୍ତର୍ଭାଵ "srclimit.h"

#ifdef GSSAPI
ସ୍ଥିର Gssctxt *gsscontext = ଖାଲି;
#endif

/* Imports */
ବାହ୍ୟ ServerOptions options;
ବାହ୍ୟ u_int utmp_len;
ବାହ୍ୟ ସଂରଚନା sshbuf *cfg;
ବାହ୍ୟ ସଂରଚନା sshbuf *loginmsg;
ବାହ୍ୟ ସଂରଚନା include_list includes;
ବାହ୍ୟ ସଂରଚନା sshauthopt *auth_opts; /* XXX move to permanent ssh->authctxt? */

/* State exported from the child */
ସ୍ଥିର ସଂରଚନା sshbuf *child_state;

/* Functions on the monitor that answer unprivileged requests */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_moduli(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_setcompat(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_sign(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_pwnamallow(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_auth2_read_banner(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_authserv(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_authpassword(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_bsdauthquery(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_bsdauthrespond(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_keyallowed(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_keyverify(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_pty(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_pty_cleanup(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_term(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_state(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);

#ifdef USE_PAM
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_pam_start(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_pam_account(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_pam_init_ctx(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_pam_query(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_pam_respond(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_pam_free_ctx(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
#endif

#ifdef GSSAPI
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_gss_setup_ctx(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_gss_accept_ctx(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_gss_userok(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_gss_checkmic(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
#endif

#ifdef SSH_AUDIT_EVENTS
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_audit_event(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_audit_command(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
#endif

ସ୍ଥିର Authctxt *authctxt;

/* local state for key verify */
ସ୍ଥିର u_char *ଚାବି_blob = ଖାଲି;
ସ୍ଥିର size_t ଚାବି_bloblen = 0;
ସ୍ଥିର u_int ଚାବି_blobtype = MM_NOKEY;
ସ୍ଥିର ସଂରଚନା sshauthopt *ଚାବି_opts = ଖାଲି;
ସ୍ଥିର ଅକ୍ଷର *hostbased_cuser = ଖାଲି;
ସ୍ଥିର ଅକ୍ଷର *hostbased_chost = ଖାଲି;
ସ୍ଥିର ଅକ୍ଷର *auth_method = "unknown";
ସ୍ଥିର ଅକ୍ଷର *auth_submethod = ଖାଲି;
ସ୍ଥିର u_int session_id2_len = 0;
ସ୍ଥିର u_char *session_id2 = ଖାଲି;
ସ୍ଥିର pid_t monitor_child_pid;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା auth_attempted = 0;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା invalid_user = 0;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା compat_set = 0;

ସଂରଚନା mon_table {
	ଗଣନା monitor_reqtype type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*f)(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *);
};

#define MON_ISAUTH	0x0004	/* Required for Authentication */
#define MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#define MON_ONCE	0x0010	/* Disable after calling */
#define MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#define MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#define MON_PERMIT	0x1000	/* Request is permitted */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା monitor_read(ସଂରଚନା ssh *, ସଂରଚନା monitor *, ସଂରଚନା mon_table *,
    ସଂରଚନା mon_table **);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା monitor_read_log(ସଂରଚନା monitor *);

ସଂରଚନା mon_table mon_dispatch_proto20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#ifdef WITH_OPENSSL
    {MONITOR_REQ_MODULI, MON_ONCE, mm_answer_moduli},
#endif
    {MONITOR_REQ_SETCOMPAT, MON_ONCE, mm_answer_setcompat},
    {MONITOR_REQ_SIGN, MON_ONCE, mm_answer_sign},
    {MONITOR_REQ_PWNAM, MON_ONCE, mm_answer_pwnamallow},
    {MONITOR_REQ_AUTHSERV, MON_ONCE, mm_answer_authserv},
    {MONITOR_REQ_AUTH2_READ_BANNER, MON_ONCE, mm_answer_auth2_read_banner},
    {MONITOR_REQ_AUTHPASSWORD, MON_AUTH, mm_answer_authpassword},
#ifdef USE_PAM
    {MONITOR_REQ_PAM_START, MON_ONCE, mm_answer_pam_start},
    {MONITOR_REQ_PAM_ACCOUNT, 0, mm_answer_pam_account},
    {MONITOR_REQ_PAM_INIT_CTX, MON_ONCE, mm_answer_pam_init_ctx},
    {MONITOR_REQ_PAM_QUERY, 0, mm_answer_pam_query},
    {MONITOR_REQ_PAM_RESPOND, MON_ONCE, mm_answer_pam_respond},
    {MONITOR_REQ_PAM_FREE_CTX, MON_ONCE|MON_AUTHDECIDE, mm_answer_pam_free_ctx},
#endif
#ifdef SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
#endif
#ifdef BSD_AUTH
    {MONITOR_REQ_BSDAUTHQUERY, MON_ISAUTH, mm_answer_bsdauthquery},
    {MONITOR_REQ_BSDAUTHRESPOND, MON_AUTH, mm_answer_bsdauthrespond},
#endif
    {MONITOR_REQ_KEYALLOWED, MON_ISAUTH, mm_answer_keyallowed},
    {MONITOR_REQ_KEYVERIFY, MON_AUTH, mm_answer_keyverify},
#ifdef GSSAPI
    {MONITOR_REQ_GSSSETUP, MON_ISAUTH, mm_answer_gss_setup_ctx},
    {MONITOR_REQ_GSSSTEP, 0, mm_answer_gss_accept_ctx},
    {MONITOR_REQ_GSSUSEROK, MON_ONCE|MON_AUTHDECIDE, mm_answer_gss_userok},
    {MONITOR_REQ_GSSCHECKMIC, MON_ONCE, mm_answer_gss_checkmic},
#endif
    {0, 0, ଖାଲି}
};

ସଂରଚନା mon_table mon_dispatch_postauth20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#ifdef WITH_OPENSSL
    {MONITOR_REQ_MODULI, 0, mm_answer_moduli},
#endif
    {MONITOR_REQ_SIGN, 0, mm_answer_sign},
    {MONITOR_REQ_PTY, 0, mm_answer_pty},
    {MONITOR_REQ_PTYCLEANUP, 0, mm_answer_pty_cleanup},
    {MONITOR_REQ_TERM, 0, mm_answer_term},
#ifdef SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
    {MONITOR_REQ_AUDIT_COMMAND, MON_PERMIT, mm_answer_audit_command},
#endif
    {0, 0, ଖାଲି}
};

ସଂରଚନା mon_table *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
ସ୍ଥିର ଶୂନ୍ୟ
monitor_permit(ସଂରଚନା mon_table *ent, ଗଣନା monitor_reqtype type, ପୂର୍ଣ୍ଣସଂଖ୍ୟା permit)
{
	ଯେତେବେଳେ (ent->f != ଖାଲି) {
		ଯଦି (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			ଫେରନ୍ତୁ;
		}
		ent++;
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
monitor_permit_authentications(ପୂର୍ଣ୍ଣସଂଖ୍ୟା permit)
{
	ସଂରଚନା mon_table *ent = mon_dispatch;

	ଯେତେବେଳେ (ent->f != ଖାଲି) {
		ଯଦି (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

ଶୂନ୍ୟ
monitor_child_preauth(ସଂରଚନା ssh *ssh, ସଂରଚନା monitor *pmonitor)
{
	ସଂରଚନା mon_table *ent;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	ଯଦି (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	ଯଦି (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = (Authctxt *)ssh->authctxt;
	memset(authctxt, 0, ଆକାର(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	mon_dispatch = mon_dispatch_proto20;
	/* Permit requests for state, moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SETCOMPAT, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);

	/* The first few requests do not require asynchronous access */
	ଯେତେବେଳେ (!authenticated) {
		partial = 0;
		auth_method = "unknown";
		auth_submethod = ଖାଲି;
		auth2_authctxt_reset_info(authctxt);

		authenticated = (monitor_read(ssh, pmonitor,
		    mon_dispatch, &ent) == 1);

		/* Record that auth was attempted to set exit status later */
		ଯଦି ((ent->flags & MON_AUTH) != 0)
			auth_attempted = 1;

		/* Special handling for multiple required authentications */
		ଯଦି (options.ଅଙ୍କ_auth_methods != 0) {
			ଯଦି (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_method, auth_submethod)) {
				debug3_f("method %s: partial", auth_method);
				authenticated = 0;
				partial = 1;
			}
		}

		ଯଦି (authenticated) {
			ଯଦି (!(ent->flags & MON_AUTHDECIDE))
				fatal_f("unexpected authentication from %d",
				    ent->type);
			ଯଦି (authctxt->pw->pw_uid == 0 &&
			    !auth_ମୂଳ_allowed(ssh, auth_method))
				authenticated = 0;
#ifdef USE_PAM
			/* PAM needs to perform account checks after auth */
			ଯଦି (options.use_pam && authenticated) {
				ସଂରଚନା sshbuf *m;

				ଯଦି ((m = sshbuf_new()) == ଖାଲି)
					fatal("%s: sshbuf_new failed",
					    __func__);
				mm_request_receive_expect(pmonitor->m_sendfd,
				    MONITOR_REQ_PAM_ACCOUNT, m);
				authenticated = mm_answer_pam_account(
				    ssh, pmonitor->m_sendfd, m);
				sshbuf_free(m);
			}
#endif
		}
		ଯଦି (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(ssh, authenticated, partial,
			    auth_method, auth_submethod);
			ଯଦି (!partial && !authenticated)
				authctxt->failures++;
			ଯଦି (authenticated || partial) {
				auth2_update_session_info(authctxt,
				    auth_method, auth_submethod);
			}
		}
		ଯଦି (authctxt->failures > options.max_authtries) {
			/* Shouldn't happen */
			fatal_f("privsep child made too many authentication "
			    "attempts");
		}
	}

	ଯଦି (!authctxt->valid)
		fatal_f("authenticated invalid user");
	ଯଦି (strcmp(auth_method, "unknown") == 0)
		fatal_f("authentication method name unknown");

	debug_f("user %s authenticated by privileged process", authctxt->user);
	auth_attempted = 0;
	ssh->authctxt = ଖାଲି;
	ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	ଯେତେବେଳେ (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	ଯେତେବେଳେ (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		ଯଦି (errno == EINTR)
			ଜାରି;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ଯଦି (WIFEXITED(status)) {
		ଯଦି (WEXITSTATUS(status) != 0)
			fatal_f("preauth child %ld exited with status %d",
			    (long)pmonitor->m_pid, WEXITSTATUS(status));
	} ଅନ୍ୟଥା ଯଦି (WIFSIGNALED(status)) {
		fatal_f("preauth child %ld terminated by signal %d",
		    (long)pmonitor->m_pid, WTERMSIG(status));
	}
	debug3_f("preauth child %ld terminated successfully",
	    (long)pmonitor->m_pid);

	ଯଦି (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	ଯଦି (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_pid = -1;
}

ସ୍ଥିର ଶୂନ୍ୟ
monitor_set_child_handler(pid_t pid)
{
	monitor_child_pid = pid;
}

ସ୍ଥିର ଶୂନ୍ୟ
monitor_child_handler(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	kill(monitor_child_pid, sig);
}

ଶୂନ୍ୟ
monitor_child_postauth(ସଂରଚନା ssh *ssh, ସଂରଚନା monitor *pmonitor)
{
	close(pmonitor->m_recvfd);
	pmonitor->m_recvfd = -1;

	monitor_set_child_handler(pmonitor->m_pid);
	ssh_signal(SIGHUP, &monitor_child_handler);
	ssh_signal(SIGTERM, &monitor_child_handler);
	ssh_signal(SIGINT, &monitor_child_handler);
#ifdef SIGXFSZ
	ssh_signal(SIGXFSZ, SIG_IGN);
#endif

	mon_dispatch = mon_dispatch_postauth20;

	/* Permit requests for moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_TERM, 1);

	ଯଦି (auth_opts->permit_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	ପାଇଁ (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, ଖାଲି);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
monitor_read_log(ସଂରଚନା monitor *pmonitor)
{
	ସଂରଚନା sshbuf *logmsg;
	u_int len, level, forced;
	ଅକ୍ଷର *ସନ୍ଦେଶ;
	u_char *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((logmsg = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");

	/* Read length */
	ଯଦି ((r = sshbuf_reserve(logmsg, 4, &p)) != 0)
		fatal_fr(r, "reserve len");
	ଯଦି (atomicio(ପଠ, pmonitor->m_log_recvfd, p, 4) != 4) {
		ଯଦି (errno == EPIPE) {
			sshbuf_free(logmsg);
			debug_f("child log fd closed");
			close(pmonitor->m_log_recvfd);
			pmonitor->m_log_recvfd = -1;
			ଫେରନ୍ତୁ -1;
		}
		fatal_f("log fd read: %s", strerror(errno));
	}
	ଯଦି ((r = sshbuf_get_u32(logmsg, &len)) != 0)
		fatal_fr(r, "parse len");
	ଯଦି (len <= 4 || len > 8192)
		fatal_f("invalid log message length %u", len);

	/* Read severity, message */
	sshbuf_reset(logmsg);
	ଯଦି ((r = sshbuf_reserve(logmsg, len, &p)) != 0)
		fatal_fr(r, "reserve msg");
	ଯଦି (atomicio(ପଠ, pmonitor->m_log_recvfd, p, len) != len)
		fatal_f("log fd read: %s", strerror(errno));
	ଯଦି ((r = sshbuf_get_u32(logmsg, &level)) != 0 ||
	    (r = sshbuf_get_u32(logmsg, &forced)) != 0 ||
	    (r = sshbuf_get_cstring(logmsg, &ସନ୍ଦେଶ, ଖାଲି)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	ଯଦି (log_level_name(level) == ଖାଲି)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", ସନ୍ଦେଶ,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	ମୁକ୍ତ(ସନ୍ଦେଶ);

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
monitor_read(ସଂରଚନା ssh *ssh, ସଂରଚନା monitor *pmonitor, ସଂରଚନା mon_table *ent,
    ସଂରଚନା mon_table **pent)
{
	ସଂରଚନା sshbuf *m;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret;
	u_char type;
	ସଂରଚନା pollfd pfd[2];

	ପାଇଁ (;;) {
		memset(&pfd, 0, ଆକାର(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		ଯଦି (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			ଯଦି (errno == EINTR || errno == EAGAIN)
				ଜାରି;
			fatal_f("poll: %s", strerror(errno));
		}
		ଯଦି (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			ଜାରି;
		}
		ଯଦି (pfd[0].revents)
			ଭାଙ୍ଗ;  /* Continues below */
	}

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	ଯଦି ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	ଯେତେବେଳେ (ent->f != ଖାଲି) {
		ଯଦି (ent->type == type)
			ଭାଙ୍ଗ;
		ent++;
	}

	ଯଦି (ent->f != ଖାଲି) {
		ଯଦି (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		ଯଦି (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		ଯଦି (pent != ଖାଲି)
			*pent = ent;

		ଫେରନ୍ତୁ ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	ଫେରନ୍ତୁ (-1);
}

/* allowed key state */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
monitor_allowed_ଚାବି(ଅଚଳ u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	ଯଦି (ଚାବି_blob == ଖାଲି || ଚାବି_bloblen != bloblen ||
	    timingsafe_bcmp(ଚାବି_blob, blob, ଚାବି_bloblen))
		ଫେରନ୍ତୁ (0);
	ଫେରନ୍ତୁ (1);
}

ସ୍ଥିର ଶୂନ୍ୟ
monitor_reset_ଚାବି_state(ଶୂନ୍ୟ)
{
	/* reset state */
	ମୁକ୍ତ(ଚାବି_blob);
	ମୁକ୍ତ(hostbased_cuser);
	ମୁକ୍ତ(hostbased_chost);
	sshauthopt_free(ଚାବି_opts);
	ଚାବି_blob = ଖାଲି;
	ଚାବି_bloblen = 0;
	ଚାବି_blobtype = MM_NOKEY;
	ଚାବି_opts = ଖାଲି;
	hostbased_cuser = ଖାଲି;
	hostbased_chost = ଖାଲି;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_state(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *unused)
{
	ସଂରଚନା sshbuf *m = ଖାଲି, *config = ଖାଲି, *hostkeys = ଖାଲି;
	ସଂରଚନା sshbuf *opts = ଖାଲି, *confdata = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା postauth;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug_f("config len %zu", sshbuf_len(cfg));

	ଯଦି ((m = sshbuf_new()) == ଖାଲି ||
	    (config = sshbuf_new()) == ଖାଲି ||
	    (opts = sshbuf_new()) == ଖାଲି ||
	    (confdata = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	hostkeys = pack_hostkeys();
	ଯଦି ((r = serialise_server_options(&options, &config)) != 0)
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
	ଯଦି ((r = sshbuf_put_stringb(m, config)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "compose config");

	postauth = (authctxt && authctxt->pw && authctxt->authenticated);
	ଯଦି (postauth) {
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

	ଫେରନ୍ତୁ (0);
}

#ifdef WITH_OPENSSL
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_moduli(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	DH *dh;
	ଅଚଳ BIGNUM *dh_p, *dh_g;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int min, want, max;

	ଯଦି ((r = sshbuf_get_u32(m, &min)) != 0 ||
	    (r = sshbuf_get_u32(m, &want)) != 0 ||
	    (r = sshbuf_get_u32(m, &max)) != 0)
		fatal_fr(r, "parse");

	debug3_f("got parameters: %d %d %d", min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	ଯଦି (max < min || want < min || max < want)
		fatal_f("bad parameters: %d %d %d", min, want, max);

	sshbuf_reset(m);

	dh = choose_dh(min, want, max);
	ଯଦି (dh == ଖାଲି) {
		ଯଦି ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} ଅନ୍ୟଥା {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, ଖାଲି, &dh_g);
		ଯଦି ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	ଫେରନ୍ତୁ (0);
}
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_setcompat(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");

	ଯଦି ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_set = 1;

	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_sign(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା auth_sock;			/* XXX move to state struct? */
	ସଂରଚନା sshkey *pubkey, *ଚାବି;
	ସଂରଚନା sshbuf *sigbuf = ଖାଲି;
	u_char *p = ଖାଲି, *signature = ଖାଲି;
	ଅକ୍ଷର *alg = ଖାଲି;
	size_t datlen, siglen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, is_proof = 0, keyid;
	u_int compat;
	ଅଚଳ ଅକ୍ଷର proof_req[] = "hostkeys-prove-00@openssh.com";
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା nhostkey_proofs_done, *hostkey_proofs_done;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	ଯଦି (!compat_set)
		fatal_f("state error: setcompat never called");

	ଯଦି ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	ଯଦି ((keyid = get_hostkey_index(pubkey, 1, ssh)) == -1)
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
	ଯଦି (datlen != 20 && datlen != 32 && datlen != 48 && datlen != 64) {
		/*
		 * Construct expected hostkey proof and compare it to what
		 * the client sent us.
		 */
		ଯଦି (session_id2_len == 0) /* hostkeys is never first */
			fatal_f("bad data length: %zu", datlen);
		ଯଦି ((ଚାବି = get_hostkey_public_by_index(keyid, ssh)) == ଖାଲି)
			fatal_f("no hostkey for index %d", keyid);
		ଯଦି (keyid >= nhostkey_proofs_done) {
			hostkey_proofs_done = xrecallocarray(
			    hostkey_proofs_done, nhostkey_proofs_done,
			    keyid + 1, ଆକାର(*hostkey_proofs_done));
			nhostkey_proofs_done = keyid + 1;
		}
		ଯଦି (hostkey_proofs_done[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(ଚାବି), keyid);
		}
		hostkey_proofs_done[keyid] = 1;
		ଯଦି ((sigbuf = sshbuf_new()) == ଖାଲି)
			fatal_f("sshbuf_new");
		ଯଦି ((r = sshbuf_put_cstring(sigbuf, proof_req)) != 0 ||
		    (r = sshbuf_put_string(sigbuf, session_id2,
		    session_id2_len)) != 0 ||
		    (r = sshkey_puts(ଚାବି, sigbuf)) != 0)
			fatal_fr(r, "assemble private key proof");
		ଯଦି (datlen != sshbuf_len(sigbuf) ||
		    memcmp(p, sshbuf_ptr(sigbuf), sshbuf_len(sigbuf)) != 0)
			fatal_f("bad data length: %zu, hostkey proof len %zu",
			    datlen, sshbuf_len(sigbuf));
		sshbuf_free(sigbuf);
		is_proof = 1;
	}

	/* save session id, it will be passed on the first call */
	ଯଦି (session_id2_len == 0) {
		session_id2_len = datlen;
		session_id2 = xmalloc(session_id2_len);
		memcpy(session_id2, p, session_id2_len);
	}

	ଯଦି ((ଚାବି = get_hostkey_by_index(keyid)) != ଖାଲି) {
		ଯଦି ((r = sshkey_sign(ଚାବି, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, ଖାଲି, compat)) != 0)
			fatal_fr(r, "sign");
	} ଅନ୍ୟଥା ଯଦି ((ଚାବି = get_hostkey_public_by_index(keyid, ssh)) != ଖାଲି &&
	    auth_sock > 0) {
		ଯଦି ((r = ssh_agent_sign(auth_sock, ଚାବି, &signature, &siglen,
		    p, datlen, alg, compat)) != 0)
			fatal_fr(r, "agent sign");
	} ଅନ୍ୟଥା
		fatal_f("no hostkey from index %d", keyid);

	debug3_f("%s %s signature len=%zu", alg,
	    is_proof ? "hostkey proof" : "KEX", siglen);

	sshbuf_reset(m);
	ଯଦି ((r = sshbuf_put_string(m, signature, siglen)) != 0)
		fatal_fr(r, "assemble");

	ମୁକ୍ତ(alg);
	ମୁକ୍ତ(p);
	ମୁକ୍ତ(signature);

	mm_request_send(sock, MONITOR_ANS_SIGN, m);

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	ଫେରନ୍ତୁ (0);
}

#define PUTPW(b, id) \
	କର { \
		ଯଦି ((r = sshbuf_put_string(b, \
		    &pwent->id, ଆକାର(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} ଯେତେବେଳେ (0)

ଶୂନ୍ୟ
mm_encode_server_options(ସଂରଚନା sshbuf *m)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା sshbuf *config;

	ଯଦି ((config = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	ଯଦି ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_pwnamallow(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	ସଂରଚନା passwd *pwent;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	ଯଦି (!compat_set)
		fatal_f("state error: setcompat never called");

	ଯଦି (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	ଯଦି ((r = sshbuf_get_cstring(m, &authctxt->user, ଖାଲି)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	ଯଦି (pwent == ଖାଲି) {
		invalid_user = 1;
		ଯଦି ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		ଯାଅ out;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	/* XXX send fake class/dir/shell, etc. */
	ଯଦି ((r = sshbuf_put_u8(m, 1)) != 0)
		fatal_fr(r, "assemble ok");
	PUTPW(m, pw_uid);
	PUTPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(m, pw_expire);
#endif
	ଯଦି ((r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
	    (r = sshbuf_put_cstring(m, "*")) != 0 ||
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_put_cstring(m, pwent->pw_gecos)) != 0 ||
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_put_cstring(m, pwent->pw_class)) != 0 ||
#endif
	    (r = sshbuf_put_cstring(m, pwent->pw_dir)) != 0 ||
	    (r = sshbuf_put_cstring(m, pwent->pw_shell)) != 0)
		fatal_fr(r, "assemble pw");

 out:
	ssh_packet_set_log_preamble(ssh, "%suser %s",
	    authctxt->valid ? "authenticating" : "invalid ", authctxt->user);

	ଯଦି (options.refuse_connection) {
		logit("administratively prohibited connection for "
		    "%s%s from %.128s port %d",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user, ssh_remote_ipaddr(ssh),
		    ssh_remote_port(ssh));
		cleanup_exit(EXIT_CONFIG_REFUSED);
	}

	/* Send active options to unpriv */
	mm_encode_server_options(m);

	/* Create valid auth method lists */
	ଯଦି (auth2_setup_methods_lists(authctxt) != 0) {
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

#ifdef USE_PAM
	ଯଦି (options.use_pam)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_START, 1);
#endif

	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_answer_auth2_read_banner(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	ଅକ୍ଷର *banner;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	ଯଦି ((r = sshbuf_put_cstring(m, banner != ଖାଲି ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	ମୁକ୍ତ(banner);

	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_authserv(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	monitor_permit_authentications(1);

	ଯଦି ((r = sshbuf_get_cstring(m, &authctxt->service, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, ଖାଲି)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	ଯଦି (strlen(authctxt->style) == 0) {
		ମୁକ୍ତ(authctxt->style);
		authctxt->style = ଖାଲି;
	}

	ଫେରନ୍ତୁ (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ଚାବି_base_type_match(ଅଚଳ ଅକ୍ଷର *method, ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ ଅକ୍ଷର *list)
{
	ଅକ୍ଷର *s, *l, *ol = xstrdup(list);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା found = 0;

	l = ol;
	ପାଇଁ ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		ଯଦି (sshkey_type_from_name(s) == ଚାବି->type) {
			found = 1;
			ଭାଙ୍ଗ;
		}
	}
	ଯଦି (!found) {
		error("%s key type %s is not in permitted list %s", method,
		    sshkey_ssh_name(ଚାବି), list);
	}

	ମୁକ୍ତ(ol);
	ଫେରନ୍ତୁ found;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_authpassword(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା call_ଗଣନା;
	ଅକ୍ଷର *passwd;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, authenticated;
	size_t plen;

	ଯଦି (!options.password_authentication)
		fatal_f("password authentication not enabled");
	ଯଦି ((r = sshbuf_get_cstring(m, &passwd, &plen)) != 0)
		fatal_fr(r, "parse");
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(ssh, passwd);
	freezero(passwd, plen);

	sshbuf_reset(m);
	ଯଦି ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");
#ifdef USE_PAM
	ଯଦି ((r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0)
		fatal_fr(r, "assemble PAM");
#endif

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_ଗଣନା++;
	ଯଦି (plen == 0 && call_ଗଣନା == 1)
		auth_method = "none";
	ଅନ୍ୟଥା
		auth_method = "password";

	/* Causes monitor loop to terminate if authenticated */
	ଫେରନ୍ତୁ (authenticated);
}

#ifdef BSD_AUTH
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_bsdauthquery(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	ଅକ୍ଷର *name, *infotxt;
	u_int numprompts, *echo_on, success;
	ଅକ୍ଷର **prompts;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	success = bsdauth_query(authctxt, &name, &infotxt, &numprompts,
	    &prompts, &echo_on) < 0 ? 0 : 1;

	sshbuf_reset(m);
	ଯଦି ((r = sshbuf_put_u32(m, success)) != 0)
		fatal_fr(r, "assemble");
	ଯଦି (success) {
		ଯଦି ((r = sshbuf_put_cstring(m, prompts[0])) != 0)
			fatal_fr(r, "assemble prompt");
	}

	debug3_f("sending challenge success: %u", success);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHQUERY, m);

	ଯଦି (success) {
		ମୁକ୍ତ(name);
		ମୁକ୍ତ(infotxt);
		ମୁକ୍ତ(prompts);
		ମୁକ୍ତ(echo_on);
	}

	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_bsdauthrespond(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	ଅକ୍ଷର *response;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, authok;

	ଯଦି (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	ଯଦି (authctxt->as == ଖାଲି)
		fatal_f("no bsd auth session");

	ଯଦି ((r = sshbuf_get_cstring(m, &response, ଖାଲି)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = ଖାଲି;
	debug3_f("<%s> = <%d>", response, authok);
	ମୁକ୍ତ(response);

	sshbuf_reset(m);
	ଯଦି ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_method = "keyboard-interactive";
	auth_submethod = "bsdauth";

	ଫେରନ୍ତୁ (authok != 0);
}
#endif

#ifdef USE_PAM
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_pam_start(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	ଯଦି (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	start_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	ଯଦି (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_pam_account(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	u_int ret;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (!options.use_pam)
		fatal_f("PAM not enabled");

	ret = do_pam_account();

	ଯଦି ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "buffer error");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	ଫେରନ୍ତୁ (ret);
}

ସ୍ଥିର ଶୂନ୍ୟ *sshpam_ctxt, *sshpam_authok;
ବାହ୍ୟ KbdintDevice sshpam_device;

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_pam_init_ctx(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	u_int ok = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");
	ଯଦି (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	ଯଦି (sshpam_ctxt != ଖାଲି)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = ଖାଲି;
	sshbuf_reset(m);
	ଯଦି (sshpam_ctxt != ଖାଲି) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	ଯଦି ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_pam_query(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	ଅକ୍ଷର *name = ଖାଲି, *info = ଖାଲି, **prompts = ଖାଲି;
	u_int i, ଅଙ୍କ = 0, *echo_on = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret;

	debug3_f("entering");
	sshpam_authok = ଖାଲି;
	ଯଦି (sshpam_ctxt == ଖାଲି)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &ଅଙ୍କ, &prompts, &echo_on);
	ଯଦି (ret == 0 && ଅଙ୍କ == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	ଯଦି (ଅଙ୍କ > 1 || name == ଖାଲି || info == ଖାଲି)
		fatal("sshpam_device.query failed");
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_RESPOND, 1);
	sshbuf_reset(m);
	ଯଦି ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0 ||
	    (r = sshbuf_put_cstring(m, info)) != 0 ||
	    (r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0 ||
	    (r = sshbuf_put_u32(m, ଅଙ୍କ)) != 0)
		fatal_fr(r, "buffer error");
	ମୁକ୍ତ(name);
	ମୁକ୍ତ(info);
	ପାଇଁ (i = 0; i < ଅଙ୍କ; ++i) {
		ଯଦି ((r = sshbuf_put_cstring(m, prompts[i])) != 0 ||
		    (r = sshbuf_put_u32(m, echo_on[i])) != 0)
			fatal_fr(r, "buffer error");
		ମୁକ୍ତ(prompts[i]);
	}
	ମୁକ୍ତ(prompts);
	ମୁକ୍ତ(echo_on);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	mm_request_send(sock, MONITOR_ANS_PAM_QUERY, m);
	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_pam_respond(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	ଅକ୍ଷର **resp;
	u_int i, ଅଙ୍କ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret;

	debug3_f("entering");
	ଯଦି (sshpam_ctxt == ଖାଲି)
		fatal_f("no context");
	sshpam_authok = ଖାଲି;
	ଯଦି ((r = sshbuf_get_u32(m, &ଅଙ୍କ)) != 0)
		fatal_fr(r, "buffer error");
	ଯଦି (ଅଙ୍କ > PAM_MAX_ଅଙ୍କ_ସନ୍ଦେଶ) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    ଅଙ୍କ, (unsigned)PAM_MAX_ଅଙ୍କ_ସନ୍ଦେଶ);
	}
	ଯଦି (ଅଙ୍କ > 0) {
		resp = xcalloc(ଅଙ୍କ, ଆକାର(ଅକ୍ଷର *));
		ପାଇଁ (i = 0; i < ଅଙ୍କ; ++i) {
			ଯଦି ((r = sshbuf_get_cstring(m, &(resp[i]), ଖାଲି)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, ଅଙ୍କ, resp);
		ପାଇଁ (i = 0; i < ଅଙ୍କ; ++i)
			ମୁକ୍ତ(resp[i]);
		ମୁକ୍ତ(resp);
	} ଅନ୍ୟଥା {
		ret = (sshpam_device.respond)(sshpam_ctxt, ଅଙ୍କ, ଖାଲି);
	}
	sshbuf_reset(m);
	ଯଦି ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	ଯଦି (ret == 0)
		sshpam_authok = sshpam_ctxt;
	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_pam_free_ctx(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = sshpam_authok != ଖାଲି && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	ଯଦି (sshpam_ctxt == ଖାଲି)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = ଖାଲି;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	ଫେରନ୍ତୁ r;
}
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_keyallowed(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ଅକ୍ଷର *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, allowed = 0;
	ସଂରଚନା sshauthopt *opts = ଖାଲି;

	debug3_f("entering");
	ଯଦି ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, ଖାଲି)) != 0 ||
	    (r = sshkey_froms(m, &ଚାବି)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	ଯଦି (ଚାବି != ଖାଲି && authctxt->valid) {
		ବାଛ (type) {
		ସ୍ଥିତି MM_USERKEY:
			auth_method = "publickey";
			ଯଦି (!options.pubkey_authentication)
				ଭାଙ୍ଗ;
			ଯଦି (auth2_ଚାବି_already_used(authctxt, ଚାବି))
				ଭାଙ୍ଗ;
			ଯଦି (!ଚାବି_base_type_match(auth_method, ଚାବି,
			    options.pubkey_accepted_algos))
				ଭାଙ୍ଗ;
			allowed = user_ଚାବି_allowed(ssh, authctxt->pw, ଚାବି,
			    pubkey_auth_attempt, &opts);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି MM_HOSTKEY:
			auth_method = "hostbased";
			ଯଦି (!options.hostbased_authentication)
				ଭାଙ୍ଗ;
			ଯଦି (auth2_ଚାବି_already_used(authctxt, ଚାବି))
				ଭାଙ୍ଗ;
			ଯଦି (!ଚାବି_base_type_match(auth_method, ଚାବି,
			    options.hostbased_accepted_algos))
				ଭାଙ୍ଗ;
			allowed = hostbased_ଚାବି_allowed(ssh, authctxt->pw,
			    cuser, chost, ଚାବି);
			auth2_record_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			fatal_f("unknown key type %u", type);
			ଭାଙ୍ଗ;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_method,
	    pubkey_auth_attempt ? "" : " test",
	    (ଚାବି == ଖାଲି || !authctxt->valid) ? "invalid" : sshkey_type(ଚାବି),
	    allowed ? "allowed" : "not allowed");

	auth2_record_ଚାବି(authctxt, 0, ଚାବି);

	/* clear temporarily storage (used by verify) */
	monitor_reset_ଚାବି_state();

	ଯଦି (allowed) {
		/* Save temporarily for comparison in verify */
		ଯଦି ((r = sshkey_to_blob(ଚାବି, &ଚାବି_blob, &ଚାବି_bloblen)) != 0)
			fatal_fr(r, "sshkey_to_blob");
		ଚାବି_blobtype = type;
		ଚାବି_opts = opts;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} ଅନ୍ୟଥା {
		/* Log failed attempt */
		auth_log(ssh, 0, 0, auth_method, ଖାଲି);
		ମୁକ୍ତ(cuser);
		ମୁକ୍ତ(chost);
	}
	sshkey_free(ଚାବି);

	sshbuf_reset(m);
	ଯଦି ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	ଯଦି (opts != ଖାଲି && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	ଯଦି (!allowed)
		sshauthopt_free(opts);

	ଫେରନ୍ତୁ (0);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
monitor_valid_userblob(ସଂରଚନା ssh *ssh, ଅଚଳ u_char *data, u_int datalen)
{
	ସଂରଚନା sshbuf *b;
	ସଂରଚନା sshkey *hostkey = ଖାଲି;
	ଅଚଳ u_char *p;
	ଅକ୍ଷର *userstyle, *cp;
	size_t len;
	u_char type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା hostbound = 0, r, fail = 0;

	ଯଦି ((b = sshbuf_from(data, datalen)) == ଖାଲି)
		fatal_f("sshbuf_from");

	ଯଦି ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	ଯଦି ((session_id2 == ଖାଲି) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	ଯଦି ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ଯଦି (type != SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST)
		fail++;
	ଯଦି ((r = sshbuf_get_cstring(b, &cp, ଖାଲି)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	ଯଦି (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	ମୁକ୍ତ(userstyle);
	ମୁକ୍ତ(cp);
	ଯଦି ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, ଖାଲି)) != 0)
		fatal_fr(r, "parse method");
	ଯଦି (strcmp("publickey", cp) != 0) {
		ଯଦି (strcmp("publickey-hostbound-v00@openssh.com", cp) == 0)
			hostbound = 1;
		ଅନ୍ୟଥା
			fail++;
	}
	ମୁକ୍ତ(cp);
	ଯଦି ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse pktype");
	ଯଦି (type == 0)
		fail++;
	ଯଦି ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0 ||	/* pkblob */
	    (hostbound && (r = sshkey_froms(b, &hostkey)) != 0))
		fatal_fr(r, "parse pk");
	ଯଦି (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	ଯଦି (hostkey != ଖାଲି) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		ଯଦି (get_hostkey_index(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	ଫେରନ୍ତୁ (fail == 0);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
monitor_valid_hostbasedblob(ଅଚଳ u_char *data, u_int datalen,
    ଅଚଳ ଅକ୍ଷର *cuser, ଅଚଳ ଅକ୍ଷର *chost)
{
	ସଂରଚନା sshbuf *b;
	ଅଚଳ u_char *p;
	ଅକ୍ଷର *cp, *userstyle;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, fail = 0;
	u_char type;

	ଯଦି ((b = sshbuf_from(data, datalen)) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	ଯଦି ((session_id2 == ଖାଲି) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	ଯଦି ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ଯଦି (type != SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST)
		fail++;
	ଯଦି ((r = sshbuf_get_cstring(b, &cp, ଖାଲି)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	ଯଦି (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	ମୁକ୍ତ(userstyle);
	ମୁକ୍ତ(cp);
	ଯଦି ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, ଖାଲି)) != 0)
		fatal_fr(r, "parse method");
	ଯଦି (strcmp(cp, "hostbased") != 0)
		fail++;
	ମୁକ୍ତ(cp);
	ଯଦି ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	ଯଦି ((r = sshbuf_get_cstring(b, &cp, ଖାଲି)) != 0)
		fatal_fr(r, "parse host");
	ଯଦି (((len = strlen(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	ଯଦି (strcmp(cp, chost) != 0)
		fail++;
	ମୁକ୍ତ(cp);

	/* verify client user */
	ଯଦି ((r = sshbuf_get_cstring(b, &cp, ଖାଲି)) != 0)
		fatal_fr(r, "parse ruser");
	ଯଦି (strcmp(cp, cuser) != 0)
		fail++;
	ମୁକ୍ତ(cp);

	ଯଦି (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	ଫେରନ୍ତୁ (fail == 0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_keyverify(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	ସଂରଚନା sshkey *ଚାବି;
	ଅଚଳ u_char *signature, *data, *blob;
	ଅକ୍ଷର *sigalg = ଖାଲି, *fp = ଖାଲି;
	size_t signaturelen, datalen, bloblen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret, req_presence = 0, req_verify = 0, valid_data = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା encoded_ret;
	ସଂରଚନା sshkey_sig_details *sig_details = ଖାଲି;

	ଯଦି ((r = sshbuf_get_string_direct(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &data, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, ଖାଲି)) != 0)
		fatal_fr(r, "parse");

	ଯଦି (hostbased_cuser == ଖାଲି || hostbased_chost == ଖାଲି ||
	  !monitor_allowed_ଚାବି(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	ଯଦି (*sigalg == '\0') {
		ମୁକ୍ତ(sigalg);
		sigalg = ଖାଲି;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	ଯଦି ((r = sshkey_from_blob(blob, bloblen, &ଚାବି)) != 0)
		fatal_fr(r, "parse key");

	ବାଛ (ଚାବି_blobtype) {
	ସ୍ଥିତି MM_USERKEY:
		valid_data = monitor_valid_userblob(ssh, data, datalen);
		auth_method = "publickey";
		ଭାଙ୍ଗ;
	ସ୍ଥିତି MM_HOSTKEY:
		valid_data = monitor_valid_hostbasedblob(data, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_method = "hostbased";
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		valid_data = 0;
		ଭାଙ୍ଗ;
	}
	ଯଦି (!valid_data)
		fatal_f("bad %s signature data blob",
		    ଚାବି_blobtype == MM_USERKEY ? "userkey" :
		    (ଚାବି_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	ଯଦି ((fp = sshkey_fingerprint(ଚାବି, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ଖାଲି)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(ଚାବି, signature, signaturelen, data, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_method,
	    sshkey_type(ଚାବି), sigalg == ଖାଲି ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	ଯଦି (ret == 0 && ଚାବି_blobtype == MM_USERKEY && sig_details != ଖାଲି) {
		req_presence = (options.pubkey_auth_options &
		    PUBKEYAUTH_TOUCH_REQUIRED) ||
		    !ଚାବି_opts->no_require_user_presence;
		ଯଦି (req_presence &&
		    (sig_details->sk_flags & SSH_SK_USER_PRESENCE_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user presence "
			    "(authenticator touch) requirement not met ",
			    sshkey_type(ଚାବି), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
		req_verify = (options.pubkey_auth_options &
		    PUBKEYAUTH_VERIFY_REQUIRED) || ଚାବି_opts->require_verify;
		ଯଦି (req_verify &&
		    (sig_details->sk_flags & SSH_SK_USER_VERIFICATION_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user verification requirement "
			    "not met ", sshkey_type(ଚାବି), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
	}
	auth2_record_ଚାବି(authctxt, ret == 0, ଚାବି);

	ଯଦି (ଚାବି_blobtype == MM_USERKEY && ret == 0)
		auth_activate_options(ssh, ଚାବି_opts);
	monitor_reset_ଚାବି_state();

	sshbuf_reset(m);

	/* encode ret != 0 as positive integer, since we're sending u32 */
	encoded_ret = (ret != 0);
	ଯଦି ((r = sshbuf_put_u32(m, encoded_ret)) != 0 ||
	    (r = sshbuf_put_u8(m, sig_details != ଖାଲି)) != 0)
		fatal_fr(r, "assemble");
	ଯଦି (sig_details != ଖାଲି) {
		ଯଦି ((r = sshbuf_put_u32(m, sig_details->sk_counter)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	ମୁକ୍ତ(sigalg);
	ମୁକ୍ତ(fp);
	sshkey_free(ଚାବି);

	ଫେରନ୍ତୁ ret == 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
mm_record_login(ସଂରଚନା ssh *ssh, Session *s, ସଂରଚନା passwd *pw)
{
	socklen_t fromlen;
	ସଂରଚନା sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, ଆକାର(from));
	fromlen = ଆକାର(from);
	ଯଦି (ssh_packet_connection_is_on_socket(ssh)) {
		ଯଦି (getpeername(ssh_packet_get_connection_in(ssh),
		    (ସଂରଚନା sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	record_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (ସଂରଚନା sockaddr *)&from, fromlen);
}

ସ୍ଥିର ଶୂନ୍ୟ
mm_session_close(Session *s)
{
	debug3_f("session %d pid %ld", s->self, (long)s->pid);
	ଯଦି (s->ttyfd != -1) {
		debug3_f("tty %s ptyfd %d", s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_unused(s->self);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_pty(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	ବାହ୍ୟ ସଂରଚନା monitor *pmonitor;
	Session *s;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	ଯଦି (s == ଖାଲି)
		ଯାଅ error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, ଆକାର(s->tty));
	ଯଦି (res == 0)
		ଯାଅ error;
	pty_setowner(authctxt->pw, s->tty);

	ଯଦି ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");

	/* We need to trick ttyslot */
	ଯଦି (dup2(s->ttyfd, 0) == -1)
		fatal_f("dup2");

	mm_record_login(ssh, s, authctxt->pw);

	/* Now we can close the file descriptor again */
	close(0);

	/* send messages generated by record_login */
	ଯଦି ((r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "assemble loginmsg");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PTY, m);

	ଯଦି (mm_send_fd(sock, s->ptyfd) == -1 ||
	    mm_send_fd(sock, s->ttyfd) == -1)
		fatal_f("send fds failed");

	/* make sure nothing uses fd 0 */
	ଯଦି ((fd0 = open(_PATH_DEVNULL, O_RDONLY)) == -1)
		fatal_f("open(/dev/null): %s", strerror(errno));
	ଯଦି (fd0 != 0)
		error_f("fd0 %d != 0", fd0);

	/* slave side of pty is not needed */
	close(s->ttyfd);
	s->ttyfd = s->ptyfd;
	/* no need to dup() because nobody closes ptyfd */
	s->ptymaster = s->ptyfd;

	debug3_f("tty %s ptyfd %d", s->tty, s->ttyfd);

	ଫେରନ୍ତୁ (0);

 error:
	ଯଦି (s != ଖାଲି)
		mm_session_close(s);
	ଯଦି ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_pty_cleanup(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	Session *s;
	ଅକ୍ଷର *tty;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");

	ଯଦି ((r = sshbuf_get_cstring(m, &tty, ଖାଲି)) != 0)
		fatal_fr(r, "parse tty");
	ଯଦି ((s = session_by_tty(tty)) != ଖାଲି)
		mm_session_close(s);
	sshbuf_reset(m);
	ମୁକ୍ତ(tty);
	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_term(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *req)
{
	ବାହ୍ୟ ସଂରଚନା monitor *pmonitor;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା res, status;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#ifdef USE_PAM
	ଯଦି (options.use_pam)
		sshpam_cleanup();
#endif

	ଯେତେବେଳେ (waitpid(pmonitor->m_pid, &status, 0) == -1)
		ଯଦି (errno != EINTR)
			exit(1);

	res = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

	/* Terminate process */
	exit(res);
}

#ifdef SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_audit_event(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା socket, ସଂରଚନା sshbuf *m)
{
	u_int n;
	ssh_audit_event_t event;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");

	ଯଦି ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	event = (ssh_audit_event_t)n;
	ବାଛ (event) {
	ସ୍ଥିତି SSH_AUTH_FAIL_PUBKEY:
	ସ୍ଥିତି SSH_AUTH_FAIL_HOSTBASED:
	ସ୍ଥିତି SSH_AUTH_FAIL_GSSAPI:
	ସ୍ଥିତି SSH_LOGIN_EXCEED_MAXTRIES:
	ସ୍ଥିତି SSH_LOGIN_ମୂଳ_DENIED:
	ସ୍ଥିତି SSH_CONNECTION_CLOSE:
	ସ୍ଥିତି SSH_INVALID_USER:
		audit_event(ssh, event);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal("Audit event type %d not permitted", event);
	}

	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_audit_command(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା socket, ସଂରଚନା sshbuf *m)
{
	ଅକ୍ଷର *cmd;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");
	ଯଦି ((r = sshbuf_get_cstring(m, &cmd, ଖାଲି)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_run_command(cmd);
	ମୁକ୍ତ(cmd);
	ଫେରନ୍ତୁ (0);
}
#endif /* SSH_AUDIT_EVENTS */

ଶୂନ୍ୟ
monitor_clear_keystate(ସଂରଚନା ssh *ssh, ସଂରଚନା monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, MODE_IN);
	ssh_clear_newkeys(ssh, MODE_OUT);
	sshbuf_free(child_state);
	child_state = ଖାଲି;
}

ଶୂନ୍ୟ
monitor_apply_keystate(ସଂରଚନା ssh *ssh, ସଂରଚନା monitor *pmonitor)
{
	ସଂରଚନା kex *kex;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("packet_set_state");
	ଯଦି ((r = ssh_packet_set_state(ssh, child_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(child_state);
	child_state = ଖାଲି;
	ଯଦି ((kex = ssh->kex) == ଖାଲି)
		fatal_f("internal error: ssh->kex == NULL");
	ଯଦି (session_id2_len != sshbuf_len(ssh->kex->session_id)) {
		fatal_f("incorrect session id length %zu (expected %u)",
		    sshbuf_len(ssh->kex->session_id), session_id2_len);
	}
	ଯଦି (memcmp(sshbuf_ptr(ssh->kex->session_id), session_id2,
	    session_id2_len) != 0)
		fatal_f("session ID mismatch");
	/* XXX set callbacks */
#ifdef WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#endif
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->load_host_public_ଚାବି=&get_hostkey_public_by_type;
	kex->load_host_private_ଚାବି=&get_hostkey_private_by_type;
	kex->host_ଚାବି_index=&get_hostkey_index;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

ଶୂନ୍ୟ
mm_get_keystate(ସଂରଚନା ssh *ssh, ସଂରଚନା monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	ଯଦି ((child_state = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    child_state);
	debug3_f("GOT new keys");
}


/* XXX */

ସ୍ଥିର ଶୂନ୍ୟ
monitor_openfds(ସଂରଚନା monitor *mon, ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_logfds)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା pair[2];
#ifdef SO_ZEROIZE
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା on = 1;
#endif

	ଯଦି (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", strerror(errno));
#ifdef SO_ZEROIZE
	ଯଦି (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, ଆକାର(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", strerror(errno));
	ଯଦି (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, ଆକାର(on)) == -1)
		error("setsockopt SO_ZEROIZE(1): %.100s", strerror(errno));
#endif
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
	mon->m_recvfd = pair[0];
	mon->m_sendfd = pair[1];

	ଯଦି (do_logfds) {
		ଯଦି (pipe(pair) == -1)
			fatal_f("pipe: %s", strerror(errno));
		FD_CLOSEONEXEC(pair[0]);
		FD_CLOSEONEXEC(pair[1]);
		mon->m_log_recvfd = pair[0];
		mon->m_log_sendfd = pair[1];
	} ଅନ୍ୟଥା
		mon->m_log_recvfd = mon->m_log_sendfd = -1;
}

ସଂରଚନା monitor *
monitor_init(ଶୂନ୍ୟ)
{
	ସଂରଚନା monitor *mon;

	mon = xcalloc(1, ଆକାର(*mon));
	monitor_openfds(mon, 1);

	ଫେରନ୍ତୁ mon;
}

ଶୂନ୍ୟ
monitor_reinit(ସଂରଚନା monitor *mon)
{
	monitor_openfds(mon, 0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
monitor_auth_attempted(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ auth_attempted;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
monitor_invalid_user(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ invalid_user;
}

#ifdef GSSAPI
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_gss_setup_ctx(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	size_t len;
	u_char *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	ଯଦି ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.length = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	ମୁକ୍ତ(goid.elements);

	sshbuf_reset(m);
	ଯଦି ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_gss_accept_ctx(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	gss_buffer_desc in;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ଯଦି ((r = ssh_gssapi_get_buffer_desc(m, &in)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &in, &out, &flags);
	ମୁକ୍ତ(in.ମୂଲ୍ୟ);

	sshbuf_reset(m);
	ଯଦି ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, out.ମୂଲ୍ୟ, out.length)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_buffer(&minor, &out);

	ଯଦି (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_gss_checkmic(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	gss_buffer_desc gssbuf, mic;
	OM_uint32 ret;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ଯଦି ((r = ssh_gssapi_get_buffer_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, &mic)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	ମୁକ୍ତ(gssbuf.ମୂଲ୍ୟ);
	ମୁକ୍ତ(mic.ମୂଲ୍ୟ);

	sshbuf_reset(m);
	ଯଦି ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	ଯଦି (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_answer_gss_userok(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *m)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, authenticated;
	ଅଚଳ ଅକ୍ଷର *displayname;

	ଯଦି (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	ଯଦି ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_method = "gssapi-with-mic";

	ଯଦି ((displayname = ssh_gssapi_displayname()) != ଖାଲି)
		auth2_record_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	ଫେରନ୍ତୁ (authenticated);
}
#endif /* GSSAPI */

