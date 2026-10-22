/* $OpenBSD: auth.h,v 1.111 2026/09/16 00:16:52 djm Exp $ */

/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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
 *
 */

#ifndef AUTH_H
#define AUTH_H

#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdio.h>

#ifdef HAVE_LOGIN_CAP
#અન્તર્ભાવ <login_cap.h>
#endif
#ifdef BSD_AUTH
#અન્તર્ભાવ <bsd_auth.h>
#endif
#ifdef KRB5
#અન્તર્ભાવ <krb5.h>
#endif

સંરચના passwd;
સંરચના ssh;
સંરચના sshbuf;
સંરચના sshkey;
સંરચના sshkey_cert;
સંરચના sshauthopt;

પ્રકારવ્યાખ્યા સંરચના Authctxt Authctxt;
પ્રકારવ્યાખ્યા સંરચના Authmethod Authmethod;
પ્રકારવ્યાખ્યા સંરચના KbdintDevice KbdintDevice;

સંરચના Authctxt {
	sig_atomic_t	 success;
	પૂર્ણાંક		 authenticated;	/* authenticated and alarms cancelled */
	પૂર્ણાંક		 postponed;	/* authentication needs another step */
	પૂર્ણાંક		 valid;		/* user exists and is allowed to login */
	પૂર્ણાંક		 attempt;
	પૂર્ણાંક		 failures;
	પૂર્ણાંક		 pk_ok_failures;
	પૂર્ણાંક		 auth_failure_already_counted;
	પૂર્ણાંક		 server_caused_failure;
	પૂર્ણાંક		 force_pwchange;
	અક્ષર		*user;		/* username sent by the client */
	અક્ષર		*service;
	સંરચના passwd	*pw;		/* set if 'valid' */
	અક્ષર		*style;

	/* Method lists for multiple authentication */
	અક્ષર		**auth_methods;	/* modified from server config */
	u_int		 અંક_auth_methods;

	/* Authentication method-specific data */
	શૂન્ય		*methoddata;
	શૂન્ય		*kbdintctxt;
#ifdef BSD_AUTH
	auth_session_t	*as;
#endif
#ifdef KRB5
	krb5_context	 krb5_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	અક્ષર		*krb5_ticket_file;
	અક્ષર		*krb5_ccname;
#endif
	સંરચના sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	સંરચના sshkey	**prev_ચાવીઓ;
	u_int		 nprev_ચાવીઓ;

	/* Last used key and ancillary information from active auth method */
	સંરચના sshkey	*auth_method_ચાવી;
	અક્ષર		*auth_method_info;

	/* Information exposed to session */
	સંરચના sshbuf	*session_info;	/* Auth info for environment */
};

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

સંરચના authmethod_cfg {
	અચલ અક્ષર *name;
	અચલ અક્ષર *synonym;
	પૂર્ણાંક *enabled;
};

સંરચના Authmethod {
	સંરચના authmethod_cfg *cfg;
	પૂર્ણાંક	(*userauth)(સંરચના ssh *, અચલ અક્ષર *);
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
સંરચના KbdintDevice
{
	અચલ અક્ષર *name;
	શૂન્ય*	(*init_ctx)(Authctxt*);
	પૂર્ણાંક	(*query)(શૂન્ય *ctx, અક્ષર **name, અક્ષર **infotxt,
		    u_int *numprompts, અક્ષર ***prompts, u_int **echo_on);
	પૂર્ણાંક	(*respond)(શૂન્ય *ctx, u_int numresp, અક્ષર **responses);
	શૂન્ય	(*free_ctx)(શૂન્ય *ctx);
};

પૂર્ણાંક
auth_rhosts2(સંરચના passwd *, અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *);

પૂર્ણાંક      auth_password(સંરચના ssh *, અચલ અક્ષર *);

પૂર્ણાંક	 hostbased_ચાવી_allowed(સંરચના ssh *, સંરચના passwd *,
	    અચલ અક્ષર *, અક્ષર *, સંરચના sshkey *);
પૂર્ણાંક	 user_ચાવી_allowed(સંરચના ssh *ssh, સંરચના passwd *, સંરચના sshkey *,
    પૂર્ણાંક, સંરચના sshauthopt **);
પૂર્ણાંક	 auth2_ચાવી_already_used(Authctxt *, અચલ સંરચના sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
શૂન્ય	 auth2_authctxt_reset_info(Authctxt *);
શૂન્ય	 auth2_record_ચાવી(Authctxt *, પૂર્ણાંક, અચલ સંરચના sshkey *);
શૂન્ય	 auth2_record_info(Authctxt *authctxt, અચલ અક્ષર *, ...)
	    __attribute__((__format__ (printf, 2, 3)))
	    __attribute__((__nonnull__ (2)));
શૂન્ય	 auth2_update_session_info(Authctxt *, અચલ અક્ષર *, અચલ અક્ષર *);

#ifdef KRB5
પૂર્ણાંક	auth_krb5_password(Authctxt *authctxt, અચલ અક્ષર *password);
શૂન્ય	krb5_cleanup_proc(Authctxt *authctxt);
#endif /* KRB5 */

#જો defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#અન્તર્ભાવ <shadow.h>
પૂર્ણાંક auth_shadow_acctexpired(સંરચના spwd *);
પૂર્ણાંક auth_shadow_pwexpired(Authctxt *);
#endif

#અન્તર્ભાવ "auth-pam.h"
#અન્તર્ભાવ "audit.h"
શૂન્ય remove_kbdint_device(અચલ અક્ષર *);

શૂન્ય	do_authentication2(સંરચના ssh *);

શૂન્ય	auth_log(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક, અચલ અક્ષર *, અચલ અક્ષર *);
શૂન્ય	auth_maxtries_exceeded(સંરચના ssh *) __attribute__((noreturn));
શૂન્ય	userauth_finish(સંરચના ssh *, પૂર્ણાંક, અચલ અક્ષર *, અચલ અક્ષર *);
પૂર્ણાંક	auth_મૂળ_allowed(સંરચના ssh *, અચલ અક્ષર *);
શૂન્ય	auth_failure_delay(Authctxt *, દ્વિગુણ);

અક્ષર	*auth2_read_banner(શૂન્ય);
પૂર્ણાંક	 auth2_methods_valid(અચલ અક્ષર *, પૂર્ણાંક);
પૂર્ણાંક	 auth2_update_methods_lists(Authctxt *, અચલ અક્ષર *, અચલ અક્ષર *);
પૂર્ણાંક	 auth2_setup_methods_lists(Authctxt *);
પૂર્ણાંક	 auth2_method_allowed(Authctxt *, અચલ અક્ષર *, અચલ અક્ષર *);

પૂર્ણાંક	auth2_challenge(સંરચના ssh *, અક્ષર *);
શૂન્ય	auth2_challenge_stop(સંરચના ssh *);
પૂર્ણાંક	bsdauth_query(શૂન્ય *, અક્ષર **, અક્ષર **, u_int *, અક્ષર ***, u_int **);
પૂર્ણાંક	bsdauth_respond(શૂન્ય *, u_int, અક્ષર **);

પૂર્ણાંક	allowed_user(સંરચના ssh *, સંરચના passwd *);
સંરચના passwd * getpwnamallow(સંરચના ssh *, અચલ અક્ષર *user);

અક્ષર	*expand_authorized_ચાવીઓ(અચલ અક્ષર *, સંરચના passwd *pw);
અક્ષર	*authorized_principals_file(સંરચના passwd *);

પૂર્ણાંક	 auth_ચાવી_is_revoked(સંરચના sshkey *);

અચલ અક્ષર	*auth_get_canonical_hostname(સંરચના ssh *, પૂર્ણાંક);

HostStatus
check_ચાવી_in_hostfiles(સંરચના passwd *, સંરચના sshkey *, અચલ અક્ષર *,
    અચલ અક્ષર *, અચલ અક્ષર *);

/* hostkey handling */
સંરચના sshkey	*get_hostkey_by_index(પૂર્ણાંક);
સંરચના sshkey	*get_hostkey_public_by_index(પૂર્ણાંક, સંરચના ssh *);
સંરચના sshkey	*get_hostkey_public_by_type(પૂર્ણાંક, પૂર્ણાંક, સંરચના ssh *);
સંરચના sshkey	*get_hostkey_private_by_type(પૂર્ણાંક, પૂર્ણાંક, સંરચના ssh *);
પૂર્ણાંક	 get_hostkey_index(સંરચના sshkey *, પૂર્ણાંક, સંરચના ssh *);
પૂર્ણાંક	 sshd_hostkey_sign(સંરચના ssh *, સંરચના sshkey *, સંરચના sshkey *,
    u_char **, size_t *, અચલ u_char *, size_t, અચલ અક્ષર *);

/* Key / cert options linkage to auth layer */
પૂર્ણાંક	 auth_activate_options(સંરચના ssh *, સંરચના sshauthopt *);
શૂન્ય	 auth_restrict_session(સંરચના ssh *);
શૂન્ય	 auth_log_authopts(અચલ અક્ષર *, અચલ સંરચના sshauthopt *, પૂર્ણાંક);

/* debug messages during authentication */
શૂન્ય	 auth_debug_add(અચલ અક્ષર *fmt,...)
    __attribute__((format(printf, 1, 2)));
શૂન્ય	 auth_debug_send(સંરચના ssh *);
શૂન્ય	 auth_debug_reset(શૂન્ય);

સંરચના passwd *fakepw(શૂન્ય);

/* auth2-pubkeyfile.c */
પૂર્ણાંક	 auth_authorise_keyopts(સંરચના passwd *, સંરચના sshauthopt *, પૂર્ણાંક,
    અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *);
પૂર્ણાંક	 auth_check_principals_લીટી(અક્ષર *, અચલ સંરચના sshkey_cert *,
    અચલ અક્ષર *, સંરચના sshauthopt **);
પૂર્ણાંક	 auth_process_principals(FILE *, અચલ અક્ષર *,
    અચલ સંરચના sshkey_cert *, સંરચના sshauthopt **);
પૂર્ણાંક	 auth_check_authkey_લીટી(સંરચના passwd *, સંરચના sshkey *,
    અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *, સંરચના sshauthopt **);
પૂર્ણાંક	 auth_check_authkeys_file(સંરચના passwd *, FILE *, અક્ષર *,
    સંરચના sshkey *, અચલ અક્ષર *, અચલ અક્ષર *, સંરચના sshauthopt **);
FILE	*auth_openkeyfile(અચલ અક્ષર *, સંરચના passwd *, પૂર્ણાંક);
FILE	*auth_openprincipals(અચલ અક્ષર *, સંરચના passwd *, પૂર્ણાંક);

પૂર્ણાંક	 sys_auth_passwd(સંરચના ssh *, અચલ અક્ષર *);

#જો defined(KRB5) && !defined(HEIMDAL)
krb5_error_code ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#endif

#endif /* AUTH_H */
