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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ AUTH_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AUTH_H

#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_CAP
#ਅਨ੍ਤਰ੍ਭਾਵ <login_cap.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BSD_AUTH
#ਅਨ੍ਤਰ੍ਭਾਵ <bsd_auth.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ KRB5
#ਅਨ੍ਤਰ੍ਭਾਵ <krb5.h>
#ਜੇ_ਅੰਤ

ਬਣਤਰ passwd;
ਬਣਤਰ ssh;
ਬਣਤਰ sshbuf;
ਬਣਤਰ sshkey;
ਬਣਤਰ sshkey_cert;
ਬਣਤਰ sshauthopt;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ Authctxt Authctxt;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ Authmethod Authmethod;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ KbdintDevice KbdintDevice;

ਬਣਤਰ Authctxt {
	sig_atomic_t	 success;
	ਪੂਰਨ		 authenticated;	/* authenticated and alarms cancelled */
	ਪੂਰਨ		 postponed;	/* authentication needs another step */
	ਪੂਰਨ		 valid;		/* user exists and is allowed to login */
	ਪੂਰਨ		 attempt;
	ਪੂਰਨ		 failures;
	ਪੂਰਨ		 pk_ok_failures;
	ਪੂਰਨ		 auth_failure_already_counted;
	ਪੂਰਨ		 server_caused_failure;
	ਪੂਰਨ		 force_pwchange;
	ਅੱਖਰ		*user;		/* username sent by the client */
	ਅੱਖਰ		*service;
	ਬਣਤਰ passwd	*pw;		/* set if 'valid' */
	ਅੱਖਰ		*style;

	/* Method lists for multiple authentication */
	ਅੱਖਰ		**auth_methods;	/* modified from server config */
	u_int		 ਅੰਕ_auth_methods;

	/* Authentication method-specific data */
	ਖਾਲੀ		*methoddata;
	ਖਾਲੀ		*kbdintctxt;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BSD_AUTH
	auth_session_t	*as;
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ KRB5
	krb5_context	 krb5_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	ਅੱਖਰ		*krb5_ticket_file;
	ਅੱਖਰ		*krb5_ccname;
#ਜੇ_ਅੰਤ
	ਬਣਤਰ sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	ਬਣਤਰ sshkey	**prev_ਕੁੰਜੀਆਂ;
	u_int		 nprev_ਕੁੰਜੀਆਂ;

	/* Last used key and ancillary information from active auth method */
	ਬਣਤਰ sshkey	*auth_ਵਿਧੀ_ਕੁੰਜੀ;
	ਅੱਖਰ		*auth_ਵਿਧੀ_info;

	/* Information exposed to session */
	ਬਣਤਰ sshbuf	*session_info;	/* Auth info for environment */
};

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

ਬਣਤਰ authmethod_cfg {
	ਅਚਲ ਅੱਖਰ *name;
	ਅਚਲ ਅੱਖਰ *synonym;
	ਪੂਰਨ *enabled;
};

ਬਣਤਰ Authmethod {
	ਬਣਤਰ authmethod_cfg *cfg;
	ਪੂਰਨ	(*userauth)(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *);
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
ਬਣਤਰ KbdintDevice
{
	ਅਚਲ ਅੱਖਰ *name;
	ਖਾਲੀ*	(*init_ctx)(Authctxt*);
	ਪੂਰਨ	(*query)(ਖਾਲੀ *ctx, ਅੱਖਰ **name, ਅੱਖਰ **infotxt,
		    u_int *numprompts, ਅੱਖਰ ***prompts, u_int **echo_on);
	ਪੂਰਨ	(*respond)(ਖਾਲੀ *ctx, u_int numresp, ਅੱਖਰ **responses);
	ਖਾਲੀ	(*free_ctx)(ਖਾਲੀ *ctx);
};

ਪੂਰਨ
auth_rhosts2(ਬਣਤਰ passwd *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);

ਪੂਰਨ      auth_password(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *);

ਪੂਰਨ	 hostbased_ਕੁੰਜੀ_allowed(ਬਣਤਰ ssh *, ਬਣਤਰ passwd *,
	    ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ *, ਬਣਤਰ sshkey *);
ਪੂਰਨ	 user_ਕੁੰਜੀ_allowed(ਬਣਤਰ ssh *ssh, ਬਣਤਰ passwd *, ਬਣਤਰ sshkey *,
    ਪੂਰਨ, ਬਣਤਰ sshauthopt **);
ਪੂਰਨ	 auth2_ਕੁੰਜੀ_already_ਵਰਤਿਆ(Authctxt *, ਅਚਲ ਬਣਤਰ sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
ਖਾਲੀ	 auth2_authctxt_reset_info(Authctxt *);
ਖਾਲੀ	 auth2_ਰਿਕਾਰਡ_ਕੁੰਜੀ(Authctxt *, ਪੂਰਨ, ਅਚਲ ਬਣਤਰ sshkey *);
ਖਾਲੀ	 auth2_ਰਿਕਾਰਡ_info(Authctxt *authctxt, ਅਚਲ ਅੱਖਰ *, ...)
	    __attribute__((__format__ (ਲਿਖੋ, 2, 3)))
	    __attribute__((__nonnull__ (2)));
ਖਾਲੀ	 auth2_update_session_info(Authctxt *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ KRB5
ਪੂਰਨ	auth_krb5_password(Authctxt *authctxt, ਅਚਲ ਅੱਖਰ *password);
ਖਾਲੀ	krb5_cleanup_proc(Authctxt *authctxt);
#ਜੇ_ਅੰਤ /* KRB5 */

#ਜੇ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#ਅਨ੍ਤਰ੍ਭਾਵ <shadow.h>
ਪੂਰਨ auth_shadow_acctexpired(ਬਣਤਰ spwd *);
ਪੂਰਨ auth_shadow_pwexpired(Authctxt *);
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "auth-pam.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "audit.h"
ਖਾਲੀ remove_kbdint_device(ਅਚਲ ਅੱਖਰ *);

ਖਾਲੀ	do_authentication2(ਬਣਤਰ ssh *);

ਖਾਲੀ	auth_log(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ	auth_maxtries_exceeded(ਬਣਤਰ ssh *) __attribute__((noreturn));
ਖਾਲੀ	userauth_ਅੰਤ(ਬਣਤਰ ssh *, ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	auth_ਜੜ੍ਹ_allowed(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ	auth_failure_delay(Authctxt *, ਦੁੱਗਣਾ);

ਅੱਖਰ	*auth2_read_banner(ਖਾਲੀ);
ਪੂਰਨ	 auth2_methods_valid(ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);
ਪੂਰਨ	 auth2_update_methods_lists(Authctxt *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 auth2_ਤਿਆਰੀ_methods_lists(Authctxt *);
ਪੂਰਨ	 auth2_ਵਿਧੀ_allowed(Authctxt *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);

ਪੂਰਨ	auth2_challenge(ਬਣਤਰ ssh *, ਅੱਖਰ *);
ਖਾਲੀ	auth2_challenge_stop(ਬਣਤਰ ssh *);
ਪੂਰਨ	bsdauth_query(ਖਾਲੀ *, ਅੱਖਰ **, ਅੱਖਰ **, u_int *, ਅੱਖਰ ***, u_int **);
ਪੂਰਨ	bsdauth_respond(ਖਾਲੀ *, u_int, ਅੱਖਰ **);

ਪੂਰਨ	allowed_user(ਬਣਤਰ ssh *, ਬਣਤਰ passwd *);
ਬਣਤਰ passwd * getpwnamallow(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *user);

ਅੱਖਰ	*expand_authorized_ਕੁੰਜੀਆਂ(ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ passwd *pw);
ਅੱਖਰ	*authorized_principals_file(ਬਣਤਰ passwd *);

ਪੂਰਨ	 auth_ਕੁੰਜੀ_is_revoked(ਬਣਤਰ sshkey *);

ਅਚਲ ਅੱਖਰ	*auth_get_canonical_hostname(ਬਣਤਰ ssh *, ਪੂਰਨ);

Host_ਸਥਿਤੀ
check_ਕੁੰਜੀ_ਵਿੱਚ_hostfiles(ਬਣਤਰ passwd *, ਬਣਤਰ sshkey *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);

/* hostkey handling */
ਬਣਤਰ sshkey	*get_hostkey_by_ਸੂਚਕਾਂਕ(ਪੂਰਨ);
ਬਣਤਰ sshkey	*get_hostkey_ਜਨਤਕ_by_ਸੂਚਕਾਂਕ(ਪੂਰਨ, ਬਣਤਰ ssh *);
ਬਣਤਰ sshkey	*get_hostkey_ਜਨਤਕ_by_type(ਪੂਰਨ, ਪੂਰਨ, ਬਣਤਰ ssh *);
ਬਣਤਰ sshkey	*get_hostkey_ਨਿੱਜੀ_by_type(ਪੂਰਨ, ਪੂਰਨ, ਬਣਤਰ ssh *);
ਪੂਰਨ	 get_hostkey_ਸੂਚਕਾਂਕ(ਬਣਤਰ sshkey *, ਪੂਰਨ, ਬਣਤਰ ssh *);
ਪੂਰਨ	 sshd_hostkey_sign(ਬਣਤਰ ssh *, ਬਣਤਰ sshkey *, ਬਣਤਰ sshkey *,
    u_char **, ਮਾਪ_t *, ਅਚਲ u_char *, ਮਾਪ_t, ਅਚਲ ਅੱਖਰ *);

/* Key / cert options linkage to auth layer */
ਪੂਰਨ	 auth_activate_options(ਬਣਤਰ ssh *, ਬਣਤਰ sshauthopt *);
ਖਾਲੀ	 auth_restrict_session(ਬਣਤਰ ssh *);
ਖਾਲੀ	 auth_log_authopts(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਬਣਤਰ sshauthopt *, ਪੂਰਨ);

/* debug messages during authentication */
ਖਾਲੀ	 auth_debug_ਜੋੜੋ(ਅਚਲ ਅੱਖਰ *fmt,...)
    __attribute__((format(ਲਿਖੋ, 1, 2)));
ਖਾਲੀ	 auth_debug_send(ਬਣਤਰ ssh *);
ਖਾਲੀ	 auth_debug_reset(ਖਾਲੀ);

ਬਣਤਰ passwd *fakepw(ਖਾਲੀ);

/* auth2-pubkeyfile.c */
ਪੂਰਨ	 auth_authorise_keyopts(ਬਣਤਰ passwd *, ਬਣਤਰ sshauthopt *, ਪੂਰਨ,
    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 auth_check_principals_ਸਤਰ(ਅੱਖਰ *, ਅਚਲ ਬਣਤਰ sshkey_cert *,
    ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sshauthopt **);
ਪੂਰਨ	 auth_process_principals(FILE *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਬਣਤਰ sshkey_cert *, ਬਣਤਰ sshauthopt **);
ਪੂਰਨ	 auth_check_authkey_ਸਤਰ(ਬਣਤਰ passwd *, ਬਣਤਰ sshkey *,
    ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sshauthopt **);
ਪੂਰਨ	 auth_check_authkeys_file(ਬਣਤਰ passwd *, FILE *, ਅੱਖਰ *,
    ਬਣਤਰ sshkey *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sshauthopt **);
FILE	*auth_openkeyfile(ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ passwd *, ਪੂਰਨ);
FILE	*auth_openprincipals(ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ passwd *, ਪੂਰਨ);

ਪੂਰਨ	 sys_auth_passwd(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *);

#ਜੇ defined(KRB5) && !defined(HEIMDAL)
krb5_error_ਕੋਡ ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ /* AUTH_H */
