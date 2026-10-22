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

#اگر_غیر_تعریف_شدہ AUTH_H
#تعریف_کرو AUTH_H

#شامل <signal.h>
#شامل <stdio.h>

#اگر_تعریف_شدہ HAVE_LOGIN_CAP
#شامل <login_cap.h>
#اگر_ختم
#اگر_تعریف_شدہ BSD_AUTH
#شامل <bsd_auth.h>
#اگر_ختم
#اگر_تعریف_شدہ KRB5
#شامل <krb5.h>
#اگر_ختم

ساخت passwd;
ساخت ssh;
ساخت sshbuf;
ساخت sshkey;
ساخت sshkey_cert;
ساخت sshauthopt;

قسمتعریف ساخت Authctxt Authctxt;
قسمتعریف ساخت Authmethod Authmethod;
قسمتعریف ساخت KbdintDevice KbdintDevice;

ساخت Authctxt {
	sig_atomic_t	 success;
	صحیح		 authenticated;	/* authenticated and alarms cancelled */
	صحیح		 postponed;	/* authentication needs another step */
	صحیح		 valid;		/* user exists and is allowed to login */
	صحیح		 attempt;
	صحیح		 failures;
	صحیح		 pk_ok_failures;
	صحیح		 auth_failure_already_counted;
	صحیح		 server_caused_failure;
	صحیح		 force_pwchange;
	حرف		*user;		/* username sent by the client */
	حرف		*service;
	ساخت passwd	*pw;		/* set if 'valid' */
	حرف		*style;

	/* Method lists for multiple authentication */
	حرف		**auth_methods;	/* modified from server config */
	u_int		 عدد_auth_methods;

	/* Authentication method-specific data */
	خالی		*methoddata;
	خالی		*kbdintctxt;
#اگر_تعریف_شدہ BSD_AUTH
	auth_session_t	*as;
#اگر_ختم
#اگر_تعریف_شدہ KRB5
	krb5_context	 krb5_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	حرف		*krb5_ticket_file;
	حرف		*krb5_ccname;
#اگر_ختم
	ساخت sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	ساخت sshkey	**پچھلا_کلیدیں;
	u_int		 nprev_کلیدیں;

	/* Last used key and ancillary information from active auth method */
	ساخت sshkey	*auth_طریقہ_کلید;
	حرف		*auth_طریقہ_info;

	/* Information exposed to session */
	ساخت sshbuf	*session_info;	/* Auth info for environment */
};

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

ساخت authmethod_cfg {
	ثابت حرف *name;
	ثابت حرف *synonym;
	صحیح *enabled;
};

ساخت Authmethod {
	ساخت authmethod_cfg *cfg;
	صحیح	(*userauth)(ساخت ssh *, ثابت حرف *);
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
ساخت KbdintDevice
{
	ثابت حرف *name;
	خالی*	(*init_ctx)(Authctxt*);
	صحیح	(*query)(خالی *ctx, حرف **name, حرف **infotxt,
		    u_int *numprompts, حرف ***prompts, u_int **echo_on);
	صحیح	(*respond)(خالی *ctx, u_int numresp, حرف **responses);
	خالی	(*free_ctx)(خالی *ctx);
};

صحیح
auth_rhosts2(ساخت passwd *, ثابت حرف *, ثابت حرف *, ثابت حرف *);

صحیح      auth_password(ساخت ssh *, ثابت حرف *);

صحیح	 hostbased_کلید_allowed(ساخت ssh *, ساخت passwd *,
	    ثابت حرف *, حرف *, ساخت sshkey *);
صحیح	 user_کلید_allowed(ساخت ssh *ssh, ساخت passwd *, ساخت sshkey *,
    صحیح, ساخت sshauthopt **);
صحیح	 auth2_کلید_already_مستعمل(Authctxt *, ثابت ساخت sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
خالی	 auth2_authctxt_reset_info(Authctxt *);
خالی	 auth2_ریکارڈ_کلید(Authctxt *, صحیح, ثابت ساخت sshkey *);
خالی	 auth2_ریکارڈ_info(Authctxt *authctxt, ثابت حرف *, ...)
	    __attribute__((__format__ (لکھو, 2, 3)))
	    __attribute__((__nonnull__ (2)));
خالی	 auth2_update_session_info(Authctxt *, ثابت حرف *, ثابت حرف *);

#اگر_تعریف_شدہ KRB5
صحیح	auth_krb5_password(Authctxt *authctxt, ثابت حرف *password);
خالی	krb5_cleanup_proc(Authctxt *authctxt);
#اگر_ختم /* KRB5 */

#اگر defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#شامل <shadow.h>
صحیح auth_shadow_acctexpired(ساخت spwd *);
صحیح auth_shadow_pwexpired(Authctxt *);
#اگر_ختم

#شامل "auth-pam.h"
#شامل "audit.h"
خالی remove_kbdint_device(ثابت حرف *);

خالی	do_authentication2(ساخت ssh *);

خالی	auth_log(ساخت ssh *, صحیح, صحیح, ثابت حرف *, ثابت حرف *);
خالی	auth_maxtries_exceeded(ساخت ssh *) __attribute__((noreturn));
خالی	userauth_اختتام(ساخت ssh *, صحیح, ثابت حرف *, ثابت حرف *);
صحیح	auth_جڑ_allowed(ساخت ssh *, ثابت حرف *);
خالی	auth_failure_delay(Authctxt *, دوہرا);

حرف	*auth2_read_banner(خالی);
صحیح	 auth2_methods_valid(ثابت حرف *, صحیح);
صحیح	 auth2_update_methods_lists(Authctxt *, ثابت حرف *, ثابت حرف *);
صحیح	 auth2_تیاری_methods_lists(Authctxt *);
صحیح	 auth2_طریقہ_allowed(Authctxt *, ثابت حرف *, ثابت حرف *);

صحیح	auth2_challenge(ساخت ssh *, حرف *);
خالی	auth2_challenge_stop(ساخت ssh *);
صحیح	bsdauth_query(خالی *, حرف **, حرف **, u_int *, حرف ***, u_int **);
صحیح	bsdauth_respond(خالی *, u_int, حرف **);

صحیح	allowed_user(ساخت ssh *, ساخت passwd *);
ساخت passwd * getpwnamallow(ساخت ssh *, ثابت حرف *user);

حرف	*expand_authorized_کلیدیں(ثابت حرف *, ساخت passwd *pw);
حرف	*authorized_principals_file(ساخت passwd *);

صحیح	 auth_کلید_is_revoked(ساخت sshkey *);

ثابت حرف	*auth_get_canonical_hostname(ساخت ssh *, صحیح);

Host_حالت
check_کلید_اندر_hostfiles(ساخت passwd *, ساخت sshkey *, ثابت حرف *,
    ثابت حرف *, ثابت حرف *);

/* hostkey handling */
ساخت sshkey	*get_hostkey_by_اشاریہ(صحیح);
ساخت sshkey	*get_hostkey_عوامی_by_اشاریہ(صحیح, ساخت ssh *);
ساخت sshkey	*get_hostkey_عوامی_by_type(صحیح, صحیح, ساخت ssh *);
ساخت sshkey	*get_hostkey_نجی_by_type(صحیح, صحیح, ساخت ssh *);
صحیح	 get_hostkey_اشاریہ(ساخت sshkey *, صحیح, ساخت ssh *);
صحیح	 sshd_hostkey_sign(ساخت ssh *, ساخت sshkey *, ساخت sshkey *,
    u_char **, سائز_t *, ثابت u_char *, سائز_t, ثابت حرف *);

/* Key / cert options linkage to auth layer */
صحیح	 auth_activate_options(ساخت ssh *, ساخت sshauthopt *);
خالی	 auth_restrict_session(ساخت ssh *);
خالی	 auth_log_authopts(ثابت حرف *, ثابت ساخت sshauthopt *, صحیح);

/* debug messages during authentication */
خالی	 auth_debug_جوڑو(ثابت حرف *fmt,...)
    __attribute__((format(لکھو, 1, 2)));
خالی	 auth_debug_send(ساخت ssh *);
خالی	 auth_debug_reset(خالی);

ساخت passwd *fakepw(خالی);

/* auth2-pubkeyfile.c */
صحیح	 auth_authorise_keyopts(ساخت passwd *, ساخت sshauthopt *, صحیح,
    ثابت حرف *, ثابت حرف *, ثابت حرف *);
صحیح	 auth_check_principals_سطر(حرف *, ثابت ساخت sshkey_cert *,
    ثابت حرف *, ساخت sshauthopt **);
صحیح	 auth_process_principals(FILE *, ثابت حرف *,
    ثابت ساخت sshkey_cert *, ساخت sshauthopt **);
صحیح	 auth_check_authkey_سطر(ساخت passwd *, ساخت sshkey *,
    حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *, ساخت sshauthopt **);
صحیح	 auth_check_authkeys_file(ساخت passwd *, FILE *, حرف *,
    ساخت sshkey *, ثابت حرف *, ثابت حرف *, ساخت sshauthopt **);
FILE	*auth_openkeyfile(ثابت حرف *, ساخت passwd *, صحیح);
FILE	*auth_openprincipals(ثابت حرف *, ساخت passwd *, صحیح);

صحیح	 sys_auth_passwd(ساخت ssh *, ثابت حرف *);

#اگر defined(KRB5) && !defined(HEIMDAL)
krb5_error_رمز ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#اگر_ختم

#اگر_ختم /* AUTH_H */
