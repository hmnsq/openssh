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

#شامل <signal.h>
#شامل <stdio.h>

#ifdef HAVE_LOGIN_CAP
#شامل <login_cap.h>
#endif
#ifdef BSD_AUTH
#شامل <bsd_auth.h>
#endif
#ifdef KRB5
#شامل <krb5.h>
#endif

ساختار passwd;
ساختار ssh;
ساختار sshbuf;
ساختار sshkey;
ساختار sshkey_cert;
ساختار sshauthopt;

تعریفنوع ساختار Authctxt Authctxt;
تعریفنوع ساختار Authmethod Authmethod;
تعریفنوع ساختار KbdintDevice KbdintDevice;

ساختار Authctxt {
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
	نویسه		*user;		/* username sent by the client */
	نویسه		*service;
	ساختار passwd	*pw;		/* set if 'valid' */
	نویسه		*style;

	/* Method lists for multiple authentication */
	نویسه		**auth_methods;	/* modified from server config */
	u_int		 رقم_auth_methods;

	/* Authentication method-specific data */
	تهی		*methoddata;
	تهی		*kbdintctxt;
#ifdef BSD_AUTH
	auth_session_t	*as;
#endif
#ifdef KRB5
	krb5_context	 krb5_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	نویسه		*krb5_ticket_file;
	نویسه		*krb5_ccname;
#endif
	ساختار sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	ساختار sshkey	**prev_کلیدها;
	u_int		 nprev_کلیدها;

	/* Last used key and ancillary information from active auth method */
	ساختار sshkey	*auth_method_کلید;
	نویسه		*auth_method_info;

	/* Information exposed to session */
	ساختار sshbuf	*session_info;	/* Auth info for environment */
};

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

ساختار authmethod_cfg {
	ثابت نویسه *name;
	ثابت نویسه *synonym;
	صحیح *enabled;
};

ساختار Authmethod {
	ساختار authmethod_cfg *cfg;
	صحیح	(*userauth)(ساختار ssh *, ثابت نویسه *);
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
ساختار KbdintDevice
{
	ثابت نویسه *name;
	تهی*	(*init_ctx)(Authctxt*);
	صحیح	(*query)(تهی *ctx, نویسه **name, نویسه **infotxt,
		    u_int *numprompts, نویسه ***prompts, u_int **echo_on);
	صحیح	(*respond)(تهی *ctx, u_int numresp, نویسه **responses);
	تهی	(*free_ctx)(تهی *ctx);
};

صحیح
auth_rhosts2(ساختار passwd *, ثابت نویسه *, ثابت نویسه *, ثابت نویسه *);

صحیح      auth_password(ساختار ssh *, ثابت نویسه *);

صحیح	 hostbased_کلید_allowed(ساختار ssh *, ساختار passwd *,
	    ثابت نویسه *, نویسه *, ساختار sshkey *);
صحیح	 user_کلید_allowed(ساختار ssh *ssh, ساختار passwd *, ساختار sshkey *,
    صحیح, ساختار sshauthopt **);
صحیح	 auth2_کلید_already_used(Authctxt *, ثابت ساختار sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
تهی	 auth2_authctxt_reset_info(Authctxt *);
تهی	 auth2_record_کلید(Authctxt *, صحیح, ثابت ساختار sshkey *);
تهی	 auth2_record_info(Authctxt *authctxt, ثابت نویسه *, ...)
	    __attribute__((__format__ (printf, 2, 3)))
	    __attribute__((__nonnull__ (2)));
تهی	 auth2_update_session_info(Authctxt *, ثابت نویسه *, ثابت نویسه *);

#ifdef KRB5
صحیح	auth_krb5_password(Authctxt *authctxt, ثابت نویسه *password);
تهی	krb5_cleanup_proc(Authctxt *authctxt);
#endif /* KRB5 */

#اگر defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#شامل <shadow.h>
صحیح auth_shadow_acctexpired(ساختار spwd *);
صحیح auth_shadow_pwexpired(Authctxt *);
#endif

#شامل "auth-pam.h"
#شامل "audit.h"
تهی remove_kbdint_device(ثابت نویسه *);

تهی	do_authentication2(ساختار ssh *);

تهی	auth_log(ساختار ssh *, صحیح, صحیح, ثابت نویسه *, ثابت نویسه *);
تهی	auth_maxtries_exceeded(ساختار ssh *) __attribute__((noreturn));
تهی	userauth_finish(ساختار ssh *, صحیح, ثابت نویسه *, ثابت نویسه *);
صحیح	auth_ریشه_allowed(ساختار ssh *, ثابت نویسه *);
تهی	auth_failure_delay(Authctxt *, دوگانه);

نویسه	*auth2_read_banner(تهی);
صحیح	 auth2_methods_valid(ثابت نویسه *, صحیح);
صحیح	 auth2_update_methods_lists(Authctxt *, ثابت نویسه *, ثابت نویسه *);
صحیح	 auth2_setup_methods_lists(Authctxt *);
صحیح	 auth2_method_allowed(Authctxt *, ثابت نویسه *, ثابت نویسه *);

صحیح	auth2_challenge(ساختار ssh *, نویسه *);
تهی	auth2_challenge_stop(ساختار ssh *);
صحیح	bsdauth_query(تهی *, نویسه **, نویسه **, u_int *, نویسه ***, u_int **);
صحیح	bsdauth_respond(تهی *, u_int, نویسه **);

صحیح	allowed_user(ساختار ssh *, ساختار passwd *);
ساختار passwd * getpwnamallow(ساختار ssh *, ثابت نویسه *user);

نویسه	*expand_authorized_کلیدها(ثابت نویسه *, ساختار passwd *pw);
نویسه	*authorized_principals_file(ساختار passwd *);

صحیح	 auth_کلید_is_revoked(ساختار sshkey *);

ثابت نویسه	*auth_get_canonical_hostname(ساختار ssh *, صحیح);

HostStatus
check_کلید_in_hostfiles(ساختار passwd *, ساختار sshkey *, ثابت نویسه *,
    ثابت نویسه *, ثابت نویسه *);

/* hostkey handling */
ساختار sshkey	*get_hostkey_by_index(صحیح);
ساختار sshkey	*get_hostkey_public_by_index(صحیح, ساختار ssh *);
ساختار sshkey	*get_hostkey_public_by_type(صحیح, صحیح, ساختار ssh *);
ساختار sshkey	*get_hostkey_private_by_type(صحیح, صحیح, ساختار ssh *);
صحیح	 get_hostkey_index(ساختار sshkey *, صحیح, ساختار ssh *);
صحیح	 sshd_hostkey_sign(ساختار ssh *, ساختار sshkey *, ساختار sshkey *,
    u_char **, size_t *, ثابت u_char *, size_t, ثابت نویسه *);

/* Key / cert options linkage to auth layer */
صحیح	 auth_activate_options(ساختار ssh *, ساختار sshauthopt *);
تهی	 auth_restrict_session(ساختار ssh *);
تهی	 auth_log_authopts(ثابت نویسه *, ثابت ساختار sshauthopt *, صحیح);

/* debug messages during authentication */
تهی	 auth_debug_add(ثابت نویسه *fmt,...)
    __attribute__((format(printf, 1, 2)));
تهی	 auth_debug_send(ساختار ssh *);
تهی	 auth_debug_reset(تهی);

ساختار passwd *fakepw(تهی);

/* auth2-pubkeyfile.c */
صحیح	 auth_authorise_keyopts(ساختار passwd *, ساختار sshauthopt *, صحیح,
    ثابت نویسه *, ثابت نویسه *, ثابت نویسه *);
صحیح	 auth_check_principals_سطر(نویسه *, ثابت ساختار sshkey_cert *,
    ثابت نویسه *, ساختار sshauthopt **);
صحیح	 auth_process_principals(FILE *, ثابت نویسه *,
    ثابت ساختار sshkey_cert *, ساختار sshauthopt **);
صحیح	 auth_check_authkey_سطر(ساختار passwd *, ساختار sshkey *,
    نویسه *, ثابت نویسه *, ثابت نویسه *, ثابت نویسه *, ساختار sshauthopt **);
صحیح	 auth_check_authkeys_file(ساختار passwd *, FILE *, نویسه *,
    ساختار sshkey *, ثابت نویسه *, ثابت نویسه *, ساختار sshauthopt **);
FILE	*auth_openkeyfile(ثابت نویسه *, ساختار passwd *, صحیح);
FILE	*auth_openprincipals(ثابت نویسه *, ساختار passwd *, صحیح);

صحیح	 sys_auth_passwd(ساختار ssh *, ثابت نویسه *);

#اگر defined(KRB5) && !defined(HEIMDAL)
krb5_error_code ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#endif

#endif /* AUTH_H */
