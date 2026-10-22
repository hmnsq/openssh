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

#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdio.h>

#ifdef HAVE_LOGIN_CAP
#अन्तर्भाव <login_cap.h>
#endif
#ifdef BSD_AUTH
#अन्तर्भाव <bsd_auth.h>
#endif
#ifdef KRB5
#अन्तर्भाव <krb5.h>
#endif

संरचना passwd;
संरचना ssh;
संरचना sshbuf;
संरचना sshkey;
संरचना sshkey_cert;
संरचना sshauthopt;

प्रकारव्याख्या संरचना Authctxt Authctxt;
प्रकारव्याख्या संरचना Authmethod Authmethod;
प्रकारव्याख्या संरचना KbdintDevice KbdintDevice;

संरचना Authctxt {
	संक_पूर्ण_प्रकार	 success;
	पूर्णांक		 authenticated;	/* authenticated and alarms cancelled */
	पूर्णांक		 postponed;	/* authentication needs another step */
	पूर्णांक		 valid;		/* user exists and is allowed to login */
	पूर्णांक		 attempt;
	पूर्णांक		 failures;
	पूर्णांक		 pk_ok_failures;
	पूर्णांक		 auth_failure_already_counted;
	पूर्णांक		 server_caused_failure;
	पूर्णांक		 force_pwchange;
	अक्षर		*user;		/* username sent by the client */
	अक्षर		*service;
	संरचना passwd	*pw;		/* set if 'valid' */
	अक्षर		*style;

	/* Method lists for multiple authentication */
	अक्षर		**auth_methods;	/* modified from server config */
	u_int		 अंक_auth_methods;

	/* Authentication method-specific data */
	शून्य		*methoddata;
	शून्य		*kbdintctxt;
#ifdef BSD_AUTH
	auth_session_t	*as;
#endif
#ifdef KRB5
	krb5_context	 krb5_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	अक्षर		*krb5_ticket_file;
	अक्षर		*krb5_ccname;
#endif
	संरचना sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	संरचना sshkey	**prev_किल्ल्या;
	u_int		 nprev_किल्ल्या;

	/* Last used key and ancillary information from active auth method */
	संरचना sshkey	*auth_method_किल्ली;
	अक्षर		*auth_method_info;

	/* Information exposed to session */
	संरचना sshbuf	*session_info;	/* Auth info for environment */
};

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

संरचना authmethod_cfg {
	स्थिरांक अक्षर *name;
	स्थिरांक अक्षर *synonym;
	पूर्णांक *enabled;
};

संरचना Authmethod {
	संरचना authmethod_cfg *cfg;
	पूर्णांक	(*userauth)(संरचना ssh *, स्थिरांक अक्षर *);
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
संरचना KbdintDevice
{
	स्थिरांक अक्षर *name;
	शून्य*	(*init_ctx)(Authctxt*);
	पूर्णांक	(*query)(शून्य *ctx, अक्षर **name, अक्षर **infotxt,
		    u_int *numprompts, अक्षर ***prompts, u_int **echo_on);
	पूर्णांक	(*respond)(शून्य *ctx, u_int numresp, अक्षर **responses);
	शून्य	(*free_ctx)(शून्य *ctx);
};

पूर्णांक
auth_rhosts2(संरचना passwd *, स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *);

पूर्णांक      auth_password(संरचना ssh *, स्थिरांक अक्षर *);

पूर्णांक	 hostbased_किल्ली_allowed(संरचना ssh *, संरचना passwd *,
	    स्थिरांक अक्षर *, अक्षर *, संरचना sshkey *);
पूर्णांक	 user_किल्ली_allowed(संरचना ssh *ssh, संरचना passwd *, संरचना sshkey *,
    पूर्णांक, संरचना sshauthopt **);
पूर्णांक	 auth2_किल्ली_already_used(Authctxt *, स्थिरांक संरचना sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
शून्य	 auth2_authctxt_reset_info(Authctxt *);
शून्य	 auth2_record_किल्ली(Authctxt *, पूर्णांक, स्थिरांक संरचना sshkey *);
शून्य	 auth2_record_info(Authctxt *authctxt, स्थिरांक अक्षर *, ...)
	    __attribute__((__format__ (म_लिखो, 2, 3)))
	    __attribute__((__nonnull__ (2)));
शून्य	 auth2_update_session_info(Authctxt *, स्थिरांक अक्षर *, स्थिरांक अक्षर *);

#ifdef KRB5
पूर्णांक	auth_krb5_password(Authctxt *authctxt, स्थिरांक अक्षर *password);
शून्य	krb5_cleanup_proc(Authctxt *authctxt);
#endif /* KRB5 */

#जर defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#अन्तर्भाव <shadow.h>
पूर्णांक auth_shadow_acctexpired(संरचना spwd *);
पूर्णांक auth_shadow_pwexpired(Authctxt *);
#endif

#अन्तर्भाव "auth-pam.h"
#अन्तर्भाव "audit.h"
शून्य remove_kbdint_device(स्थिरांक अक्षर *);

शून्य	do_authentication2(संरचना ssh *);

शून्य	auth_log(संरचना ssh *, पूर्णांक, पूर्णांक, स्थिरांक अक्षर *, स्थिरांक अक्षर *);
शून्य	auth_maxtries_exceeded(संरचना ssh *) __attribute__((noreturn));
शून्य	userauth_finish(संरचना ssh *, पूर्णांक, स्थिरांक अक्षर *, स्थिरांक अक्षर *);
पूर्णांक	auth_मूळ_allowed(संरचना ssh *, स्थिरांक अक्षर *);
शून्य	auth_failure_delay(Authctxt *, द्विगुण);

अक्षर	*auth2_read_banner(शून्य);
पूर्णांक	 auth2_methods_valid(स्थिरांक अक्षर *, पूर्णांक);
पूर्णांक	 auth2_update_methods_lists(Authctxt *, स्थिरांक अक्षर *, स्थिरांक अक्षर *);
पूर्णांक	 auth2_setup_methods_lists(Authctxt *);
पूर्णांक	 auth2_method_allowed(Authctxt *, स्थिरांक अक्षर *, स्थिरांक अक्षर *);

पूर्णांक	auth2_challenge(संरचना ssh *, अक्षर *);
शून्य	auth2_challenge_stop(संरचना ssh *);
पूर्णांक	bsdauth_query(शून्य *, अक्षर **, अक्षर **, u_int *, अक्षर ***, u_int **);
पूर्णांक	bsdauth_respond(शून्य *, u_int, अक्षर **);

पूर्णांक	allowed_user(संरचना ssh *, संरचना passwd *);
संरचना passwd * getpwnamallow(संरचना ssh *, स्थिरांक अक्षर *user);

अक्षर	*expand_authorized_किल्ल्या(स्थिरांक अक्षर *, संरचना passwd *pw);
अक्षर	*authorized_principals_file(संरचना passwd *);

पूर्णांक	 auth_किल्ली_is_revoked(संरचना sshkey *);

स्थिरांक अक्षर	*auth_get_canonical_hostname(संरचना ssh *, पूर्णांक);

HostStatus
check_किल्ली_in_hostfiles(संरचना passwd *, संरचना sshkey *, स्थिरांक अक्षर *,
    स्थिरांक अक्षर *, स्थिरांक अक्षर *);

/* hostkey handling */
संरचना sshkey	*get_hostkey_by_index(पूर्णांक);
संरचना sshkey	*get_hostkey_public_by_index(पूर्णांक, संरचना ssh *);
संरचना sshkey	*get_hostkey_public_by_type(पूर्णांक, पूर्णांक, संरचना ssh *);
संरचना sshkey	*get_hostkey_private_by_type(पूर्णांक, पूर्णांक, संरचना ssh *);
पूर्णांक	 get_hostkey_index(संरचना sshkey *, पूर्णांक, संरचना ssh *);
पूर्णांक	 sshd_hostkey_sign(संरचना ssh *, संरचना sshkey *, संरचना sshkey *,
    u_char **, माप_प्रकार *, स्थिरांक u_char *, माप_प्रकार, स्थिरांक अक्षर *);

/* Key / cert options linkage to auth layer */
पूर्णांक	 auth_activate_options(संरचना ssh *, संरचना sshauthopt *);
शून्य	 auth_restrict_session(संरचना ssh *);
शून्य	 auth_log_authopts(स्थिरांक अक्षर *, स्थिरांक संरचना sshauthopt *, पूर्णांक);

/* debug messages during authentication */
शून्य	 auth_debug_add(स्थिरांक अक्षर *fmt,...)
    __attribute__((format(म_लिखो, 1, 2)));
शून्य	 auth_debug_send(संरचना ssh *);
शून्य	 auth_debug_reset(शून्य);

संरचना passwd *fakepw(शून्य);

/* auth2-pubkeyfile.c */
पूर्णांक	 auth_authorise_keyopts(संरचना passwd *, संरचना sshauthopt *, पूर्णांक,
    स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *);
पूर्णांक	 auth_check_principals_ओळ(अक्षर *, स्थिरांक संरचना sshkey_cert *,
    स्थिरांक अक्षर *, संरचना sshauthopt **);
पूर्णांक	 auth_process_principals(खाता *, स्थिरांक अक्षर *,
    स्थिरांक संरचना sshkey_cert *, संरचना sshauthopt **);
पूर्णांक	 auth_check_authkey_ओळ(संरचना passwd *, संरचना sshkey *,
    अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *, संरचना sshauthopt **);
पूर्णांक	 auth_check_authkeys_file(संरचना passwd *, खाता *, अक्षर *,
    संरचना sshkey *, स्थिरांक अक्षर *, स्थिरांक अक्षर *, संरचना sshauthopt **);
खाता	*auth_openkeyfile(स्थिरांक अक्षर *, संरचना passwd *, पूर्णांक);
खाता	*auth_openprincipals(स्थिरांक अक्षर *, संरचना passwd *, पूर्णांक);

पूर्णांक	 sys_auth_passwd(संरचना ssh *, स्थिरांक अक्षर *);

#जर defined(KRB5) && !defined(HEIMDAL)
krb5_error_code ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#endif

#endif /* AUTH_H */
