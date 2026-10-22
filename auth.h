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

#अगर_अघोषित AUTH_H
#घोषणा AUTH_H

#समावेश <signal.h>
#समावेश <stdio.h>

#अगर_घोषित HAVE_LOGIN_CAP
#समावेश <login_cap.h>
#पूर्ण_अगर
#अगर_घोषित BSD_AUTH
#समावेश <bsd_auth.h>
#पूर्ण_अगर
#अगर_घोषित KRB5
#समावेश <krb5.h>
#पूर्ण_अगर

काष्ठा passwd;
काष्ठा ssh;
काष्ठा sshbuf;
काष्ठा sshkey;
काष्ठा sshkey_cert;
काष्ठा sshauthopt;

प्रकार काष्ठा Authctxt Authctxt;
प्रकार काष्ठा Authmethod Authmethod;
प्रकार काष्ठा KbdintDevice KbdintDevice;

काष्ठा Authctxt {
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
	काष्ठा passwd	*pw;		/* set if 'valid' */
	अक्षर		*style;

	/* Method lists for multiple authentication */
	अक्षर		**auth_methods;	/* modified from server config */
	u_int		 अंक_auth_methods;

	/* Authentication method-specific data */
	व्योम		*methoddata;
	व्योम		*kbdintctxt;
#अगर_घोषित BSD_AUTH
	auth_session_t	*as;
#पूर्ण_अगर
#अगर_घोषित KRB5
	krb5_context	 krb5_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	अक्षर		*krb5_ticket_file;
	अक्षर		*krb5_ccname;
#पूर्ण_अगर
	काष्ठा sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	काष्ठा sshkey	**पूर्व_कुंजियाँ;
	u_int		 nprev_कुंजियाँ;

	/* Last used key and ancillary information from active auth method */
	काष्ठा sshkey	*auth_method_कुंजी;
	अक्षर		*auth_method_info;

	/* Information exposed to session */
	काष्ठा sshbuf	*session_info;	/* Auth info for environment */
};

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

काष्ठा authmethod_cfg {
	स्थिर अक्षर *name;
	स्थिर अक्षर *synonym;
	पूर्णांक *enabled;
};

काष्ठा Authmethod {
	काष्ठा authmethod_cfg *cfg;
	पूर्णांक	(*userauth)(काष्ठा ssh *, स्थिर अक्षर *);
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
काष्ठा KbdintDevice
{
	स्थिर अक्षर *name;
	व्योम*	(*init_ctx)(Authctxt*);
	पूर्णांक	(*query)(व्योम *ctx, अक्षर **name, अक्षर **infotxt,
		    u_int *numprompts, अक्षर ***prompts, u_int **echo_on);
	पूर्णांक	(*respond)(व्योम *ctx, u_int numresp, अक्षर **responses);
	व्योम	(*free_ctx)(व्योम *ctx);
};

पूर्णांक
auth_rhosts2(काष्ठा passwd *, स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *);

पूर्णांक      auth_password(काष्ठा ssh *, स्थिर अक्षर *);

पूर्णांक	 hostbased_कुंजी_allowed(काष्ठा ssh *, काष्ठा passwd *,
	    स्थिर अक्षर *, अक्षर *, काष्ठा sshkey *);
पूर्णांक	 user_कुंजी_allowed(काष्ठा ssh *ssh, काष्ठा passwd *, काष्ठा sshkey *,
    पूर्णांक, काष्ठा sshauthopt **);
पूर्णांक	 auth2_कुंजी_already_used(Authctxt *, स्थिर काष्ठा sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
व्योम	 auth2_authctxt_reset_info(Authctxt *);
व्योम	 auth2_record_कुंजी(Authctxt *, पूर्णांक, स्थिर काष्ठा sshkey *);
व्योम	 auth2_record_info(Authctxt *authctxt, स्थिर अक्षर *, ...)
	    __attribute__((__format__ (म_लिखो, 2, 3)))
	    __attribute__((__nonnull__ (2)));
व्योम	 auth2_update_session_info(Authctxt *, स्थिर अक्षर *, स्थिर अक्षर *);

#अगर_घोषित KRB5
पूर्णांक	auth_krb5_password(Authctxt *authctxt, स्थिर अक्षर *password);
व्योम	krb5_cleanup_proc(Authctxt *authctxt);
#पूर्ण_अगर /* KRB5 */

#अगर defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#समावेश <shadow.h>
पूर्णांक auth_shadow_acctexpired(काष्ठा spwd *);
पूर्णांक auth_shadow_pwexpired(Authctxt *);
#पूर्ण_अगर

#समावेश "auth-pam.h"
#समावेश "audit.h"
व्योम remove_kbdint_device(स्थिर अक्षर *);

व्योम	do_authentication2(काष्ठा ssh *);

व्योम	auth_log(काष्ठा ssh *, पूर्णांक, पूर्णांक, स्थिर अक्षर *, स्थिर अक्षर *);
व्योम	auth_maxtries_exceeded(काष्ठा ssh *) __attribute__((noreturn));
व्योम	userauth_finish(काष्ठा ssh *, पूर्णांक, स्थिर अक्षर *, स्थिर अक्षर *);
पूर्णांक	auth_मूल_allowed(काष्ठा ssh *, स्थिर अक्षर *);
व्योम	auth_failure_delay(Authctxt *, द्विगुन);

अक्षर	*auth2_read_banner(व्योम);
पूर्णांक	 auth2_methods_valid(स्थिर अक्षर *, पूर्णांक);
पूर्णांक	 auth2_update_methods_lists(Authctxt *, स्थिर अक्षर *, स्थिर अक्षर *);
पूर्णांक	 auth2_setup_methods_lists(Authctxt *);
पूर्णांक	 auth2_method_allowed(Authctxt *, स्थिर अक्षर *, स्थिर अक्षर *);

पूर्णांक	auth2_challenge(काष्ठा ssh *, अक्षर *);
व्योम	auth2_challenge_stop(काष्ठा ssh *);
पूर्णांक	bsdauth_query(व्योम *, अक्षर **, अक्षर **, u_int *, अक्षर ***, u_int **);
पूर्णांक	bsdauth_respond(व्योम *, u_int, अक्षर **);

पूर्णांक	allowed_user(काष्ठा ssh *, काष्ठा passwd *);
काष्ठा passwd * getpwnamallow(काष्ठा ssh *, स्थिर अक्षर *user);

अक्षर	*expand_authorized_कुंजियाँ(स्थिर अक्षर *, काष्ठा passwd *pw);
अक्षर	*authorized_principals_file(काष्ठा passwd *);

पूर्णांक	 auth_कुंजी_is_revoked(काष्ठा sshkey *);

स्थिर अक्षर	*auth_get_canonical_hostname(काष्ठा ssh *, पूर्णांक);

HostStatus
check_कुंजी_in_hostfiles(काष्ठा passwd *, काष्ठा sshkey *, स्थिर अक्षर *,
    स्थिर अक्षर *, स्थिर अक्षर *);

/* hostkey handling */
काष्ठा sshkey	*get_hostkey_by_सूचकांक(पूर्णांक);
काष्ठा sshkey	*get_hostkey_public_by_सूचकांक(पूर्णांक, काष्ठा ssh *);
काष्ठा sshkey	*get_hostkey_public_by_type(पूर्णांक, पूर्णांक, काष्ठा ssh *);
काष्ठा sshkey	*get_hostkey_private_by_type(पूर्णांक, पूर्णांक, काष्ठा ssh *);
पूर्णांक	 get_hostkey_सूचकांक(काष्ठा sshkey *, पूर्णांक, काष्ठा ssh *);
पूर्णांक	 sshd_hostkey_sign(काष्ठा ssh *, काष्ठा sshkey *, काष्ठा sshkey *,
    u_char **, माप_प्रकार *, स्थिर u_char *, माप_प्रकार, स्थिर अक्षर *);

/* Key / cert options linkage to auth layer */
पूर्णांक	 auth_activate_options(काष्ठा ssh *, काष्ठा sshauthopt *);
व्योम	 auth_restrict_session(काष्ठा ssh *);
व्योम	 auth_log_authopts(स्थिर अक्षर *, स्थिर काष्ठा sshauthopt *, पूर्णांक);

/* debug messages during authentication */
व्योम	 auth_debug_add(स्थिर अक्षर *fmt,...)
    __attribute__((format(म_लिखो, 1, 2)));
व्योम	 auth_debug_send(काष्ठा ssh *);
व्योम	 auth_debug_reset(व्योम);

काष्ठा passwd *fakepw(व्योम);

/* auth2-pubkeyfile.c */
पूर्णांक	 auth_authorise_keyopts(काष्ठा passwd *, काष्ठा sshauthopt *, पूर्णांक,
    स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *);
पूर्णांक	 auth_check_principals_पंक्ति(अक्षर *, स्थिर काष्ठा sshkey_cert *,
    स्थिर अक्षर *, काष्ठा sshauthopt **);
पूर्णांक	 auth_process_principals(खाता *, स्थिर अक्षर *,
    स्थिर काष्ठा sshkey_cert *, काष्ठा sshauthopt **);
पूर्णांक	 auth_check_authkey_पंक्ति(काष्ठा passwd *, काष्ठा sshkey *,
    अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *, काष्ठा sshauthopt **);
पूर्णांक	 auth_check_authkeys_file(काष्ठा passwd *, खाता *, अक्षर *,
    काष्ठा sshkey *, स्थिर अक्षर *, स्थिर अक्षर *, काष्ठा sshauthopt **);
खाता	*auth_openkeyfile(स्थिर अक्षर *, काष्ठा passwd *, पूर्णांक);
खाता	*auth_openprincipals(स्थिर अक्षर *, काष्ठा passwd *, पूर्णांक);

पूर्णांक	 sys_auth_passwd(काष्ठा ssh *, स्थिर अक्षर *);

#अगर defined(KRB5) && !defined(HEIMDAL)
krb5_error_code ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#पूर्ण_अगर

#पूर्ण_अगर /* AUTH_H */
