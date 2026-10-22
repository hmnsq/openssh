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

#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

#ifdef HAVE_LOGIN_CAP
#ಅನ್ತರ್ಭಾವ <login_cap.h>
#endif
#ifdef BSD_AUTH
#ಅನ್ತರ್ಭಾವ <bsd_auth.h>
#endif
#ifdef KRB5
#ಅನ್ತರ್ಭಾವ <krb5.h>
#endif

ಸಂರಚನಾ passwd;
ಸಂರಚನಾ ssh;
ಸಂರಚನಾ sshbuf;
ಸಂರಚನಾ sshkey;
ಸಂರಚನಾ sshkey_cert;
ಸಂರಚನಾ sshauthopt;

ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ Authctxt Authctxt;
ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ Authmethod Authmethod;
ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ KbdintDevice KbdintDevice;

ಸಂರಚನಾ Authctxt {
	sig_atomic_t	 success;
	ಪೂರ್ಣಾಙ್ಕ		 authenticated;	/* authenticated and alarms cancelled */
	ಪೂರ್ಣಾಙ್ಕ		 postponed;	/* authentication needs another step */
	ಪೂರ್ಣಾಙ್ಕ		 valid;		/* user exists and is allowed to login */
	ಪೂರ್ಣಾಙ್ಕ		 attempt;
	ಪೂರ್ಣಾಙ್ಕ		 failures;
	ಪೂರ್ಣಾಙ್ಕ		 pk_ok_failures;
	ಪೂರ್ಣಾಙ್ಕ		 auth_failure_already_counted;
	ಪೂರ್ಣಾಙ್ಕ		 server_caused_failure;
	ಪೂರ್ಣಾಙ್ಕ		 force_pwchange;
	ವರ್ಣ		*user;		/* username sent by the client */
	ವರ್ಣ		*service;
	ಸಂರಚನಾ passwd	*pw;		/* set if 'valid' */
	ವರ್ಣ		*style;

	/* Method lists for multiple authentication */
	ವರ್ಣ		**auth_methods;	/* modified from server config */
	u_int		 ಅಂಕೆ_auth_methods;

	/* Authentication method-specific data */
	ಶೂನ್ಯ		*methoddata;
	ಶೂನ್ಯ		*kbdintctxt;
#ifdef BSD_AUTH
	auth_session_t	*as;
#endif
#ifdef KRB5
	krb5_context	 krb5_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	ವರ್ಣ		*krb5_ticket_file;
	ವರ್ಣ		*krb5_ccname;
#endif
	ಸಂರಚನಾ sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	ಸಂರಚನಾ sshkey	**prev_ಕೀಲಿಗಳು;
	u_int		 nprev_ಕೀಲಿಗಳು;

	/* Last used key and ancillary information from active auth method */
	ಸಂರಚನಾ sshkey	*auth_method_ಕೀಲಿ;
	ವರ್ಣ		*auth_method_info;

	/* Information exposed to session */
	ಸಂರಚನಾ sshbuf	*session_info;	/* Auth info for environment */
};

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

ಸಂರಚನಾ authmethod_cfg {
	ಧ್ರುವ ವರ್ಣ *name;
	ಧ್ರುವ ವರ್ಣ *synonym;
	ಪೂರ್ಣಾಙ್ಕ *enabled;
};

ಸಂರಚನಾ Authmethod {
	ಸಂರಚನಾ authmethod_cfg *cfg;
	ಪೂರ್ಣಾಙ್ಕ	(*userauth)(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *);
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
ಸಂರಚನಾ KbdintDevice
{
	ಧ್ರುವ ವರ್ಣ *name;
	ಶೂನ್ಯ*	(*init_ctx)(Authctxt*);
	ಪೂರ್ಣಾಙ್ಕ	(*query)(ಶೂನ್ಯ *ctx, ವರ್ಣ **name, ವರ್ಣ **infotxt,
		    u_int *numprompts, ವರ್ಣ ***prompts, u_int **echo_on);
	ಪೂರ್ಣಾಙ್ಕ	(*respond)(ಶೂನ್ಯ *ctx, u_int numresp, ವರ್ಣ **responses);
	ಶೂನ್ಯ	(*free_ctx)(ಶೂನ್ಯ *ctx);
};

ಪೂರ್ಣಾಙ್ಕ
auth_rhosts2(ಸಂರಚನಾ passwd *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);

ಪೂರ್ಣಾಙ್ಕ      auth_password(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *);

ಪೂರ್ಣಾಙ್ಕ	 hostbased_ಕೀಲಿ_allowed(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ passwd *,
	    ಧ್ರುವ ವರ್ಣ *, ವರ್ಣ *, ಸಂರಚನಾ sshkey *);
ಪೂರ್ಣಾಙ್ಕ	 user_ಕೀಲಿ_allowed(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ passwd *, ಸಂರಚನಾ sshkey *,
    ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshauthopt **);
ಪೂರ್ಣಾಙ್ಕ	 auth2_ಕೀಲಿ_already_used(Authctxt *, ಧ್ರುವ ಸಂರಚನಾ sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
ಶೂನ್ಯ	 auth2_authctxt_reset_info(Authctxt *);
ಶೂನ್ಯ	 auth2_record_ಕೀಲಿ(Authctxt *, ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ಸಂರಚನಾ sshkey *);
ಶೂನ್ಯ	 auth2_record_info(Authctxt *authctxt, ಧ್ರುವ ವರ್ಣ *, ...)
	    __attribute__((__format__ (printf, 2, 3)))
	    __attribute__((__nonnull__ (2)));
ಶೂನ್ಯ	 auth2_update_session_info(Authctxt *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);

#ifdef KRB5
ಪೂರ್ಣಾಙ್ಕ	auth_krb5_password(Authctxt *authctxt, ಧ್ರುವ ವರ್ಣ *password);
ಶೂನ್ಯ	krb5_cleanup_proc(Authctxt *authctxt);
#endif /* KRB5 */

#ಯದಿ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#ಅನ್ತರ್ಭಾವ <shadow.h>
ಪೂರ್ಣಾಙ್ಕ auth_shadow_acctexpired(ಸಂರಚನಾ spwd *);
ಪೂರ್ಣಾಙ್ಕ auth_shadow_pwexpired(Authctxt *);
#endif

#ಅನ್ತರ್ಭಾವ "auth-pam.h"
#ಅನ್ತರ್ಭಾವ "audit.h"
ಶೂನ್ಯ remove_kbdint_device(ಧ್ರುವ ವರ್ಣ *);

ಶೂನ್ಯ	do_authentication2(ಸಂರಚನಾ ssh *);

ಶೂನ್ಯ	auth_log(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
ಶೂನ್ಯ	auth_maxtries_exceeded(ಸಂರಚನಾ ssh *) __attribute__((noreturn));
ಶೂನ್ಯ	userauth_finish(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	auth_ಬೇರು_allowed(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *);
ಶೂನ್ಯ	auth_failure_delay(Authctxt *, ದ್ವಿಗುಣ);

ವರ್ಣ	*auth2_read_banner(ಶೂನ್ಯ);
ಪೂರ್ಣಾಙ್ಕ	 auth2_methods_valid(ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 auth2_update_methods_lists(Authctxt *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 auth2_setup_methods_lists(Authctxt *);
ಪೂರ್ಣಾಙ್ಕ	 auth2_method_allowed(Authctxt *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);

ಪೂರ್ಣಾಙ್ಕ	auth2_challenge(ಸಂರಚನಾ ssh *, ವರ್ಣ *);
ಶೂನ್ಯ	auth2_challenge_stop(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	bsdauth_query(ಶೂನ್ಯ *, ವರ್ಣ **, ವರ್ಣ **, u_int *, ವರ್ಣ ***, u_int **);
ಪೂರ್ಣಾಙ್ಕ	bsdauth_respond(ಶೂನ್ಯ *, u_int, ವರ್ಣ **);

ಪೂರ್ಣಾಙ್ಕ	allowed_user(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ passwd *);
ಸಂರಚನಾ passwd * getpwnamallow(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *user);

ವರ್ಣ	*expand_authorized_ಕೀಲಿಗಳು(ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ passwd *pw);
ವರ್ಣ	*authorized_principals_file(ಸಂರಚನಾ passwd *);

ಪೂರ್ಣಾಙ್ಕ	 auth_ಕೀಲಿ_is_revoked(ಸಂರಚನಾ sshkey *);

ಧ್ರುವ ವರ್ಣ	*auth_get_canonical_hostname(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ);

HostStatus
check_ಕೀಲಿ_in_hostfiles(ಸಂರಚನಾ passwd *, ಸಂರಚನಾ sshkey *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);

/* hostkey handling */
ಸಂರಚನಾ sshkey	*get_hostkey_by_index(ಪೂರ್ಣಾಙ್ಕ);
ಸಂರಚನಾ sshkey	*get_hostkey_public_by_index(ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ ssh *);
ಸಂರಚನಾ sshkey	*get_hostkey_public_by_type(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ ssh *);
ಸಂರಚನಾ sshkey	*get_hostkey_private_by_type(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 get_hostkey_index(ಸಂರಚನಾ sshkey *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 sshd_hostkey_sign(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ sshkey *,
    u_char **, size_t *, ಧ್ರುವ u_char *, size_t, ಧ್ರುವ ವರ್ಣ *);

/* Key / cert options linkage to auth layer */
ಪೂರ್ಣಾಙ್ಕ	 auth_activate_options(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ sshauthopt *);
ಶೂನ್ಯ	 auth_restrict_session(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ	 auth_log_authopts(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ಸಂರಚನಾ sshauthopt *, ಪೂರ್ಣಾಙ್ಕ);

/* debug messages during authentication */
ಶೂನ್ಯ	 auth_debug_add(ಧ್ರುವ ವರ್ಣ *fmt,...)
    __attribute__((format(printf, 1, 2)));
ಶೂನ್ಯ	 auth_debug_send(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ	 auth_debug_reset(ಶೂನ್ಯ);

ಸಂರಚನಾ passwd *fakepw(ಶೂನ್ಯ);

/* auth2-pubkeyfile.c */
ಪೂರ್ಣಾಙ್ಕ	 auth_authorise_keyopts(ಸಂರಚನಾ passwd *, ಸಂರಚನಾ sshauthopt *, ಪೂರ್ಣಾಙ್ಕ,
    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 auth_check_principals_ಸಾಲು(ವರ್ಣ *, ಧ್ರುವ ಸಂರಚನಾ sshkey_cert *,
    ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ sshauthopt **);
ಪೂರ್ಣಾಙ್ಕ	 auth_process_principals(FILE *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ಸಂರಚನಾ sshkey_cert *, ಸಂರಚನಾ sshauthopt **);
ಪೂರ್ಣಾಙ್ಕ	 auth_check_authkey_ಸಾಲು(ಸಂರಚನಾ passwd *, ಸಂರಚನಾ sshkey *,
    ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ sshauthopt **);
ಪೂರ್ಣಾಙ್ಕ	 auth_check_authkeys_file(ಸಂರಚನಾ passwd *, FILE *, ವರ್ಣ *,
    ಸಂರಚನಾ sshkey *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ sshauthopt **);
FILE	*auth_openkeyfile(ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ passwd *, ಪೂರ್ಣಾಙ್ಕ);
FILE	*auth_openprincipals(ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ passwd *, ಪೂರ್ಣಾಙ್ಕ);

ಪೂರ್ಣಾಙ್ಕ	 sys_auth_passwd(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *);

#ಯದಿ defined(KRB5) && !defined(HEIMDAL)
krb5_error_code ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#endif

#endif /* AUTH_H */
