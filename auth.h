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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ AUTH_H
#ವ್ಯಾಖ್ಯಾನಿಸು AUTH_H

#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_CAP
#ಅನ್ತರ್ಭಾವ <login_cap.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BSD_AUTH
#ಅನ್ತರ್ಭಾವ <bsd_auth.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ KRB5
#ಅನ್ತರ್ಭಾವ <krb5.h>
#ಆದರೆ_ಅಂತ್ಯ

ರಚನೆ passwd;
ರಚನೆ ssh;
ರಚನೆ sshbuf;
ರಚನೆ sshkey;
ರಚನೆ sshkey_cert;
ರಚನೆ sshauthopt;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Authctxt Authctxt;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Authmethod Authmethod;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ KbdintDevice KbdintDevice;

ರಚನೆ Authctxt {
	sig_atomic_t	 success;
	ಪೂರ್ಣಾಂಕ		 authenticated;	/* authenticated and alarms cancelled */
	ಪೂರ್ಣಾಂಕ		 postponed;	/* authentication needs another step */
	ಪೂರ್ಣಾಂಕ		 valid;		/* user exists and is allowed to login */
	ಪೂರ್ಣಾಂಕ		 attempt;
	ಪೂರ್ಣಾಂಕ		 failures;
	ಪೂರ್ಣಾಂಕ		 pk_ok_failures;
	ಪೂರ್ಣಾಂಕ		 auth_failure_already_counted;
	ಪೂರ್ಣಾಂಕ		 server_caused_failure;
	ಪೂರ್ಣಾಂಕ		 force_pwchange;
	ಅಕ್ಷರ		*user;		/* username sent by the client */
	ಅಕ್ಷರ		*service;
	ರಚನೆ passwd	*pw;		/* set if 'valid' */
	ಅಕ್ಷರ		*style;

	/* Method lists for multiple authentication */
	ಅಕ್ಷರ		**auth_methods;	/* modified from server config */
	u_int		 ಅಂಕೆ_auth_methods;

	/* Authentication method-specific data */
	ಶೂನ್ಯ		*methoddata;
	ಶೂನ್ಯ		*kbdintctxt;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BSD_AUTH
	auth_session_t	*as;
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ KRB5
	krb5_context	 krb5_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	ಅಕ್ಷರ		*krb5_ticket_file;
	ಅಕ್ಷರ		*krb5_ccname;
#ಆದರೆ_ಅಂತ್ಯ
	ರಚನೆ sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	ರಚನೆ sshkey	**prev_ಕೀಲಿಗಳು;
	u_int		 nprev_ಕೀಲಿಗಳು;

	/* Last used key and ancillary information from active auth method */
	ರಚನೆ sshkey	*auth_ವಿಧಾನ_ಕೀಲಿ;
	ಅಕ್ಷರ		*auth_ವಿಧಾನ_info;

	/* Information exposed to session */
	ರಚನೆ sshbuf	*session_info;	/* Auth info for environment */
};

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

ರಚನೆ authmethod_cfg {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *synonym;
	ಪೂರ್ಣಾಂಕ *enabled;
};

ರಚನೆ Authmethod {
	ರಚನೆ authmethod_cfg *cfg;
	ಪೂರ್ಣಾಂಕ	(*userauth)(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
ರಚನೆ KbdintDevice
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name;
	ಶೂನ್ಯ*	(*init_ctx)(Authctxt*);
	ಪೂರ್ಣಾಂಕ	(*query)(ಶೂನ್ಯ *ctx, ಅಕ್ಷರ **name, ಅಕ್ಷರ **infotxt,
		    u_int *numprompts, ಅಕ್ಷರ ***prompts, u_int **echo_on);
	ಪೂರ್ಣಾಂಕ	(*respond)(ಶೂನ್ಯ *ctx, u_int numresp, ಅಕ್ಷರ **responses);
	ಶೂನ್ಯ	(*free_ctx)(ಶೂನ್ಯ *ctx);
};

ಪೂರ್ಣಾಂಕ
auth_rhosts2(ರಚನೆ passwd *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ಪೂರ್ಣಾಂಕ      auth_password(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ಪೂರ್ಣಾಂಕ	 hostbased_ಕೀಲಿ_allowed(ರಚನೆ ssh *, ರಚನೆ passwd *,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *, ರಚನೆ sshkey *);
ಪೂರ್ಣಾಂಕ	 user_ಕೀಲಿ_allowed(ರಚನೆ ssh *ssh, ರಚನೆ passwd *, ರಚನೆ sshkey *,
    ಪೂರ್ಣಾಂಕ, ರಚನೆ sshauthopt **);
ಪೂರ್ಣಾಂಕ	 auth2_ಕೀಲಿ_already_ಬಳಸಿದ(Authctxt *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
ಶೂನ್ಯ	 auth2_authctxt_reset_info(Authctxt *);
ಶೂನ್ಯ	 auth2_ದಾಖಲೆ_ಕೀಲಿ(Authctxt *, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *);
ಶೂನ್ಯ	 auth2_ದಾಖಲೆ_info(Authctxt *authctxt, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...)
	    __attribute__((__format__ (ಬರೆ, 2, 3)))
	    __attribute__((__nonnull__ (2)));
ಶೂನ್ಯ	 auth2_update_session_info(Authctxt *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ KRB5
ಪೂರ್ಣಾಂಕ	auth_krb5_password(Authctxt *authctxt, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *password);
ಶೂನ್ಯ	krb5_cleanup_proc(Authctxt *authctxt);
#ಆದರೆ_ಅಂತ್ಯ /* KRB5 */

#ಆದರೆ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#ಅನ್ತರ್ಭಾವ <shadow.h>
ಪೂರ್ಣಾಂಕ auth_shadow_acctexpired(ರಚನೆ spwd *);
ಪೂರ್ಣಾಂಕ auth_shadow_pwexpired(Authctxt *);
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "auth-pam.h"
#ಅನ್ತರ್ಭಾವ "audit.h"
ಶೂನ್ಯ remove_kbdint_device(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ಶೂನ್ಯ	do_authentication2(ರಚನೆ ssh *);

ಶೂನ್ಯ	auth_log(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ	auth_maxtries_exceeded(ರಚನೆ ssh *) __attribute__((noreturn));
ಶೂನ್ಯ	userauth_ಮುಕ್ತಾಯ(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	auth_ಬೇರು_allowed(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ	auth_failure_delay(Authctxt *, ದ್ವಿಗುಣ);

ಅಕ್ಷರ	*auth2_read_banner(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ	 auth2_methods_valid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 auth2_update_methods_lists(Authctxt *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 auth2_ಸಿದ್ಧತೆ_methods_lists(Authctxt *);
ಪೂರ್ಣಾಂಕ	 auth2_ವಿಧಾನ_allowed(Authctxt *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ಪೂರ್ಣಾಂಕ	auth2_challenge(ರಚನೆ ssh *, ಅಕ್ಷರ *);
ಶೂನ್ಯ	auth2_challenge_stop(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	bsdauth_query(ಶೂನ್ಯ *, ಅಕ್ಷರ **, ಅಕ್ಷರ **, u_int *, ಅಕ್ಷರ ***, u_int **);
ಪೂರ್ಣಾಂಕ	bsdauth_respond(ಶೂನ್ಯ *, u_int, ಅಕ್ಷರ **);

ಪೂರ್ಣಾಂಕ	allowed_user(ರಚನೆ ssh *, ರಚನೆ passwd *);
ರಚನೆ passwd * getpwnamallow(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user);

ಅಕ್ಷರ	*expand_authorized_ಕೀಲಿಗಳು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ passwd *pw);
ಅಕ್ಷರ	*authorized_principals_file(ರಚನೆ passwd *);

ಪೂರ್ಣಾಂಕ	 auth_ಕೀಲಿ_is_revoked(ರಚನೆ sshkey *);

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ	*auth_get_canonical_hostname(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ);

Host_ಸ್ಥಿತಿ
check_ಕೀಲಿ_ಒಳ_hostfiles(ರಚನೆ passwd *, ರಚನೆ sshkey *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

/* hostkey handling */
ರಚನೆ sshkey	*get_hostkey_by_ಸೂಚ್ಯಂಕ(ಪೂರ್ಣಾಂಕ);
ರಚನೆ sshkey	*get_hostkey_ಬಹಿರಂಗ_by_ಸೂಚ್ಯಂಕ(ಪೂರ್ಣಾಂಕ, ರಚನೆ ssh *);
ರಚನೆ sshkey	*get_hostkey_ಬಹಿರಂಗ_by_type(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ರಚನೆ ssh *);
ರಚನೆ sshkey	*get_hostkey_ಖಾಸಗಿ_by_type(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 get_hostkey_ಸೂಚ್ಯಂಕ(ರಚನೆ sshkey *, ಪೂರ್ಣಾಂಕ, ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 sshd_hostkey_sign(ರಚನೆ ssh *, ರಚನೆ sshkey *, ರಚನೆ sshkey *,
    u_char **, ಗಾತ್ರ_t *, ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

/* Key / cert options linkage to auth layer */
ಪೂರ್ಣಾಂಕ	 auth_activate_options(ರಚನೆ ssh *, ರಚನೆ sshauthopt *);
ಶೂನ್ಯ	 auth_restrict_session(ರಚನೆ ssh *);
ಶೂನ್ಯ	 auth_log_authopts(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshauthopt *, ಪೂರ್ಣಾಂಕ);

/* debug messages during authentication */
ಶೂನ್ಯ	 auth_debug_ಕೂಡಿಸು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt,...)
    __attribute__((format(ಬರೆ, 1, 2)));
ಶೂನ್ಯ	 auth_debug_send(ರಚನೆ ssh *);
ಶೂನ್ಯ	 auth_debug_reset(ಶೂನ್ಯ);

ರಚನೆ passwd *fakepw(ಶೂನ್ಯ);

/* auth2-pubkeyfile.c */
ಪೂರ್ಣಾಂಕ	 auth_authorise_keyopts(ರಚನೆ passwd *, ರಚನೆ sshauthopt *, ಪೂರ್ಣಾಂಕ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 auth_check_principals_ಸಾಲು(ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_cert *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sshauthopt **);
ಪೂರ್ಣಾಂಕ	 auth_process_principals(FILE *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_cert *, ರಚನೆ sshauthopt **);
ಪೂರ್ಣಾಂಕ	 auth_check_authkey_ಸಾಲು(ರಚನೆ passwd *, ರಚನೆ sshkey *,
    ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sshauthopt **);
ಪೂರ್ಣಾಂಕ	 auth_check_authkeys_file(ರಚನೆ passwd *, FILE *, ಅಕ್ಷರ *,
    ರಚನೆ sshkey *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sshauthopt **);
FILE	*auth_openkeyfile(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ passwd *, ಪೂರ್ಣಾಂಕ);
FILE	*auth_openprincipals(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ passwd *, ಪೂರ್ಣಾಂಕ);

ಪೂರ್ಣಾಂಕ	 sys_auth_passwd(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

#ಆದರೆ defined(KRB5) && !defined(HEIMDAL)
krb5_error_ಸಂಕೇತ ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ /* AUTH_H */
