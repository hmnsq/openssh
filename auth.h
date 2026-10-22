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

#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>

#ifdef HAVE_LOGIN_CAP
#ଅନ୍ତର୍ଭାଵ <login_cap.h>
#endif
#ifdef BSD_AUTH
#ଅନ୍ତର୍ଭାଵ <bsd_auth.h>
#endif
#ifdef KRB5
#ଅନ୍ତର୍ଭାଵ <krb5.h>
#endif

ସଂରଚନା passwd;
ସଂରଚନା ssh;
ସଂରଚନା sshbuf;
ସଂରଚନା sshkey;
ସଂରଚନା sshkey_cert;
ସଂରଚନା sshauthopt;

ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା Authctxt Authctxt;
ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା Authmethod Authmethod;
ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା KbdintDevice KbdintDevice;

ସଂରଚନା Authctxt {
	sig_atomic_t	 success;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 authenticated;	/* authenticated and alarms cancelled */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 postponed;	/* authentication needs another step */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 valid;		/* user exists and is allowed to login */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 attempt;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 failures;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 pk_ok_failures;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 auth_failure_already_counted;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 server_caused_failure;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 force_pwchange;
	ଅକ୍ଷର		*user;		/* username sent by the client */
	ଅକ୍ଷର		*service;
	ସଂରଚନା passwd	*pw;		/* set if 'valid' */
	ଅକ୍ଷର		*style;

	/* Method lists for multiple authentication */
	ଅକ୍ଷର		**auth_methods;	/* modified from server config */
	u_int		 ଅଙ୍କ_auth_methods;

	/* Authentication method-specific data */
	ଶୂନ୍ୟ		*methoddata;
	ଶୂନ୍ୟ		*kbdintctxt;
#ifdef BSD_AUTH
	auth_session_t	*as;
#endif
#ifdef KRB5
	krb5_context	 krb5_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	ଅକ୍ଷର		*krb5_ticket_file;
	ଅକ୍ଷର		*krb5_ccname;
#endif
	ସଂରଚନା sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	ସଂରଚନା sshkey	**prev_ଚାବିଗୁଡ଼ିକ;
	u_int		 nprev_ଚାବିଗୁଡ଼ିକ;

	/* Last used key and ancillary information from active auth method */
	ସଂରଚନା sshkey	*auth_method_ଚାବି;
	ଅକ୍ଷର		*auth_method_info;

	/* Information exposed to session */
	ସଂରଚନା sshbuf	*session_info;	/* Auth info for environment */
};

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

ସଂରଚନା authmethod_cfg {
	ଅଚଳ ଅକ୍ଷର *name;
	ଅଚଳ ଅକ୍ଷର *synonym;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା *enabled;
};

ସଂରଚନା Authmethod {
	ସଂରଚନା authmethod_cfg *cfg;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	(*userauth)(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *);
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
ସଂରଚନା KbdintDevice
{
	ଅଚଳ ଅକ୍ଷର *name;
	ଶୂନ୍ୟ*	(*init_ctx)(Authctxt*);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	(*query)(ଶୂନ୍ୟ *ctx, ଅକ୍ଷର **name, ଅକ୍ଷର **infotxt,
		    u_int *numprompts, ଅକ୍ଷର ***prompts, u_int **echo_on);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	(*respond)(ଶୂନ୍ୟ *ctx, u_int numresp, ଅକ୍ଷର **responses);
	ଶୂନ୍ୟ	(*free_ctx)(ଶୂନ୍ୟ *ctx);
};

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth_rhosts2(ସଂରଚନା passwd *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା      auth_password(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 hostbased_ଚାବି_allowed(ସଂରଚନା ssh *, ସଂରଚନା passwd *,
	    ଅଚଳ ଅକ୍ଷର *, ଅକ୍ଷର *, ସଂରଚନା sshkey *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 user_ଚାବି_allowed(ସଂରଚନା ssh *ssh, ସଂରଚନା passwd *, ସଂରଚନା sshkey *,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshauthopt **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 auth2_ଚାବି_already_used(Authctxt *, ଅଚଳ ସଂରଚନା sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
ଶୂନ୍ୟ	 auth2_authctxt_reset_info(Authctxt *);
ଶୂନ୍ୟ	 auth2_record_ଚାବି(Authctxt *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ସଂରଚନା sshkey *);
ଶୂନ୍ୟ	 auth2_record_info(Authctxt *authctxt, ଅଚଳ ଅକ୍ଷର *, ...)
	    __attribute__((__format__ (printf, 2, 3)))
	    __attribute__((__nonnull__ (2)));
ଶୂନ୍ୟ	 auth2_update_session_info(Authctxt *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);

#ifdef KRB5
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	auth_krb5_password(Authctxt *authctxt, ଅଚଳ ଅକ୍ଷର *password);
ଶୂନ୍ୟ	krb5_cleanup_proc(Authctxt *authctxt);
#endif /* KRB5 */

#ଯଦି defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#ଅନ୍ତର୍ଭାଵ <shadow.h>
ପୂର୍ଣ୍ଣସଂଖ୍ୟା auth_shadow_acctexpired(ସଂରଚନା spwd *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା auth_shadow_pwexpired(Authctxt *);
#endif

#ଅନ୍ତର୍ଭାଵ "auth-pam.h"
#ଅନ୍ତର୍ଭାଵ "audit.h"
ଶୂନ୍ୟ remove_kbdint_device(ଅଚଳ ଅକ୍ଷର *);

ଶୂନ୍ୟ	do_authentication2(ସଂରଚନା ssh *);

ଶୂନ୍ୟ	auth_log(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ଶୂନ୍ୟ	auth_maxtries_exceeded(ସଂରଚନା ssh *) __attribute__((noreturn));
ଶୂନ୍ୟ	userauth_finish(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	auth_ମୂଳ_allowed(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *);
ଶୂନ୍ୟ	auth_failure_delay(Authctxt *, ଦ୍ୱିଗୁଣ);

ଅକ୍ଷର	*auth2_read_banner(ଶୂନ୍ୟ);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 auth2_methods_valid(ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 auth2_update_methods_lists(Authctxt *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 auth2_setup_methods_lists(Authctxt *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 auth2_method_allowed(Authctxt *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	auth2_challenge(ସଂରଚନା ssh *, ଅକ୍ଷର *);
ଶୂନ୍ୟ	auth2_challenge_stop(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	bsdauth_query(ଶୂନ୍ୟ *, ଅକ୍ଷର **, ଅକ୍ଷର **, u_int *, ଅକ୍ଷର ***, u_int **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	bsdauth_respond(ଶୂନ୍ୟ *, u_int, ଅକ୍ଷର **);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	allowed_user(ସଂରଚନା ssh *, ସଂରଚନା passwd *);
ସଂରଚନା passwd * getpwnamallow(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *user);

ଅକ୍ଷର	*expand_authorized_ଚାବିଗୁଡ଼ିକ(ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା passwd *pw);
ଅକ୍ଷର	*authorized_principals_file(ସଂରଚନା passwd *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 auth_ଚାବି_is_revoked(ସଂରଚନା sshkey *);

ଅଚଳ ଅକ୍ଷର	*auth_get_canonical_hostname(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

HostStatus
check_ଚାବି_in_hostfiles(ସଂରଚନା passwd *, ସଂରଚନା sshkey *, ଅଚଳ ଅକ୍ଷର *,
    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);

/* hostkey handling */
ସଂରଚନା sshkey	*get_hostkey_by_index(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ସଂରଚନା sshkey	*get_hostkey_public_by_index(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା ssh *);
ସଂରଚନା sshkey	*get_hostkey_public_by_type(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା ssh *);
ସଂରଚନା sshkey	*get_hostkey_private_by_type(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 get_hostkey_index(ସଂରଚନା sshkey *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshd_hostkey_sign(ସଂରଚନା ssh *, ସଂରଚନା sshkey *, ସଂରଚନା sshkey *,
    u_char **, size_t *, ଅଚଳ u_char *, size_t, ଅଚଳ ଅକ୍ଷର *);

/* Key / cert options linkage to auth layer */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 auth_activate_options(ସଂରଚନା ssh *, ସଂରଚନା sshauthopt *);
ଶୂନ୍ୟ	 auth_restrict_session(ସଂରଚନା ssh *);
ଶୂନ୍ୟ	 auth_log_authopts(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ସଂରଚନା sshauthopt *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/* debug messages during authentication */
ଶୂନ୍ୟ	 auth_debug_add(ଅଚଳ ଅକ୍ଷର *fmt,...)
    __attribute__((format(printf, 1, 2)));
ଶୂନ୍ୟ	 auth_debug_send(ସଂରଚନା ssh *);
ଶୂନ୍ୟ	 auth_debug_reset(ଶୂନ୍ୟ);

ସଂରଚନା passwd *fakepw(ଶୂନ୍ୟ);

/* auth2-pubkeyfile.c */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 auth_authorise_keyopts(ସଂରଚନା passwd *, ସଂରଚନା sshauthopt *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 auth_check_principals_ଧାଡ଼ି(ଅକ୍ଷର *, ଅଚଳ ସଂରଚନା sshkey_cert *,
    ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା sshauthopt **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 auth_process_principals(FILE *, ଅଚଳ ଅକ୍ଷର *,
    ଅଚଳ ସଂରଚନା sshkey_cert *, ସଂରଚନା sshauthopt **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 auth_check_authkey_ଧାଡ଼ି(ସଂରଚନା passwd *, ସଂରଚନା sshkey *,
    ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା sshauthopt **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 auth_check_authkeys_file(ସଂରଚନା passwd *, FILE *, ଅକ୍ଷର *,
    ସଂରଚନା sshkey *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା sshauthopt **);
FILE	*auth_openkeyfile(ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା passwd *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
FILE	*auth_openprincipals(ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା passwd *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sys_auth_passwd(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *);

#ଯଦି defined(KRB5) && !defined(HEIMDAL)
krb5_error_code ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#endif

#endif /* AUTH_H */
