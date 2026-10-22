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

#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdio.h>

#ifdef HAVE_LOGIN_CAP
#অন্তর্ভাব <login_cap.h>
#endif
#ifdef BSD_AUTH
#অন্তর্ভাব <bsd_auth.h>
#endif
#ifdef KRB5
#অন্তর্ভাব <krb5.h>
#endif

কাঠামো passwd;
কাঠামো ssh;
কাঠামো sshbuf;
কাঠামো sshkey;
কাঠামো sshkey_cert;
কাঠামো sshauthopt;

প্রকারলেখ কাঠামো Authctxt Authctxt;
প্রকারলেখ কাঠামো Authmethod Authmethod;
প্রকারলেখ কাঠামো KbdintDevice KbdintDevice;

কাঠামো Authctxt {
	sig_atomic_t	 success;
	পূর্ণসংখ্যা		 authenticated;	/* authenticated and alarms cancelled */
	পূর্ণসংখ্যা		 postponed;	/* authentication needs another step */
	পূর্ণসংখ্যা		 valid;		/* user exists and is allowed to login */
	পূর্ণসংখ্যা		 attempt;
	পূর্ণসংখ্যা		 failures;
	পূর্ণসংখ্যা		 pk_ok_failures;
	পূর্ণসংখ্যা		 auth_failure_already_counted;
	পূর্ণসংখ্যা		 server_caused_failure;
	পূর্ণসংখ্যা		 force_pwchange;
	অক্ষর		*user;		/* username sent by the client */
	অক্ষর		*service;
	কাঠামো passwd	*pw;		/* set if 'valid' */
	অক্ষর		*style;

	/* Method lists for multiple authentication */
	অক্ষর		**auth_methods;	/* modified from server config */
	u_int		 অঙ্ক_auth_methods;

	/* Authentication method-specific data */
	শূন্য		*methoddata;
	শূন্য		*kbdintctxt;
#ifdef BSD_AUTH
	auth_session_t	*as;
#endif
#ifdef KRB5
	krb5_context	 krb5_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	অক্ষর		*krb5_ticket_file;
	অক্ষর		*krb5_ccname;
#endif
	কাঠামো sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	কাঠামো sshkey	**পূর্ব_চাবিগুলি;
	u_int		 nprev_চাবিগুলি;

	/* Last used key and ancillary information from active auth method */
	কাঠামো sshkey	*auth_method_চাবি;
	অক্ষর		*auth_method_info;

	/* Information exposed to session */
	কাঠামো sshbuf	*session_info;	/* Auth info for environment */
};

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

কাঠামো authmethod_cfg {
	ধ্রুবক অক্ষর *name;
	ধ্রুবক অক্ষর *synonym;
	পূর্ণসংখ্যা *enabled;
};

কাঠামো Authmethod {
	কাঠামো authmethod_cfg *cfg;
	পূর্ণসংখ্যা	(*userauth)(কাঠামো ssh *, ধ্রুবক অক্ষর *);
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
কাঠামো KbdintDevice
{
	ধ্রুবক অক্ষর *name;
	শূন্য*	(*init_ctx)(Authctxt*);
	পূর্ণসংখ্যা	(*query)(শূন্য *ctx, অক্ষর **name, অক্ষর **infotxt,
		    u_int *numprompts, অক্ষর ***prompts, u_int **echo_on);
	পূর্ণসংখ্যা	(*respond)(শূন্য *ctx, u_int numresp, অক্ষর **responses);
	শূন্য	(*free_ctx)(শূন্য *ctx);
};

পূর্ণসংখ্যা
auth_rhosts2(কাঠামো passwd *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);

পূর্ণসংখ্যা      auth_password(কাঠামো ssh *, ধ্রুবক অক্ষর *);

পূর্ণসংখ্যা	 hostbased_চাবি_allowed(কাঠামো ssh *, কাঠামো passwd *,
	    ধ্রুবক অক্ষর *, অক্ষর *, কাঠামো sshkey *);
পূর্ণসংখ্যা	 user_চাবি_allowed(কাঠামো ssh *ssh, কাঠামো passwd *, কাঠামো sshkey *,
    পূর্ণসংখ্যা, কাঠামো sshauthopt **);
পূর্ণসংখ্যা	 auth2_চাবি_already_used(Authctxt *, ধ্রুবক কাঠামো sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
শূন্য	 auth2_authctxt_reset_info(Authctxt *);
শূন্য	 auth2_record_চাবি(Authctxt *, পূর্ণসংখ্যা, ধ্রুবক কাঠামো sshkey *);
শূন্য	 auth2_record_info(Authctxt *authctxt, ধ্রুবক অক্ষর *, ...)
	    __attribute__((__format__ (printf, 2, 3)))
	    __attribute__((__nonnull__ (2)));
শূন্য	 auth2_update_session_info(Authctxt *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);

#ifdef KRB5
পূর্ণসংখ্যা	auth_krb5_password(Authctxt *authctxt, ধ্রুবক অক্ষর *password);
শূন্য	krb5_cleanup_proc(Authctxt *authctxt);
#endif /* KRB5 */

#যদি defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#অন্তর্ভাব <shadow.h>
পূর্ণসংখ্যা auth_shadow_acctexpired(কাঠামো spwd *);
পূর্ণসংখ্যা auth_shadow_pwexpired(Authctxt *);
#endif

#অন্তর্ভাব "auth-pam.h"
#অন্তর্ভাব "audit.h"
শূন্য remove_kbdint_device(ধ্রুবক অক্ষর *);

শূন্য	do_authentication2(কাঠামো ssh *);

শূন্য	auth_log(কাঠামো ssh *, পূর্ণসংখ্যা, পূর্ণসংখ্যা, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
শূন্য	auth_maxtries_exceeded(কাঠামো ssh *) __attribute__((noreturn));
শূন্য	userauth_finish(কাঠামো ssh *, পূর্ণসংখ্যা, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	auth_মূল_allowed(কাঠামো ssh *, ধ্রুবক অক্ষর *);
শূন্য	auth_failure_delay(Authctxt *, দ্বিগুণ);

অক্ষর	*auth2_read_banner(শূন্য);
পূর্ণসংখ্যা	 auth2_methods_valid(ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 auth2_update_methods_lists(Authctxt *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 auth2_setup_methods_lists(Authctxt *);
পূর্ণসংখ্যা	 auth2_method_allowed(Authctxt *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);

পূর্ণসংখ্যা	auth2_challenge(কাঠামো ssh *, অক্ষর *);
শূন্য	auth2_challenge_stop(কাঠামো ssh *);
পূর্ণসংখ্যা	bsdauth_query(শূন্য *, অক্ষর **, অক্ষর **, u_int *, অক্ষর ***, u_int **);
পূর্ণসংখ্যা	bsdauth_respond(শূন্য *, u_int, অক্ষর **);

পূর্ণসংখ্যা	allowed_user(কাঠামো ssh *, কাঠামো passwd *);
কাঠামো passwd * getpwnamallow(কাঠামো ssh *, ধ্রুবক অক্ষর *user);

অক্ষর	*expand_authorized_চাবিগুলি(ধ্রুবক অক্ষর *, কাঠামো passwd *pw);
অক্ষর	*authorized_principals_file(কাঠামো passwd *);

পূর্ণসংখ্যা	 auth_চাবি_is_revoked(কাঠামো sshkey *);

ধ্রুবক অক্ষর	*auth_get_canonical_hostname(কাঠামো ssh *, পূর্ণসংখ্যা);

HostStatus
check_চাবি_in_hostfiles(কাঠামো passwd *, কাঠামো sshkey *, ধ্রুবক অক্ষর *,
    ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);

/* hostkey handling */
কাঠামো sshkey	*get_hostkey_by_সূচক(পূর্ণসংখ্যা);
কাঠামো sshkey	*get_hostkey_public_by_সূচক(পূর্ণসংখ্যা, কাঠামো ssh *);
কাঠামো sshkey	*get_hostkey_public_by_type(পূর্ণসংখ্যা, পূর্ণসংখ্যা, কাঠামো ssh *);
কাঠামো sshkey	*get_hostkey_private_by_type(পূর্ণসংখ্যা, পূর্ণসংখ্যা, কাঠামো ssh *);
পূর্ণসংখ্যা	 get_hostkey_সূচক(কাঠামো sshkey *, পূর্ণসংখ্যা, কাঠামো ssh *);
পূর্ণসংখ্যা	 sshd_hostkey_sign(কাঠামো ssh *, কাঠামো sshkey *, কাঠামো sshkey *,
    u_char **, আকার_t *, ধ্রুবক u_char *, আকার_t, ধ্রুবক অক্ষর *);

/* Key / cert options linkage to auth layer */
পূর্ণসংখ্যা	 auth_activate_options(কাঠামো ssh *, কাঠামো sshauthopt *);
শূন্য	 auth_restrict_session(কাঠামো ssh *);
শূন্য	 auth_log_authopts(ধ্রুবক অক্ষর *, ধ্রুবক কাঠামো sshauthopt *, পূর্ণসংখ্যা);

/* debug messages during authentication */
শূন্য	 auth_debug_add(ধ্রুবক অক্ষর *fmt,...)
    __attribute__((format(printf, 1, 2)));
শূন্য	 auth_debug_send(কাঠামো ssh *);
শূন্য	 auth_debug_reset(শূন্য);

কাঠামো passwd *fakepw(শূন্য);

/* auth2-pubkeyfile.c */
পূর্ণসংখ্যা	 auth_authorise_keyopts(কাঠামো passwd *, কাঠামো sshauthopt *, পূর্ণসংখ্যা,
    ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 auth_check_principals_সারি(অক্ষর *, ধ্রুবক কাঠামো sshkey_cert *,
    ধ্রুবক অক্ষর *, কাঠামো sshauthopt **);
পূর্ণসংখ্যা	 auth_process_principals(FILE *, ধ্রুবক অক্ষর *,
    ধ্রুবক কাঠামো sshkey_cert *, কাঠামো sshauthopt **);
পূর্ণসংখ্যা	 auth_check_authkey_সারি(কাঠামো passwd *, কাঠামো sshkey *,
    অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, কাঠামো sshauthopt **);
পূর্ণসংখ্যা	 auth_check_authkeys_file(কাঠামো passwd *, FILE *, অক্ষর *,
    কাঠামো sshkey *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, কাঠামো sshauthopt **);
FILE	*auth_openkeyfile(ধ্রুবক অক্ষর *, কাঠামো passwd *, পূর্ণসংখ্যা);
FILE	*auth_openprincipals(ধ্রুবক অক্ষর *, কাঠামো passwd *, পূর্ণসংখ্যা);

পূর্ণসংখ্যা	 sys_auth_passwd(কাঠামো ssh *, ধ্রুবক অক্ষর *);

#যদি defined(KRB5) && !defined(HEIMDAL)
krb5_error_code ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#endif

#endif /* AUTH_H */
