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

সংরচনা passwd;
সংরচনা ssh;
সংরচনা sshbuf;
সংরচনা sshkey;
সংরচনা sshkey_cert;
সংরচনা sshauthopt;

প্রকারনির্দেশ সংরচনা Authctxt Authctxt;
প্রকারনির্দেশ সংরচনা Authmethod Authmethod;
প্রকারনির্দেশ সংরচনা KbdintDevice KbdintDevice;

সংরচনা Authctxt {
	sig_atomic_t	 success;
	পূর্ণাঙ্ক		 authenticated;	/* authenticated and alarms cancelled */
	পূর্ণাঙ্ক		 postponed;	/* authentication needs another step */
	পূর্ণাঙ্ক		 valid;		/* user exists and is allowed to login */
	পূর্ণাঙ্ক		 attempt;
	পূর্ণাঙ্ক		 failures;
	পূর্ণাঙ্ক		 pk_ok_failures;
	পূর্ণাঙ্ক		 auth_failure_already_counted;
	পূর্ণাঙ্ক		 server_caused_failure;
	পূর্ণাঙ্ক		 force_pwchange;
	বর্ণ		*user;		/* username sent by the client */
	বর্ণ		*service;
	সংরচনা passwd	*pw;		/* set if 'valid' */
	বর্ণ		*style;

	/* Method lists for multiple authentication */
	বর্ণ		**auth_methods;	/* modified from server config */
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
	বর্ণ		*krb5_ticket_file;
	বর্ণ		*krb5_ccname;
#endif
	সংরচনা sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	সংরচনা sshkey	**prev_চাবিগুলি;
	u_int		 nprev_চাবিগুলি;

	/* Last used key and ancillary information from active auth method */
	সংরচনা sshkey	*auth_method_চাবি;
	বর্ণ		*auth_method_info;

	/* Information exposed to session */
	সংরচনা sshbuf	*session_info;	/* Auth info for environment */
};

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

সংরচনা authmethod_cfg {
	ধ্রুব বর্ণ *name;
	ধ্রুব বর্ণ *synonym;
	পূর্ণাঙ্ক *enabled;
};

সংরচনা Authmethod {
	সংরচনা authmethod_cfg *cfg;
	পূর্ণাঙ্ক	(*userauth)(সংরচনা ssh *, ধ্রুব বর্ণ *);
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
সংরচনা KbdintDevice
{
	ধ্রুব বর্ণ *name;
	শূন্য*	(*init_ctx)(Authctxt*);
	পূর্ণাঙ্ক	(*query)(শূন্য *ctx, বর্ণ **name, বর্ণ **infotxt,
		    u_int *numprompts, বর্ণ ***prompts, u_int **echo_on);
	পূর্ণাঙ্ক	(*respond)(শূন্য *ctx, u_int numresp, বর্ণ **responses);
	শূন্য	(*free_ctx)(শূন্য *ctx);
};

পূর্ণাঙ্ক
auth_rhosts2(সংরচনা passwd *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);

পূর্ণাঙ্ক      auth_password(সংরচনা ssh *, ধ্রুব বর্ণ *);

পূর্ণাঙ্ক	 hostbased_চাবি_allowed(সংরচনা ssh *, সংরচনা passwd *,
	    ধ্রুব বর্ণ *, বর্ণ *, সংরচনা sshkey *);
পূর্ণাঙ্ক	 user_চাবি_allowed(সংরচনা ssh *ssh, সংরচনা passwd *, সংরচনা sshkey *,
    পূর্ণাঙ্ক, সংরচনা sshauthopt **);
পূর্ণাঙ্ক	 auth2_চাবি_already_used(Authctxt *, ধ্রুব সংরচনা sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
শূন্য	 auth2_authctxt_reset_info(Authctxt *);
শূন্য	 auth2_record_চাবি(Authctxt *, পূর্ণাঙ্ক, ধ্রুব সংরচনা sshkey *);
শূন্য	 auth2_record_info(Authctxt *authctxt, ধ্রুব বর্ণ *, ...)
	    __attribute__((__format__ (printf, 2, 3)))
	    __attribute__((__nonnull__ (2)));
শূন্য	 auth2_update_session_info(Authctxt *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);

#ifdef KRB5
পূর্ণাঙ্ক	auth_krb5_password(Authctxt *authctxt, ধ্রুব বর্ণ *password);
শূন্য	krb5_cleanup_proc(Authctxt *authctxt);
#endif /* KRB5 */

#যদি defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#অন্তর্ভাব <shadow.h>
পূর্ণাঙ্ক auth_shadow_acctexpired(সংরচনা spwd *);
পূর্ণাঙ্ক auth_shadow_pwexpired(Authctxt *);
#endif

#অন্তর্ভাব "auth-pam.h"
#অন্তর্ভাব "audit.h"
শূন্য remove_kbdint_device(ধ্রুব বর্ণ *);

শূন্য	do_authentication2(সংরচনা ssh *);

শূন্য	auth_log(সংরচনা ssh *, পূর্ণাঙ্ক, পূর্ণাঙ্ক, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);
শূন্য	auth_maxtries_exceeded(সংরচনা ssh *) __attribute__((noreturn));
শূন্য	userauth_finish(সংরচনা ssh *, পূর্ণাঙ্ক, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);
পূর্ণাঙ্ক	auth_মূল_allowed(সংরচনা ssh *, ধ্রুব বর্ণ *);
শূন্য	auth_failure_delay(Authctxt *, দ্বিগুণ);

বর্ণ	*auth2_read_banner(শূন্য);
পূর্ণাঙ্ক	 auth2_methods_valid(ধ্রুব বর্ণ *, পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 auth2_update_methods_lists(Authctxt *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);
পূর্ণাঙ্ক	 auth2_setup_methods_lists(Authctxt *);
পূর্ণাঙ্ক	 auth2_method_allowed(Authctxt *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);

পূর্ণাঙ্ক	auth2_challenge(সংরচনা ssh *, বর্ণ *);
শূন্য	auth2_challenge_stop(সংরচনা ssh *);
পূর্ণাঙ্ক	bsdauth_query(শূন্য *, বর্ণ **, বর্ণ **, u_int *, বর্ণ ***, u_int **);
পূর্ণাঙ্ক	bsdauth_respond(শূন্য *, u_int, বর্ণ **);

পূর্ণাঙ্ক	allowed_user(সংরচনা ssh *, সংরচনা passwd *);
সংরচনা passwd * getpwnamallow(সংরচনা ssh *, ধ্রুব বর্ণ *user);

বর্ণ	*expand_authorized_চাবিগুলি(ধ্রুব বর্ণ *, সংরচনা passwd *pw);
বর্ণ	*authorized_principals_file(সংরচনা passwd *);

পূর্ণাঙ্ক	 auth_চাবি_is_revoked(সংরচনা sshkey *);

ধ্রুব বর্ণ	*auth_get_canonical_hostname(সংরচনা ssh *, পূর্ণাঙ্ক);

HostStatus
check_চাবি_in_hostfiles(সংরচনা passwd *, সংরচনা sshkey *, ধ্রুব বর্ণ *,
    ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);

/* hostkey handling */
সংরচনা sshkey	*get_hostkey_by_index(পূর্ণাঙ্ক);
সংরচনা sshkey	*get_hostkey_public_by_index(পূর্ণাঙ্ক, সংরচনা ssh *);
সংরচনা sshkey	*get_hostkey_public_by_type(পূর্ণাঙ্ক, পূর্ণাঙ্ক, সংরচনা ssh *);
সংরচনা sshkey	*get_hostkey_private_by_type(পূর্ণাঙ্ক, পূর্ণাঙ্ক, সংরচনা ssh *);
পূর্ণাঙ্ক	 get_hostkey_index(সংরচনা sshkey *, পূর্ণাঙ্ক, সংরচনা ssh *);
পূর্ণাঙ্ক	 sshd_hostkey_sign(সংরচনা ssh *, সংরচনা sshkey *, সংরচনা sshkey *,
    u_char **, size_t *, ধ্রুব u_char *, size_t, ধ্রুব বর্ণ *);

/* Key / cert options linkage to auth layer */
পূর্ণাঙ্ক	 auth_activate_options(সংরচনা ssh *, সংরচনা sshauthopt *);
শূন্য	 auth_restrict_session(সংরচনা ssh *);
শূন্য	 auth_log_authopts(ধ্রুব বর্ণ *, ধ্রুব সংরচনা sshauthopt *, পূর্ণাঙ্ক);

/* debug messages during authentication */
শূন্য	 auth_debug_add(ধ্রুব বর্ণ *fmt,...)
    __attribute__((format(printf, 1, 2)));
শূন্য	 auth_debug_send(সংরচনা ssh *);
শূন্য	 auth_debug_reset(শূন্য);

সংরচনা passwd *fakepw(শূন্য);

/* auth2-pubkeyfile.c */
পূর্ণাঙ্ক	 auth_authorise_keyopts(সংরচনা passwd *, সংরচনা sshauthopt *, পূর্ণাঙ্ক,
    ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);
পূর্ণাঙ্ক	 auth_check_principals_সারি(বর্ণ *, ধ্রুব সংরচনা sshkey_cert *,
    ধ্রুব বর্ণ *, সংরচনা sshauthopt **);
পূর্ণাঙ্ক	 auth_process_principals(FILE *, ধ্রুব বর্ণ *,
    ধ্রুব সংরচনা sshkey_cert *, সংরচনা sshauthopt **);
পূর্ণাঙ্ক	 auth_check_authkey_সারি(সংরচনা passwd *, সংরচনা sshkey *,
    বর্ণ *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, সংরচনা sshauthopt **);
পূর্ণাঙ্ক	 auth_check_authkeys_file(সংরচনা passwd *, FILE *, বর্ণ *,
    সংরচনা sshkey *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, সংরচনা sshauthopt **);
FILE	*auth_openkeyfile(ধ্রুব বর্ণ *, সংরচনা passwd *, পূর্ণাঙ্ক);
FILE	*auth_openprincipals(ধ্রুব বর্ণ *, সংরচনা passwd *, পূর্ণাঙ্ক);

পূর্ণাঙ্ক	 sys_auth_passwd(সংরচনা ssh *, ধ্রুব বর্ণ *);

#যদি defined(KRB5) && !defined(HEIMDAL)
krb5_error_code ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#endif

#endif /* AUTH_H */
