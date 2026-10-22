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

#నిర్వచితం_కాకపోతే AUTH_H
#నిర్వచించు AUTH_H

#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdio.h>

#నిర్వచితమైతే HAVE_LOGIN_CAP
#అన్తర్భావ <login_cap.h>
#అయితే_ముగింపు
#నిర్వచితమైతే BSD_AUTH
#అన్తర్భావ <bsd_auth.h>
#అయితే_ముగింపు
#నిర్వచితమైతే KRB5
#అన్తర్భావ <krb5.h>
#అయితే_ముగింపు

నిర్మాణం passwd;
నిర్మాణం ssh;
నిర్మాణం sshbuf;
నిర్మాణం sshkey;
నిర్మాణం sshkey_cert;
నిర్మాణం sshauthopt;

రకనిర్వచనం నిర్మాణం Authctxt Authctxt;
రకనిర్వచనం నిర్మాణం Authmethod Authmethod;
రకనిర్వచనం నిర్మాణం KbdintDevice KbdintDevice;

నిర్మాణం Authctxt {
	sig_atomic_t	 success;
	పూర్ణాంకం		 authenticated;	/* authenticated and alarms cancelled */
	పూర్ణాంకం		 postponed;	/* authentication needs another step */
	పూర్ణాంకం		 valid;		/* user exists and is allowed to login */
	పూర్ణాంకం		 attempt;
	పూర్ణాంకం		 failures;
	పూర్ణాంకం		 pk_ok_failures;
	పూర్ణాంకం		 auth_failure_already_counted;
	పూర్ణాంకం		 server_caused_failure;
	పూర్ణాంకం		 force_pwchange;
	అక్షరం		*user;		/* username sent by the client */
	అక్షరం		*service;
	నిర్మాణం passwd	*pw;		/* set if 'valid' */
	అక్షరం		*style;

	/* Method lists for multiple authentication */
	అక్షరం		**auth_methods;	/* modified from server config */
	u_int		 అంకె_auth_methods;

	/* Authentication method-specific data */
	శూన్య		*methoddata;
	శూన్య		*kbdintctxt;
#నిర్వచితమైతే BSD_AUTH
	auth_session_t	*as;
#అయితే_ముగింపు
#నిర్వచితమైతే KRB5
	krb5_context	 krb5_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	అక్షరం		*krb5_ticket_file;
	అక్షరం		*krb5_ccname;
#అయితే_ముగింపు
	నిర్మాణం sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	నిర్మాణం sshkey	**prev_కీలకాలు;
	u_int		 nprev_కీలకాలు;

	/* Last used key and ancillary information from active auth method */
	నిర్మాణం sshkey	*auth_పద్ధతి_కీలకం;
	అక్షరం		*auth_పద్ధతి_info;

	/* Information exposed to session */
	నిర్మాణం sshbuf	*session_info;	/* Auth info for environment */
};

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

నిర్మాణం authmethod_cfg {
	స్థిరరాశి అక్షరం *name;
	స్థిరరాశి అక్షరం *synonym;
	పూర్ణాంకం *enabled;
};

నిర్మాణం Authmethod {
	నిర్మాణం authmethod_cfg *cfg;
	పూర్ణాంకం	(*userauth)(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *);
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
నిర్మాణం KbdintDevice
{
	స్థిరరాశి అక్షరం *name;
	శూన్య*	(*init_ctx)(Authctxt*);
	పూర్ణాంకం	(*query)(శూన్య *ctx, అక్షరం **name, అక్షరం **infotxt,
		    u_int *numprompts, అక్షరం ***prompts, u_int **echo_on);
	పూర్ణాంకం	(*respond)(శూన్య *ctx, u_int numresp, అక్షరం **responses);
	శూన్య	(*free_ctx)(శూన్య *ctx);
};

పూర్ణాంకం
auth_rhosts2(నిర్మాణం passwd *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);

పూర్ణాంకం      auth_password(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *);

పూర్ణాంకం	 hostbased_కీలకం_allowed(నిర్మాణం ssh *, నిర్మాణం passwd *,
	    స్థిరరాశి అక్షరం *, అక్షరం *, నిర్మాణం sshkey *);
పూర్ణాంకం	 user_కీలకం_allowed(నిర్మాణం ssh *ssh, నిర్మాణం passwd *, నిర్మాణం sshkey *,
    పూర్ణాంకం, నిర్మాణం sshauthopt **);
పూర్ణాంకం	 auth2_కీలకం_already_వాడిన(Authctxt *, స్థిరరాశి నిర్మాణం sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
శూన్య	 auth2_authctxt_reset_info(Authctxt *);
శూన్య	 auth2_రికార్డు_కీలకం(Authctxt *, పూర్ణాంకం, స్థిరరాశి నిర్మాణం sshkey *);
శూన్య	 auth2_రికార్డు_info(Authctxt *authctxt, స్థిరరాశి అక్షరం *, ...)
	    __attribute__((__format__ (రాయి, 2, 3)))
	    __attribute__((__nonnull__ (2)));
శూన్య	 auth2_update_session_info(Authctxt *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);

#నిర్వచితమైతే KRB5
పూర్ణాంకం	auth_krb5_password(Authctxt *authctxt, స్థిరరాశి అక్షరం *password);
శూన్య	krb5_cleanup_proc(Authctxt *authctxt);
#అయితే_ముగింపు /* KRB5 */

#ఒకవేళ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#అన్తర్భావ <shadow.h>
పూర్ణాంకం auth_shadow_acctexpired(నిర్మాణం spwd *);
పూర్ణాంకం auth_shadow_pwexpired(Authctxt *);
#అయితే_ముగింపు

#అన్తర్భావ "auth-pam.h"
#అన్తర్భావ "audit.h"
శూన్య remove_kbdint_device(స్థిరరాశి అక్షరం *);

శూన్య	do_authentication2(నిర్మాణం ssh *);

శూన్య	auth_log(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
శూన్య	auth_maxtries_exceeded(నిర్మాణం ssh *) __attribute__((noreturn));
శూన్య	userauth_ముగింపు(నిర్మాణం ssh *, పూర్ణాంకం, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	auth_మూలం_allowed(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *);
శూన్య	auth_failure_delay(Authctxt *, ద్విగుణ);

అక్షరం	*auth2_read_banner(శూన్య);
పూర్ణాంకం	 auth2_methods_valid(స్థిరరాశి అక్షరం *, పూర్ణాంకం);
పూర్ణాంకం	 auth2_update_methods_lists(Authctxt *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 auth2_అమరిక_methods_lists(Authctxt *);
పూర్ణాంకం	 auth2_పద్ధతి_allowed(Authctxt *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);

పూర్ణాంకం	auth2_challenge(నిర్మాణం ssh *, అక్షరం *);
శూన్య	auth2_challenge_stop(నిర్మాణం ssh *);
పూర్ణాంకం	bsdauth_query(శూన్య *, అక్షరం **, అక్షరం **, u_int *, అక్షరం ***, u_int **);
పూర్ణాంకం	bsdauth_respond(శూన్య *, u_int, అక్షరం **);

పూర్ణాంకం	allowed_user(నిర్మాణం ssh *, నిర్మాణం passwd *);
నిర్మాణం passwd * getpwnamallow(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *user);

అక్షరం	*expand_authorized_కీలకాలు(స్థిరరాశి అక్షరం *, నిర్మాణం passwd *pw);
అక్షరం	*authorized_principals_file(నిర్మాణం passwd *);

పూర్ణాంకం	 auth_కీలకం_is_revoked(నిర్మాణం sshkey *);

స్థిరరాశి అక్షరం	*auth_get_canonical_hostname(నిర్మాణం ssh *, పూర్ణాంకం);

Host_స్థితి
check_కీలకం_లోపల_hostfiles(నిర్మాణం passwd *, నిర్మాణం sshkey *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);

/* hostkey handling */
నిర్మాణం sshkey	*get_hostkey_by_సూచీ(పూర్ణాంకం);
నిర్మాణం sshkey	*get_hostkey_ప్రజా_by_సూచీ(పూర్ణాంకం, నిర్మాణం ssh *);
నిర్మాణం sshkey	*get_hostkey_ప్రజా_by_type(పూర్ణాంకం, పూర్ణాంకం, నిర్మాణం ssh *);
నిర్మాణం sshkey	*get_hostkey_వ్యక్తిగత_by_type(పూర్ణాంకం, పూర్ణాంకం, నిర్మాణం ssh *);
పూర్ణాంకం	 get_hostkey_సూచీ(నిర్మాణం sshkey *, పూర్ణాంకం, నిర్మాణం ssh *);
పూర్ణాంకం	 sshd_hostkey_sign(నిర్మాణం ssh *, నిర్మాణం sshkey *, నిర్మాణం sshkey *,
    u_char **, కొలత_t *, స్థిరరాశి u_char *, కొలత_t, స్థిరరాశి అక్షరం *);

/* Key / cert options linkage to auth layer */
పూర్ణాంకం	 auth_activate_options(నిర్మాణం ssh *, నిర్మాణం sshauthopt *);
శూన్య	 auth_restrict_session(నిర్మాణం ssh *);
శూన్య	 auth_log_authopts(స్థిరరాశి అక్షరం *, స్థిరరాశి నిర్మాణం sshauthopt *, పూర్ణాంకం);

/* debug messages during authentication */
శూన్య	 auth_debug_కూడు(స్థిరరాశి అక్షరం *fmt,...)
    __attribute__((format(రాయి, 1, 2)));
శూన్య	 auth_debug_send(నిర్మాణం ssh *);
శూన్య	 auth_debug_reset(శూన్య);

నిర్మాణం passwd *fakepw(శూన్య);

/* auth2-pubkeyfile.c */
పూర్ణాంకం	 auth_authorise_keyopts(నిర్మాణం passwd *, నిర్మాణం sshauthopt *, పూర్ణాంకం,
    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 auth_check_principals_పంక్తి(అక్షరం *, స్థిరరాశి నిర్మాణం sshkey_cert *,
    స్థిరరాశి అక్షరం *, నిర్మాణం sshauthopt **);
పూర్ణాంకం	 auth_process_principals(FILE *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి నిర్మాణం sshkey_cert *, నిర్మాణం sshauthopt **);
పూర్ణాంకం	 auth_check_authkey_పంక్తి(నిర్మాణం passwd *, నిర్మాణం sshkey *,
    అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, నిర్మాణం sshauthopt **);
పూర్ణాంకం	 auth_check_authkeys_file(నిర్మాణం passwd *, FILE *, అక్షరం *,
    నిర్మాణం sshkey *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, నిర్మాణం sshauthopt **);
FILE	*auth_openkeyfile(స్థిరరాశి అక్షరం *, నిర్మాణం passwd *, పూర్ణాంకం);
FILE	*auth_openprincipals(స్థిరరాశి అక్షరం *, నిర్మాణం passwd *, పూర్ణాంకం);

పూర్ణాంకం	 sys_auth_passwd(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *);

#ఒకవేళ defined(KRB5) && !defined(HEIMDAL)
krb5_error_సంకేతం ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#అయితే_ముగింపు

#అయితే_ముగింపు /* AUTH_H */
