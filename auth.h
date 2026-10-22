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

प्रकारनिर्देश संरचना Authctxt Authctxt;
प्रकारनिर्देश संरचना Authmethod Authmethod;
प्रकारनिर्देश संरचना KbdintDevice KbdintDevice;

संरचना Authctxt {
	sig_atomic_t	 success;
	पूर्णाङ्क		 authenticated;	/* authenticated and alarms cancelled */
	पूर्णाङ्क		 postponed;	/* authentication needs another step */
	पूर्णाङ्क		 valid;		/* user exists and is allowed to login */
	पूर्णाङ्क		 attempt;
	पूर्णाङ्क		 failures;
	पूर्णाङ्क		 pk_ok_failures;
	पूर्णाङ्क		 auth_failure_already_counted;
	पूर्णाङ्क		 server_caused_failure;
	पूर्णाङ्क		 force_pwchange;
	वर्ण		*user;		/* username sent by the client */
	वर्ण		*service;
	संरचना passwd	*pw;		/* set if 'valid' */
	वर्ण		*style;

	/* Method lists for multiple authentication */
	वर्ण		**auth_methods;	/* modified from server config */
	u_int		 अङ्कः_auth_methods;

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
	वर्ण		*krb5_ticket_file;
	वर्ण		*krb5_ccname;
#endif
	संरचना sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	संरचना sshkey	**prev_कुञ्चिकाः;
	u_int		 nprev_कुञ्चिकाः;

	/* Last used key and ancillary information from active auth method */
	संरचना sshkey	*auth_method_कुञ्चिका;
	वर्ण		*auth_method_info;

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
	ध्रुव वर्ण *name;
	ध्रुव वर्ण *synonym;
	पूर्णाङ्क *enabled;
};

संरचना Authmethod {
	संरचना authmethod_cfg *cfg;
	पूर्णाङ्क	(*userauth)(संरचना ssh *, ध्रुव वर्ण *);
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
	ध्रुव वर्ण *name;
	शून्य*	(*init_ctx)(Authctxt*);
	पूर्णाङ्क	(*query)(शून्य *ctx, वर्ण **name, वर्ण **infotxt,
		    u_int *numprompts, वर्ण ***prompts, u_int **echo_on);
	पूर्णाङ्क	(*respond)(शून्य *ctx, u_int numresp, वर्ण **responses);
	शून्य	(*free_ctx)(शून्य *ctx);
};

पूर्णाङ्क
auth_rhosts2(संरचना passwd *, ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *);

पूर्णाङ्क      auth_password(संरचना ssh *, ध्रुव वर्ण *);

पूर्णाङ्क	 hostbased_कुञ्चिका_allowed(संरचना ssh *, संरचना passwd *,
	    ध्रुव वर्ण *, वर्ण *, संरचना sshkey *);
पूर्णाङ्क	 user_कुञ्चिका_allowed(संरचना ssh *ssh, संरचना passwd *, संरचना sshkey *,
    पूर्णाङ्क, संरचना sshauthopt **);
पूर्णाङ्क	 auth2_कुञ्चिका_already_used(Authctxt *, ध्रुव संरचना sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
शून्य	 auth2_authctxt_reset_info(Authctxt *);
शून्य	 auth2_record_कुञ्चिका(Authctxt *, पूर्णाङ्क, ध्रुव संरचना sshkey *);
शून्य	 auth2_record_info(Authctxt *authctxt, ध्रुव वर्ण *, ...)
	    __attribute__((__format__ (printf, 2, 3)))
	    __attribute__((__nonnull__ (2)));
शून्य	 auth2_update_session_info(Authctxt *, ध्रुव वर्ण *, ध्रुव वर्ण *);

#ifdef KRB5
पूर्णाङ्क	auth_krb5_password(Authctxt *authctxt, ध्रुव वर्ण *password);
शून्य	krb5_cleanup_proc(Authctxt *authctxt);
#endif /* KRB5 */

#सचे defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#अन्तर्भाव <shadow.h>
पूर्णाङ्क auth_shadow_acctexpired(संरचना spwd *);
पूर्णाङ्क auth_shadow_pwexpired(Authctxt *);
#endif

#अन्तर्भाव "auth-pam.h"
#अन्तर्भाव "audit.h"
शून्य remove_kbdint_device(ध्रुव वर्ण *);

शून्य	do_authentication2(संरचना ssh *);

शून्य	auth_log(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क, ध्रुव वर्ण *, ध्रुव वर्ण *);
शून्य	auth_maxtries_exceeded(संरचना ssh *) __attribute__((noreturn));
शून्य	userauth_finish(संरचना ssh *, पूर्णाङ्क, ध्रुव वर्ण *, ध्रुव वर्ण *);
पूर्णाङ्क	auth_मूलम्_allowed(संरचना ssh *, ध्रुव वर्ण *);
शून्य	auth_failure_delay(Authctxt *, द्विगुण);

वर्ण	*auth2_read_banner(शून्य);
पूर्णाङ्क	 auth2_methods_valid(ध्रुव वर्ण *, पूर्णाङ्क);
पूर्णाङ्क	 auth2_update_methods_lists(Authctxt *, ध्रुव वर्ण *, ध्रुव वर्ण *);
पूर्णाङ्क	 auth2_setup_methods_lists(Authctxt *);
पूर्णाङ्क	 auth2_method_allowed(Authctxt *, ध्रुव वर्ण *, ध्रुव वर्ण *);

पूर्णाङ्क	auth2_challenge(संरचना ssh *, वर्ण *);
शून्य	auth2_challenge_stop(संरचना ssh *);
पूर्णाङ्क	bsdauth_query(शून्य *, वर्ण **, वर्ण **, u_int *, वर्ण ***, u_int **);
पूर्णाङ्क	bsdauth_respond(शून्य *, u_int, वर्ण **);

पूर्णाङ्क	allowed_user(संरचना ssh *, संरचना passwd *);
संरचना passwd * getpwnamallow(संरचना ssh *, ध्रुव वर्ण *user);

वर्ण	*expand_authorized_कुञ्चिकाः(ध्रुव वर्ण *, संरचना passwd *pw);
वर्ण	*authorized_principals_file(संरचना passwd *);

पूर्णाङ्क	 auth_कुञ्चिका_is_revoked(संरचना sshkey *);

ध्रुव वर्ण	*auth_get_canonical_hostname(संरचना ssh *, पूर्णाङ्क);

HostStatus
check_कुञ्चिका_in_hostfiles(संरचना passwd *, संरचना sshkey *, ध्रुव वर्ण *,
    ध्रुव वर्ण *, ध्रुव वर्ण *);

/* hostkey handling */
संरचना sshkey	*get_hostkey_by_index(पूर्णाङ्क);
संरचना sshkey	*get_hostkey_public_by_index(पूर्णाङ्क, संरचना ssh *);
संरचना sshkey	*get_hostkey_public_by_type(पूर्णाङ्क, पूर्णाङ्क, संरचना ssh *);
संरचना sshkey	*get_hostkey_private_by_type(पूर्णाङ्क, पूर्णाङ्क, संरचना ssh *);
पूर्णाङ्क	 get_hostkey_index(संरचना sshkey *, पूर्णाङ्क, संरचना ssh *);
पूर्णाङ्क	 sshd_hostkey_sign(संरचना ssh *, संरचना sshkey *, संरचना sshkey *,
    u_char **, size_t *, ध्रुव u_char *, size_t, ध्रुव वर्ण *);

/* Key / cert options linkage to auth layer */
पूर्णाङ्क	 auth_activate_options(संरचना ssh *, संरचना sshauthopt *);
शून्य	 auth_restrict_session(संरचना ssh *);
शून्य	 auth_log_authopts(ध्रुव वर्ण *, ध्रुव संरचना sshauthopt *, पूर्णाङ्क);

/* debug messages during authentication */
शून्य	 auth_debug_add(ध्रुव वर्ण *fmt,...)
    __attribute__((format(printf, 1, 2)));
शून्य	 auth_debug_send(संरचना ssh *);
शून्य	 auth_debug_reset(शून्य);

संरचना passwd *fakepw(शून्य);

/* auth2-pubkeyfile.c */
पूर्णाङ्क	 auth_authorise_keyopts(संरचना passwd *, संरचना sshauthopt *, पूर्णाङ्क,
    ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *);
पूर्णाङ्क	 auth_check_principals_पङ्क्तिः(वर्ण *, ध्रुव संरचना sshkey_cert *,
    ध्रुव वर्ण *, संरचना sshauthopt **);
पूर्णाङ्क	 auth_process_principals(FILE *, ध्रुव वर्ण *,
    ध्रुव संरचना sshkey_cert *, संरचना sshauthopt **);
पूर्णाङ्क	 auth_check_authkey_पङ्क्तिः(संरचना passwd *, संरचना sshkey *,
    वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *, संरचना sshauthopt **);
पूर्णाङ्क	 auth_check_authkeys_file(संरचना passwd *, FILE *, वर्ण *,
    संरचना sshkey *, ध्रुव वर्ण *, ध्रुव वर्ण *, संरचना sshauthopt **);
FILE	*auth_openkeyfile(ध्रुव वर्ण *, संरचना passwd *, पूर्णाङ्क);
FILE	*auth_openprincipals(ध्रुव वर्ण *, संरचना passwd *, पूर्णाङ्क);

पूर्णाङ्क	 sys_auth_passwd(संरचना ssh *, ध्रुव वर्ण *);

#सचे defined(KRB5) && !defined(HEIMDAL)
krb5_error_code ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#endif

#endif /* AUTH_H */
