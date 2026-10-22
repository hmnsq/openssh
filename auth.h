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

#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdio.h>

#ifdef HAVE_LOGIN_CAP
#அந்தர்பாவ <login_cap.h>
#endif
#ifdef BSD_AUTH
#அந்தர்பாவ <bsd_auth.h>
#endif
#ifdef KRB5
#அந்தர்பாவ <krb5.h>
#endif

கட்டமைப்பு passwd;
கட்டமைப்பு ssh;
கட்டமைப்பு sshbuf;
கட்டமைப்பு sshkey;
கட்டமைப்பு sshkey_cert;
கட்டமைப்பு sshauthopt;

வகைவரை கட்டமைப்பு Authctxt Authctxt;
வகைவரை கட்டமைப்பு Authmethod Authmethod;
வகைவரை கட்டமைப்பு KbdintDevice KbdintDevice;

கட்டமைப்பு Authctxt {
	sig_atomic_t	 success;
	முழு		 authenticated;	/* authenticated and alarms cancelled */
	முழு		 postponed;	/* authentication needs another step */
	முழு		 valid;		/* user exists and is allowed to login */
	முழு		 attempt;
	முழு		 failures;
	முழு		 pk_ok_failures;
	முழு		 auth_failure_already_counted;
	முழு		 server_caused_failure;
	முழு		 force_pwchange;
	எழுத்து		*user;		/* username sent by the client */
	எழுத்து		*service;
	கட்டமைப்பு passwd	*pw;		/* set if 'valid' */
	எழுத்து		*style;

	/* Method lists for multiple authentication */
	எழுத்து		**auth_methods;	/* modified from server config */
	u_int		 இலக்கம்_auth_methods;

	/* Authentication method-specific data */
	வெறுமை		*methoddata;
	வெறுமை		*kbdintctxt;
#ifdef BSD_AUTH
	auth_session_t	*as;
#endif
#ifdef KRB5
	krb5_context	 krb5_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	எழுத்து		*krb5_ticket_file;
	எழுத்து		*krb5_ccname;
#endif
	கட்டமைப்பு sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	கட்டமைப்பு sshkey	**prev_சாவிகள்;
	u_int		 nprev_சாவிகள்;

	/* Last used key and ancillary information from active auth method */
	கட்டமைப்பு sshkey	*auth_method_சாவி;
	எழுத்து		*auth_method_info;

	/* Information exposed to session */
	கட்டமைப்பு sshbuf	*session_info;	/* Auth info for environment */
};

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

கட்டமைப்பு authmethod_cfg {
	மாறிலி எழுத்து *name;
	மாறிலி எழுத்து *synonym;
	முழு *enabled;
};

கட்டமைப்பு Authmethod {
	கட்டமைப்பு authmethod_cfg *cfg;
	முழு	(*userauth)(கட்டமைப்பு ssh *, மாறிலி எழுத்து *);
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
கட்டமைப்பு KbdintDevice
{
	மாறிலி எழுத்து *name;
	வெறுமை*	(*init_ctx)(Authctxt*);
	முழு	(*query)(வெறுமை *ctx, எழுத்து **name, எழுத்து **infotxt,
		    u_int *numprompts, எழுத்து ***prompts, u_int **echo_on);
	முழு	(*respond)(வெறுமை *ctx, u_int numresp, எழுத்து **responses);
	வெறுமை	(*free_ctx)(வெறுமை *ctx);
};

முழு
auth_rhosts2(கட்டமைப்பு passwd *, மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *);

முழு      auth_password(கட்டமைப்பு ssh *, மாறிலி எழுத்து *);

முழு	 hostbased_சாவி_allowed(கட்டமைப்பு ssh *, கட்டமைப்பு passwd *,
	    மாறிலி எழுத்து *, எழுத்து *, கட்டமைப்பு sshkey *);
முழு	 user_சாவி_allowed(கட்டமைப்பு ssh *ssh, கட்டமைப்பு passwd *, கட்டமைப்பு sshkey *,
    முழு, கட்டமைப்பு sshauthopt **);
முழு	 auth2_சாவி_already_used(Authctxt *, மாறிலி கட்டமைப்பு sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
வெறுமை	 auth2_authctxt_reset_info(Authctxt *);
வெறுமை	 auth2_record_சாவி(Authctxt *, முழு, மாறிலி கட்டமைப்பு sshkey *);
வெறுமை	 auth2_record_info(Authctxt *authctxt, மாறிலி எழுத்து *, ...)
	    __attribute__((__format__ (printf, 2, 3)))
	    __attribute__((__nonnull__ (2)));
வெறுமை	 auth2_update_session_info(Authctxt *, மாறிலி எழுத்து *, மாறிலி எழுத்து *);

#ifdef KRB5
முழு	auth_krb5_password(Authctxt *authctxt, மாறிலி எழுத்து *password);
வெறுமை	krb5_cleanup_proc(Authctxt *authctxt);
#endif /* KRB5 */

#எனில் defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#அந்தர்பாவ <shadow.h>
முழு auth_shadow_acctexpired(கட்டமைப்பு spwd *);
முழு auth_shadow_pwexpired(Authctxt *);
#endif

#அந்தர்பாவ "auth-pam.h"
#அந்தர்பாவ "audit.h"
வெறுமை remove_kbdint_device(மாறிலி எழுத்து *);

வெறுமை	do_authentication2(கட்டமைப்பு ssh *);

வெறுமை	auth_log(கட்டமைப்பு ssh *, முழு, முழு, மாறிலி எழுத்து *, மாறிலி எழுத்து *);
வெறுமை	auth_maxtries_exceeded(கட்டமைப்பு ssh *) __attribute__((noreturn));
வெறுமை	userauth_finish(கட்டமைப்பு ssh *, முழு, மாறிலி எழுத்து *, மாறிலி எழுத்து *);
முழு	auth_வேர்_allowed(கட்டமைப்பு ssh *, மாறிலி எழுத்து *);
வெறுமை	auth_failure_delay(Authctxt *, இரட்டை);

எழுத்து	*auth2_read_banner(வெறுமை);
முழு	 auth2_methods_valid(மாறிலி எழுத்து *, முழு);
முழு	 auth2_update_methods_lists(Authctxt *, மாறிலி எழுத்து *, மாறிலி எழுத்து *);
முழு	 auth2_setup_methods_lists(Authctxt *);
முழு	 auth2_method_allowed(Authctxt *, மாறிலி எழுத்து *, மாறிலி எழுத்து *);

முழு	auth2_challenge(கட்டமைப்பு ssh *, எழுத்து *);
வெறுமை	auth2_challenge_stop(கட்டமைப்பு ssh *);
முழு	bsdauth_query(வெறுமை *, எழுத்து **, எழுத்து **, u_int *, எழுத்து ***, u_int **);
முழு	bsdauth_respond(வெறுமை *, u_int, எழுத்து **);

முழு	allowed_user(கட்டமைப்பு ssh *, கட்டமைப்பு passwd *);
கட்டமைப்பு passwd * getpwnamallow(கட்டமைப்பு ssh *, மாறிலி எழுத்து *user);

எழுத்து	*expand_authorized_சாவிகள்(மாறிலி எழுத்து *, கட்டமைப்பு passwd *pw);
எழுத்து	*authorized_principals_file(கட்டமைப்பு passwd *);

முழு	 auth_சாவி_is_revoked(கட்டமைப்பு sshkey *);

மாறிலி எழுத்து	*auth_get_canonical_hostname(கட்டமைப்பு ssh *, முழு);

HostStatus
check_சாவி_in_hostfiles(கட்டமைப்பு passwd *, கட்டமைப்பு sshkey *, மாறிலி எழுத்து *,
    மாறிலி எழுத்து *, மாறிலி எழுத்து *);

/* hostkey handling */
கட்டமைப்பு sshkey	*get_hostkey_by_index(முழு);
கட்டமைப்பு sshkey	*get_hostkey_public_by_index(முழு, கட்டமைப்பு ssh *);
கட்டமைப்பு sshkey	*get_hostkey_public_by_type(முழு, முழு, கட்டமைப்பு ssh *);
கட்டமைப்பு sshkey	*get_hostkey_private_by_type(முழு, முழு, கட்டமைப்பு ssh *);
முழு	 get_hostkey_index(கட்டமைப்பு sshkey *, முழு, கட்டமைப்பு ssh *);
முழு	 sshd_hostkey_sign(கட்டமைப்பு ssh *, கட்டமைப்பு sshkey *, கட்டமைப்பு sshkey *,
    u_char **, size_t *, மாறிலி u_char *, size_t, மாறிலி எழுத்து *);

/* Key / cert options linkage to auth layer */
முழு	 auth_activate_options(கட்டமைப்பு ssh *, கட்டமைப்பு sshauthopt *);
வெறுமை	 auth_restrict_session(கட்டமைப்பு ssh *);
வெறுமை	 auth_log_authopts(மாறிலி எழுத்து *, மாறிலி கட்டமைப்பு sshauthopt *, முழு);

/* debug messages during authentication */
வெறுமை	 auth_debug_add(மாறிலி எழுத்து *fmt,...)
    __attribute__((format(printf, 1, 2)));
வெறுமை	 auth_debug_send(கட்டமைப்பு ssh *);
வெறுமை	 auth_debug_reset(வெறுமை);

கட்டமைப்பு passwd *fakepw(வெறுமை);

/* auth2-pubkeyfile.c */
முழு	 auth_authorise_keyopts(கட்டமைப்பு passwd *, கட்டமைப்பு sshauthopt *, முழு,
    மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *);
முழு	 auth_check_principals_வரி(எழுத்து *, மாறிலி கட்டமைப்பு sshkey_cert *,
    மாறிலி எழுத்து *, கட்டமைப்பு sshauthopt **);
முழு	 auth_process_principals(FILE *, மாறிலி எழுத்து *,
    மாறிலி கட்டமைப்பு sshkey_cert *, கட்டமைப்பு sshauthopt **);
முழு	 auth_check_authkey_வரி(கட்டமைப்பு passwd *, கட்டமைப்பு sshkey *,
    எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *, கட்டமைப்பு sshauthopt **);
முழு	 auth_check_authkeys_file(கட்டமைப்பு passwd *, FILE *, எழுத்து *,
    கட்டமைப்பு sshkey *, மாறிலி எழுத்து *, மாறிலி எழுத்து *, கட்டமைப்பு sshauthopt **);
FILE	*auth_openkeyfile(மாறிலி எழுத்து *, கட்டமைப்பு passwd *, முழு);
FILE	*auth_openprincipals(மாறிலி எழுத்து *, கட்டமைப்பு passwd *, முழு);

முழு	 sys_auth_passwd(கட்டமைப்பு ssh *, மாறிலி எழுத்து *);

#எனில் defined(KRB5) && !defined(HEIMDAL)
krb5_error_code ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#endif

#endif /* AUTH_H */
