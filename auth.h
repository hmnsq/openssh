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

#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdio.h>

#ifdef HAVE_LOGIN_CAP
#അന്തര്ഭാവ <login_cap.h>
#endif
#ifdef BSD_AUTH
#അന്തര്ഭാവ <bsd_auth.h>
#endif
#ifdef KRB5
#അന്തര്ഭാവ <krb5.h>
#endif

ഘടന passwd;
ഘടന ssh;
ഘടന sshbuf;
ഘടന sshkey;
ഘടന sshkey_cert;
ഘടന sshauthopt;

തരനിർവചനം ഘടന Authctxt Authctxt;
തരനിർവചനം ഘടന Authmethod Authmethod;
തരനിർവചനം ഘടന KbdintDevice KbdintDevice;

ഘടന Authctxt {
	sig_atomic_t	 success;
	പൂർണ്ണസംഖ്യ		 authenticated;	/* authenticated and alarms cancelled */
	പൂർണ്ണസംഖ്യ		 postponed;	/* authentication needs another step */
	പൂർണ്ണസംഖ്യ		 valid;		/* user exists and is allowed to login */
	പൂർണ്ണസംഖ്യ		 attempt;
	പൂർണ്ണസംഖ്യ		 failures;
	പൂർണ്ണസംഖ്യ		 pk_ok_failures;
	പൂർണ്ണസംഖ്യ		 auth_failure_already_counted;
	പൂർണ്ണസംഖ്യ		 server_caused_failure;
	പൂർണ്ണസംഖ്യ		 force_pwchange;
	അക്ഷരം		*user;		/* username sent by the client */
	അക്ഷരം		*service;
	ഘടന passwd	*pw;		/* set if 'valid' */
	അക്ഷരം		*style;

	/* Method lists for multiple authentication */
	അക്ഷരം		**auth_methods;	/* modified from server config */
	u_int		 അക്കം_auth_methods;

	/* Authentication method-specific data */
	ശൂന്യം		*methoddata;
	ശൂന്യം		*kbdintctxt;
#ifdef BSD_AUTH
	auth_session_t	*as;
#endif
#ifdef KRB5
	krb5_context	 krb5_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	അക്ഷരം		*krb5_ticket_file;
	അക്ഷരം		*krb5_ccname;
#endif
	ഘടന sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	ഘടന sshkey	**prev_താക്കോലുകൾ;
	u_int		 nprev_താക്കോലുകൾ;

	/* Last used key and ancillary information from active auth method */
	ഘടന sshkey	*auth_method_താക്കോൽ;
	അക്ഷരം		*auth_method_info;

	/* Information exposed to session */
	ഘടന sshbuf	*session_info;	/* Auth info for environment */
};

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

ഘടന authmethod_cfg {
	സ്ഥിരം അക്ഷരം *name;
	സ്ഥിരം അക്ഷരം *synonym;
	പൂർണ്ണസംഖ്യ *enabled;
};

ഘടന Authmethod {
	ഘടന authmethod_cfg *cfg;
	പൂർണ്ണസംഖ്യ	(*userauth)(ഘടന ssh *, സ്ഥിരം അക്ഷരം *);
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
ഘടന KbdintDevice
{
	സ്ഥിരം അക്ഷരം *name;
	ശൂന്യം*	(*init_ctx)(Authctxt*);
	പൂർണ്ണസംഖ്യ	(*query)(ശൂന്യം *ctx, അക്ഷരം **name, അക്ഷരം **infotxt,
		    u_int *numprompts, അക്ഷരം ***prompts, u_int **echo_on);
	പൂർണ്ണസംഖ്യ	(*respond)(ശൂന്യം *ctx, u_int numresp, അക്ഷരം **responses);
	ശൂന്യം	(*free_ctx)(ശൂന്യം *ctx);
};

പൂർണ്ണസംഖ്യ
auth_rhosts2(ഘടന passwd *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);

പൂർണ്ണസംഖ്യ      auth_password(ഘടന ssh *, സ്ഥിരം അക്ഷരം *);

പൂർണ്ണസംഖ്യ	 hostbased_താക്കോൽ_allowed(ഘടന ssh *, ഘടന passwd *,
	    സ്ഥിരം അക്ഷരം *, അക്ഷരം *, ഘടന sshkey *);
പൂർണ്ണസംഖ്യ	 user_താക്കോൽ_allowed(ഘടന ssh *ssh, ഘടന passwd *, ഘടന sshkey *,
    പൂർണ്ണസംഖ്യ, ഘടന sshauthopt **);
പൂർണ്ണസംഖ്യ	 auth2_താക്കോൽ_already_used(Authctxt *, സ്ഥിരം ഘടന sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
ശൂന്യം	 auth2_authctxt_reset_info(Authctxt *);
ശൂന്യം	 auth2_record_താക്കോൽ(Authctxt *, പൂർണ്ണസംഖ്യ, സ്ഥിരം ഘടന sshkey *);
ശൂന്യം	 auth2_record_info(Authctxt *authctxt, സ്ഥിരം അക്ഷരം *, ...)
	    __attribute__((__format__ (printf, 2, 3)))
	    __attribute__((__nonnull__ (2)));
ശൂന്യം	 auth2_update_session_info(Authctxt *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);

#ifdef KRB5
പൂർണ്ണസംഖ്യ	auth_krb5_password(Authctxt *authctxt, സ്ഥിരം അക്ഷരം *password);
ശൂന്യം	krb5_cleanup_proc(Authctxt *authctxt);
#endif /* KRB5 */

#എങ്കിൽ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#അന്തര്ഭാവ <shadow.h>
പൂർണ്ണസംഖ്യ auth_shadow_acctexpired(ഘടന spwd *);
പൂർണ്ണസംഖ്യ auth_shadow_pwexpired(Authctxt *);
#endif

#അന്തര്ഭാവ "auth-pam.h"
#അന്തര്ഭാവ "audit.h"
ശൂന്യം remove_kbdint_device(സ്ഥിരം അക്ഷരം *);

ശൂന്യം	do_authentication2(ഘടന ssh *);

ശൂന്യം	auth_log(ഘടന ssh *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
ശൂന്യം	auth_maxtries_exceeded(ഘടന ssh *) __attribute__((noreturn));
ശൂന്യം	userauth_finish(ഘടന ssh *, പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	auth_വേര്_allowed(ഘടന ssh *, സ്ഥിരം അക്ഷരം *);
ശൂന്യം	auth_failure_delay(Authctxt *, ഇരട്ട);

അക്ഷരം	*auth2_read_banner(ശൂന്യം);
പൂർണ്ണസംഖ്യ	 auth2_methods_valid(സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 auth2_update_methods_lists(Authctxt *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 auth2_setup_methods_lists(Authctxt *);
പൂർണ്ണസംഖ്യ	 auth2_method_allowed(Authctxt *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);

പൂർണ്ണസംഖ്യ	auth2_challenge(ഘടന ssh *, അക്ഷരം *);
ശൂന്യം	auth2_challenge_stop(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	bsdauth_query(ശൂന്യം *, അക്ഷരം **, അക്ഷരം **, u_int *, അക്ഷരം ***, u_int **);
പൂർണ്ണസംഖ്യ	bsdauth_respond(ശൂന്യം *, u_int, അക്ഷരം **);

പൂർണ്ണസംഖ്യ	allowed_user(ഘടന ssh *, ഘടന passwd *);
ഘടന passwd * getpwnamallow(ഘടന ssh *, സ്ഥിരം അക്ഷരം *user);

അക്ഷരം	*expand_authorized_താക്കോലുകൾ(സ്ഥിരം അക്ഷരം *, ഘടന passwd *pw);
അക്ഷരം	*authorized_principals_file(ഘടന passwd *);

പൂർണ്ണസംഖ്യ	 auth_താക്കോൽ_is_revoked(ഘടന sshkey *);

സ്ഥിരം അക്ഷരം	*auth_get_canonical_hostname(ഘടന ssh *, പൂർണ്ണസംഖ്യ);

HostStatus
check_താക്കോൽ_in_hostfiles(ഘടന passwd *, ഘടന sshkey *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);

/* hostkey handling */
ഘടന sshkey	*get_hostkey_by_index(പൂർണ്ണസംഖ്യ);
ഘടന sshkey	*get_hostkey_public_by_index(പൂർണ്ണസംഖ്യ, ഘടന ssh *);
ഘടന sshkey	*get_hostkey_public_by_type(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, ഘടന ssh *);
ഘടന sshkey	*get_hostkey_private_by_type(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 get_hostkey_index(ഘടന sshkey *, പൂർണ്ണസംഖ്യ, ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 sshd_hostkey_sign(ഘടന ssh *, ഘടന sshkey *, ഘടന sshkey *,
    u_char **, size_t *, സ്ഥിരം u_char *, size_t, സ്ഥിരം അക്ഷരം *);

/* Key / cert options linkage to auth layer */
പൂർണ്ണസംഖ്യ	 auth_activate_options(ഘടന ssh *, ഘടന sshauthopt *);
ശൂന്യം	 auth_restrict_session(ഘടന ssh *);
ശൂന്യം	 auth_log_authopts(സ്ഥിരം അക്ഷരം *, സ്ഥിരം ഘടന sshauthopt *, പൂർണ്ണസംഖ്യ);

/* debug messages during authentication */
ശൂന്യം	 auth_debug_add(സ്ഥിരം അക്ഷരം *fmt,...)
    __attribute__((format(printf, 1, 2)));
ശൂന്യം	 auth_debug_send(ഘടന ssh *);
ശൂന്യം	 auth_debug_reset(ശൂന്യം);

ഘടന passwd *fakepw(ശൂന്യം);

/* auth2-pubkeyfile.c */
പൂർണ്ണസംഖ്യ	 auth_authorise_keyopts(ഘടന passwd *, ഘടന sshauthopt *, പൂർണ്ണസംഖ്യ,
    സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 auth_check_principals_വരി(അക്ഷരം *, സ്ഥിരം ഘടന sshkey_cert *,
    സ്ഥിരം അക്ഷരം *, ഘടന sshauthopt **);
പൂർണ്ണസംഖ്യ	 auth_process_principals(FILE *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം ഘടന sshkey_cert *, ഘടന sshauthopt **);
പൂർണ്ണസംഖ്യ	 auth_check_authkey_വരി(ഘടന passwd *, ഘടന sshkey *,
    അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, ഘടന sshauthopt **);
പൂർണ്ണസംഖ്യ	 auth_check_authkeys_file(ഘടന passwd *, FILE *, അക്ഷരം *,
    ഘടന sshkey *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, ഘടന sshauthopt **);
FILE	*auth_openkeyfile(സ്ഥിരം അക്ഷരം *, ഘടന passwd *, പൂർണ്ണസംഖ്യ);
FILE	*auth_openprincipals(സ്ഥിരം അക്ഷരം *, ഘടന passwd *, പൂർണ്ണസംഖ്യ);

പൂർണ്ണസംഖ്യ	 sys_auth_passwd(ഘടന ssh *, സ്ഥിരം അക്ഷരം *);

#എങ്കിൽ defined(KRB5) && !defined(HEIMDAL)
krb5_error_code ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#endif

#endif /* AUTH_H */
