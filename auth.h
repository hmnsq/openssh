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

#include <signal.h>
#include <stdio.h>

#ifdef HAVE_LOGIN_CAP
#include <login_cap.h>
#endif
#ifdef BSD_AUTH
#include <bsd_auth.h>
#endif
#ifdef KRB5
#include <krb5.h>
#endif

sa_nracanaa passwd;
sa_nracanaa ssh;
sa_nracanaa sshbuf;
sa_nracanaa sshkey;
sa_nracanaa sshkey_cert;
sa_nracanaa sshauthopt;

typedef sa_nracanaa Authctxt Authctxt;
typedef sa_nracanaa Authmethod Authmethod;
typedef sa_nracanaa KbdintDevice KbdintDevice;

sa_nracanaa Authctxt {
	sig_atomic_t	 success;
	puur_naa_nka		 authenticated;	/* authenticated and alarms cancelled */
	puur_naa_nka		 postponed;	/* authentication needs another step */
	puur_naa_nka		 valid;		/* user exists and is allowed to login */
	puur_naa_nka		 attempt;
	puur_naa_nka		 failures;
	puur_naa_nka		 pk_ok_failures;
	puur_naa_nka		 auth_failure_already_counted;
	puur_naa_nka		 server_caused_failure;
	puur_naa_nka		 force_pwchange;
	var_na		*user;		/* username sent by the client */
	var_na		*service;
	sa_nracanaa passwd	*pw;		/* set if 'valid' */
	var_na		*style;

	/* Method lists for multiple authentication */
	var_na		**auth_methods;	/* modified from server config */
	u_int		 num_auth_methods;

	/* Authentication method-specific data */
	void		*methoddata;
	void		*kbdintctxt;
#ifdef BSD_AUTH
	auth_session_t	*as;
#endif
#ifdef KRB5
	krb5_context	 krb5_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	var_na		*krb5_ticket_file;
	var_na		*krb5_ccname;
#endif
	sa_nracanaa sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	sa_nracanaa sshkey	**prev_keys;
	u_int		 nprev_keys;

	/* Last used key and ancillary information from active auth method */
	sa_nracanaa sshkey	*auth_method_key;
	var_na		*auth_method_info;

	/* Information exposed to session */
	sa_nracanaa sshbuf	*session_info;	/* Auth info for environment */
};

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

sa_nracanaa authmethod_cfg {
	const var_na *name;
	const var_na *synonym;
	puur_naa_nka *enabled;
};

sa_nracanaa Authmethod {
	sa_nracanaa authmethod_cfg *cfg;
	puur_naa_nka	(*userauth)(sa_nracanaa ssh *, const var_na *);
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
sa_nracanaa KbdintDevice
{
	const var_na *name;
	void*	(*init_ctx)(Authctxt*);
	puur_naa_nka	(*query)(void *ctx, var_na **name, var_na **infotxt,
		    u_int *numprompts, var_na ***prompts, u_int **echo_on);
	puur_naa_nka	(*respond)(void *ctx, u_int numresp, var_na **responses);
	void	(*free_ctx)(void *ctx);
};

puur_naa_nka
auth_rhosts2(sa_nracanaa passwd *, const var_na *, const var_na *, const var_na *);

puur_naa_nka      auth_password(sa_nracanaa ssh *, const var_na *);

puur_naa_nka	 hostbased_key_allowed(sa_nracanaa ssh *, sa_nracanaa passwd *,
	    const var_na *, var_na *, sa_nracanaa sshkey *);
puur_naa_nka	 user_key_allowed(sa_nracanaa ssh *ssh, sa_nracanaa passwd *, sa_nracanaa sshkey *,
    puur_naa_nka, sa_nracanaa sshauthopt **);
puur_naa_nka	 auth2_key_already_used(Authctxt *, const sa_nracanaa sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
void	 auth2_authctxt_reset_info(Authctxt *);
void	 auth2_record_key(Authctxt *, puur_naa_nka, const sa_nracanaa sshkey *);
void	 auth2_record_info(Authctxt *authctxt, const var_na *, ...)
	    __attribute__((__format__ (printf, 2, 3)))
	    __attribute__((__nonnull__ (2)));
void	 auth2_update_session_info(Authctxt *, const var_na *, const var_na *);

#ifdef KRB5
puur_naa_nka	auth_krb5_password(Authctxt *authctxt, const var_na *password);
void	krb5_cleanup_proc(Authctxt *authctxt);
#endif /* KRB5 */

#ᬬᬾᬦ᭄ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#include <shadow.h>
puur_naa_nka auth_shadow_acctexpired(sa_nracanaa spwd *);
puur_naa_nka auth_shadow_pwexpired(Authctxt *);
#endif

#include "auth-pam.h"
#include "audit.h"
void remove_kbdint_device(const var_na *);

void	do_authentication2(sa_nracanaa ssh *);

void	auth_log(sa_nracanaa ssh *, puur_naa_nka, puur_naa_nka, const var_na *, const var_na *);
void	auth_maxtries_exceeded(sa_nracanaa ssh *) __attribute__((noreturn));
void	userauth_finish(sa_nracanaa ssh *, puur_naa_nka, const var_na *, const var_na *);
puur_naa_nka	auth_root_allowed(sa_nracanaa ssh *, const var_na *);
void	auth_failure_delay(Authctxt *, dviguu_na);

var_na	*auth2_read_banner(void);
puur_naa_nka	 auth2_methods_valid(const var_na *, puur_naa_nka);
puur_naa_nka	 auth2_update_methods_lists(Authctxt *, const var_na *, const var_na *);
puur_naa_nka	 auth2_setup_methods_lists(Authctxt *);
puur_naa_nka	 auth2_method_allowed(Authctxt *, const var_na *, const var_na *);

puur_naa_nka	auth2_challenge(sa_nracanaa ssh *, var_na *);
void	auth2_challenge_stop(sa_nracanaa ssh *);
puur_naa_nka	bsdauth_query(void *, var_na **, var_na **, u_int *, var_na ***, u_int **);
puur_naa_nka	bsdauth_respond(void *, u_int, var_na **);

puur_naa_nka	allowed_user(sa_nracanaa ssh *, sa_nracanaa passwd *);
sa_nracanaa passwd * getpwnamallow(sa_nracanaa ssh *, const var_na *user);

var_na	*expand_authorized_keys(const var_na *, sa_nracanaa passwd *pw);
var_na	*authorized_principals_file(sa_nracanaa passwd *);

puur_naa_nka	 auth_key_is_revoked(sa_nracanaa sshkey *);

const var_na	*auth_get_canonical_hostname(sa_nracanaa ssh *, puur_naa_nka);

HostStatus
check_key_in_hostfiles(sa_nracanaa passwd *, sa_nracanaa sshkey *, const var_na *,
    const var_na *, const var_na *);

/* hostkey handling */
sa_nracanaa sshkey	*get_hostkey_by_index(puur_naa_nka);
sa_nracanaa sshkey	*get_hostkey_public_by_index(puur_naa_nka, sa_nracanaa ssh *);
sa_nracanaa sshkey	*get_hostkey_public_by_type(puur_naa_nka, puur_naa_nka, sa_nracanaa ssh *);
sa_nracanaa sshkey	*get_hostkey_private_by_type(puur_naa_nka, puur_naa_nka, sa_nracanaa ssh *);
puur_naa_nka	 get_hostkey_index(sa_nracanaa sshkey *, puur_naa_nka, sa_nracanaa ssh *);
puur_naa_nka	 sshd_hostkey_sign(sa_nracanaa ssh *, sa_nracanaa sshkey *, sa_nracanaa sshkey *,
    u_char **, size_t *, const u_char *, size_t, const var_na *);

/* Key / cert options linkage to auth layer */
puur_naa_nka	 auth_activate_options(sa_nracanaa ssh *, sa_nracanaa sshauthopt *);
void	 auth_restrict_session(sa_nracanaa ssh *);
void	 auth_log_authopts(const var_na *, const sa_nracanaa sshauthopt *, puur_naa_nka);

/* debug messages during authentication */
void	 auth_debug_add(const var_na *fmt,...)
    __attribute__((format(printf, 1, 2)));
void	 auth_debug_send(sa_nracanaa ssh *);
void	 auth_debug_reset(void);

sa_nracanaa passwd *fakepw(void);

/* auth2-pubkeyfile.c */
puur_naa_nka	 auth_authorise_keyopts(sa_nracanaa passwd *, sa_nracanaa sshauthopt *, puur_naa_nka,
    const var_na *, const var_na *, const var_na *);
puur_naa_nka	 auth_check_principals_line(var_na *, const sa_nracanaa sshkey_cert *,
    const var_na *, sa_nracanaa sshauthopt **);
puur_naa_nka	 auth_process_principals(FILE *, const var_na *,
    const sa_nracanaa sshkey_cert *, sa_nracanaa sshauthopt **);
puur_naa_nka	 auth_check_authkey_line(sa_nracanaa passwd *, sa_nracanaa sshkey *,
    var_na *, const var_na *, const var_na *, const var_na *, sa_nracanaa sshauthopt **);
puur_naa_nka	 auth_check_authkeys_file(sa_nracanaa passwd *, FILE *, var_na *,
    sa_nracanaa sshkey *, const var_na *, const var_na *, sa_nracanaa sshauthopt **);
FILE	*auth_openkeyfile(const var_na *, sa_nracanaa passwd *, puur_naa_nka);
FILE	*auth_openprincipals(const var_na *, sa_nracanaa passwd *, puur_naa_nka);

puur_naa_nka	 sys_auth_passwd(sa_nracanaa ssh *, const var_na *);

#ᬬᬾᬦ᭄ defined(KRB5) && !defined(HEIMDAL)
krb5_error_code ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#endif

#endif /* AUTH_H */
