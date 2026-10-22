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

struct passwd;
struct ssh;
struct sshbuf;
struct sshkey;
struct sshkey_cert;
struct sshauthopt;

typedef struct Authctxt Authctxt;
typedef struct Authmethod Authmethod;
typedef struct KbdintDevice KbdintDevice;

struct Authctxt {
	sig_atomic_t	 success;
	цяло		 authenticated;	/* authenticated and alarms cancelled */
	цяло		 postponed;	/* authentication needs another step */
	цяло		 valid;		/* user exists and is allowed to login */
	цяло		 attempt;
	цяло		 failures;
	цяло		 pk_ok_failures;
	цяло		 auth_failure_already_counted;
	цяло		 server_caused_failure;
	цяло		 force_pwchange;
	char		*user;		/* username sent by the client */
	char		*service;
	struct passwd	*pw;		/* set if 'valid' */
	char		*style;

	/* Method lists for multiple authentication */
	char		**auth_methods;	/* modified from server config */
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
	char		*krb5_ticket_file;
	char		*krb5_ccname;
#endif
	struct sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	struct sshkey	**prev_keys;
	u_int		 nprev_keys;

	/* Last used key and ancillary information from active auth method */
	struct sshkey	*auth_method_key;
	char		*auth_method_info;

	/* Information exposed to session */
	struct sshbuf	*session_info;	/* Auth info for environment */
};

/*
 * Every authentication method has to handle authentication requests for
 * non-existing users, or for users that are not allowed to login. In this
 * case 'valid' is set to 0, but 'user' points to the username requested by
 * the client.
 */

struct authmethod_cfg {
	const char *name;
	const char *synonym;
	цяло *enabled;
};

struct Authmethod {
	struct authmethod_cfg *cfg;
	цяло	(*userauth)(struct ssh *, const char *);
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
struct KbdintDevice
{
	const char *name;
	void*	(*init_ctx)(Authctxt*);
	цяло	(*query)(void *ctx, char **name, char **infotxt,
		    u_int *numprompts, char ***prompts, u_int **echo_on);
	цяло	(*respond)(void *ctx, u_int numresp, char **responses);
	void	(*free_ctx)(void *ctx);
};

цяло
auth_rhosts2(struct passwd *, const char *, const char *, const char *);

цяло      auth_password(struct ssh *, const char *);

цяло	 hostbased_key_allowed(struct ssh *, struct passwd *,
	    const char *, char *, struct sshkey *);
цяло	 user_key_allowed(struct ssh *ssh, struct passwd *, struct sshkey *,
    цяло, struct sshauthopt **);
цяло	 auth2_key_already_used(Authctxt *, const struct sshkey *);

/*
 * Handling auth method-specific information for logging and prevention
 * of key reuse during multiple authentication.
 */
void	 auth2_authctxt_reset_info(Authctxt *);
void	 auth2_record_key(Authctxt *, цяло, const struct sshkey *);
void	 auth2_record_info(Authctxt *authctxt, const char *, ...)
	    __attribute__((__format__ (printf, 2, 3)))
	    __attribute__((__nonnull__ (2)));
void	 auth2_update_session_info(Authctxt *, const char *, const char *);

#ifdef KRB5
цяло	auth_krb5_password(Authctxt *authctxt, const char *password);
void	krb5_cleanup_proc(Authctxt *authctxt);
#endif /* KRB5 */

#ако defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#include <shadow.h>
цяло auth_shadow_acctexpired(struct spwd *);
цяло auth_shadow_pwexpired(Authctxt *);
#endif

#include "auth-pam.h"
#include "audit.h"
void remove_kbdint_device(const char *);

void	do_authentication2(struct ssh *);

void	auth_log(struct ssh *, цяло, цяло, const char *, const char *);
void	auth_maxtries_exceeded(struct ssh *) __attribute__((noreturn));
void	userauth_finish(struct ssh *, цяло, const char *, const char *);
цяло	auth_root_allowed(struct ssh *, const char *);
void	auth_failure_delay(Authctxt *, double);

char	*auth2_read_banner(void);
цяло	 auth2_methods_valid(const char *, цяло);
цяло	 auth2_update_methods_lists(Authctxt *, const char *, const char *);
цяло	 auth2_setup_methods_lists(Authctxt *);
цяло	 auth2_method_allowed(Authctxt *, const char *, const char *);

цяло	auth2_challenge(struct ssh *, char *);
void	auth2_challenge_stop(struct ssh *);
цяло	bsdauth_query(void *, char **, char **, u_int *, char ***, u_int **);
цяло	bsdauth_respond(void *, u_int, char **);

цяло	allowed_user(struct ssh *, struct passwd *);
struct passwd * getpwnamallow(struct ssh *, const char *user);

char	*expand_authorized_keys(const char *, struct passwd *pw);
char	*authorized_principals_file(struct passwd *);

цяло	 auth_key_is_revoked(struct sshkey *);

const char	*auth_get_canonical_hostname(struct ssh *, цяло);

HostStatus
check_key_in_hostfiles(struct passwd *, struct sshkey *, const char *,
    const char *, const char *);

/* hostkey handling */
struct sshkey	*get_hostkey_by_index(цяло);
struct sshkey	*get_hostkey_public_by_index(цяло, struct ssh *);
struct sshkey	*get_hostkey_public_by_type(цяло, цяло, struct ssh *);
struct sshkey	*get_hostkey_private_by_type(цяло, цяло, struct ssh *);
цяло	 get_hostkey_index(struct sshkey *, цяло, struct ssh *);
цяло	 sshd_hostkey_sign(struct ssh *, struct sshkey *, struct sshkey *,
    u_char **, size_t *, const u_char *, size_t, const char *);

/* Key / cert options linkage to auth layer */
цяло	 auth_activate_options(struct ssh *, struct sshauthopt *);
void	 auth_restrict_session(struct ssh *);
void	 auth_log_authopts(const char *, const struct sshauthopt *, цяло);

/* debug messages during authentication */
void	 auth_debug_add(const char *fmt,...)
    __attribute__((format(printf, 1, 2)));
void	 auth_debug_send(struct ssh *);
void	 auth_debug_reset(void);

struct passwd *fakepw(void);

/* auth2-pubkeyfile.c */
цяло	 auth_authorise_keyopts(struct passwd *, struct sshauthopt *, цяло,
    const char *, const char *, const char *);
цяло	 auth_check_principals_line(char *, const struct sshkey_cert *,
    const char *, struct sshauthopt **);
цяло	 auth_process_principals(FILE *, const char *,
    const struct sshkey_cert *, struct sshauthopt **);
цяло	 auth_check_authkey_line(struct passwd *, struct sshkey *,
    char *, const char *, const char *, const char *, struct sshauthopt **);
цяло	 auth_check_authkeys_file(struct passwd *, FILE *, char *,
    struct sshkey *, const char *, const char *, struct sshauthopt **);
FILE	*auth_openkeyfile(const char *, struct passwd *, цяло);
FILE	*auth_openprincipals(const char *, struct passwd *, цяло);

цяло	 sys_auth_passwd(struct ssh *, const char *);

#ако defined(KRB5) && !defined(HEIMDAL)
krb5_error_code ssh_krb5_cc_gen(krb5_context, krb5_ccache *);
#endif

#endif /* AUTH_H */
