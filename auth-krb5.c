/* $OpenBSD: auth-krb5.c,v 1.26 2026/02/08 19:54:31 dtucker Exp $ */
/*
 *    Kerberos v5 authentication and ticket-passing routines.
 *
 * From: FreeBSD: src/crypto/openssh/auth-krb5.c,v 1.6 2001/02/13 16:58:04 assar
 */
/*
 * Copyright (c) 2002 Daniel Kouril.  All rights reserved.
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
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "uidswap.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"

#ifdef KRB5
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <krb5.h>

બાહ્ય ServerOptions	 options;

સ્થિર પૂર્ણાંક
krb5_init(શૂન્ય *context)
{
	Authctxt *authctxt = (Authctxt *)context;
	krb5_error_code problem;

	જો (authctxt->krb5_ctx == ખાલી) {
		problem = krb5_init_context(&authctxt->krb5_ctx);
		જો (problem)
			પાછા (problem);
	}
	પાછા (0);
}

પૂર્ણાંક
auth_krb5_password(Authctxt *authctxt, અચલ અક્ષર *password)
{
#ifndef HEIMDAL
	krb5_creds creds;
	krb5_principal server;
#endif
	krb5_error_code problem;
	krb5_ccache ccache = ખાલી;
	પૂર્ણાંક len;
	અક્ષર *client, *platform_client;
	અચલ અક્ષર *errmsg;

	/* get platform-specific kerberos client principal name (if it exists) */
	platform_client = platform_krb5_get_principal_name(authctxt->pw->pw_name);
	client = platform_client ? platform_client : authctxt->pw->pw_name;

	temporarily_use_uid(authctxt->pw);

	problem = krb5_init(authctxt);
	જો (problem)
		જાઓ out;

	problem = krb5_parse_name(authctxt->krb5_ctx, client,
		    &authctxt->krb5_user);
	જો (problem)
		જાઓ out;

#ifdef HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_mcc_ops.prefix, ખાલી, &ccache);
# નહીંતર
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_mcc_ops, &ccache);
# endif
	જો (problem)
		જાઓ out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx, ccache,
		authctxt->krb5_user);
	જો (problem)
		જાઓ out;

	restore_uid();

	problem = krb5_verify_user(authctxt->krb5_ctx, authctxt->krb5_user,
	    ccache, password, 1, ખાલી);

	temporarily_use_uid(authctxt->pw);

	જો (problem)
		જાઓ out;

# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_fcc_ops.prefix, ખાલી, &authctxt->krb5_fwd_ccache);
# નહીંતર
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_fcc_ops,
	    &authctxt->krb5_fwd_ccache);
# endif
	જો (problem)
		જાઓ out;

	problem = krb5_cc_copy_cache(authctxt->krb5_ctx, ccache,
	    authctxt->krb5_fwd_ccache);
	krb5_cc_destroy(authctxt->krb5_ctx, ccache);
	ccache = ખાલી;
	જો (problem)
		જાઓ out;

#નહીંતર
	problem = krb5_get_init_creds_password(authctxt->krb5_ctx, &creds,
	    authctxt->krb5_user, (અક્ષર *)password, ખાલી, ખાલી, 0, ખાલી, ખાલી);
	જો (problem)
		જાઓ out;

	problem = krb5_sname_to_principal(authctxt->krb5_ctx, ખાલી, ખાલી,
	    KRB5_NT_SRV_HST, &server);
	જો (problem)
		જાઓ out;

	restore_uid();
	problem = krb5_verify_init_creds(authctxt->krb5_ctx, &creds, server,
	    ખાલી, ખાલી, ખાલી);
	krb5_free_principal(authctxt->krb5_ctx, server);
	temporarily_use_uid(authctxt->pw);
	જો (problem)
		જાઓ out;

	જો (!krb5_kuserok(authctxt->krb5_ctx, authctxt->krb5_user,
	    authctxt->pw->pw_name)) {
		problem = -1;
		જાઓ out;
	}

	problem = ssh_krb5_cc_gen(authctxt->krb5_ctx,
	    &authctxt->krb5_fwd_ccache);
	જો (problem)
		જાઓ out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, authctxt->krb5_user);
	જો (problem)
		જાઓ out;

	problem = krb5_cc_store_cred(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, &creds);
	જો (problem)
		જાઓ out;
#endif

	authctxt->krb5_ticket_file = (અક્ષર *)krb5_cc_get_name(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);

	len = strlen(authctxt->krb5_ticket_file) + 6;
	authctxt->krb5_ccname = xmalloc(len);
	snprintf(authctxt->krb5_ccname, len, "FILE:%s",
	    authctxt->krb5_ticket_file);

#ifdef USE_PAM
	જો (options.use_pam)
		do_pam_putenv("KRB5CCNAME", authctxt->krb5_ccname);
#endif

 out:
	restore_uid();
	
	મુક્ત(platform_client);

	જો (problem) {
		જો (ccache)
			krb5_cc_destroy(authctxt->krb5_ctx, ccache);

		જો (authctxt->krb5_ctx != ખાલી && problem!=-1) {
			errmsg = krb5_get_error_message(authctxt->krb5_ctx,
			    problem);
			debug("Kerberos password authentication failed: %s",
			    errmsg);
			krb5_free_error_message(authctxt->krb5_ctx, errmsg);
		} નહીંતર
			debug("Kerberos password authentication failed: %d",
			    problem);

		krb5_cleanup_proc(authctxt);

		જો (options.kerberos_or_local_passwd)
			પાછા (-1);
		નહીંતર
			પાછા (0);
	}
	પાછા (authctxt->valid ? 1 : 0);
}

શૂન્ય
krb5_cleanup_proc(Authctxt *authctxt)
{
	debug("krb5_cleanup_proc called");
	જો (authctxt->krb5_fwd_ccache) {
		krb5_cc_destroy(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);
		authctxt->krb5_fwd_ccache = ખાલી;
	}
	જો (authctxt->krb5_user) {
		krb5_free_principal(authctxt->krb5_ctx, authctxt->krb5_user);
		authctxt->krb5_user = ખાલી;
	}
	જો (authctxt->krb5_ctx) {
		krb5_free_context(authctxt->krb5_ctx);
		authctxt->krb5_ctx = ખાલી;
	}
}

#ifndef HEIMDAL
krb5_error_code
ssh_krb5_cc_gen(krb5_context ctx, krb5_ccache *ccache) {
	પૂર્ણાંક tmpfd, ret, oerrno;
	અક્ષર ccname[40];
	mode_t old_umask;

	ret = snprintf(ccname, કદ(ccname),
	    "FILE:/tmp/krb5cc_%d_XXXXXXXXXX", geteuid());
	જો (ret < 0 || (size_t)ret >= કદ(ccname))
		પાછા ENOMEM;

	old_umask = umask(0177);
	tmpfd = mkstemp(ccname + strlen("FILE:"));
	oerrno = errno;
	umask(old_umask);
	જો (tmpfd == -1) {
		logit("mkstemp(): %.100s", strerror(oerrno));
		પાછા oerrno;
	}

	જો (fchmod(tmpfd,S_IRUSR | S_IWUSR) == -1) {
		oerrno = errno;
		logit("fchmod(): %.100s", strerror(oerrno));
		close(tmpfd);
		પાછા oerrno;
	}
	close(tmpfd);

	પાછા (krb5_cc_resolve(ctx, ccname, ccache));
}
#endif /* !HEIMDAL */
#endif /* KRB5 */
