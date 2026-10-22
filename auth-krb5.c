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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "uidswap.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"

#ifdef KRB5
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <krb5.h>

வெளி ServerOptions	 options;

நிலையான முழு
krb5_init(வெறுமை *context)
{
	Authctxt *authctxt = (Authctxt *)context;
	krb5_error_code problem;

	எனில் (authctxt->krb5_ctx == வெற்று) {
		problem = krb5_init_context(&authctxt->krb5_ctx);
		எனில் (problem)
			திரும்பு (problem);
	}
	திரும்பு (0);
}

முழு
auth_krb5_password(Authctxt *authctxt, மாறிலி எழுத்து *password)
{
#ifndef HEIMDAL
	krb5_creds creds;
	krb5_principal server;
#endif
	krb5_error_code problem;
	krb5_ccache ccache = வெற்று;
	முழு len;
	எழுத்து *client, *platform_client;
	மாறிலி எழுத்து *errmsg;

	/* get platform-specific kerberos client principal name (if it exists) */
	platform_client = platform_krb5_get_principal_name(authctxt->pw->pw_name);
	client = platform_client ? platform_client : authctxt->pw->pw_name;

	temporarily_use_uid(authctxt->pw);

	problem = krb5_init(authctxt);
	எனில் (problem)
		செல் out;

	problem = krb5_parse_name(authctxt->krb5_ctx, client,
		    &authctxt->krb5_user);
	எனில் (problem)
		செல் out;

#ifdef HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_mcc_ops.prefix, வெற்று, &ccache);
# இல்லையெனில்
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_mcc_ops, &ccache);
# endif
	எனில் (problem)
		செல் out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx, ccache,
		authctxt->krb5_user);
	எனில் (problem)
		செல் out;

	restore_uid();

	problem = krb5_verify_user(authctxt->krb5_ctx, authctxt->krb5_user,
	    ccache, password, 1, வெற்று);

	temporarily_use_uid(authctxt->pw);

	எனில் (problem)
		செல் out;

# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_fcc_ops.prefix, வெற்று, &authctxt->krb5_fwd_ccache);
# இல்லையெனில்
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_fcc_ops,
	    &authctxt->krb5_fwd_ccache);
# endif
	எனில் (problem)
		செல் out;

	problem = krb5_cc_copy_cache(authctxt->krb5_ctx, ccache,
	    authctxt->krb5_fwd_ccache);
	krb5_cc_destroy(authctxt->krb5_ctx, ccache);
	ccache = வெற்று;
	எனில் (problem)
		செல் out;

#இல்லையெனில்
	problem = krb5_get_init_creds_password(authctxt->krb5_ctx, &creds,
	    authctxt->krb5_user, (எழுத்து *)password, வெற்று, வெற்று, 0, வெற்று, வெற்று);
	எனில் (problem)
		செல் out;

	problem = krb5_sname_to_principal(authctxt->krb5_ctx, வெற்று, வெற்று,
	    KRB5_NT_SRV_HST, &server);
	எனில் (problem)
		செல் out;

	restore_uid();
	problem = krb5_verify_init_creds(authctxt->krb5_ctx, &creds, server,
	    வெற்று, வெற்று, வெற்று);
	krb5_free_principal(authctxt->krb5_ctx, server);
	temporarily_use_uid(authctxt->pw);
	எனில் (problem)
		செல் out;

	எனில் (!krb5_kuserok(authctxt->krb5_ctx, authctxt->krb5_user,
	    authctxt->pw->pw_name)) {
		problem = -1;
		செல் out;
	}

	problem = ssh_krb5_cc_gen(authctxt->krb5_ctx,
	    &authctxt->krb5_fwd_ccache);
	எனில் (problem)
		செல் out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, authctxt->krb5_user);
	எனில் (problem)
		செல் out;

	problem = krb5_cc_store_cred(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, &creds);
	எனில் (problem)
		செல் out;
#endif

	authctxt->krb5_ticket_file = (எழுத்து *)krb5_cc_get_name(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);

	len = strlen(authctxt->krb5_ticket_file) + 6;
	authctxt->krb5_ccname = xmalloc(len);
	snprintf(authctxt->krb5_ccname, len, "FILE:%s",
	    authctxt->krb5_ticket_file);

#ifdef USE_PAM
	எனில் (options.use_pam)
		do_pam_putenv("KRB5CCNAME", authctxt->krb5_ccname);
#endif

 out:
	restore_uid();
	
	விடுவி(platform_client);

	எனில் (problem) {
		எனில் (ccache)
			krb5_cc_destroy(authctxt->krb5_ctx, ccache);

		எனில் (authctxt->krb5_ctx != வெற்று && problem!=-1) {
			errmsg = krb5_get_error_message(authctxt->krb5_ctx,
			    problem);
			debug("Kerberos password authentication failed: %s",
			    errmsg);
			krb5_free_error_message(authctxt->krb5_ctx, errmsg);
		} இல்லையெனில்
			debug("Kerberos password authentication failed: %d",
			    problem);

		krb5_cleanup_proc(authctxt);

		எனில் (options.kerberos_or_local_passwd)
			திரும்பு (-1);
		இல்லையெனில்
			திரும்பு (0);
	}
	திரும்பு (authctxt->valid ? 1 : 0);
}

வெறுமை
krb5_cleanup_proc(Authctxt *authctxt)
{
	debug("krb5_cleanup_proc called");
	எனில் (authctxt->krb5_fwd_ccache) {
		krb5_cc_destroy(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);
		authctxt->krb5_fwd_ccache = வெற்று;
	}
	எனில் (authctxt->krb5_user) {
		krb5_free_principal(authctxt->krb5_ctx, authctxt->krb5_user);
		authctxt->krb5_user = வெற்று;
	}
	எனில் (authctxt->krb5_ctx) {
		krb5_free_context(authctxt->krb5_ctx);
		authctxt->krb5_ctx = வெற்று;
	}
}

#ifndef HEIMDAL
krb5_error_code
ssh_krb5_cc_gen(krb5_context ctx, krb5_ccache *ccache) {
	முழு tmpfd, ret, oerrno;
	எழுத்து ccname[40];
	mode_t old_umask;

	ret = snprintf(ccname, அளவு(ccname),
	    "FILE:/tmp/krb5cc_%d_XXXXXXXXXX", geteuid());
	எனில் (ret < 0 || (size_t)ret >= அளவு(ccname))
		திரும்பு ENOMEM;

	old_umask = umask(0177);
	tmpfd = mkstemp(ccname + strlen("FILE:"));
	oerrno = errno;
	umask(old_umask);
	எனில் (tmpfd == -1) {
		logit("mkstemp(): %.100s", strerror(oerrno));
		திரும்பு oerrno;
	}

	எனில் (fchmod(tmpfd,S_IRUSR | S_IWUSR) == -1) {
		oerrno = errno;
		logit("fchmod(): %.100s", strerror(oerrno));
		close(tmpfd);
		திரும்பு oerrno;
	}
	close(tmpfd);

	திரும்பு (krb5_cc_resolve(ctx, ccname, ccache));
}
#endif /* !HEIMDAL */
#endif /* KRB5 */
