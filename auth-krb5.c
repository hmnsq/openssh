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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <pwd.h>
#অন্তর্ভাৱ <stdarg.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "ssh.h"
#অন্তর্ভাৱ "packet.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "servconf.h"
#অন্তর্ভাৱ "uidswap.h"
#অন্তর্ভাৱ "hostfile.h"
#অন্তর্ভাৱ "auth.h"

#ifdef KRB5
#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <krb5.h>

বাহ্য ServerOptions	 options;

স্থির পূর্ণাঙ্ক
krb5_init(শূন্য *context)
{
	Authctxt *authctxt = (Authctxt *)context;
	krb5_error_code problem;

	যদি (authctxt->krb5_ctx == রিক্ত) {
		problem = krb5_init_context(&authctxt->krb5_ctx);
		যদি (problem)
			ঘূৰাই (problem);
	}
	ঘূৰাই (0);
}

পূর্ণাঙ্ক
auth_krb5_password(Authctxt *authctxt, ধ্রুৱ ৱর্ণ *password)
{
#ifndef HEIMDAL
	krb5_creds creds;
	krb5_principal server;
#endif
	krb5_error_code problem;
	krb5_ccache ccache = রিক্ত;
	পূর্ণাঙ্ক len;
	ৱর্ণ *client, *platform_client;
	ধ্রুৱ ৱর্ণ *errmsg;

	/* get platform-specific kerberos client principal name (if it exists) */
	platform_client = platform_krb5_get_principal_name(authctxt->pw->pw_name);
	client = platform_client ? platform_client : authctxt->pw->pw_name;

	temporarily_use_uid(authctxt->pw);

	problem = krb5_init(authctxt);
	যদি (problem)
		গচ্ছ out;

	problem = krb5_parse_name(authctxt->krb5_ctx, client,
		    &authctxt->krb5_user);
	যদি (problem)
		গচ্ছ out;

#ifdef HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_mcc_ops.prefix, রিক্ত, &ccache);
# অন্যথা
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_mcc_ops, &ccache);
# endif
	যদি (problem)
		গচ্ছ out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx, ccache,
		authctxt->krb5_user);
	যদি (problem)
		গচ্ছ out;

	restore_uid();

	problem = krb5_verify_user(authctxt->krb5_ctx, authctxt->krb5_user,
	    ccache, password, 1, রিক্ত);

	temporarily_use_uid(authctxt->pw);

	যদি (problem)
		গচ্ছ out;

# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_fcc_ops.prefix, রিক্ত, &authctxt->krb5_fwd_ccache);
# অন্যথা
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_fcc_ops,
	    &authctxt->krb5_fwd_ccache);
# endif
	যদি (problem)
		গচ্ছ out;

	problem = krb5_cc_copy_cache(authctxt->krb5_ctx, ccache,
	    authctxt->krb5_fwd_ccache);
	krb5_cc_destroy(authctxt->krb5_ctx, ccache);
	ccache = রিক্ত;
	যদি (problem)
		গচ্ছ out;

#অন্যথা
	problem = krb5_get_init_creds_password(authctxt->krb5_ctx, &creds,
	    authctxt->krb5_user, (ৱর্ণ *)password, রিক্ত, রিক্ত, 0, রিক্ত, রিক্ত);
	যদি (problem)
		গচ্ছ out;

	problem = krb5_sname_to_principal(authctxt->krb5_ctx, রিক্ত, রিক্ত,
	    KRB5_NT_SRV_HST, &server);
	যদি (problem)
		গচ্ছ out;

	restore_uid();
	problem = krb5_verify_init_creds(authctxt->krb5_ctx, &creds, server,
	    রিক্ত, রিক্ত, রিক্ত);
	krb5_free_principal(authctxt->krb5_ctx, server);
	temporarily_use_uid(authctxt->pw);
	যদি (problem)
		গচ্ছ out;

	যদি (!krb5_kuserok(authctxt->krb5_ctx, authctxt->krb5_user,
	    authctxt->pw->pw_name)) {
		problem = -1;
		গচ্ছ out;
	}

	problem = ssh_krb5_cc_gen(authctxt->krb5_ctx,
	    &authctxt->krb5_fwd_ccache);
	যদি (problem)
		গচ্ছ out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, authctxt->krb5_user);
	যদি (problem)
		গচ্ছ out;

	problem = krb5_cc_store_cred(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, &creds);
	যদি (problem)
		গচ্ছ out;
#endif

	authctxt->krb5_ticket_file = (ৱর্ণ *)krb5_cc_get_name(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);

	len = strlen(authctxt->krb5_ticket_file) + 6;
	authctxt->krb5_ccname = xmalloc(len);
	snprintf(authctxt->krb5_ccname, len, "FILE:%s",
	    authctxt->krb5_ticket_file);

#ifdef USE_PAM
	যদি (options.use_pam)
		do_pam_putenv("KRB5CCNAME", authctxt->krb5_ccname);
#endif

 out:
	restore_uid();
	
	মুক্ত(platform_client);

	যদি (problem) {
		যদি (ccache)
			krb5_cc_destroy(authctxt->krb5_ctx, ccache);

		যদি (authctxt->krb5_ctx != রিক্ত && problem!=-1) {
			errmsg = krb5_get_error_message(authctxt->krb5_ctx,
			    problem);
			debug("Kerberos password authentication failed: %s",
			    errmsg);
			krb5_free_error_message(authctxt->krb5_ctx, errmsg);
		} অন্যথা
			debug("Kerberos password authentication failed: %d",
			    problem);

		krb5_cleanup_proc(authctxt);

		যদি (options.kerberos_or_local_passwd)
			ঘূৰাই (-1);
		অন্যথা
			ঘূৰাই (0);
	}
	ঘূৰাই (authctxt->valid ? 1 : 0);
}

শূন্য
krb5_cleanup_proc(Authctxt *authctxt)
{
	debug("krb5_cleanup_proc called");
	যদি (authctxt->krb5_fwd_ccache) {
		krb5_cc_destroy(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);
		authctxt->krb5_fwd_ccache = রিক্ত;
	}
	যদি (authctxt->krb5_user) {
		krb5_free_principal(authctxt->krb5_ctx, authctxt->krb5_user);
		authctxt->krb5_user = রিক্ত;
	}
	যদি (authctxt->krb5_ctx) {
		krb5_free_context(authctxt->krb5_ctx);
		authctxt->krb5_ctx = রিক্ত;
	}
}

#ifndef HEIMDAL
krb5_error_code
ssh_krb5_cc_gen(krb5_context ctx, krb5_ccache *ccache) {
	পূর্ণাঙ্ক tmpfd, ret, oerrno;
	ৱর্ণ ccname[40];
	mode_t old_umask;

	ret = snprintf(ccname, পরিমাণ(ccname),
	    "FILE:/tmp/krb5cc_%d_XXXXXXXXXX", geteuid());
	যদি (ret < 0 || (size_t)ret >= পরিমাণ(ccname))
		ঘূৰাই ENOMEM;

	old_umask = umask(0177);
	tmpfd = mkstemp(ccname + strlen("FILE:"));
	oerrno = errno;
	umask(old_umask);
	যদি (tmpfd == -1) {
		logit("mkstemp(): %.100s", strerror(oerrno));
		ঘূৰাই oerrno;
	}

	যদি (fchmod(tmpfd,S_IRUSR | S_IWUSR) == -1) {
		oerrno = errno;
		logit("fchmod(): %.100s", strerror(oerrno));
		close(tmpfd);
		ঘূৰাই oerrno;
	}
	close(tmpfd);

	ঘূৰাই (krb5_cc_resolve(ctx, ccname, ccache));
}
#endif /* !HEIMDAL */
#endif /* KRB5 */
