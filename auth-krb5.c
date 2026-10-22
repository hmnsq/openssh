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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <pwd.h>
#ضمن <stdarg.h>

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "packet.h"
#ضمن "log.h"
#ضمن "sshbuf.h"
#ضمن "sshkey.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "uidswap.h"
#ضمن "hostfile.h"
#ضمن "auth.h"

#ifdef KRB5
#ضمن <errno.h>
#ضمن <unistd.h>
#ضمن <string.h>
#ضمن <krb5.h>

خارجي ServerOptions	 options;

ساكن صحيح
krb5_init(فراغ *context)
{
	Authctxt *authctxt = (Authctxt *)context;
	krb5_error_code problem;

	𐤀𐤌 (authctxt->krb5_ctx == عدم) {
		problem = krb5_init_context(&authctxt->krb5_ctx);
		𐤀𐤌 (problem)
			أرجع (problem);
	}
	أرجع (0);
}

صحيح
auth_krb5_password(Authctxt *authctxt, ثابت حرف *password)
{
#ifndef HEIMDAL
	krb5_creds creds;
	krb5_principal server;
#endif
	krb5_error_code problem;
	krb5_ccache ccache = عدم;
	صحيح len;
	حرف *client, *platform_client;
	ثابت حرف *errmsg;

	/* get platform-specific kerberos client principal name (if it exists) */
	platform_client = platform_krb5_get_principal_name(authctxt->pw->pw_name);
	client = platform_client ? platform_client : authctxt->pw->pw_name;

	temporarily_use_uid(authctxt->pw);

	problem = krb5_init(authctxt);
	𐤀𐤌 (problem)
		اذهب out;

	problem = krb5_parse_name(authctxt->krb5_ctx, client,
		    &authctxt->krb5_user);
	𐤀𐤌 (problem)
		اذهب out;

#ifdef HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_mcc_ops.prefix, عدم, &ccache);
# وإلا
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_mcc_ops, &ccache);
# endif
	𐤀𐤌 (problem)
		اذهب out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx, ccache,
		authctxt->krb5_user);
	𐤀𐤌 (problem)
		اذهب out;

	restore_uid();

	problem = krb5_verify_user(authctxt->krb5_ctx, authctxt->krb5_user,
	    ccache, password, 1, عدم);

	temporarily_use_uid(authctxt->pw);

	𐤀𐤌 (problem)
		اذهب out;

# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_fcc_ops.prefix, عدم, &authctxt->krb5_fwd_ccache);
# وإلا
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_fcc_ops,
	    &authctxt->krb5_fwd_ccache);
# endif
	𐤀𐤌 (problem)
		اذهب out;

	problem = krb5_cc_copy_cache(authctxt->krb5_ctx, ccache,
	    authctxt->krb5_fwd_ccache);
	krb5_cc_destroy(authctxt->krb5_ctx, ccache);
	ccache = عدم;
	𐤀𐤌 (problem)
		اذهب out;

#وإلا
	problem = krb5_get_init_creds_password(authctxt->krb5_ctx, &creds,
	    authctxt->krb5_user, (حرف *)password, عدم, عدم, 0, عدم, عدم);
	𐤀𐤌 (problem)
		اذهب out;

	problem = krb5_sname_to_principal(authctxt->krb5_ctx, عدم, عدم,
	    KRB5_NT_SRV_HST, &server);
	𐤀𐤌 (problem)
		اذهب out;

	restore_uid();
	problem = krb5_verify_init_creds(authctxt->krb5_ctx, &creds, server,
	    عدم, عدم, عدم);
	krb5_free_principal(authctxt->krb5_ctx, server);
	temporarily_use_uid(authctxt->pw);
	𐤀𐤌 (problem)
		اذهب out;

	𐤀𐤌 (!krb5_kuserok(authctxt->krb5_ctx, authctxt->krb5_user,
	    authctxt->pw->pw_name)) {
		problem = -1;
		اذهب out;
	}

	problem = ssh_krb5_cc_gen(authctxt->krb5_ctx,
	    &authctxt->krb5_fwd_ccache);
	𐤀𐤌 (problem)
		اذهب out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, authctxt->krb5_user);
	𐤀𐤌 (problem)
		اذهب out;

	problem = krb5_cc_store_cred(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, &creds);
	𐤀𐤌 (problem)
		اذهب out;
#endif

	authctxt->krb5_ticket_file = (حرف *)krb5_cc_get_name(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);

	len = strlen(authctxt->krb5_ticket_file) + 6;
	authctxt->krb5_ccname = xmalloc(len);
	snprintf(authctxt->krb5_ccname, len, "FILE:%s",
	    authctxt->krb5_ticket_file);

#ifdef USE_PAM
	𐤀𐤌 (options.use_pam)
		do_pam_putenv("KRB5CCNAME", authctxt->krb5_ccname);
#endif

 out:
	restore_uid();
	
	حرر(platform_client);

	𐤀𐤌 (problem) {
		𐤀𐤌 (ccache)
			krb5_cc_destroy(authctxt->krb5_ctx, ccache);

		𐤀𐤌 (authctxt->krb5_ctx != عدم && problem!=-1) {
			errmsg = krb5_get_error_message(authctxt->krb5_ctx,
			    problem);
			debug("Kerberos password authentication failed: %s",
			    errmsg);
			krb5_free_error_message(authctxt->krb5_ctx, errmsg);
		} وإلا
			debug("Kerberos password authentication failed: %d",
			    problem);

		krb5_cleanup_proc(authctxt);

		𐤀𐤌 (options.kerberos_or_local_passwd)
			أرجع (-1);
		وإلا
			أرجع (0);
	}
	أرجع (authctxt->valid ? 1 : 0);
}

فراغ
krb5_cleanup_proc(Authctxt *authctxt)
{
	debug("krb5_cleanup_proc called");
	𐤀𐤌 (authctxt->krb5_fwd_ccache) {
		krb5_cc_destroy(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);
		authctxt->krb5_fwd_ccache = عدم;
	}
	𐤀𐤌 (authctxt->krb5_user) {
		krb5_free_principal(authctxt->krb5_ctx, authctxt->krb5_user);
		authctxt->krb5_user = عدم;
	}
	𐤀𐤌 (authctxt->krb5_ctx) {
		krb5_free_context(authctxt->krb5_ctx);
		authctxt->krb5_ctx = عدم;
	}
}

#ifndef HEIMDAL
krb5_error_code
ssh_krb5_cc_gen(krb5_context ctx, krb5_ccache *ccache) {
	صحيح tmpfd, ret, oerrno;
	حرف ccname[40];
	mode_t old_umask;

	ret = snprintf(ccname, حجم(ccname),
	    "FILE:/tmp/krb5cc_%d_XXXXXXXXXX", geteuid());
	𐤀𐤌 (ret < 0 || (size_t)ret >= حجم(ccname))
		أرجع ENOMEM;

	old_umask = umask(0177);
	tmpfd = mkstemp(ccname + strlen("FILE:"));
	oerrno = errno;
	umask(old_umask);
	𐤀𐤌 (tmpfd == -1) {
		logit("mkstemp(): %.100s", strerror(oerrno));
		أرجع oerrno;
	}

	𐤀𐤌 (fchmod(tmpfd,S_IRUSR | S_IWUSR) == -1) {
		oerrno = errno;
		logit("fchmod(): %.100s", strerror(oerrno));
		close(tmpfd);
		أرجع oerrno;
	}
	close(tmpfd);

	أرجع (krb5_cc_resolve(ctx, ccname, ccache));
}
#endif /* !HEIMDAL */
#endif /* KRB5 */
