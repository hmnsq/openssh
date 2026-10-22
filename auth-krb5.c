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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <pwd.h>
#شامل <stdarg.h>

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "packet.h"
#شامل "log.h"
#شامل "sshbuf.h"
#شامل "sshkey.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "uidswap.h"
#شامل "hostfile.h"
#شامل "auth.h"

#اگر_تعریف_شدہ KRB5
#شامل <errno.h>
#شامل <unistd.h>
#شامل <string.h>
#شامل <krb5.h>

خارجی ServerOptions	 options;

ساکن صحیح
krb5_init(خالی *context)
{
	Authctxt *authctxt = (Authctxt *)context;
	krb5_error_رمز problem;

	اگر (authctxt->krb5_ctx == تہی) {
		problem = krb5_init_context(&authctxt->krb5_ctx);
		اگر (problem)
			واپس (problem);
	}
	واپس (0);
}

صحیح
auth_krb5_password(Authctxt *authctxt, ثابت حرف *password)
{
#اگر_غیر_تعریف_شدہ HEIMDAL
	krb5_creds creds;
	krb5_principal server;
#اگر_ختم
	krb5_error_رمز problem;
	krb5_ccache ccache = تہی;
	صحیح len;
	حرف *client, *platform_client;
	ثابت حرف *errmsg;

	/* get platform-specific kerberos client principal name (if it exists) */
	platform_client = platform_krb5_get_principal_name(authctxt->pw->pw_name);
	client = platform_client ? platform_client : authctxt->pw->pw_name;

	temporarily_use_uid(authctxt->pw);

	problem = krb5_init(authctxt);
	اگر (problem)
		جاؤ برآمد;

	problem = krb5_parse_name(authctxt->krb5_ctx, client,
		    &authctxt->krb5_user);
	اگر (problem)
		جاؤ برآمد;

#اگر_تعریف_شدہ HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_mcc_ops.سابقہ, تہی, &ccache);
# ورنہ
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_mcc_ops, &ccache);
# endif
	اگر (problem)
		جاؤ برآمد;

	problem = krb5_cc_initialize(authctxt->krb5_ctx, ccache,
		authctxt->krb5_user);
	اگر (problem)
		جاؤ برآمد;

	restore_uid();

	problem = krb5_verify_user(authctxt->krb5_ctx, authctxt->krb5_user,
	    ccache, password, 1, تہی);

	temporarily_use_uid(authctxt->pw);

	اگر (problem)
		جاؤ برآمد;

# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_fcc_ops.سابقہ, تہی, &authctxt->krb5_fwd_ccache);
# ورنہ
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_fcc_ops,
	    &authctxt->krb5_fwd_ccache);
# endif
	اگر (problem)
		جاؤ برآمد;

	problem = krb5_cc_copy_cache(authctxt->krb5_ctx, ccache,
	    authctxt->krb5_fwd_ccache);
	krb5_cc_destroy(authctxt->krb5_ctx, ccache);
	ccache = تہی;
	اگر (problem)
		جاؤ برآمد;

#ورنہ
	problem = krb5_get_init_creds_password(authctxt->krb5_ctx, &creds,
	    authctxt->krb5_user, (حرف *)password, تہی, تہی, 0, تہی, تہی);
	اگر (problem)
		جاؤ برآمد;

	problem = krb5_sname_مقصد_principal(authctxt->krb5_ctx, تہی, تہی,
	    KRB5_NT_SRV_HST, &server);
	اگر (problem)
		جاؤ برآمد;

	restore_uid();
	problem = krb5_verify_init_creds(authctxt->krb5_ctx, &creds, server,
	    تہی, تہی, تہی);
	krb5_free_principal(authctxt->krb5_ctx, server);
	temporarily_use_uid(authctxt->pw);
	اگر (problem)
		جاؤ برآمد;

	اگر (!krb5_kuserok(authctxt->krb5_ctx, authctxt->krb5_user,
	    authctxt->pw->pw_name)) {
		problem = -1;
		جاؤ برآمد;
	}

	problem = ssh_krb5_cc_gen(authctxt->krb5_ctx,
	    &authctxt->krb5_fwd_ccache);
	اگر (problem)
		جاؤ برآمد;

	problem = krb5_cc_initialize(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, authctxt->krb5_user);
	اگر (problem)
		جاؤ برآمد;

	problem = krb5_cc_store_cred(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, &creds);
	اگر (problem)
		جاؤ برآمد;
#اگر_ختم

	authctxt->krb5_ticket_file = (حرف *)krb5_cc_get_name(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);

	len = لڑی_لمبائی(authctxt->krb5_ticket_file) + 6;
	authctxt->krb5_ccname = xmalloc(len);
	snprintf(authctxt->krb5_ccname, len, "FILE:%s",
	    authctxt->krb5_ticket_file);

#اگر_تعریف_شدہ USE_PAM
	اگر (options.use_pam)
		do_pam_putenv("KRB5CCNAME", authctxt->krb5_ccname);
#اگر_ختم

 برآمد:
	restore_uid();
	
	آزاد(platform_client);

	اگر (problem) {
		اگر (ccache)
			krb5_cc_destroy(authctxt->krb5_ctx, ccache);

		اگر (authctxt->krb5_ctx != تہی && problem!=-1) {
			errmsg = krb5_get_error_پیغام(authctxt->krb5_ctx,
			    problem);
			debug("Kerberos password authentication failed: %s",
			    errmsg);
			krb5_free_error_پیغام(authctxt->krb5_ctx, errmsg);
		} ورنہ
			debug("Kerberos password authentication failed: %d",
			    problem);

		krb5_cleanup_proc(authctxt);

		اگر (options.kerberos_or_local_passwd)
			واپس (-1);
		ورنہ
			واپس (0);
	}
	واپس (authctxt->valid ? 1 : 0);
}

خالی
krb5_cleanup_proc(Authctxt *authctxt)
{
	debug("krb5_cleanup_proc called");
	اگر (authctxt->krb5_fwd_ccache) {
		krb5_cc_destroy(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);
		authctxt->krb5_fwd_ccache = تہی;
	}
	اگر (authctxt->krb5_user) {
		krb5_free_principal(authctxt->krb5_ctx, authctxt->krb5_user);
		authctxt->krb5_user = تہی;
	}
	اگر (authctxt->krb5_ctx) {
		krb5_free_context(authctxt->krb5_ctx);
		authctxt->krb5_ctx = تہی;
	}
}

#اگر_غیر_تعریف_شدہ HEIMDAL
krb5_error_رمز
ssh_krb5_cc_gen(krb5_context ctx, krb5_ccache *ccache) {
	صحیح tmpfd, ret, oerrno;
	حرف ccname[40];
	منوال_t old_umask;

	ret = snprintf(ccname, حجم(ccname),
	    "FILE:/tmp/krb5cc_%d_XXXXXXXXXX", geteuid());
	اگر (ret < 0 || (سائز_t)ret >= حجم(ccname))
		واپس ENOMEM;

	old_umask = umask(0177);
	tmpfd = mkstemp(ccname + لڑی_لمبائی("FILE:"));
	oerrno = errno;
	umask(old_umask);
	اگر (tmpfd == -1) {
		logit("mkstemp(): %.100s", strerror(oerrno));
		واپس oerrno;
	}

	اگر (fchmod(tmpfd,S_IRUSR | S_IWUSR) == -1) {
		oerrno = errno;
		logit("fchmod(): %.100s", strerror(oerrno));
		close(tmpfd);
		واپس oerrno;
	}
	close(tmpfd);

	واپس (krb5_cc_resolve(ctx, ccname, ccache));
}
#اگر_ختم /* !HEIMDAL */
#اگر_ختم /* KRB5 */
