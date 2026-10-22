/* $OpenBSD: gss-serv-krb5.c,v 1.10 2026/02/08 15:28:01 dtucker Exp $ */

/*
 * Copyright (c) 2001-2003 Simon Wilkinson. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ KRB5

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"

ਬਾਹਰੀ ServerOptions options;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HEIMDAL
# include <krb5.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_GSSAPI_KRB5_H
# include <gssapi_krb5.h>
#ਜਾਂਜੇ HAVE_GSSAPI_GSSAPI_KRB5_H
# include <gssapi/gssapi_krb5.h>
#ਜੇ_ਅੰਤ

ਸਥਿਰ krb5_context krb_context = ਨਿਰਾ;

/* Initialise the krb5 library, for the stuff that GSSAPI won't do */

ਸਥਿਰ ਪੂਰਨ
ssh_gssapi_krb5_init(ਖਾਲੀ)
{
	krb5_error_ਕੋਡ problem;

	ਜੇ (krb_context != ਨਿਰਾ)
		ਵਾਪਸ 1;

	problem = krb5_init_context(&krb_context);
	ਜੇ (problem) {
		logit("Cannot initialize krb5 context");
		ਵਾਪਸ 0;
	}

	ਵਾਪਸ 1;
}

/* Check if this user is OK to login. This only works with krb5 - other
 * GSSAPI mechanisms will need their own.
 * Returns true if the user is OK to log in, otherwise returns 0
 */

ਸਥਿਰ ਪੂਰਨ
ssh_gssapi_krb5_userok(ssh_gssapi_client *client, ਅੱਖਰ *name)
{
	krb5_principal princ;
	ਪੂਰਨ retval;
	ਅਚਲ ਅੱਖਰ *errmsg;

	ਜੇ (ssh_gssapi_krb5_init() == 0)
		ਵਾਪਸ 0;

	ਜੇ ((retval = krb5_parse_name(krb_context, client->exportedname.ਮੁੱਲ,
	    &princ))) {
		errmsg = krb5_get_error_ਸੁਨੇਹਾ(krb_context, retval);
		logit("krb5_parse_name(): %.100s", errmsg);
		krb5_free_error_ਸੁਨੇਹਾ(krb_context, errmsg);
		ਵਾਪਸ 0;
	}
	ਜੇ (krb5_kuserok(krb_context, princ, name)) {
		retval = 1;
		logit("Authorized to %s, krb5 principal %s (krb5_kuserok)",
		    name, (ਅੱਖਰ *)client->displayname.ਮੁੱਲ);
	} ਨਹੀਂਤਾਂ
		retval = 0;

	krb5_free_principal(krb_context, princ);
	ਵਾਪਸ retval;
}


/* This writes out any forwarded credentials from the structure populated
 * during userauth. Called after we have setuid to the user */

ਸਥਿਰ ਖਾਲੀ
ssh_gssapi_krb5_storecreds(ssh_gssapi_client *client)
{
	krb5_ccache ccache;
	krb5_error_ਕੋਡ problem;
	krb5_principal princ;
	OM_uint32 maj_ਸਥਿਤੀ, min_ਸਥਿਤੀ;
	ਪੂਰਨ len;
	ਅਚਲ ਅੱਖਰ *errmsg;

	ਜੇ (client->creds == ਨਿਰਾ) {
		debug("No credentials stored");
		ਵਾਪਸ;
	}

	ਜੇ (ssh_gssapi_krb5_init() == 0)
		ਵਾਪਸ;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	ਜੇ ((problem = krb5_cc_new_unique(krb_context, krb5_fcc_ops.ਅਗੇਤਰ,
	    ਨਿਰਾ, &ccache)) != 0) {
		errmsg = krb5_get_error_ਸੁਨੇਹਾ(krb_context, problem);
		logit("krb5_cc_new_unique(): %.100s", errmsg);
# ਨਹੀਂਤਾਂ
	ਜੇ ((problem = krb5_cc_gen_new(krb_context, &krb5_fcc_ops, &ccache))) {
	    logit("krb5_cc_gen_new(): %.100s",
		krb5_get_err_ਪਾਠ(krb_context, problem));
# endif
		krb5_free_error_ਸੁਨੇਹਾ(krb_context, errmsg);
		ਵਾਪਸ;
	}
#ਨਹੀਂਤਾਂ
	ਜੇ ((problem = ssh_krb5_cc_gen(krb_context, &ccache))) {
		errmsg = krb5_get_error_ਸੁਨੇਹਾ(krb_context, problem);
		logit("ssh_krb5_cc_gen(): %.100s", errmsg);
		krb5_free_error_ਸੁਨੇਹਾ(krb_context, errmsg);
		ਵਾਪਸ;
	}
#ਜੇ_ਅੰਤ	/* #ifdef HEIMDAL */

	ਜੇ ((problem = krb5_parse_name(krb_context,
	    client->exportedname.ਮੁੱਲ, &princ))) {
		errmsg = krb5_get_error_ਸੁਨੇਹਾ(krb_context, problem);
		logit("krb5_parse_name(): %.100s", errmsg);
		krb5_free_error_ਸੁਨੇਹਾ(krb_context, errmsg);
		ਵਾਪਸ;
	}

	ਜੇ ((problem = krb5_cc_initialize(krb_context, ccache, princ))) {
		errmsg = krb5_get_error_ਸੁਨੇਹਾ(krb_context, problem);
		logit("krb5_cc_initialize(): %.100s", errmsg);
		krb5_free_error_ਸੁਨੇਹਾ(krb_context, errmsg);
		krb5_free_principal(krb_context, princ);
		krb5_cc_destroy(krb_context, ccache);
		ਵਾਪਸ;
	}

	krb5_free_principal(krb_context, princ);

	ਜੇ ((maj_ਸਥਿਤੀ = gss_krb5_copy_ccache(&min_ਸਥਿਤੀ,
	    client->creds, ccache))) {
		logit("gss_krb5_copy_ccache() failed");
		krb5_cc_destroy(krb_context, ccache);
		ਵਾਪਸ;
	}

	client->store.filename = xstrdup(krb5_cc_get_name(krb_context, ccache));
	client->store.envvar = "KRB5CCNAME";
	len = ਲੜੀ_ਲੰਬਾਈ(client->store.filename) + 6;
	client->store.envval = xmalloc(len);
	snprintf(client->store.envval, len, "FILE:%s", client->store.filename);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	ਜੇ (options.use_pam)
		do_pam_putenv(client->store.envvar, client->store.envval);
#ਜੇ_ਅੰਤ

	krb5_cc_close(krb_context, ccache);

	ਵਾਪਸ;
}

ssh_gssapi_mech gssapi_kerberos_mech = {
	"toWM5Slw5Ew8Mqkay+al2g==",
	"Kerberos",
	{9, "\x2A\x86\x48\x86\xF7\x12\x01\x02\x02"},
	ਨਿਰਾ,
	&ssh_gssapi_krb5_userok,
	ਨਿਰਾ,
	&ssh_gssapi_krb5_storecreds
};

#ਜੇ_ਅੰਤ /* KRB5 */

#ਜੇ_ਅੰਤ /* GSSAPI */
