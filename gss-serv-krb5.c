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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ KRB5

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"

#ಅನ್ತರ್ಭಾವ "ssh-gss.h"

ಬಾಹ್ಯ ServerOptions options;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HEIMDAL
# include <krb5.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_GSSAPI_KRB5_H
# include <gssapi_krb5.h>
#ಅಥವಾಆದರೆ HAVE_GSSAPI_GSSAPI_KRB5_H
# include <gssapi/gssapi_krb5.h>
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ krb5_context krb_context = ಖಾಲಿ;

/* Initialise the krb5 library, for the stuff that GSSAPI won't do */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_gssapi_krb5_init(ಶೂನ್ಯ)
{
	krb5_error_ಸಂಕೇತ problem;

	ಆದರೆ (krb_context != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 1;

	problem = krb5_init_context(&krb_context);
	ಆದರೆ (problem) {
		logit("Cannot initialize krb5 context");
		ಹಿಂತಿರುಗಿ 0;
	}

	ಹಿಂತಿರುಗಿ 1;
}

/* Check if this user is OK to login. This only works with krb5 - other
 * GSSAPI mechanisms will need their own.
 * Returns true if the user is OK to log in, otherwise returns 0
 */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_gssapi_krb5_userok(ssh_gssapi_client *client, ಅಕ್ಷರ *name)
{
	krb5_principal princ;
	ಪೂರ್ಣಾಂಕ retval;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errmsg;

	ಆದರೆ (ssh_gssapi_krb5_init() == 0)
		ಹಿಂತಿರುಗಿ 0;

	ಆದರೆ ((retval = krb5_parse_name(krb_context, client->exportedname.ಮೌಲ್ಯ,
	    &princ))) {
		errmsg = krb5_get_error_ಸಂದೇಶ(krb_context, retval);
		logit("krb5_parse_name(): %.100s", errmsg);
		krb5_free_error_ಸಂದೇಶ(krb_context, errmsg);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (krb5_kuserok(krb_context, princ, name)) {
		retval = 1;
		logit("Authorized to %s, krb5 principal %s (krb5_kuserok)",
		    name, (ಅಕ್ಷರ *)client->displayname.ಮೌಲ್ಯ);
	} ಇಲ್ಲದಿದ್ದರೆ
		retval = 0;

	krb5_free_principal(krb_context, princ);
	ಹಿಂತಿರುಗಿ retval;
}


/* This writes out any forwarded credentials from the structure populated
 * during userauth. Called after we have setuid to the user */

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_gssapi_krb5_storecreds(ssh_gssapi_client *client)
{
	krb5_ccache ccache;
	krb5_error_ಸಂಕೇತ problem;
	krb5_principal princ;
	OM_uint32 maj_ಸ್ಥಿತಿ, min_ಸ್ಥಿತಿ;
	ಪೂರ್ಣಾಂಕ len;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errmsg;

	ಆದರೆ (client->creds == ಖಾಲಿ) {
		debug("No credentials stored");
		ಹಿಂತಿರುಗಿ;
	}

	ಆದರೆ (ssh_gssapi_krb5_init() == 0)
		ಹಿಂತಿರುಗಿ;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	ಆದರೆ ((problem = krb5_cc_new_unique(krb_context, krb5_fcc_ops.ಪೂರ್ವಪ್ರತ್ಯಯ,
	    ಖಾಲಿ, &ccache)) != 0) {
		errmsg = krb5_get_error_ಸಂದೇಶ(krb_context, problem);
		logit("krb5_cc_new_unique(): %.100s", errmsg);
# ಇಲ್ಲದಿದ್ದರೆ
	ಆದರೆ ((problem = krb5_cc_gen_new(krb_context, &krb5_fcc_ops, &ccache))) {
	    logit("krb5_cc_gen_new(): %.100s",
		krb5_get_err_ಪಠ್ಯ(krb_context, problem));
# endif
		krb5_free_error_ಸಂದೇಶ(krb_context, errmsg);
		ಹಿಂತಿರುಗಿ;
	}
#ಇಲ್ಲದಿದ್ದರೆ
	ಆದರೆ ((problem = ssh_krb5_cc_gen(krb_context, &ccache))) {
		errmsg = krb5_get_error_ಸಂದೇಶ(krb_context, problem);
		logit("ssh_krb5_cc_gen(): %.100s", errmsg);
		krb5_free_error_ಸಂದೇಶ(krb_context, errmsg);
		ಹಿಂತಿರುಗಿ;
	}
#ಆದರೆ_ಅಂತ್ಯ	/* #ifdef HEIMDAL */

	ಆದರೆ ((problem = krb5_parse_name(krb_context,
	    client->exportedname.ಮೌಲ್ಯ, &princ))) {
		errmsg = krb5_get_error_ಸಂದೇಶ(krb_context, problem);
		logit("krb5_parse_name(): %.100s", errmsg);
		krb5_free_error_ಸಂದೇಶ(krb_context, errmsg);
		ಹಿಂತಿರುಗಿ;
	}

	ಆದರೆ ((problem = krb5_cc_initialize(krb_context, ccache, princ))) {
		errmsg = krb5_get_error_ಸಂದೇಶ(krb_context, problem);
		logit("krb5_cc_initialize(): %.100s", errmsg);
		krb5_free_error_ಸಂದೇಶ(krb_context, errmsg);
		krb5_free_principal(krb_context, princ);
		krb5_cc_destroy(krb_context, ccache);
		ಹಿಂತಿರುಗಿ;
	}

	krb5_free_principal(krb_context, princ);

	ಆದರೆ ((maj_ಸ್ಥಿತಿ = gss_krb5_copy_ccache(&min_ಸ್ಥಿತಿ,
	    client->creds, ccache))) {
		logit("gss_krb5_copy_ccache() failed");
		krb5_cc_destroy(krb_context, ccache);
		ಹಿಂತಿರುಗಿ;
	}

	client->store.filename = xstrdup(krb5_cc_get_name(krb_context, ccache));
	client->store.envvar = "KRB5CCNAME";
	len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(client->store.filename) + 6;
	client->store.envval = xmalloc(len);
	snprintf(client->store.envval, len, "FILE:%s", client->store.filename);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	ಆದರೆ (options.use_pam)
		do_pam_putenv(client->store.envvar, client->store.envval);
#ಆದರೆ_ಅಂತ್ಯ

	krb5_cc_close(krb_context, ccache);

	ಹಿಂತಿರುಗಿ;
}

ssh_gssapi_mech gssapi_kerberos_mech = {
	"toWM5Slw5Ew8Mqkay+al2g==",
	"Kerberos",
	{9, "\x2A\x86\x48\x86\xF7\x12\x01\x02\x02"},
	ಖಾಲಿ,
	&ssh_gssapi_krb5_userok,
	ಖಾಲಿ,
	&ssh_gssapi_krb5_storecreds
};

#ಆದರೆ_ಅಂತ್ಯ /* KRB5 */

#ಆದರೆ_ಅಂತ್ಯ /* GSSAPI */
