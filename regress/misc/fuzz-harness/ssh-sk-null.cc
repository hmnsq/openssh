/* $OpenBSD$ */
/*
 * Copyright (c) 2019 Google LLC
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

बाह्य "C" {

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "ssh-sk.h"

पूर्णांक
sshsk_enroll(पूर्णांक type, स्थिरांक अक्षर *provider_path, स्थिरांक अक्षर *device,
    स्थिरांक अक्षर *application, स्थिरांक अक्षर *userid, uint8_t flags,
    स्थिरांक अक्षर *pin, संरचना sshbuf *challenge_buf,
    संरचना sshkey **keyp, संरचना sshbuf *attest)
{
	परत SSH_ERR_FEATURE_UNSUPPORTED;
}

पूर्णांक
sshsk_sign(स्थिरांक अक्षर *provider_path, संरचना sshkey *किल्ली,
    u_char **sigp, माप_प्रकार *lenp, स्थिरांक u_char *data, माप_प्रकार datalen,
    u_int compat, स्थिरांक अक्षर *pin)
{
	परत SSH_ERR_FEATURE_UNSUPPORTED;
}

पूर्णांक
sshsk_load_resident(स्थिरांक अक्षर *provider_path, स्थिरांक अक्षर *device,
    स्थिरांक अक्षर *pin, u_int flags, संरचना sshsk_resident_किल्ली ***srksp,
    माप_प्रकार *nsrksp)
{
	परत SSH_ERR_FEATURE_UNSUPPORTED;
}

};
