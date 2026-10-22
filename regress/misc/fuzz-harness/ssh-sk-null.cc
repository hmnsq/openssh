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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश "ssherr.h"
#समावेश "ssh-sk.h"

पूर्णांक
sshsk_enroll(पूर्णांक type, स्थिर अक्षर *provider_path, स्थिर अक्षर *device,
    स्थिर अक्षर *application, स्थिर अक्षर *userid, uint8_t flags,
    स्थिर अक्षर *pin, काष्ठा sshbuf *challenge_buf,
    काष्ठा sshkey **keyp, काष्ठा sshbuf *attest)
{
	वापस SSH_ERR_FEATURE_UNSUPPORTED;
}

पूर्णांक
sshsk_sign(स्थिर अक्षर *provider_path, काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp, स्थिर u_char *तथ्य, माप_प्रकार datalen,
    u_int compat, स्थिर अक्षर *pin)
{
	वापस SSH_ERR_FEATURE_UNSUPPORTED;
}

पूर्णांक
sshsk_load_resident(स्थिर अक्षर *provider_path, स्थिर अक्षर *device,
    स्थिर अक्षर *pin, u_int flags, काष्ठा sshsk_resident_कुंजी ***srksp,
    माप_प्रकार *nsrksp)
{
	वापस SSH_ERR_FEATURE_UNSUPPORTED;
}

};
