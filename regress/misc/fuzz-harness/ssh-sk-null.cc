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

ବାହ୍ୟ "C" {

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "ssh-sk.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsk_enroll(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ଅଚଳ ଅକ୍ଷର *provider_path, ଅଚଳ ଅକ୍ଷର *device,
    ଅଚଳ ଅକ୍ଷର *application, ଅଚଳ ଅକ୍ଷର *userid, uint8_t flags,
    ଅଚଳ ଅକ୍ଷର *pin, ସଂରଚନା sshbuf *challenge_buf,
    ସଂରଚନା sshkey **keyp, ସଂରଚନା sshbuf *attest)
{
	ଫେରନ୍ତୁ SSH_ERR_FEATURE_UNSUPPORTED;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsk_sign(ଅଚଳ ଅକ୍ଷର *provider_path, ସଂରଚନା sshkey *ଚାବି,
    u_char **sigp, size_t *lenp, ଅଚଳ u_char *data, size_t datalen,
    u_int compat, ଅଚଳ ଅକ୍ଷର *pin)
{
	ଫେରନ୍ତୁ SSH_ERR_FEATURE_UNSUPPORTED;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsk_load_resident(ଅଚଳ ଅକ୍ଷର *provider_path, ଅଚଳ ଅକ୍ଷର *device,
    ଅଚଳ ଅକ୍ଷର *pin, u_int flags, ସଂରଚନା sshsk_resident_ଚାବି ***srksp,
    size_t *nsrksp)
{
	ଫେରନ୍ତୁ SSH_ERR_FEATURE_UNSUPPORTED;
}

};
