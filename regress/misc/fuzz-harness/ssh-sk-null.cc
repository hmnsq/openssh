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

ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "ssh-sk.h"

ಪೂರ್ಣಾಙ್ಕ
sshsk_enroll(ಪೂರ್ಣಾಙ್ಕ type, ಧ್ರುವ ವರ್ಣ *provider_path, ಧ್ರುವ ವರ್ಣ *device,
    ಧ್ರುವ ವರ್ಣ *application, ಧ್ರುವ ವರ್ಣ *userid, uint8_t flags,
    ಧ್ರುವ ವರ್ಣ *pin, ಸಂರಚನಾ sshbuf *challenge_buf,
    ಸಂರಚನಾ sshkey **keyp, ಸಂರಚನಾ sshbuf *attest)
{
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_FEATURE_UNSUPPORTED;
}

ಪೂರ್ಣಾಙ್ಕ
sshsk_sign(ಧ್ರುವ ವರ್ಣ *provider_path, ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    u_char **sigp, size_t *lenp, ಧ್ರುವ u_char *data, size_t datalen,
    u_int compat, ಧ್ರುವ ವರ್ಣ *pin)
{
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_FEATURE_UNSUPPORTED;
}

ಪೂರ್ಣಾಙ್ಕ
sshsk_load_resident(ಧ್ರುವ ವರ್ಣ *provider_path, ಧ್ರುವ ವರ್ಣ *device,
    ಧ್ರುವ ವರ್ಣ *pin, u_int flags, ಸಂರಚನಾ sshsk_resident_ಕೀಲಿ ***srksp,
    size_t *nsrksp)
{
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_FEATURE_UNSUPPORTED;
}

};
