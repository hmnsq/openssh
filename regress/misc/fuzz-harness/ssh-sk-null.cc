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

ಪೂರ್ಣಾಂಕ
sshsk_enroll(ಪೂರ್ಣಾಂಕ type, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider_ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *device,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *userid, uint8_t flags,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sshbuf *challenge_buf,
    ರಚನೆ sshkey **keyp, ರಚನೆ sshbuf *attest)
{
	ಹಿಂತಿರುಗಿ SSH_ERR_FEATURE_UNSUPPORTED;
}

ಪೂರ್ಣಾಂಕ
sshsk_sign(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider_ಮಾರ್ಗ, ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp, ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    u_int compat, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin)
{
	ಹಿಂತಿರುಗಿ SSH_ERR_FEATURE_UNSUPPORTED;
}

ಪೂರ್ಣಾಂಕ
sshsk_ತುಂಬು_resident(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider_ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *device,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, u_int flags, ರಚನೆ sshsk_resident_ಕೀಲಿ ***srksp,
    ಗಾತ್ರ_t *nsrksp)
{
	ಹಿಂತಿರುಗಿ SSH_ERR_FEATURE_UNSUPPORTED;
}

};
