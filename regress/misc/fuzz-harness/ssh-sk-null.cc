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

पूर्णाङ्क
sshsk_enroll(पूर्णाङ्क type, ध्रुव वर्ण *provider_मार्गः, ध्रुव वर्ण *device,
    ध्रुव वर्ण *application, ध्रुव वर्ण *userid, uint8_t flags,
    ध्रुव वर्ण *pin, संरचना sshbuf *challenge_buf,
    संरचना sshkey **keyp, संरचना sshbuf *attest)
{
	प्रत्यागम SSH_ERR_FEATURE_UNSUPPORTED;
}

पूर्णाङ्क
sshsk_sign(ध्रुव वर्ण *provider_मार्गः, संरचना sshkey *कुञ्चिका,
    u_char **sigp, आकार_t *lenp, ध्रुव u_char *दत्त, आकार_t datalen,
    u_int compat, ध्रुव वर्ण *pin)
{
	प्रत्यागम SSH_ERR_FEATURE_UNSUPPORTED;
}

पूर्णाङ्क
sshsk_आरोपय_resident(ध्रुव वर्ण *provider_मार्गः, ध्रुव वर्ण *device,
    ध्रुव वर्ण *pin, u_int flags, संरचना sshsk_resident_कुञ्चिका ***srksp,
    आकार_t *nsrksp)
{
	प्रत्यागम SSH_ERR_FEATURE_UNSUPPORTED;
}

};
