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

خارجی "C" {

#شامل "includes.h"

#شامل <sys/types.h>

#شامل "ssherr.h"
#شامل "ssh-sk.h"

صحیح
sshsk_enroll(صحیح type, ثابت حرف *provider_راستہ, ثابت حرف *device,
    ثابت حرف *application, ثابت حرف *userid, uint8_t flags,
    ثابت حرف *pin, ساخت sshbuf *challenge_buf,
    ساخت sshkey **keyp, ساخت sshbuf *attest)
{
	واپس SSH_ERR_FEATURE_UNSUPPORTED;
}

صحیح
sshsk_sign(ثابت حرف *provider_راستہ, ساخت sshkey *کلید,
    u_char **sigp, سائز_t *lenp, ثابت u_char *ڈیٹا, سائز_t datalen,
    u_int compat, ثابت حرف *pin)
{
	واپس SSH_ERR_FEATURE_UNSUPPORTED;
}

صحیح
sshsk_بھرو_resident(ثابت حرف *provider_راستہ, ثابت حرف *device,
    ثابت حرف *pin, u_int flags, ساخت sshsk_resident_کلید ***srksp,
    سائز_t *nsrksp)
{
	واپس SSH_ERR_FEATURE_UNSUPPORTED;
}

};
