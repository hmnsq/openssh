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

বাহ্য "C" {

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "ssh-sk.h"

পূর্ণাঙ্ক
sshsk_enroll(পূর্ণাঙ্ক type, ধ্রুব বর্ণ *provider_path, ধ্রুব বর্ণ *device,
    ধ্রুব বর্ণ *application, ধ্রুব বর্ণ *userid, uint8_t flags,
    ধ্রুব বর্ণ *pin, সংরচনা sshbuf *challenge_buf,
    সংরচনা sshkey **keyp, সংরচনা sshbuf *attest)
{
	প্রত্যাগম SSH_ERR_FEATURE_UNSUPPORTED;
}

পূর্ণাঙ্ক
sshsk_sign(ধ্রুব বর্ণ *provider_path, সংরচনা sshkey *চাবি,
    u_char **sigp, size_t *lenp, ধ্রুব u_char *data, size_t datalen,
    u_int compat, ধ্রুব বর্ণ *pin)
{
	প্রত্যাগম SSH_ERR_FEATURE_UNSUPPORTED;
}

পূর্ণাঙ্ক
sshsk_load_resident(ধ্রুব বর্ণ *provider_path, ধ্রুব বর্ণ *device,
    ধ্রুব বর্ণ *pin, u_int flags, সংরচনা sshsk_resident_চাবি ***srksp,
    size_t *nsrksp)
{
	প্রত্যাগম SSH_ERR_FEATURE_UNSUPPORTED;
}

};
