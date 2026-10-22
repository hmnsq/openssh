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

বাহ্যিক "C" {

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "ssh-sk.h"

পূর্ণসংখ্যা
sshsk_enroll(পূর্ণসংখ্যা type, ধ্রুবক অক্ষর *provider_path, ধ্রুবক অক্ষর *device,
    ধ্রুবক অক্ষর *application, ধ্রুবক অক্ষর *userid, uint8_t flags,
    ধ্রুবক অক্ষর *pin, কাঠামো sshbuf *challenge_buf,
    কাঠামো sshkey **keyp, কাঠামো sshbuf *attest)
{
	ফেরত SSH_ERR_FEATURE_UNSUPPORTED;
}

পূর্ণসংখ্যা
sshsk_sign(ধ্রুবক অক্ষর *provider_path, কাঠামো sshkey *চাবি,
    u_char **sigp, আকার_t *lenp, ধ্রুবক u_char *তথ্য, আকার_t datalen,
    u_int compat, ধ্রুবক অক্ষর *pin)
{
	ফেরত SSH_ERR_FEATURE_UNSUPPORTED;
}

পূর্ণসংখ্যা
sshsk_load_resident(ধ্রুবক অক্ষর *provider_path, ধ্রুবক অক্ষর *device,
    ধ্রুবক অক্ষর *pin, u_int flags, কাঠামো sshsk_resident_চাবি ***srksp,
    আকার_t *nsrksp)
{
	ফেরত SSH_ERR_FEATURE_UNSUPPORTED;
}

};
