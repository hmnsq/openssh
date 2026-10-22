/*
 * Copyright (c) 2012 Damien Miller <djm@mindrot.org>
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

/* $OpenBSD: krl.h,v 1.11 2026/03/03 09:57:25 dtucker Exp $ */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _KRL_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _KRL_H

/* Functions to manage key revocation lists */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KRL_MAGIC		"SSHKRL\n\0"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KRL_FORMAT_ਸੰਸਕਰਣ	1

/* KRL section types */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KRL_SECTION_CERTIFICATES	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KRL_SECTION_EXPLICIT_ਕੁੰਜੀ	2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KRL_SECTION_FINGERPRINT_SHA1	3
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KRL_SECTION_SIGNATURE		4
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KRL_SECTION_FINGERPRINT_SHA256	5
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KRL_SECTION_EXTENSION		255

/* KRL_SECTION_CERTIFICATES subsection types */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KRL_SECTION_CERT_SERIAL_LIST	0x20
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KRL_SECTION_CERT_SERIAL_RANGE	0x21
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KRL_SECTION_CERT_ਕੁੰਜੀ_ID		0x23
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KRL_SECTION_CERT_EXTENSION	0x39

ਬਣਤਰ sshkey;
ਬਣਤਰ sshbuf;
ਬਣਤਰ ssh_krl;

ਬਣਤਰ ssh_krl *ssh_krl_init(ਖਾਲੀ);
ਖਾਲੀ ssh_krl_free(ਬਣਤਰ ssh_krl *krl);
ਖਾਲੀ ssh_krl_ਸੈੱਟ_ਸੰਸਕਰਣ(ਬਣਤਰ ssh_krl *krl, uint64_t ਸੰਸਕਰਣ);
ਪੂਰਨ ssh_krl_ਸੈੱਟ_comment(ਬਣਤਰ ssh_krl *krl, ਅਚਲ ਅੱਖਰ *comment);
ਪੂਰਨ ssh_krl_revoke_cert_by_serial(ਬਣਤਰ ssh_krl *krl,
    ਅਚਲ ਬਣਤਰ sshkey *ca_ਕੁੰਜੀ, uint64_t serial);
ਪੂਰਨ ssh_krl_revoke_cert_by_serial_range(ਬਣਤਰ ssh_krl *krl,
    ਅਚਲ ਬਣਤਰ sshkey *ca_ਕੁੰਜੀ, uint64_t lo, uint64_t hi);
ਪੂਰਨ ssh_krl_revoke_cert_by_ਕੁੰਜੀ_id(ਬਣਤਰ ssh_krl *krl,
    ਅਚਲ ਬਣਤਰ sshkey *ca_ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *ਕੁੰਜੀ_id);
ਪੂਰਨ ssh_krl_revoke_ਕੁੰਜੀ_explicit(ਬਣਤਰ ssh_krl *krl, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ);
ਪੂਰਨ ssh_krl_revoke_ਕੁੰਜੀ_sha1(ਬਣਤਰ ssh_krl *krl, ਅਚਲ u_char *p, ਮਾਪ_t len);
ਪੂਰਨ ssh_krl_revoke_ਕੁੰਜੀ_sha256(ਬਣਤਰ ssh_krl *krl, ਅਚਲ u_char *p, ਮਾਪ_t len);
ਪੂਰਨ ssh_krl_revoke_ਕੁੰਜੀ(ਬਣਤਰ ssh_krl *krl, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ);
ਪੂਰਨ ssh_krl_ਮੰਜ਼ਿਲ_blob(ਬਣਤਰ ssh_krl *krl, ਬਣਤਰ sshbuf *buf);
ਪੂਰਨ ssh_krl_from_blob(ਬਣਤਰ sshbuf *buf, ਬਣਤਰ ssh_krl **krlp);
ਪੂਰਨ ssh_krl_check_ਕੁੰਜੀ(ਬਣਤਰ ssh_krl *krl, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ);
ਪੂਰਨ ssh_krl_file_ਸ਼ਾਮਲ_ਹੈ_ਕੁੰਜੀ(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ);
ਪੂਰਨ krl_dump(ਬਣਤਰ ssh_krl *krl, FILE *f);

#ਜੇ_ਅੰਤ /* _KRL_H */

