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

#यदि_अपरिभाषितम् _KRL_H
#परिभाषय _KRL_H

/* Functions to manage key revocation lists */

#परिभाषय KRL_MAGIC		"SSHKRL\n\0"
#परिभाषय KRL_FORMAT_संस्करणम्	1

/* KRL section types */
#परिभाषय KRL_SECTION_CERTIFICATES	1
#परिभाषय KRL_SECTION_EXPLICIT_कुञ्चिका	2
#परिभाषय KRL_SECTION_FINGERPRINT_SHA1	3
#परिभाषय KRL_SECTION_SIGNATURE		4
#परिभाषय KRL_SECTION_FINGERPRINT_SHA256	5
#परिभाषय KRL_SECTION_EXTENSION		255

/* KRL_SECTION_CERTIFICATES subsection types */
#परिभाषय KRL_SECTION_CERT_SERIAL_LIST	0x20
#परिभाषय KRL_SECTION_CERT_SERIAL_RANGE	0x21
#परिभाषय KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#परिभाषय KRL_SECTION_CERT_कुञ्चिका_ID		0x23
#परिभाषय KRL_SECTION_CERT_EXTENSION	0x39

संरचना sshkey;
संरचना sshbuf;
संरचना ssh_krl;

संरचना ssh_krl *ssh_krl_init(शून्य);
शून्य ssh_krl_free(संरचना ssh_krl *krl);
शून्य ssh_krl_समुच्चयः_संस्करणम्(संरचना ssh_krl *krl, uint64_t संस्करणम्);
पूर्णाङ्क ssh_krl_समुच्चयः_comment(संरचना ssh_krl *krl, ध्रुव वर्ण *comment);
पूर्णाङ्क ssh_krl_revoke_cert_by_serial(संरचना ssh_krl *krl,
    ध्रुव संरचना sshkey *ca_कुञ्चिका, uint64_t serial);
पूर्णाङ्क ssh_krl_revoke_cert_by_serial_range(संरचना ssh_krl *krl,
    ध्रुव संरचना sshkey *ca_कुञ्चिका, uint64_t lo, uint64_t hi);
पूर्णाङ्क ssh_krl_revoke_cert_by_कुञ्चिका_id(संरचना ssh_krl *krl,
    ध्रुव संरचना sshkey *ca_कुञ्चिका, ध्रुव वर्ण *कुञ्चिका_id);
पूर्णाङ्क ssh_krl_revoke_कुञ्चिका_explicit(संरचना ssh_krl *krl, ध्रुव संरचना sshkey *कुञ्चिका);
पूर्णाङ्क ssh_krl_revoke_कुञ्चिका_sha1(संरचना ssh_krl *krl, ध्रुव u_char *p, आकार_t len);
पूर्णाङ्क ssh_krl_revoke_कुञ्चिका_sha256(संरचना ssh_krl *krl, ध्रुव u_char *p, आकार_t len);
पूर्णाङ्क ssh_krl_revoke_कुञ्चिका(संरचना ssh_krl *krl, ध्रुव संरचना sshkey *कुञ्चिका);
पूर्णाङ्क ssh_krl_गन्तव्यम्_blob(संरचना ssh_krl *krl, संरचना sshbuf *buf);
पूर्णाङ्क ssh_krl_from_blob(संरचना sshbuf *buf, संरचना ssh_krl **krlp);
पूर्णाङ्क ssh_krl_check_कुञ्चिका(संरचना ssh_krl *krl, ध्रुव संरचना sshkey *कुञ्चिका);
पूर्णाङ्क ssh_krl_file_अन्तर्भवति_कुञ्चिका(ध्रुव वर्ण *मार्गः, ध्रुव संरचना sshkey *कुञ्चिका);
पूर्णाङ्क krl_dump(संरचना ssh_krl *krl, FILE *f);

#यदि_अन्तः /* _KRL_H */

