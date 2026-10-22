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

#अगर_अघोषित _KRL_H
#घोषणा _KRL_H

/* Functions to manage key revocation lists */

#घोषणा KRL_MAGIC		"SSHKRL\n\0"
#घोषणा KRL_FORMAT_VERSION	1

/* KRL section types */
#घोषणा KRL_SECTION_CERTIFICATES	1
#घोषणा KRL_SECTION_EXPLICIT_कुंजी	2
#घोषणा KRL_SECTION_FINGERPRINT_SHA1	3
#घोषणा KRL_SECTION_SIGNATURE		4
#घोषणा KRL_SECTION_FINGERPRINT_SHA256	5
#घोषणा KRL_SECTION_EXTENSION		255

/* KRL_SECTION_CERTIFICATES subsection types */
#घोषणा KRL_SECTION_CERT_SERIAL_LIST	0x20
#घोषणा KRL_SECTION_CERT_SERIAL_RANGE	0x21
#घोषणा KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#घोषणा KRL_SECTION_CERT_कुंजी_ID		0x23
#घोषणा KRL_SECTION_CERT_EXTENSION	0x39

काष्ठा sshkey;
काष्ठा sshbuf;
काष्ठा ssh_krl;

काष्ठा ssh_krl *ssh_krl_init(व्योम);
व्योम ssh_krl_free(काष्ठा ssh_krl *krl);
व्योम ssh_krl_set_version(काष्ठा ssh_krl *krl, uint64_t version);
पूर्णांक ssh_krl_set_comment(काष्ठा ssh_krl *krl, स्थिर अक्षर *comment);
पूर्णांक ssh_krl_revoke_cert_by_serial(काष्ठा ssh_krl *krl,
    स्थिर काष्ठा sshkey *ca_कुंजी, uint64_t serial);
पूर्णांक ssh_krl_revoke_cert_by_serial_range(काष्ठा ssh_krl *krl,
    स्थिर काष्ठा sshkey *ca_कुंजी, uint64_t lo, uint64_t hi);
पूर्णांक ssh_krl_revoke_cert_by_कुंजी_id(काष्ठा ssh_krl *krl,
    स्थिर काष्ठा sshkey *ca_कुंजी, स्थिर अक्षर *कुंजी_id);
पूर्णांक ssh_krl_revoke_कुंजी_explicit(काष्ठा ssh_krl *krl, स्थिर काष्ठा sshkey *कुंजी);
पूर्णांक ssh_krl_revoke_कुंजी_sha1(काष्ठा ssh_krl *krl, स्थिर u_char *p, माप_प्रकार len);
पूर्णांक ssh_krl_revoke_कुंजी_sha256(काष्ठा ssh_krl *krl, स्थिर u_char *p, माप_प्रकार len);
पूर्णांक ssh_krl_revoke_कुंजी(काष्ठा ssh_krl *krl, स्थिर काष्ठा sshkey *कुंजी);
पूर्णांक ssh_krl_to_blob(काष्ठा ssh_krl *krl, काष्ठा sshbuf *buf);
पूर्णांक ssh_krl_from_blob(काष्ठा sshbuf *buf, काष्ठा ssh_krl **krlp);
पूर्णांक ssh_krl_check_कुंजी(काष्ठा ssh_krl *krl, स्थिर काष्ठा sshkey *कुंजी);
पूर्णांक ssh_krl_file_contains_कुंजी(स्थिर अक्षर *path, स्थिर काष्ठा sshkey *कुंजी);
पूर्णांक krl_dump(काष्ठा ssh_krl *krl, खाता *f);

#पूर्ण_अगर /* _KRL_H */

