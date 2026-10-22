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

#ifndef _KRL_H
#define _KRL_H

/* Functions to manage key revocation lists */

#define KRL_MAGIC		"SSHKRL\n\0"
#define KRL_FORMAT_VERSION	1

/* KRL section types */
#define KRL_SECTION_CERTIFICATES	1
#define KRL_SECTION_EXPLICIT_சாவி	2
#define KRL_SECTION_FINGERPRINT_SHA1	3
#define KRL_SECTION_SIGNATURE		4
#define KRL_SECTION_FINGERPRINT_SHA256	5
#define KRL_SECTION_EXTENSION		255

/* KRL_SECTION_CERTIFICATES subsection types */
#define KRL_SECTION_CERT_SERIAL_LIST	0x20
#define KRL_SECTION_CERT_SERIAL_RANGE	0x21
#define KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#define KRL_SECTION_CERT_சாவி_ID		0x23
#define KRL_SECTION_CERT_EXTENSION	0x39

கட்டமைப்பு sshkey;
கட்டமைப்பு sshbuf;
கட்டமைப்பு ssh_krl;

கட்டமைப்பு ssh_krl *ssh_krl_init(வெறுமை);
வெறுமை ssh_krl_free(கட்டமைப்பு ssh_krl *krl);
வெறுமை ssh_krl_set_version(கட்டமைப்பு ssh_krl *krl, uint64_t version);
முழு ssh_krl_set_comment(கட்டமைப்பு ssh_krl *krl, மாறிலி எழுத்து *comment);
முழு ssh_krl_revoke_cert_by_serial(கட்டமைப்பு ssh_krl *krl,
    மாறிலி கட்டமைப்பு sshkey *ca_சாவி, uint64_t serial);
முழு ssh_krl_revoke_cert_by_serial_range(கட்டமைப்பு ssh_krl *krl,
    மாறிலி கட்டமைப்பு sshkey *ca_சாவி, uint64_t lo, uint64_t hi);
முழு ssh_krl_revoke_cert_by_சாவி_id(கட்டமைப்பு ssh_krl *krl,
    மாறிலி கட்டமைப்பு sshkey *ca_சாவி, மாறிலி எழுத்து *சாவி_id);
முழு ssh_krl_revoke_சாவி_explicit(கட்டமைப்பு ssh_krl *krl, மாறிலி கட்டமைப்பு sshkey *சாவி);
முழு ssh_krl_revoke_சாவி_sha1(கட்டமைப்பு ssh_krl *krl, மாறிலி u_char *p, size_t len);
முழு ssh_krl_revoke_சாவி_sha256(கட்டமைப்பு ssh_krl *krl, மாறிலி u_char *p, size_t len);
முழு ssh_krl_revoke_சாவி(கட்டமைப்பு ssh_krl *krl, மாறிலி கட்டமைப்பு sshkey *சாவி);
முழு ssh_krl_to_blob(கட்டமைப்பு ssh_krl *krl, கட்டமைப்பு sshbuf *buf);
முழு ssh_krl_from_blob(கட்டமைப்பு sshbuf *buf, கட்டமைப்பு ssh_krl **krlp);
முழு ssh_krl_check_சாவி(கட்டமைப்பு ssh_krl *krl, மாறிலி கட்டமைப்பு sshkey *சாவி);
முழு ssh_krl_file_contains_சாவி(மாறிலி எழுத்து *path, மாறிலி கட்டமைப்பு sshkey *சாவி);
முழு krl_dump(கட்டமைப்பு ssh_krl *krl, FILE *f);

#endif /* _KRL_H */

