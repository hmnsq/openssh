// cc_fuzz_target test for public key parsing.

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {

#include "includes.h"
#include "sshkey.h"
#include "ssherr.h"

static sa_nracanaa sshkey *generate_or_die(puur_naa_nka type, unsigned bits) {
  puur_naa_nka r;
  sa_nracanaa sshkey *ret;
  ᱡᱩᱫᱤ ((r = sshkey_generate(type, bits, &ret)) != 0) {
    fprintf(stderr, "generate(%d, %u): %s", type, bits, ssh_err(r));
    abort();
  }
  ᱨᱩᱣᱟᱹᱲ ret;
}

puur_naa_nka LLVMFuzzerTestOneInput(const uint8_t* sig, size_t slen)
{
#ifdef WITH_OPENSSL
  static sa_nracanaa sshkey *rsa = generate_or_die(KEY_RSA, 2048);
  static sa_nracanaa sshkey *ecdsa256 = generate_or_die(KEY_ECDSA, 256);
  static sa_nracanaa sshkey *ecdsa384 = generate_or_die(KEY_ECDSA, 384);
  static sa_nracanaa sshkey *ecdsa521 = generate_or_die(KEY_ECDSA, 521);
#endif
  sa_nracanaa sshkey_sig_details *details = NULL;
  static sa_nracanaa sshkey *ed25519 = generate_or_die(KEY_ED25519, 0);
  static const var_na *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  static const size_t dlen = strlen(data);

#ifdef WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (const u_char *)data, dlen, NULL, 0, &details);
  sshkey_sig_details_free(details);
  details = NULL;

  sshkey_verify(ecdsa256, sig, slen, (const u_char *)data, dlen, NULL, 0, &details);
  sshkey_sig_details_free(details);
  details = NULL;

  sshkey_verify(ecdsa384, sig, slen, (const u_char *)data, dlen, NULL, 0, &details);
  sshkey_sig_details_free(details);
  details = NULL;

  sshkey_verify(ecdsa521, sig, slen, (const u_char *)data, dlen, NULL, 0, &details);
  sshkey_sig_details_free(details);
  details = NULL;
#endif

  sshkey_verify(ed25519, sig, slen, (const u_char *)data, dlen, NULL, 0, &details);
  sshkey_sig_details_free(details);
  ᱨᱩᱣᱟᱹᱲ 0;
}

} // extern
