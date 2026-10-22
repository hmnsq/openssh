// cc_fuzz_target test for public key parsing.

#অন্তর্ভাৱ <stddef.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>

বাহ্য "C" {

#অন্তর্ভাৱ "includes.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "ssherr.h"

স্থির সংরচনা sshkey *generate_or_die(পূর্ণাঙ্ক type, unsigned bits) {
  পূর্ণাঙ্ক r;
  সংরচনা sshkey *ret;
  যদি ((r = sshkey_generate(type, bits, &ret)) != 0) {
    fprintf(stderr, "generate(%d, %u): %s", type, bits, ssh_err(r));
    abort();
  }
  ঘূৰাই ret;
}

পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্ৰবেশ(ধ্রুৱ uint8_t* sig, size_t slen)
{
#ifdef WITH_OPENSSL
  স্থির সংরচনা sshkey *rsa = generate_or_die(চাবি_RSA, 2048);
  স্থির সংরচনা sshkey *ecdsa256 = generate_or_die(চাবি_ECDSA, 256);
  স্থির সংরচনা sshkey *ecdsa384 = generate_or_die(চাবি_ECDSA, 384);
  স্থির সংরচনা sshkey *ecdsa521 = generate_or_die(চাবি_ECDSA, 521);
#endif
  সংরচনা sshkey_sig_details *details = রিক্ত;
  স্থির সংরচনা sshkey *ed25519 = generate_or_die(চাবি_ED25519, 0);
  স্থির ধ্রুৱ ৱর্ণ *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  স্থির ধ্রুৱ size_t dlen = strlen(data);

#ifdef WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (ধ্রুৱ u_char *)data, dlen, রিক্ত, 0, &details);
  sshkey_sig_details_free(details);
  details = রিক্ত;

  sshkey_verify(ecdsa256, sig, slen, (ধ্রুৱ u_char *)data, dlen, রিক্ত, 0, &details);
  sshkey_sig_details_free(details);
  details = রিক্ত;

  sshkey_verify(ecdsa384, sig, slen, (ধ্রুৱ u_char *)data, dlen, রিক্ত, 0, &details);
  sshkey_sig_details_free(details);
  details = রিক্ত;

  sshkey_verify(ecdsa521, sig, slen, (ধ্রুৱ u_char *)data, dlen, রিক্ত, 0, &details);
  sshkey_sig_details_free(details);
  details = রিক্ত;
#endif

  sshkey_verify(ed25519, sig, slen, (ধ্রুৱ u_char *)data, dlen, রিক্ত, 0, &details);
  sshkey_sig_details_free(details);
  ঘূৰাই 0;
}

} // extern
