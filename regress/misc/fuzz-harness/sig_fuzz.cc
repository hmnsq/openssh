// cc_fuzz_target test for public key parsing.

#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

ବାହ୍ୟ "C" {

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"

ସ୍ଥିର ସଂରଚନା sshkey *generate_or_die(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, unsigned bits) {
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
  ସଂରଚନା sshkey *ret;
  ଯଦି ((r = sshkey_generate(type, bits, &ret)) != 0) {
    fprintf(stderr, "generate(%d, %u): %s", type, bits, ssh_err(r));
    abort();
  }
  ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t* sig, size_t slen)
{
#ifdef WITH_OPENSSL
  ସ୍ଥିର ସଂରଚନା sshkey *rsa = generate_or_die(ଚାବି_RSA, 2048);
  ସ୍ଥିର ସଂରଚନା sshkey *ecdsa256 = generate_or_die(ଚାବି_ECDSA, 256);
  ସ୍ଥିର ସଂରଚନା sshkey *ecdsa384 = generate_or_die(ଚାବି_ECDSA, 384);
  ସ୍ଥିର ସଂରଚନା sshkey *ecdsa521 = generate_or_die(ଚାବି_ECDSA, 521);
#endif
  ସଂରଚନା sshkey_sig_details *details = ଖାଲି;
  ସ୍ଥିର ସଂରଚନା sshkey *ed25519 = generate_or_die(ଚାବି_ED25519, 0);
  ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  ସ୍ଥିର ଅଚଳ size_t dlen = strlen(data);

#ifdef WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (ଅଚଳ u_char *)data, dlen, ଖାଲି, 0, &details);
  sshkey_sig_details_free(details);
  details = ଖାଲି;

  sshkey_verify(ecdsa256, sig, slen, (ଅଚଳ u_char *)data, dlen, ଖାଲି, 0, &details);
  sshkey_sig_details_free(details);
  details = ଖାଲି;

  sshkey_verify(ecdsa384, sig, slen, (ଅଚଳ u_char *)data, dlen, ଖାଲି, 0, &details);
  sshkey_sig_details_free(details);
  details = ଖାଲି;

  sshkey_verify(ecdsa521, sig, slen, (ଅଚଳ u_char *)data, dlen, ଖାଲି, 0, &details);
  sshkey_sig_details_free(details);
  details = ଖାଲି;
#endif

  sshkey_verify(ed25519, sig, slen, (ଅଚଳ u_char *)data, dlen, ଖାଲି, 0, &details);
  sshkey_sig_details_free(details);
  ଫେରନ୍ତୁ 0;
}

} // extern
