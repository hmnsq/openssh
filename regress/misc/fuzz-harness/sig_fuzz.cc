// cc_fuzz_target test for public key parsing.

#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

બાહ્ય "C" {

#અન્તર્ભાવ "includes.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "ssherr.h"

સ્થિર સંરચના sshkey *generate_or_die(પૂર્ણાંક type, unsigned bits) {
  પૂર્ણાંક r;
  સંરચના sshkey *ret;
  જો ((r = sshkey_generate(type, bits, &ret)) != 0) {
    fprintf(stderr, "generate(%d, %u): %s", type, bits, ssh_err(r));
    abort();
  }
  પાછા ret;
}

પૂર્ણાંક LLVMFuzzer_Test_One_આગત(અચલ uint8_t* sig, size_t slen)
{
#ifdef WITH_OPENSSL
  સ્થિર સંરચના sshkey *rsa = generate_or_die(ચાવી_RSA, 2048);
  સ્થિર સંરચના sshkey *ecdsa256 = generate_or_die(ચાવી_ECDSA, 256);
  સ્થિર સંરચના sshkey *ecdsa384 = generate_or_die(ચાવી_ECDSA, 384);
  સ્થિર સંરચના sshkey *ecdsa521 = generate_or_die(ચાવી_ECDSA, 521);
#endif
  સંરચના sshkey_sig_details *details = ખાલી;
  સ્થિર સંરચના sshkey *ed25519 = generate_or_die(ચાવી_ED25519, 0);
  સ્થિર અચલ અક્ષર *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  સ્થિર અચલ size_t dlen = strlen(data);

#ifdef WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (અચલ u_char *)data, dlen, ખાલી, 0, &details);
  sshkey_sig_details_free(details);
  details = ખાલી;

  sshkey_verify(ecdsa256, sig, slen, (અચલ u_char *)data, dlen, ખાલી, 0, &details);
  sshkey_sig_details_free(details);
  details = ખાલી;

  sshkey_verify(ecdsa384, sig, slen, (અચલ u_char *)data, dlen, ખાલી, 0, &details);
  sshkey_sig_details_free(details);
  details = ખાલી;

  sshkey_verify(ecdsa521, sig, slen, (અચલ u_char *)data, dlen, ખાલી, 0, &details);
  sshkey_sig_details_free(details);
  details = ખાલી;
#endif

  sshkey_verify(ed25519, sig, slen, (અચલ u_char *)data, dlen, ખાલી, 0, &details);
  sshkey_sig_details_free(details);
  પાછા 0;
}

} // extern
