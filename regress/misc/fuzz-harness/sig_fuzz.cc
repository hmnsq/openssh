// cc_fuzz_target test for public key parsing.

#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ "includes.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *generate_or_die(ಪೂರ್ಣಾಙ್ಕ type, unsigned bits) {
  ಪೂರ್ಣಾಙ್ಕ r;
  ಸಂರಚನಾ sshkey *ret;
  ಯದಿ ((r = sshkey_generate(type, bits, &ret)) != 0) {
    fprintf(stderr, "generate(%d, %u): %s", type, bits, ssh_err(r));
    abort();
  }
  ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t* sig, size_t slen)
{
#ifdef WITH_OPENSSL
  ಸ್ಥಿರ ಸಂರಚನಾ sshkey *rsa = generate_or_die(ಕೀಲಿ_RSA, 2048);
  ಸ್ಥಿರ ಸಂರಚನಾ sshkey *ecdsa256 = generate_or_die(ಕೀಲಿ_ECDSA, 256);
  ಸ್ಥಿರ ಸಂರಚನಾ sshkey *ecdsa384 = generate_or_die(ಕೀಲಿ_ECDSA, 384);
  ಸ್ಥಿರ ಸಂರಚನಾ sshkey *ecdsa521 = generate_or_die(ಕೀಲಿ_ECDSA, 521);
#endif
  ಸಂರಚನಾ sshkey_sig_details *details = ರಿಕ್ತ;
  ಸ್ಥಿರ ಸಂರಚನಾ sshkey *ed25519 = generate_or_die(ಕೀಲಿ_ED25519, 0);
  ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  ಸ್ಥಿರ ಧ್ರುವ size_t dlen = strlen(data);

#ifdef WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (ಧ್ರುವ u_char *)data, dlen, ರಿಕ್ತ, 0, &details);
  sshkey_sig_details_free(details);
  details = ರಿಕ್ತ;

  sshkey_verify(ecdsa256, sig, slen, (ಧ್ರುವ u_char *)data, dlen, ರಿಕ್ತ, 0, &details);
  sshkey_sig_details_free(details);
  details = ರಿಕ್ತ;

  sshkey_verify(ecdsa384, sig, slen, (ಧ್ರುವ u_char *)data, dlen, ರಿಕ್ತ, 0, &details);
  sshkey_sig_details_free(details);
  details = ರಿಕ್ತ;

  sshkey_verify(ecdsa521, sig, slen, (ಧ್ರುವ u_char *)data, dlen, ರಿಕ್ತ, 0, &details);
  sshkey_sig_details_free(details);
  details = ರಿಕ್ತ;
#endif

  sshkey_verify(ed25519, sig, slen, (ಧ್ರುವ u_char *)data, dlen, ರಿಕ್ತ, 0, &details);
  sshkey_sig_details_free(details);
  ಪ್ರತ್ಯಾಗಮ 0;
}

} // extern
