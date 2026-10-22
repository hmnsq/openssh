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

ಸ್ಥಿರ ರಚನೆ sshkey *generate_or_die(ಪೂರ್ಣಾಂಕ type, ಚಿಹ್ನೆರಹಿತ ಬಿಟ್ಟುಗಳು) {
  ಪೂರ್ಣಾಂಕ r;
  ರಚನೆ sshkey *ret;
  ಆದರೆ ((r = sshkey_generate(type, ಬಿಟ್ಟುಗಳು, &ret)) != 0) {
    fprintf(stderr, "generate(%d, %u): %s", type, ಬಿಟ್ಟುಗಳು, ssh_err(r));
    abort();
  }
  ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಸ್ಥಿರಾಂಕ uint8_t* sig, ಗಾತ್ರ_t slen)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
  ಸ್ಥಿರ ರಚನೆ sshkey *rsa = generate_or_die(ಕೀಲಿ_RSA, 2048);
  ಸ್ಥಿರ ರಚನೆ sshkey *ecdsa256 = generate_or_die(ಕೀಲಿ_ECDSA, 256);
  ಸ್ಥಿರ ರಚನೆ sshkey *ecdsa384 = generate_or_die(ಕೀಲಿ_ECDSA, 384);
  ಸ್ಥಿರ ರಚನೆ sshkey *ecdsa521 = generate_or_die(ಕೀಲಿ_ECDSA, 521);
#ಆದರೆ_ಅಂತ್ಯ
  ರಚನೆ sshkey_sig_details *details = ಖಾಲಿ;
  ಸ್ಥಿರ ರಚನೆ sshkey *ed25519 = generate_or_die(ಕೀಲಿ_ED25519, 0);
  ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ದತ್ತಾಂಶ = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಗಾತ್ರ_t dlen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ದತ್ತಾಂಶ);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (ಸ್ಥಿರಾಂಕ u_char *)ದತ್ತಾಂಶ, dlen, ಖಾಲಿ, 0, &details);
  sshkey_sig_details_free(details);
  details = ಖಾಲಿ;

  sshkey_verify(ecdsa256, sig, slen, (ಸ್ಥಿರಾಂಕ u_char *)ದತ್ತಾಂಶ, dlen, ಖಾಲಿ, 0, &details);
  sshkey_sig_details_free(details);
  details = ಖಾಲಿ;

  sshkey_verify(ecdsa384, sig, slen, (ಸ್ಥಿರಾಂಕ u_char *)ದತ್ತಾಂಶ, dlen, ಖಾಲಿ, 0, &details);
  sshkey_sig_details_free(details);
  details = ಖಾಲಿ;

  sshkey_verify(ecdsa521, sig, slen, (ಸ್ಥಿರಾಂಕ u_char *)ದತ್ತಾಂಶ, dlen, ಖಾಲಿ, 0, &details);
  sshkey_sig_details_free(details);
  details = ಖಾಲಿ;
#ಆದರೆ_ಅಂತ್ಯ

  sshkey_verify(ed25519, sig, slen, (ಸ್ಥಿರಾಂಕ u_char *)ದತ್ತಾಂಶ, dlen, ಖಾಲಿ, 0, &details);
  sshkey_sig_details_free(details);
  ಹಿಂತಿರುಗಿ 0;
}

} // extern
