// cc_fuzz_target test for public key parsing.

#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

बाह्य "C" {

#अन्तर्भाव "includes.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "ssherr.h"

स्थिर संरचना sshkey *generate_or_die(पूर्णाङ्क type, अचिह्नित द्वयङ्काः) {
  पूर्णाङ्क r;
  संरचना sshkey *ret;
  यदि ((r = sshkey_generate(type, द्वयङ्काः, &ret)) != 0) {
    fprintf(stderr, "generate(%d, %u): %s", type, द्वयङ्काः, ssh_err(r));
    abort();
  }
  प्रत्यागम ret;
}

पूर्णाङ्क LLVMFuzzer_Test_One_निवेशः(ध्रुव uint8_t* sig, आकार_t slen)
{
#यदि_परिभाषितम् WITH_OPENSSL
  स्थिर संरचना sshkey *rsa = generate_or_die(कुञ्चिका_RSA, 2048);
  स्थिर संरचना sshkey *ecdsa256 = generate_or_die(कुञ्चिका_ECDSA, 256);
  स्थिर संरचना sshkey *ecdsa384 = generate_or_die(कुञ्चिका_ECDSA, 384);
  स्थिर संरचना sshkey *ecdsa521 = generate_or_die(कुञ्चिका_ECDSA, 521);
#यदि_अन्तः
  संरचना sshkey_sig_details *details = रिक्त;
  स्थिर संरचना sshkey *ed25519 = generate_or_die(कुञ्चिका_ED25519, 0);
  स्थिर ध्रुव वर्ण *दत्त = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  स्थिर ध्रुव आकार_t dlen = वाक्यदैर्घ्यम्(दत्त);

#यदि_परिभाषितम् WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (ध्रुव u_char *)दत्त, dlen, रिक्त, 0, &details);
  sshkey_sig_details_free(details);
  details = रिक्त;

  sshkey_verify(ecdsa256, sig, slen, (ध्रुव u_char *)दत्त, dlen, रिक्त, 0, &details);
  sshkey_sig_details_free(details);
  details = रिक्त;

  sshkey_verify(ecdsa384, sig, slen, (ध्रुव u_char *)दत्त, dlen, रिक्त, 0, &details);
  sshkey_sig_details_free(details);
  details = रिक्त;

  sshkey_verify(ecdsa521, sig, slen, (ध्रुव u_char *)दत्त, dlen, रिक्त, 0, &details);
  sshkey_sig_details_free(details);
  details = रिक्त;
#यदि_अन्तः

  sshkey_verify(ed25519, sig, slen, (ध्रुव u_char *)दत्त, dlen, रिक्त, 0, &details);
  sshkey_sig_details_free(details);
  प्रत्यागम 0;
}

} // extern
