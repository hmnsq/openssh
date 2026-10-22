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

स्थिर संरचना sshkey *generate_or_die(पूर्णांक type, अचिन्हित bits) {
  पूर्णांक r;
  संरचना sshkey *ret;
  जर ((r = sshkey_generate(type, bits, &ret)) != 0) {
    ख_लिखो(मानक_त्रुटि, "generate(%d, %u): %s", type, bits, ssh_err(r));
    पात();
  }
  परत ret;
}

पूर्णांक LLVMFuzzer_Test_One_आदान(स्थिरांक uint8_t* sig, माप_प्रकार slen)
{
#ifdef WITH_OPENSSL
  स्थिर संरचना sshkey *rsa = generate_or_die(किल्ली_RSA, 2048);
  स्थिर संरचना sshkey *ecdsa256 = generate_or_die(किल्ली_ECDSA, 256);
  स्थिर संरचना sshkey *ecdsa384 = generate_or_die(किल्ली_ECDSA, 384);
  स्थिर संरचना sshkey *ecdsa521 = generate_or_die(किल्ली_ECDSA, 521);
#endif
  संरचना sshkey_sig_details *details = रिक्त;
  स्थिर संरचना sshkey *ed25519 = generate_or_die(किल्ली_ED25519, 0);
  स्थिर स्थिरांक अक्षर *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  स्थिर स्थिरांक माप_प्रकार dlen = म_माप(data);

#ifdef WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (स्थिरांक u_char *)data, dlen, रिक्त, 0, &details);
  sshkey_sig_details_free(details);
  details = रिक्त;

  sshkey_verify(ecdsa256, sig, slen, (स्थिरांक u_char *)data, dlen, रिक्त, 0, &details);
  sshkey_sig_details_free(details);
  details = रिक्त;

  sshkey_verify(ecdsa384, sig, slen, (स्थिरांक u_char *)data, dlen, रिक्त, 0, &details);
  sshkey_sig_details_free(details);
  details = रिक्त;

  sshkey_verify(ecdsa521, sig, slen, (स्थिरांक u_char *)data, dlen, रिक्त, 0, &details);
  sshkey_sig_details_free(details);
  details = रिक्त;
#endif

  sshkey_verify(ed25519, sig, slen, (स्थिरांक u_char *)data, dlen, रिक्त, 0, &details);
  sshkey_sig_details_free(details);
  परत 0;
}

} // extern
