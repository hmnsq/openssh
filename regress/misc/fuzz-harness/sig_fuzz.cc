// cc_fuzz_target test for public key parsing.

#समावेश <stddef.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>

बाह्य "C" {

#समावेश "includes.h"
#समावेश "sshkey.h"
#समावेश "ssherr.h"

अटल काष्ठा sshkey *generate_or_die(पूर्णांक type, अचिन्हित bits) {
  पूर्णांक r;
  काष्ठा sshkey *ret;
  अगर ((r = sshkey_generate(type, bits, &ret)) != 0) {
    ख_लिखो(मानक_त्रुटि, "generate(%d, %u): %s", type, bits, ssh_err(r));
    पात();
  }
  वापस ret;
}

पूर्णांक LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t* sig, माप_प्रकार slen)
{
#अगर_घोषित WITH_OPENSSL
  अटल काष्ठा sshkey *rsa = generate_or_die(कुंजी_RSA, 2048);
  अटल काष्ठा sshkey *ecdsa256 = generate_or_die(कुंजी_ECDSA, 256);
  अटल काष्ठा sshkey *ecdsa384 = generate_or_die(कुंजी_ECDSA, 384);
  अटल काष्ठा sshkey *ecdsa521 = generate_or_die(कुंजी_ECDSA, 521);
#पूर्ण_अगर
  काष्ठा sshkey_sig_details *details = शून्य;
  अटल काष्ठा sshkey *ed25519 = generate_or_die(कुंजी_ED25519, 0);
  अटल स्थिर अक्षर *तथ्य = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  अटल स्थिर माप_प्रकार dlen = म_माप(तथ्य);

#अगर_घोषित WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (स्थिर u_char *)तथ्य, dlen, शून्य, 0, &details);
  sshkey_sig_details_free(details);
  details = शून्य;

  sshkey_verify(ecdsa256, sig, slen, (स्थिर u_char *)तथ्य, dlen, शून्य, 0, &details);
  sshkey_sig_details_free(details);
  details = शून्य;

  sshkey_verify(ecdsa384, sig, slen, (स्थिर u_char *)तथ्य, dlen, शून्य, 0, &details);
  sshkey_sig_details_free(details);
  details = शून्य;

  sshkey_verify(ecdsa521, sig, slen, (स्थिर u_char *)तथ्य, dlen, शून्य, 0, &details);
  sshkey_sig_details_free(details);
  details = शून्य;
#पूर्ण_अगर

  sshkey_verify(ed25519, sig, slen, (स्थिर u_char *)तथ्य, dlen, शून्य, 0, &details);
  sshkey_sig_details_free(details);
  वापस 0;
}

} // extern
