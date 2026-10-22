// cc_fuzz_target test for public key parsing.

#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

بیرونی "C" {

#شامل "includes.h"
#شامل "sshkey.h"
#شامل "ssherr.h"

ایستا ساختار sshkey *generate_or_die(صحیح type, unsigned bits) {
  صحیح r;
  ساختار sshkey *ret;
  اگر ((r = sshkey_generate(type, bits, &ret)) != 0) {
    fprintf(stderr, "generate(%d, %u): %s", type, bits, ssh_err(r));
    abort();
  }
  بازگشت ret;
}

صحیح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* sig, size_t slen)
{
#ifdef WITH_OPENSSL
  ایستا ساختار sshkey *rsa = generate_or_die(کلید_RSA, 2048);
  ایستا ساختار sshkey *ecdsa256 = generate_or_die(کلید_ECDSA, 256);
  ایستا ساختار sshkey *ecdsa384 = generate_or_die(کلید_ECDSA, 384);
  ایستا ساختار sshkey *ecdsa521 = generate_or_die(کلید_ECDSA, 521);
#endif
  ساختار sshkey_sig_details *details = پوچ;
  ایستا ساختار sshkey *ed25519 = generate_or_die(کلید_ED25519, 0);
  ایستا ثابت نویسه *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  ایستا ثابت size_t dlen = strlen(data);

#ifdef WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (ثابت u_char *)data, dlen, پوچ, 0, &details);
  sshkey_sig_details_free(details);
  details = پوچ;

  sshkey_verify(ecdsa256, sig, slen, (ثابت u_char *)data, dlen, پوچ, 0, &details);
  sshkey_sig_details_free(details);
  details = پوچ;

  sshkey_verify(ecdsa384, sig, slen, (ثابت u_char *)data, dlen, پوچ, 0, &details);
  sshkey_sig_details_free(details);
  details = پوچ;

  sshkey_verify(ecdsa521, sig, slen, (ثابت u_char *)data, dlen, پوچ, 0, &details);
  sshkey_sig_details_free(details);
  details = پوچ;
#endif

  sshkey_verify(ed25519, sig, slen, (ثابت u_char *)data, dlen, پوچ, 0, &details);
  sshkey_sig_details_free(details);
  بازگشت 0;
}

} // extern
