// cc_fuzz_target test for public key parsing.

#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

خارجي "C" {

#ضمن "includes.h"
#ضمن "sshkey.h"
#ضمن "ssherr.h"

ساكن بنية sshkey *generate_or_die(صحيح type, unsigned bits) {
  صحيح r;
  بنية sshkey *ret;
  إذا ((r = sshkey_generate(type, bits, &ret)) != 0) {
    fprintf(stderr, "generate(%d, %u): %s", type, bits, ssh_err(r));
    abort();
  }
  أرجع ret;
}

صحيح LLVMFuzzer_Test_One_كىرگۈزۈش(ثابت uint8_t* sig, size_t slen)
{
#ifdef WITH_OPENSSL
  ساكن بنية sshkey *rsa = generate_or_die(ئاچقۇچ_RSA, 2048);
  ساكن بنية sshkey *ecdsa256 = generate_or_die(ئاچقۇچ_ECDSA, 256);
  ساكن بنية sshkey *ecdsa384 = generate_or_die(ئاچقۇچ_ECDSA, 384);
  ساكن بنية sshkey *ecdsa521 = generate_or_die(ئاچقۇچ_ECDSA, 521);
#endif
  بنية sshkey_sig_details *details = عدم;
  ساكن بنية sshkey *ed25519 = generate_or_die(ئاچقۇچ_ED25519, 0);
  ساكن ثابت حرف *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  ساكن ثابت size_t dlen = strlen(data);

#ifdef WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (ثابت u_char *)data, dlen, عدم, 0, &details);
  sshkey_sig_details_free(details);
  details = عدم;

  sshkey_verify(ecdsa256, sig, slen, (ثابت u_char *)data, dlen, عدم, 0, &details);
  sshkey_sig_details_free(details);
  details = عدم;

  sshkey_verify(ecdsa384, sig, slen, (ثابت u_char *)data, dlen, عدم, 0, &details);
  sshkey_sig_details_free(details);
  details = عدم;

  sshkey_verify(ecdsa521, sig, slen, (ثابت u_char *)data, dlen, عدم, 0, &details);
  sshkey_sig_details_free(details);
  details = عدم;
#endif

  sshkey_verify(ed25519, sig, slen, (ثابت u_char *)data, dlen, عدم, 0, &details);
  sshkey_sig_details_free(details);
  أرجع 0;
}

} // extern
