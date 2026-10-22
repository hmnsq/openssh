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

ساكن بنية sshkey *generate_or_die(صحيح type, بیعلامت بیتها) {
  صحيح r;
  بنية sshkey *ret;
  إذا ((r = sshkey_generate(type, بیتها, &ret)) != 0) {
    fprintf(stderr, "generate(%d, %u): %s", type, بیتها, ssh_err(r));
    abort();
  }
  أرجع ret;
}

صحيح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* sig, اندازه_t slen)
{
#اگر_تعریف_شده WITH_OPENSSL
  ساكن بنية sshkey *rsa = generate_or_die(کلید_RSA, 2048);
  ساكن بنية sshkey *ecdsa256 = generate_or_die(کلید_ECDSA, 256);
  ساكن بنية sshkey *ecdsa384 = generate_or_die(کلید_ECDSA, 384);
  ساكن بنية sshkey *ecdsa521 = generate_or_die(کلید_ECDSA, 521);
#پایان_اگر
  بنية sshkey_sig_details *details = عدم;
  ساكن بنية sshkey *ed25519 = generate_or_die(کلید_ED25519, 0);
  ساكن ثابت حرف *داده = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  ساكن ثابت اندازه_t dlen = طول_رشته(داده);

#اگر_تعریف_شده WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (ثابت u_char *)داده, dlen, عدم, 0, &details);
  sshkey_sig_details_free(details);
  details = عدم;

  sshkey_verify(ecdsa256, sig, slen, (ثابت u_char *)داده, dlen, عدم, 0, &details);
  sshkey_sig_details_free(details);
  details = عدم;

  sshkey_verify(ecdsa384, sig, slen, (ثابت u_char *)داده, dlen, عدم, 0, &details);
  sshkey_sig_details_free(details);
  details = عدم;

  sshkey_verify(ecdsa521, sig, slen, (ثابت u_char *)داده, dlen, عدم, 0, &details);
  sshkey_sig_details_free(details);
  details = عدم;
#پایان_اگر

  sshkey_verify(ed25519, sig, slen, (ثابت u_char *)داده, dlen, عدم, 0, &details);
  sshkey_sig_details_free(details);
  أرجع 0;
}

} // extern
