// cc_fuzz_target test for public key parsing.

#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

خارجی "C" {

#شامل "includes.h"
#شامل "sshkey.h"
#شامل "ssherr.h"

ساکن ساخت sshkey *generate_or_die(صحیح type, غیرعلامتی بٹ) {
  صحیح r;
  ساخت sshkey *ret;
  اگر ((r = sshkey_generate(type, بٹ, &ret)) != 0) {
    fprintf(stderr, "generate(%d, %u): %s", type, بٹ, ssh_err(r));
    abort();
  }
  واپس ret;
}

صحیح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* sig, سائز_t slen)
{
#اگر_تعریف_شدہ WITH_OPENSSL
  ساکن ساخت sshkey *rsa = generate_or_die(کلید_RSA, 2048);
  ساکن ساخت sshkey *ecdsa256 = generate_or_die(کلید_ECDSA, 256);
  ساکن ساخت sshkey *ecdsa384 = generate_or_die(کلید_ECDSA, 384);
  ساکن ساخت sshkey *ecdsa521 = generate_or_die(کلید_ECDSA, 521);
#اگر_ختم
  ساخت sshkey_sig_details *details = تہی;
  ساکن ساخت sshkey *ed25519 = generate_or_die(کلید_ED25519, 0);
  ساکن ثابت حرف *ڈیٹا = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  ساکن ثابت سائز_t dlen = لڑی_لمبائی(ڈیٹا);

#اگر_تعریف_شدہ WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (ثابت u_char *)ڈیٹا, dlen, تہی, 0, &details);
  sshkey_sig_details_free(details);
  details = تہی;

  sshkey_verify(ecdsa256, sig, slen, (ثابت u_char *)ڈیٹا, dlen, تہی, 0, &details);
  sshkey_sig_details_free(details);
  details = تہی;

  sshkey_verify(ecdsa384, sig, slen, (ثابت u_char *)ڈیٹا, dlen, تہی, 0, &details);
  sshkey_sig_details_free(details);
  details = تہی;

  sshkey_verify(ecdsa521, sig, slen, (ثابت u_char *)ڈیٹا, dlen, تہی, 0, &details);
  sshkey_sig_details_free(details);
  details = تہی;
#اگر_ختم

  sshkey_verify(ed25519, sig, slen, (ثابت u_char *)ڈیٹا, dlen, تہی, 0, &details);
  sshkey_sig_details_free(details);
  واپس 0;
}

} // extern
