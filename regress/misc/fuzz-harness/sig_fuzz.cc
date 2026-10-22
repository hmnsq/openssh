// cc_fuzz_target test for public key parsing.

#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

বাহ্যিক "C" {

#অন্তর্ভাব "includes.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "ssherr.h"

স্থির কাঠামো sshkey *generate_or_die(পূর্ণসংখ্যা type, unsigned bits) {
  পূর্ণসংখ্যা r;
  কাঠামো sshkey *ret;
  যদি ((r = sshkey_generate(type, bits, &ret)) != 0) {
    fprintf(stderr, "generate(%d, %u): %s", type, bits, ssh_err(r));
    abort();
  }
  ফেরত ret;
}

পূর্ণসংখ্যা LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t* sig, আকার_t slen)
{
#ifdef WITH_OPENSSL
  স্থির কাঠামো sshkey *rsa = generate_or_die(চাবি_RSA, 2048);
  স্থির কাঠামো sshkey *ecdsa256 = generate_or_die(চাবি_ECDSA, 256);
  স্থির কাঠামো sshkey *ecdsa384 = generate_or_die(চাবি_ECDSA, 384);
  স্থির কাঠামো sshkey *ecdsa521 = generate_or_die(চাবি_ECDSA, 521);
#endif
  কাঠামো sshkey_sig_details *details = ফাঁকা;
  স্থির কাঠামো sshkey *ed25519 = generate_or_die(চাবি_ED25519, 0);
  স্থির ধ্রুবক অক্ষর *তথ্য = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  স্থির ধ্রুবক আকার_t dlen = strlen(তথ্য);

#ifdef WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (ধ্রুবক u_char *)তথ্য, dlen, ফাঁকা, 0, &details);
  sshkey_sig_details_free(details);
  details = ফাঁকা;

  sshkey_verify(ecdsa256, sig, slen, (ধ্রুবক u_char *)তথ্য, dlen, ফাঁকা, 0, &details);
  sshkey_sig_details_free(details);
  details = ফাঁকা;

  sshkey_verify(ecdsa384, sig, slen, (ধ্রুবক u_char *)তথ্য, dlen, ফাঁকা, 0, &details);
  sshkey_sig_details_free(details);
  details = ফাঁকা;

  sshkey_verify(ecdsa521, sig, slen, (ধ্রুবক u_char *)তথ্য, dlen, ফাঁকা, 0, &details);
  sshkey_sig_details_free(details);
  details = ফাঁকা;
#endif

  sshkey_verify(ed25519, sig, slen, (ধ্রুবক u_char *)তথ্য, dlen, ফাঁকা, 0, &details);
  sshkey_sig_details_free(details);
  ফেরত 0;
}

} // extern
