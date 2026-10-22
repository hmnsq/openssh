// cc_fuzz_target test for public key parsing.

#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

ਬਾਹਰੀ "C" {

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

ਸਥਿਰ ਬਣਤਰ sshkey *generate_or_die(ਪੂਰਨ type, ਬਿਨਾਨਿਸ਼ਾਨੀ ਬਿੱਟ) {
  ਪੂਰਨ r;
  ਬਣਤਰ sshkey *ret;
  ਜੇ ((r = sshkey_generate(type, ਬਿੱਟ, &ret)) != 0) {
    fprintf(stderr, "generate(%d, %u): %s", type, ਬਿੱਟ, ssh_err(r));
    abort();
  }
  ਵਾਪਸ ret;
}

ਪੂਰਨ LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t* sig, ਮਾਪ_t slen)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
  ਸਥਿਰ ਬਣਤਰ sshkey *rsa = generate_or_die(ਕੁੰਜੀ_RSA, 2048);
  ਸਥਿਰ ਬਣਤਰ sshkey *ecdsa256 = generate_or_die(ਕੁੰਜੀ_ECDSA, 256);
  ਸਥਿਰ ਬਣਤਰ sshkey *ecdsa384 = generate_or_die(ਕੁੰਜੀ_ECDSA, 384);
  ਸਥਿਰ ਬਣਤਰ sshkey *ecdsa521 = generate_or_die(ਕੁੰਜੀ_ECDSA, 521);
#ਜੇ_ਅੰਤ
  ਬਣਤਰ sshkey_sig_details *details = ਨਿਰਾ;
  ਸਥਿਰ ਬਣਤਰ sshkey *ed25519 = generate_or_die(ਕੁੰਜੀ_ED25519, 0);
  ਸਥਿਰ ਅਚਲ ਅੱਖਰ *ਅੰਕੜੇ = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  ਸਥਿਰ ਅਚਲ ਮਾਪ_t dlen = ਲੜੀ_ਲੰਬਾਈ(ਅੰਕੜੇ);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (ਅਚਲ u_char *)ਅੰਕੜੇ, dlen, ਨਿਰਾ, 0, &details);
  sshkey_sig_details_free(details);
  details = ਨਿਰਾ;

  sshkey_verify(ecdsa256, sig, slen, (ਅਚਲ u_char *)ਅੰਕੜੇ, dlen, ਨਿਰਾ, 0, &details);
  sshkey_sig_details_free(details);
  details = ਨਿਰਾ;

  sshkey_verify(ecdsa384, sig, slen, (ਅਚਲ u_char *)ਅੰਕੜੇ, dlen, ਨਿਰਾ, 0, &details);
  sshkey_sig_details_free(details);
  details = ਨਿਰਾ;

  sshkey_verify(ecdsa521, sig, slen, (ਅਚਲ u_char *)ਅੰਕੜੇ, dlen, ਨਿਰਾ, 0, &details);
  sshkey_sig_details_free(details);
  details = ਨਿਰਾ;
#ਜੇ_ਅੰਤ

  sshkey_verify(ed25519, sig, slen, (ਅਚਲ u_char *)ਅੰਕੜੇ, dlen, ਨਿਰਾ, 0, &details);
  sshkey_sig_details_free(details);
  ਵਾਪਸ 0;
}

} // extern
