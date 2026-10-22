// cc_fuzz_target test for public key parsing.

#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

ബാഹ്യ "C" {

#അന്തര്ഭാവ "includes.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "ssherr.h"

സ്ഥിതം ഘടന sshkey *generate_or_die(പൂർണ്ണസംഖ്യ type, unsigned bits) {
  പൂർണ്ണസംഖ്യ r;
  ഘടന sshkey *ret;
  എങ്കിൽ ((r = sshkey_generate(type, bits, &ret)) != 0) {
    fprintf(stderr, "generate(%d, %u): %s", type, bits, ssh_err(r));
    abort();
  }
  തിരികെ ret;
}

പൂർണ്ണസംഖ്യ LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t* sig, size_t slen)
{
#ifdef WITH_OPENSSL
  സ്ഥിതം ഘടന sshkey *rsa = generate_or_die(താക്കോൽ_RSA, 2048);
  സ്ഥിതം ഘടന sshkey *ecdsa256 = generate_or_die(താക്കോൽ_ECDSA, 256);
  സ്ഥിതം ഘടന sshkey *ecdsa384 = generate_or_die(താക്കോൽ_ECDSA, 384);
  സ്ഥിതം ഘടന sshkey *ecdsa521 = generate_or_die(താക്കോൽ_ECDSA, 521);
#endif
  ഘടന sshkey_sig_details *details = ശൂന്യ;
  സ്ഥിതം ഘടന sshkey *ed25519 = generate_or_die(താക്കോൽ_ED25519, 0);
  സ്ഥിതം സ്ഥിരം അക്ഷരം *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  സ്ഥിതം സ്ഥിരം size_t dlen = strlen(data);

#ifdef WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (സ്ഥിരം u_char *)data, dlen, ശൂന്യ, 0, &details);
  sshkey_sig_details_free(details);
  details = ശൂന്യ;

  sshkey_verify(ecdsa256, sig, slen, (സ്ഥിരം u_char *)data, dlen, ശൂന്യ, 0, &details);
  sshkey_sig_details_free(details);
  details = ശൂന്യ;

  sshkey_verify(ecdsa384, sig, slen, (സ്ഥിരം u_char *)data, dlen, ശൂന്യ, 0, &details);
  sshkey_sig_details_free(details);
  details = ശൂന്യ;

  sshkey_verify(ecdsa521, sig, slen, (സ്ഥിരം u_char *)data, dlen, ശൂന്യ, 0, &details);
  sshkey_sig_details_free(details);
  details = ശൂന്യ;
#endif

  sshkey_verify(ed25519, sig, slen, (സ്ഥിരം u_char *)data, dlen, ശൂന്യ, 0, &details);
  sshkey_sig_details_free(details);
  തിരികെ 0;
}

} // extern
