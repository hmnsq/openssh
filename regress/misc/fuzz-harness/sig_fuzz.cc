// cc_fuzz_target test for public key parsing.

#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

வெளி "C" {

#அந்தர்பாவ "includes.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "ssherr.h"

நிலையான கட்டமைப்பு sshkey *generate_or_die(முழு type, unsigned bits) {
  முழு r;
  கட்டமைப்பு sshkey *ret;
  எனில் ((r = sshkey_generate(type, bits, &ret)) != 0) {
    fprintf(stderr, "generate(%d, %u): %s", type, bits, ssh_err(r));
    abort();
  }
  திரும்பு ret;
}

முழு LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t* sig, size_t slen)
{
#ifdef WITH_OPENSSL
  நிலையான கட்டமைப்பு sshkey *rsa = generate_or_die(சாவி_RSA, 2048);
  நிலையான கட்டமைப்பு sshkey *ecdsa256 = generate_or_die(சாவி_ECDSA, 256);
  நிலையான கட்டமைப்பு sshkey *ecdsa384 = generate_or_die(சாவி_ECDSA, 384);
  நிலையான கட்டமைப்பு sshkey *ecdsa521 = generate_or_die(சாவி_ECDSA, 521);
#endif
  கட்டமைப்பு sshkey_sig_details *details = வெற்று;
  நிலையான கட்டமைப்பு sshkey *ed25519 = generate_or_die(சாவி_ED25519, 0);
  நிலையான மாறிலி எழுத்து *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  நிலையான மாறிலி size_t dlen = strlen(data);

#ifdef WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (மாறிலி u_char *)data, dlen, வெற்று, 0, &details);
  sshkey_sig_details_free(details);
  details = வெற்று;

  sshkey_verify(ecdsa256, sig, slen, (மாறிலி u_char *)data, dlen, வெற்று, 0, &details);
  sshkey_sig_details_free(details);
  details = வெற்று;

  sshkey_verify(ecdsa384, sig, slen, (மாறிலி u_char *)data, dlen, வெற்று, 0, &details);
  sshkey_sig_details_free(details);
  details = வெற்று;

  sshkey_verify(ecdsa521, sig, slen, (மாறிலி u_char *)data, dlen, வெற்று, 0, &details);
  sshkey_sig_details_free(details);
  details = வெற்று;
#endif

  sshkey_verify(ed25519, sig, slen, (மாறிலி u_char *)data, dlen, வெற்று, 0, &details);
  sshkey_sig_details_free(details);
  திரும்பு 0;
}

} // extern
