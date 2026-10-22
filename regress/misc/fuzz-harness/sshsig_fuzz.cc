// cc_fuzz_target test for sshsig verification.

#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

வெளி "C" {

#அந்தர்பாவ "includes.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sshsig.h"
#அந்தர்பாவ "log.h"

முழு LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t* sig, size_t slen)
{
  நிலையான மாறிலி எழுத்து *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  கட்டமைப்பு sshbuf *signature = sshbuf_from(sig, slen);
  கட்டமைப்பு sshbuf *message = sshbuf_from(data, strlen(data));
  கட்டமைப்பு sshkey *k = வெற்று;
  கட்டமைப்பு sshkey_sig_details *details = வெற்று;
  வெளி எழுத்து *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, message, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(message);
  திரும்பு 0;
}

} // extern
