// cc_fuzz_target test for sshsig verification.

#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

બાહ્ય "C" {

#અન્તર્ભાવ "includes.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshsig.h"
#અન્તર્ભાવ "log.h"

પૂર્ણાંક LLVMFuzzer_Test_One_આગત(અચલ uint8_t* sig, size_t slen)
{
  સ્થિર અચલ અક્ષર *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  સંરચના sshbuf *signature = sshbuf_from(sig, slen);
  સંરચના sshbuf *message = sshbuf_from(data, strlen(data));
  સંરચના sshkey *k = ખાલી;
  સંરચના sshkey_sig_details *details = ખાલી;
  બાહ્ય અક્ષર *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, message, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(message);
  પાછા 0;
}

} // extern
