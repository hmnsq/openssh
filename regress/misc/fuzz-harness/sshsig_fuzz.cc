// cc_fuzz_target test for sshsig verification.

#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ "includes.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshsig.h"
#ಅನ್ತರ್ಭಾವ "log.h"

ಪೂರ್ಣಾಙ್ಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t* sig, size_t slen)
{
  ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  ಸಂರಚನಾ sshbuf *signature = sshbuf_from(sig, slen);
  ಸಂರಚನಾ sshbuf *message = sshbuf_from(data, strlen(data));
  ಸಂರಚನಾ sshkey *k = ರಿಕ್ತ;
  ಸಂರಚನಾ sshkey_sig_details *details = ರಿಕ್ತ;
  ಬಾಹ್ಯ ವರ್ಣ *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, message, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(message);
  ಪ್ರತ್ಯಾಗಮ 0;
}

} // extern
