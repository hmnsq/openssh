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

ಪೂರ್ಣಾಂಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಸ್ಥಿರಾಂಕ uint8_t* sig, ಗಾತ್ರ_t slen)
{
  ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ದತ್ತಾಂಶ = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  ರಚನೆ sshbuf *signature = sshbuf_from(sig, slen);
  ರಚನೆ sshbuf *ಸಂದೇಶ_2 = sshbuf_from(ದತ್ತಾಂಶ, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ದತ್ತಾಂಶ));
  ರಚನೆ sshkey *k = ಖಾಲಿ;
  ರಚನೆ sshkey_sig_details *details = ಖಾಲಿ;
  ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, ಸಂದೇಶ_2, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(ಸಂದೇಶ_2);
  ಹಿಂತಿರುಗಿ 0;
}

} // extern
