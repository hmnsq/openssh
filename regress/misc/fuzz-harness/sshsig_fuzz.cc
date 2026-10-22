// cc_fuzz_target test for sshsig verification.

#অন্তর্ভাৱ <stddef.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>

বাহ্য "C" {

#অন্তর্ভাৱ "includes.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "sshsig.h"
#অন্তর্ভাৱ "log.h"

পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্ৰবেশ(ধ্রুৱ uint8_t* sig, size_t slen)
{
  স্থির ধ্রুৱ ৱর্ণ *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  সংরচনা sshbuf *signature = sshbuf_from(sig, slen);
  সংরচনা sshbuf *message = sshbuf_from(data, strlen(data));
  সংরচনা sshkey *k = রিক্ত;
  সংরচনা sshkey_sig_details *details = রিক্ত;
  বাহ্য ৱর্ণ *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, message, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(message);
  ঘূৰাই 0;
}

} // extern
