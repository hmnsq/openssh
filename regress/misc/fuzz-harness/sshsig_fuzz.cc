// cc_fuzz_target test for sshsig verification.

#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

বাহ্য "C" {

#অন্তর্ভাব "includes.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshsig.h"
#অন্তর্ভাব "log.h"

পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্রবেশ(ধ্রুব uint8_t* sig, size_t slen)
{
  স্থির ধ্রুব বর্ণ *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  সংরচনা sshbuf *signature = sshbuf_from(sig, slen);
  সংরচনা sshbuf *message = sshbuf_from(data, strlen(data));
  সংরচনা sshkey *k = রিক্ত;
  সংরচনা sshkey_sig_details *details = রিক্ত;
  বাহ্য বর্ণ *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, message, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(message);
  প্রত্যাগম 0;
}

} // extern
