// cc_fuzz_target test for sshsig verification.

#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

বাহ্যিক "C" {

#অন্তর্ভাব "includes.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshsig.h"
#অন্তর্ভাব "log.h"

পূর্ণসংখ্যা LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t* sig, আকার_t slen)
{
  স্থির ধ্রুবক অক্ষর *তথ্য = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  কাঠামো sshbuf *signature = sshbuf_from(sig, slen);
  কাঠামো sshbuf *message = sshbuf_from(তথ্য, strlen(তথ্য));
  কাঠামো sshkey *k = ফাঁকা;
  কাঠামো sshkey_sig_details *details = ফাঁকা;
  বাহ্যিক অক্ষর *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, message, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(message);
  ফেরত 0;
}

} // extern
