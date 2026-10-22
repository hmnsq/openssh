// cc_fuzz_target test for sshsig verification.

#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

बाह्य "C" {

#अन्तर्भाव "includes.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshsig.h"
#अन्तर्भाव "log.h"

पूर्णांक LLVMFuzzer_Test_One_आदान(स्थिरांक uint8_t* sig, माप_प्रकार slen)
{
  स्थिर स्थिरांक अक्षर *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  संरचना sshbuf *signature = sshbuf_from(sig, slen);
  संरचना sshbuf *message = sshbuf_from(data, म_माप(data));
  संरचना sshkey *k = रिक्त;
  संरचना sshkey_sig_details *details = रिक्त;
  बाह्य अक्षर *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, message, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(message);
  परत 0;
}

} // extern
