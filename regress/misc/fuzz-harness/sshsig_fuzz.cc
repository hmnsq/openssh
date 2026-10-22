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

पूर्णाङ्क LLVMFuzzer_Test_One_निवेशः(ध्रुव uint8_t* sig, size_t slen)
{
  स्थिर ध्रुव वर्ण *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  संरचना sshbuf *signature = sshbuf_from(sig, slen);
  संरचना sshbuf *message = sshbuf_from(data, strlen(data));
  संरचना sshkey *k = रिक्त;
  संरचना sshkey_sig_details *details = रिक्त;
  बाह्य वर्ण *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, message, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(message);
  पटिनिवत्त 0;
}

} // extern
