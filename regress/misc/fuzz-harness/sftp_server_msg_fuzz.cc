/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdint.h>

బాహ్య "C" శూన్య fuzz_server_one(స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t కొలత);

బాహ్య "C" పూర్ణాంకం
LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t కొలత)
{
	fuzz_server_one(దత్తాంశం, కొలత);
	తిరిగి 0;
}
