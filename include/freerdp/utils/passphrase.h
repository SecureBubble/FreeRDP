/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Passphrase Handling Utils
 *
 * Copyright 2011 Shea Levy <shea@shealevy.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FREERDP_UTILS_PASSPHRASE_H
#define FREERDP_UTILS_PASSPHRASE_H

#include <stdlib.h>
#include <stdio.h>

#include <freerdp/api.h>
#include <freerdp/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

	FREERDP_API int freerdp_interruptible_getc(rdpContext* context, FILE* file);
	FREERDP_API SSIZE_T freerdp_interruptible_get_line(rdpContext* context, char** lineptr,
	                                                   size_t* size, FILE* stream);
	FREERDP_API const char* freerdp_passphrase_read(rdpContext* context, const char* prompt,
	                                                char* buf, size_t bufsiz, int from_stdin);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_UTILS_PASSPHRASE_H */
