/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Generic BIO functions
 *
 * Copyright 2021 David Fort <contact@hardening-consulting.com>
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
#include <string.h>
#include "bio.h"

int bio_generic_new(BIO* bio)
{
	BIO_set_init(bio, 1);
	BIO_set_flags(bio, BIO_FLAGS_SHOULD_RETRY);
	return 1;
}

int bio_generic_puts(BIO* bio, const char* str)
{
	size_t size;
	int status;

	if (!str)
		return 0;

	size = strlen(str);
	status = BIO_write(bio, str, size);
	return status;
}

int bio_generic_gets(BIO* bio, char* str, int size)
{
	return BIO_read(bio, str, size);
}

long bio_generic_callback_ctrl(BIO* bio, int cmd, bio_info_cb* fp)
{
	return 0;
}

