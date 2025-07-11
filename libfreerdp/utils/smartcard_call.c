/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Smartcard Device Service Virtual Channel
 *
 * Copyright (C) Alexi Volkov <alexi@myrealbox.com> 2006
 * Copyright 2011 O.S. Systems Software Ltda.
 * Copyright 2011 Anthony Tong <atong@trustedcs.com>
 * Copyright 2015 Thincast Technologies GmbH
 * Copyright 2015 DI (FH) Martin Haimberger <martin.haimberger@thincast.com>
 * Copyright 2017 Armin Novak <armin.novak@thincast.com>
 * Copyright 2017 Thincast Technologies GmbH
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

#include <freerdp/config.h>

#include <winpr/assert.h>

#include <winpr/crt.h>
#include <winpr/print.h>
#include <winpr/stream.h>
#include <winpr/library.h>
#include <winpr/smartcard.h>

#include <freerdp/freerdp.h>
#include <freerdp/channels/rdpdr.h>
#include <freerdp/channels/scard.h>

#include <freerdp/utils/rdpdr_utils.h>
#include <freerdp/utils/smartcard_pack.h>
#include <freerdp/utils/smartcard_call.h>

#include "smartcard_pack.h"

#include <freerdp/log.h>
#define SCARD_TAG FREERDP_TAG("utils.smartcard.call")

#if defined(WITH_SMARTCARD_EMULATE)
#include <freerdp/emulate/scard/smartcard_emulate.h>

#define wrap(ctx, fkt, ...)                                             \
	ctx->useEmulatedCard ? Emulate_##fkt(ctx->emulation, ##__VA_ARGS__) \
	                     : ctx->pWinSCardApi->pfn##fkt(__VA_ARGS__)
#define wrap_ptr(ctx, fkt, ...) wrap(ctx, fkt, ##__VA_ARGS__)
#else
#define wrap(ctx, fkt, ...) \
	ctx->useEmulatedCard ? SCARD_F_INTERNAL_ERROR : ctx->pWinSCardApi->pfn##fkt(__VA_ARGS__)
#define wrap_ptr(ctx, fkt, ...) \
	ctx->useEmulatedCard ? NULL : ctx->pWinSCardApi->pfn##fkt(__VA_ARGS__)
#endif

struct s_scard_call_context
{
	BOOL useEmulatedCard;
	HANDLE StartedEvent;
	wLinkedList* names;
	wHashTable* rgSCardContextList;
#if defined(WITH_SMARTCARD_EMULATE)
	SmartcardEmulationContext* emulation;
#endif
	HANDLE hWinSCardLibrary;
	SCardApiFunctionTable WinSCardApi;
	const SCardApiFunctionTable* pWinSCardApi;
	HANDLE stopEvent;
	void* userdata;

	void* (*fn_new)(void*, SCARDCONTEXT);
	void (*fn_free)(void*);
	wLog* log;
};

struct s_scard_context_element
{
	void* context;
	void (*fn_free)(void*);
};

static void context_free(void* arg);

static LONG smartcard_EstablishContext_Call(scard_call_context* smartcard, wStream* out,
                                            SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	SCARDCONTEXT hContext = { 0 };
	EstablishContext_Return ret = { 0 };
	EstablishContext_Call* call = &operation->call.establishContext;
	status = ret.ReturnCode =
	    wrap(smartcard, SCardEstablishContext, call->dwScope, NULL, NULL, &hContext);

	if (ret.ReturnCode == SCARD_S_SUCCESS)
	{
		const void* key = (void*)(size_t)hContext;
		struct s_scard_context_element* pContext =
		    calloc(1, sizeof(struct s_scard_context_element));
		if (!pContext)
			return STATUS_NO_MEMORY;

		pContext->fn_free = smartcard->fn_free;

		if (smartcard->fn_new)
		{
			pContext->context = smartcard->fn_new(smartcard->userdata, hContext);
			if (!pContext->context)
			{
				free(pContext);
				return STATUS_NO_MEMORY;
			}
		}

		if (!HashTable_Insert(smartcard->rgSCardContextList, key, (void*)pContext))
		{
			WLog_Print(smartcard->log, WLOG_ERROR, "ListDictionary_Add failed!");
			context_free(pContext);
			return STATUS_INTERNAL_ERROR;
		}
	}
	else
	{
		return scard_log_status_error_wlog(smartcard->log, "SCardEstablishContext", status);
	}

	// NOLINTNEXTLINE(clang-analyzer-unix.Malloc): HashTable_Insert takes ownership of pContext
	smartcard_scard_context_native_to_redir(&(ret.hContext), hContext);

	status = smartcard_pack_establish_context_return(out, &ret);
	if (status != SCARD_S_SUCCESS)
	{
		return scard_log_status_error_wlog(smartcard->log,
		                                   "smartcard_pack_establish_context_return", status);
	}

	return ret.ReturnCode;
}

static LONG smartcard_ReleaseContext_Call(scard_call_context* smartcard,
                                          WINPR_ATTR_UNUSED wStream* out,
                                          SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	ret.ReturnCode = wrap(smartcard, SCardReleaseContext, operation->hContext);

	if (ret.ReturnCode == SCARD_S_SUCCESS)
		HashTable_Remove(smartcard->rgSCardContextList, (void*)operation->hContext);
	else
	{
		return scard_log_status_error_wlog(smartcard->log, "SCardReleaseContext", ret.ReturnCode);
	}

	smartcard_trace_long_return_int(smartcard->log, &ret, "ReleaseContext");
	return ret.ReturnCode;
}

static LONG smartcard_IsValidContext_Call(scard_call_context* smartcard,
                                          WINPR_ATTR_UNUSED wStream* out,
                                          SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	ret.ReturnCode = wrap(smartcard, SCardIsValidContext, operation->hContext);
	smartcard_trace_long_return_int(smartcard->log, &ret, "IsValidContext");
	return ret.ReturnCode;
}

static LONG smartcard_ListReaderGroupsA_Call(scard_call_context* smartcard, wStream* out,
                                             SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	ListReaderGroups_Return ret = { 0 };
	LPSTR mszGroups = NULL;
	DWORD cchGroups = 0;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	cchGroups = SCARD_AUTOALLOCATE;
	ret.ReturnCode =
	    wrap(smartcard, SCardListReaderGroupsA, operation->hContext, (LPSTR)&mszGroups, &cchGroups);
	if ((ret.ReturnCode == SCARD_S_SUCCESS) && (cchGroups == SCARD_AUTOALLOCATE))
		return SCARD_F_UNKNOWN_ERROR;

	ret.msz = (BYTE*)mszGroups;
	ret.cBytes = cchGroups;

	status = smartcard_pack_list_reader_groups_return(out, &ret, FALSE);

	if (status != SCARD_S_SUCCESS)
		return status;

	if (mszGroups)
		wrap(smartcard, SCardFreeMemory, operation->hContext, mszGroups);

	return ret.ReturnCode;
}

static LONG smartcard_ListReaderGroupsW_Call(scard_call_context* smartcard, wStream* out,
                                             SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	ListReaderGroups_Return ret = { 0 };
	LPWSTR mszGroups = NULL;
	DWORD cchGroups = 0;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	cchGroups = SCARD_AUTOALLOCATE;
	status = ret.ReturnCode = wrap(smartcard, SCardListReaderGroupsW, operation->hContext,
	                               (LPWSTR)&mszGroups, &cchGroups);
	if ((ret.ReturnCode == SCARD_S_SUCCESS) && (cchGroups == SCARD_AUTOALLOCATE))
		return SCARD_F_UNKNOWN_ERROR;

	ret.msz = (BYTE*)mszGroups;

	WINPR_ASSERT(cchGroups < SCARD_AUTOALLOCATE / sizeof(WCHAR));
	const size_t blen = sizeof(WCHAR) * cchGroups;
	WINPR_ASSERT(blen <= UINT32_MAX);
	ret.cBytes = (UINT32)blen;

	if (status != SCARD_S_SUCCESS)
		return status;

	status = smartcard_pack_list_reader_groups_return(out, &ret, TRUE);

	if (status != SCARD_S_SUCCESS)
		return status;

	if (mszGroups)
		wrap(smartcard, SCardFreeMemory, operation->hContext, mszGroups);

	return ret.ReturnCode;
}

static BOOL filter_match(wLinkedList* list, LPCSTR reader, size_t readerLen)
{
	if (readerLen < 1)
		return FALSE;

	LinkedList_Enumerator_Reset(list);

	while (LinkedList_Enumerator_MoveNext(list))
	{
		const char* filter = LinkedList_Enumerator_Current(list);

		if (filter)
		{
			if (strstr(reader, filter) != NULL)
				return TRUE;
		}
	}

	return FALSE;
}

static DWORD filter_device_by_name_a(wLinkedList* list, LPSTR* mszReaders, DWORD cchReaders)
{
	size_t rpos = 0;
	size_t wpos = 0;

	if (*mszReaders == NULL || LinkedList_Count(list) < 1)
		return cchReaders;

	do
	{
		LPCSTR rreader = &(*mszReaders)[rpos];
		LPSTR wreader = &(*mszReaders)[wpos];
		size_t readerLen = strnlen(rreader, cchReaders - rpos);

		rpos += readerLen + 1;

		if (filter_match(list, rreader, readerLen))
		{
			if (rreader != wreader)
				memmove(wreader, rreader, readerLen + 1);

			wpos += readerLen + 1;
		}
	} while (rpos < cchReaders);

	/* this string must be double 0 terminated */
	if (rpos != wpos)
	{
		if (wpos >= cchReaders)
			return 0;

		(*mszReaders)[wpos++] = '\0';
	}

	return (DWORD)wpos;
}

static DWORD filter_device_by_name_w(wLinkedList* list, LPWSTR* mszReaders, DWORD cchReaders)
{
	DWORD rc = 0;
	LPSTR readers = NULL;

	if (LinkedList_Count(list) < 1)
		return cchReaders;

	readers = ConvertMszWCharNToUtf8Alloc(*mszReaders, cchReaders, NULL);

	if (!readers)
	{
		free(readers);
		return 0;
	}

	free(*mszReaders);
	*mszReaders = NULL;
	rc = filter_device_by_name_a(list, &readers, cchReaders);

	*mszReaders = ConvertMszUtf8NToWCharAlloc(readers, rc, NULL);
	if (!*mszReaders)
		rc = 0;

	free(readers);
	return rc;
}

static LONG smartcard_ListReadersA_Call(scard_call_context* smartcard, wStream* out,
                                        SMARTCARD_OPERATION* operation)
{
	ListReaders_Return ret = { 0 };
	LPSTR mszReaders = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	ListReaders_Call* call = &operation->call.listReaders;
	DWORD cchReaders = SCARD_AUTOALLOCATE;
	LONG status = ret.ReturnCode = wrap(smartcard, SCardListReadersA, operation->hContext,
	                                    (LPCSTR)call->mszGroups, (LPSTR)&mszReaders, &cchReaders);
	if (status == SCARD_S_SUCCESS)
	{
		if (cchReaders == SCARD_AUTOALLOCATE)
			status = SCARD_F_UNKNOWN_ERROR;
	}

	if (status != SCARD_S_SUCCESS)
	{
		(void)scard_log_status_error_wlog(smartcard->log, "SCardListReadersA", status);
		return smartcard_pack_list_readers_return(out, &ret, FALSE);
	}

	cchReaders = filter_device_by_name_a(smartcard->names, &mszReaders, cchReaders);
	ret.msz = (BYTE*)mszReaders;
	ret.cBytes = cchReaders;

	status = smartcard_pack_list_readers_return(out, &ret, FALSE);
	if (mszReaders)
		wrap(smartcard, SCardFreeMemory, operation->hContext, mszReaders);

	if (status != SCARD_S_SUCCESS)
		return scard_log_status_error_wlog(smartcard->log, "smartcard_pack_list_readers_return",
		                                   status);

	return ret.ReturnCode;
}

static LONG smartcard_ListReadersW_Call(scard_call_context* smartcard, wStream* out,
                                        SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	ListReaders_Return ret = { 0 };
	DWORD cchReaders = 0;
	ListReaders_Call* call = NULL;
	union
	{
		const BYTE* bp;
		const char* sz;
		const WCHAR* wz;
	} string;
	union
	{
		WCHAR** ppw;
		WCHAR* pw;
		CHAR* pc;
		BYTE* pb;
	} mszReaders;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(operation);

	call = &operation->call.listReaders;

	string.bp = call->mszGroups;
	cchReaders = SCARD_AUTOALLOCATE;
	status = ret.ReturnCode = wrap(smartcard, SCardListReadersW, operation->hContext, string.wz,
	                               (LPWSTR)&mszReaders.pw, &cchReaders);
	if (status == SCARD_S_SUCCESS)
	{
		if (cchReaders == SCARD_AUTOALLOCATE)
			status = SCARD_F_UNKNOWN_ERROR;
	}

	if (status != SCARD_S_SUCCESS)
	{
		(void)scard_log_status_error_wlog(smartcard->log, "SCardListReadersW", status);
		return smartcard_pack_list_readers_return(out, &ret, TRUE);
	}

	cchReaders = filter_device_by_name_w(smartcard->names, &mszReaders.pw, cchReaders);
	ret.msz = mszReaders.pb;
	ret.cBytes = cchReaders * sizeof(WCHAR);
	status = smartcard_pack_list_readers_return(out, &ret, TRUE);

	if (mszReaders.pb)
		wrap(smartcard, SCardFreeMemory, operation->hContext, mszReaders.pb);

	if (status != SCARD_S_SUCCESS)
		return status;

	return ret.ReturnCode;
}

static LONG smartcard_IntroduceReaderGroupA_Call(scard_call_context* smartcard,
                                                 WINPR_ATTR_UNUSED wStream* out,
                                                 SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };
	ContextAndStringA_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.contextAndStringA;
	ret.ReturnCode = wrap(smartcard, SCardIntroduceReaderGroupA, operation->hContext, call->sz);
	scard_log_status_error_wlog(smartcard->log, "SCardIntroduceReaderGroupA", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "IntroduceReaderGroupA");
	return ret.ReturnCode;
}

static LONG smartcard_IntroduceReaderGroupW_Call(scard_call_context* smartcard,
                                                 WINPR_ATTR_UNUSED wStream* out,
                                                 SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };
	ContextAndStringW_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.contextAndStringW;
	ret.ReturnCode = wrap(smartcard, SCardIntroduceReaderGroupW, operation->hContext, call->sz);
	scard_log_status_error_wlog(smartcard->log, "SCardIntroduceReaderGroupW", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "IntroduceReaderGroupW");
	return ret.ReturnCode;
}

static LONG smartcard_IntroduceReaderA_Call(scard_call_context* smartcard,
                                            WINPR_ATTR_UNUSED wStream* out,
                                            SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };
	ContextAndTwoStringA_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.contextAndTwoStringA;
	ret.ReturnCode =
	    wrap(smartcard, SCardIntroduceReaderA, operation->hContext, call->sz1, call->sz2);
	scard_log_status_error_wlog(smartcard->log, "SCardIntroduceReaderA", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "IntroduceReaderA");
	return ret.ReturnCode;
}

static LONG smartcard_IntroduceReaderW_Call(scard_call_context* smartcard,
                                            WINPR_ATTR_UNUSED wStream* out,
                                            SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };
	ContextAndTwoStringW_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.contextAndTwoStringW;
	ret.ReturnCode =
	    wrap(smartcard, SCardIntroduceReaderW, operation->hContext, call->sz1, call->sz2);
	scard_log_status_error_wlog(smartcard->log, "SCardIntroduceReaderW", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "IntroduceReaderW");
	return ret.ReturnCode;
}

static LONG smartcard_ForgetReaderA_Call(scard_call_context* smartcard,
                                         WINPR_ATTR_UNUSED wStream* out,
                                         SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };
	ContextAndStringA_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.contextAndStringA;
	ret.ReturnCode = wrap(smartcard, SCardForgetReaderA, operation->hContext, call->sz);
	scard_log_status_error_wlog(smartcard->log, "SCardForgetReaderA", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "SCardForgetReaderA");
	return ret.ReturnCode;
}

static LONG smartcard_ForgetReaderW_Call(scard_call_context* smartcard,
                                         WINPR_ATTR_UNUSED wStream* out,
                                         SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };
	ContextAndStringW_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.contextAndStringW;
	ret.ReturnCode = wrap(smartcard, SCardForgetReaderW, operation->hContext, call->sz);
	scard_log_status_error_wlog(smartcard->log, "SCardForgetReaderW", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "SCardForgetReaderW");
	return ret.ReturnCode;
}

static LONG smartcard_AddReaderToGroupA_Call(scard_call_context* smartcard,
                                             WINPR_ATTR_UNUSED wStream* out,
                                             SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };
	ContextAndTwoStringA_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.contextAndTwoStringA;
	ret.ReturnCode =
	    wrap(smartcard, SCardAddReaderToGroupA, operation->hContext, call->sz1, call->sz2);
	scard_log_status_error_wlog(smartcard->log, "SCardAddReaderToGroupA", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "SCardAddReaderToGroupA");
	return ret.ReturnCode;
}

static LONG smartcard_AddReaderToGroupW_Call(scard_call_context* smartcard,
                                             WINPR_ATTR_UNUSED wStream* out,
                                             SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };
	ContextAndTwoStringW_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.contextAndTwoStringW;
	ret.ReturnCode =
	    wrap(smartcard, SCardAddReaderToGroupW, operation->hContext, call->sz1, call->sz2);
	scard_log_status_error_wlog(smartcard->log, "SCardAddReaderToGroupW", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "SCardAddReaderToGroupA");
	return ret.ReturnCode;
}

static LONG smartcard_RemoveReaderFromGroupA_Call(scard_call_context* smartcard,
                                                  WINPR_ATTR_UNUSED wStream* out,
                                                  SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };
	ContextAndTwoStringA_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.contextAndTwoStringA;
	ret.ReturnCode =
	    wrap(smartcard, SCardRemoveReaderFromGroupA, operation->hContext, call->sz1, call->sz2);
	scard_log_status_error_wlog(smartcard->log, "SCardRemoveReaderFromGroupA", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "SCardRemoveReaderFromGroupA");
	return ret.ReturnCode;
}

static LONG smartcard_RemoveReaderFromGroupW_Call(scard_call_context* smartcard,
                                                  WINPR_ATTR_UNUSED wStream* out,
                                                  SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };
	ContextAndTwoStringW_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.contextAndTwoStringW;
	ret.ReturnCode =
	    wrap(smartcard, SCardRemoveReaderFromGroupW, operation->hContext, call->sz1, call->sz2);
	scard_log_status_error_wlog(smartcard->log, "SCardRemoveReaderFromGroupW", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "SCardRemoveReaderFromGroupW");
	return ret.ReturnCode;
}

static LONG smartcard_LocateCardsA_Call(scard_call_context* smartcard, wStream* out,
                                        SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	LocateCards_Return ret = { 0 };
	LocateCardsA_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(operation);

	call = &operation->call.locateCardsA;

	ret.ReturnCode = wrap(smartcard, SCardLocateCardsA, operation->hContext, call->mszCards,
	                      call->rgReaderStates, call->cReaders);
	scard_log_status_error_wlog(smartcard->log, "SCardLocateCardsA", ret.ReturnCode);
	ret.cReaders = call->cReaders;
	ret.rgReaderStates = NULL;

	if (ret.cReaders > 0)
	{
		ret.rgReaderStates = (ReaderState_Return*)calloc(ret.cReaders, sizeof(ReaderState_Return));

		if (!ret.rgReaderStates)
			return STATUS_NO_MEMORY;
	}

	for (UINT32 x = 0; x < ret.cReaders; x++)
	{
		ret.rgReaderStates[x].dwCurrentState = call->rgReaderStates[x].dwCurrentState;
		ret.rgReaderStates[x].dwEventState = call->rgReaderStates[x].dwEventState;
		ret.rgReaderStates[x].cbAtr = call->rgReaderStates[x].cbAtr;
		CopyMemory(&(ret.rgReaderStates[x].rgbAtr), &(call->rgReaderStates[x].rgbAtr),
		           sizeof(ret.rgReaderStates[x].rgbAtr));
	}

	status = smartcard_pack_locate_cards_return(out, &ret);

	if (status != SCARD_S_SUCCESS)
		return status;

	return ret.ReturnCode;
}

static LONG smartcard_LocateCardsW_Call(scard_call_context* smartcard, wStream* out,
                                        SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	LocateCards_Return ret = { 0 };
	LocateCardsW_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(operation);

	call = &operation->call.locateCardsW;

	ret.ReturnCode = wrap(smartcard, SCardLocateCardsW, operation->hContext, call->mszCards,
	                      call->rgReaderStates, call->cReaders);
	scard_log_status_error_wlog(smartcard->log, "SCardLocateCardsW", ret.ReturnCode);
	ret.cReaders = call->cReaders;
	ret.rgReaderStates = NULL;

	if (ret.cReaders > 0)
	{
		ret.rgReaderStates = (ReaderState_Return*)calloc(ret.cReaders, sizeof(ReaderState_Return));

		if (!ret.rgReaderStates)
			return STATUS_NO_MEMORY;
	}

	for (UINT32 x = 0; x < ret.cReaders; x++)
	{
		ret.rgReaderStates[x].dwCurrentState = call->rgReaderStates[x].dwCurrentState;
		ret.rgReaderStates[x].dwEventState = call->rgReaderStates[x].dwEventState;
		ret.rgReaderStates[x].cbAtr = call->rgReaderStates[x].cbAtr;
		CopyMemory(&(ret.rgReaderStates[x].rgbAtr), &(call->rgReaderStates[x].rgbAtr),
		           sizeof(ret.rgReaderStates[x].rgbAtr));
	}

	status = smartcard_pack_locate_cards_return(out, &ret);

	if (status != SCARD_S_SUCCESS)
		return status;

	return ret.ReturnCode;
}

static LONG smartcard_ReadCacheA_Call(scard_call_context* smartcard, wStream* out,
                                      SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	BOOL autoalloc = 0;
	ReadCache_Return ret = { 0 };
	ReadCacheA_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.readCacheA;
	autoalloc = (call->Common.cbDataLen == SCARD_AUTOALLOCATE);

	if (!call->Common.fPbDataIsNULL)
	{
		ret.cbDataLen = call->Common.cbDataLen;
		if (!autoalloc)
		{
			ret.pbData = malloc(ret.cbDataLen);
			if (!ret.pbData)
				return SCARD_F_INTERNAL_ERROR;
		}
	}

	if (autoalloc)
		ret.ReturnCode = wrap(smartcard, SCardReadCacheA, operation->hContext,
		                      call->Common.CardIdentifier, call->Common.FreshnessCounter,
		                      call->szLookupName, (BYTE*)&ret.pbData, &ret.cbDataLen);
	else
		ret.ReturnCode =
		    wrap(smartcard, SCardReadCacheA, operation->hContext, call->Common.CardIdentifier,
		         call->Common.FreshnessCounter, call->szLookupName, ret.pbData, &ret.cbDataLen);
	if ((ret.ReturnCode != SCARD_W_CACHE_ITEM_NOT_FOUND) &&
	    (ret.ReturnCode != SCARD_W_CACHE_ITEM_STALE))
	{
		scard_log_status_error_wlog(smartcard->log, "SCardReadCacheA", ret.ReturnCode);
	}

	status = smartcard_pack_read_cache_return(out, &ret);
	if (autoalloc)
		wrap(smartcard, SCardFreeMemory, operation->hContext, ret.pbData);
	else
		free(ret.pbData);
	if (status != SCARD_S_SUCCESS)
		return status;

	return ret.ReturnCode;
}

static LONG smartcard_ReadCacheW_Call(scard_call_context* smartcard, wStream* out,
                                      SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	ReadCache_Return ret = { 0 };
	ReadCacheW_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.readCacheW;

	if (!call->Common.fPbDataIsNULL)
		ret.cbDataLen = SCARD_AUTOALLOCATE;

	ret.ReturnCode =
	    wrap(smartcard, SCardReadCacheW, operation->hContext, call->Common.CardIdentifier,
	         call->Common.FreshnessCounter, call->szLookupName, (BYTE*)&ret.pbData, &ret.cbDataLen);

	if ((ret.ReturnCode != SCARD_W_CACHE_ITEM_NOT_FOUND) &&
	    (ret.ReturnCode != SCARD_W_CACHE_ITEM_STALE))
	{
		scard_log_status_error_wlog(smartcard->log, "SCardReadCacheW", ret.ReturnCode);
	}

	status = smartcard_pack_read_cache_return(out, &ret);

	wrap(smartcard, SCardFreeMemory, operation->hContext, ret.pbData);

	if (status != SCARD_S_SUCCESS)
		return status;

	return ret.ReturnCode;
}

static LONG smartcard_WriteCacheA_Call(scard_call_context* smartcard,
                                       WINPR_ATTR_UNUSED wStream* out,
                                       SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };
	WriteCacheA_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.writeCacheA;

	ret.ReturnCode = wrap(smartcard, SCardWriteCacheA, operation->hContext,
	                      call->Common.CardIdentifier, call->Common.FreshnessCounter,
	                      call->szLookupName, call->Common.pbData, call->Common.cbDataLen);
	scard_log_status_error_wlog(smartcard->log, "SCardWriteCacheA", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "SCardWriteCacheA");
	return ret.ReturnCode;
}

static LONG smartcard_WriteCacheW_Call(scard_call_context* smartcard,
                                       WINPR_ATTR_UNUSED wStream* out,
                                       SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };
	WriteCacheW_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.writeCacheW;

	ret.ReturnCode = wrap(smartcard, SCardWriteCacheW, operation->hContext,
	                      call->Common.CardIdentifier, call->Common.FreshnessCounter,
	                      call->szLookupName, call->Common.pbData, call->Common.cbDataLen);
	scard_log_status_error_wlog(smartcard->log, "SCardWriteCacheW", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "SCardWriteCacheW");
	return ret.ReturnCode;
}

static LONG smartcard_GetTransmitCount_Call(scard_call_context* smartcard, wStream* out,
                                            SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	GetTransmitCount_Return ret = { 0 };

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	ret.ReturnCode = wrap(smartcard, SCardGetTransmitCount, operation->hCard, &ret.cTransmitCount);
	scard_log_status_error_wlog(smartcard->log, "SCardGetTransmitCount", ret.ReturnCode);
	status = smartcard_pack_get_transmit_count_return(out, &ret);
	if (status != SCARD_S_SUCCESS)
		return status;

	return ret.ReturnCode;
}

static LONG smartcard_ReleaseStartedEvent_Call(scard_call_context* smartcard, wStream* out,
                                               SMARTCARD_OPERATION* operation)
{
	WINPR_UNUSED(smartcard);
	WINPR_UNUSED(out);
	WINPR_UNUSED(operation);

	WLog_Print(smartcard->log, WLOG_WARN,
	           "According to [MS-RDPESC] 3.1.4 Message Processing Events and Sequencing Rules "
	           "this is not supported?!?");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

static LONG smartcard_GetReaderIcon_Call(scard_call_context* smartcard, wStream* out,
                                         SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	GetReaderIcon_Return ret = { 0 };
	GetReaderIcon_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.getReaderIcon;

	ret.cbDataLen = SCARD_AUTOALLOCATE;
	ret.ReturnCode = wrap(smartcard, SCardGetReaderIconW, operation->hContext, call->szReaderName,
	                      (LPBYTE)&ret.pbData, &ret.cbDataLen);
	scard_log_status_error_wlog(smartcard->log, "SCardGetReaderIconW", ret.ReturnCode);
	if ((ret.ReturnCode == SCARD_S_SUCCESS) && (ret.cbDataLen == SCARD_AUTOALLOCATE))
		return SCARD_F_UNKNOWN_ERROR;

	status = smartcard_pack_get_reader_icon_return(out, &ret);
	wrap(smartcard, SCardFreeMemory, operation->hContext, ret.pbData);
	if (status != SCARD_S_SUCCESS)
		return status;

	return ret.ReturnCode;
}

static LONG smartcard_GetDeviceTypeId_Call(scard_call_context* smartcard, wStream* out,
                                           SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	GetDeviceTypeId_Return ret = { 0 };
	GetDeviceTypeId_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.getDeviceTypeId;

	ret.ReturnCode = wrap(smartcard, SCardGetDeviceTypeIdW, operation->hContext, call->szReaderName,
	                      &ret.dwDeviceId);
	scard_log_status_error_wlog(smartcard->log, "SCardGetDeviceTypeIdW", ret.ReturnCode);

	status = smartcard_pack_device_type_id_return(out, &ret);
	if (status != SCARD_S_SUCCESS)
		return status;

	return ret.ReturnCode;
}

static LONG smartcard_GetStatusChangeA_Call(scard_call_context* smartcard, wStream* out,
                                            SMARTCARD_OPERATION* operation)
{
	LONG status = STATUS_NO_MEMORY;
	DWORD dwTimeOut = 0;
	const DWORD dwTimeStep = 100;
	GetStatusChange_Return ret = { 0 };
	GetStatusChangeA_Call* call = NULL;
	LPSCARD_READERSTATEA rgReaderStates = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.getStatusChangeA;
	dwTimeOut = call->dwTimeOut;

	if (call->cReaders > 0)
	{
		ret.cReaders = call->cReaders;
		rgReaderStates = calloc(ret.cReaders, sizeof(SCARD_READERSTATEA));
		ret.rgReaderStates = (ReaderState_Return*)calloc(ret.cReaders, sizeof(ReaderState_Return));
		if (!rgReaderStates || !ret.rgReaderStates)
			goto fail;
	}

	for (UINT32 x = 0; x < MAX(1, dwTimeOut);)
	{
		if (call->cReaders > 0)
			memcpy(rgReaderStates, call->rgReaderStates,
			       call->cReaders * sizeof(SCARD_READERSTATEA));
		ret.ReturnCode = wrap(smartcard, SCardGetStatusChangeA, operation->hContext,
		                      MIN(dwTimeOut, dwTimeStep), rgReaderStates, call->cReaders);
		if (ret.ReturnCode != SCARD_E_TIMEOUT)
			break;
		if (WaitForSingleObject(smartcard->stopEvent, 0) == WAIT_OBJECT_0)
			break;
		if (dwTimeOut != INFINITE)
			x += dwTimeStep;
	}
	scard_log_status_error_wlog(smartcard->log, "SCardGetStatusChangeA", ret.ReturnCode);

	for (UINT32 index = 0; index < ret.cReaders; index++)
	{
		const SCARD_READERSTATEA* cur = &rgReaderStates[index];
		ReaderState_Return* rout = &ret.rgReaderStates[index];

		rout->dwCurrentState = cur->dwCurrentState;
		rout->dwEventState = cur->dwEventState;
		rout->cbAtr = cur->cbAtr;
		CopyMemory(&(rout->rgbAtr), cur->rgbAtr, sizeof(rout->rgbAtr));
	}

	status = smartcard_pack_get_status_change_return(out, &ret, FALSE);
fail:
	free(ret.rgReaderStates);
	free(rgReaderStates);
	if (status != SCARD_S_SUCCESS)
		return status;
	return ret.ReturnCode;
}

static LONG smartcard_GetStatusChangeW_Call(scard_call_context* smartcard, wStream* out,
                                            SMARTCARD_OPERATION* operation)
{
	LONG status = STATUS_NO_MEMORY;
	DWORD dwTimeOut = 0;
	const DWORD dwTimeStep = 100;
	GetStatusChange_Return ret = { 0 };
	LPSCARD_READERSTATEW rgReaderStates = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	GetStatusChangeW_Call* call = &operation->call.getStatusChangeW;
	dwTimeOut = call->dwTimeOut;

	if (call->cReaders > 0)
	{
		ret.cReaders = call->cReaders;
		rgReaderStates = calloc(ret.cReaders, sizeof(SCARD_READERSTATEW));
		ret.rgReaderStates = (ReaderState_Return*)calloc(ret.cReaders, sizeof(ReaderState_Return));
		if (!rgReaderStates || !ret.rgReaderStates)
			goto fail;
	}

	for (UINT32 x = 0; x < MAX(1, dwTimeOut);)
	{
		if (call->cReaders > 0)
			memcpy(rgReaderStates, call->rgReaderStates,
			       call->cReaders * sizeof(SCARD_READERSTATEW));
		{
			ret.ReturnCode = wrap(smartcard, SCardGetStatusChangeW, operation->hContext,
			                      MIN(dwTimeOut, dwTimeStep), rgReaderStates, call->cReaders);
		}
		if (ret.ReturnCode != SCARD_E_TIMEOUT)
			break;
		if (WaitForSingleObject(smartcard->stopEvent, 0) == WAIT_OBJECT_0)
			break;
		if (dwTimeOut != INFINITE)
			x += dwTimeStep;
	}
	scard_log_status_error_wlog(smartcard->log, "SCardGetStatusChangeW", ret.ReturnCode);

	for (UINT32 index = 0; index < ret.cReaders; index++)
	{
		const SCARD_READERSTATEW* cur = &rgReaderStates[index];
		ReaderState_Return* rout = &ret.rgReaderStates[index];

		rout->dwCurrentState = cur->dwCurrentState;
		rout->dwEventState = cur->dwEventState;
		rout->cbAtr = cur->cbAtr;
		CopyMemory(&(rout->rgbAtr), cur->rgbAtr, sizeof(rout->rgbAtr));
	}

	status = smartcard_pack_get_status_change_return(out, &ret, TRUE);
fail:
	free(ret.rgReaderStates);
	free(rgReaderStates);
	if (status != SCARD_S_SUCCESS)
		return status;
	return ret.ReturnCode;
}

static LONG smartcard_Cancel_Call(scard_call_context* smartcard, WINPR_ATTR_UNUSED wStream* out,
                                  SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	ret.ReturnCode = wrap(smartcard, SCardCancel, operation->hContext);
	scard_log_status_error_wlog(smartcard->log, "SCardCancel", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "Cancel");
	return ret.ReturnCode;
}

static LONG smartcard_ConnectA_Call(scard_call_context* smartcard, wStream* out,
                                    SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	SCARDHANDLE hCard = 0;
	Connect_Return ret = { 0 };
	ConnectA_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.connectA;

	if ((call->Common.dwPreferredProtocols == SCARD_PROTOCOL_UNDEFINED) &&
	    (call->Common.dwShareMode != SCARD_SHARE_DIRECT))
	{
		call->Common.dwPreferredProtocols = SCARD_PROTOCOL_Tx;
	}

	ret.ReturnCode = wrap(smartcard, SCardConnectA, operation->hContext, (char*)call->szReader,
	                      call->Common.dwShareMode, call->Common.dwPreferredProtocols, &hCard,
	                      &ret.dwActiveProtocol);
	smartcard_scard_context_native_to_redir(&(ret.hContext), operation->hContext);
	smartcard_scard_handle_native_to_redir(&(ret.hCard), hCard);

	status = smartcard_pack_connect_return(out, &ret);
	if (status != SCARD_S_SUCCESS)
		goto out_fail;

	status = ret.ReturnCode;
out_fail:

	return status;
}

static LONG smartcard_ConnectW_Call(scard_call_context* smartcard, wStream* out,
                                    SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	SCARDHANDLE hCard = 0;
	Connect_Return ret = { 0 };
	ConnectW_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.connectW;

	if ((call->Common.dwPreferredProtocols == SCARD_PROTOCOL_UNDEFINED) &&
	    (call->Common.dwShareMode != SCARD_SHARE_DIRECT))
	{
		call->Common.dwPreferredProtocols = SCARD_PROTOCOL_Tx;
	}

	ret.ReturnCode = wrap(smartcard, SCardConnectW, operation->hContext, (WCHAR*)call->szReader,
	                      call->Common.dwShareMode, call->Common.dwPreferredProtocols, &hCard,
	                      &ret.dwActiveProtocol);
	smartcard_scard_context_native_to_redir(&(ret.hContext), operation->hContext);
	smartcard_scard_handle_native_to_redir(&(ret.hCard), hCard);

	status = smartcard_pack_connect_return(out, &ret);
	if (status != SCARD_S_SUCCESS)
		goto out_fail;

	status = ret.ReturnCode;
out_fail:

	return status;
}

static LONG smartcard_Reconnect_Call(scard_call_context* smartcard, wStream* out,
                                     SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	Reconnect_Return ret = { 0 };
	Reconnect_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.reconnect;
	ret.ReturnCode =
	    wrap(smartcard, SCardReconnect, operation->hCard, call->dwShareMode,
	         call->dwPreferredProtocols, call->dwInitialization, &ret.dwActiveProtocol);
	scard_log_status_error_wlog(smartcard->log, "SCardReconnect", ret.ReturnCode);
	status = smartcard_pack_reconnect_return(out, &ret);
	if (status != SCARD_S_SUCCESS)
		return status;

	return ret.ReturnCode;
}

static LONG smartcard_Disconnect_Call(scard_call_context* smartcard, WINPR_ATTR_UNUSED wStream* out,
                                      SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };
	HCardAndDisposition_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.hCardAndDisposition;

	ret.ReturnCode = wrap(smartcard, SCardDisconnect, operation->hCard, call->dwDisposition);
	scard_log_status_error_wlog(smartcard->log, "SCardDisconnect", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "Disconnect");

	return ret.ReturnCode;
}

static LONG smartcard_BeginTransaction_Call(scard_call_context* smartcard,
                                            WINPR_ATTR_UNUSED wStream* out,
                                            SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	ret.ReturnCode = wrap(smartcard, SCardBeginTransaction, operation->hCard);
	scard_log_status_error_wlog(smartcard->log, "SCardBeginTransaction", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "BeginTransaction");
	return ret.ReturnCode;
}

static LONG smartcard_EndTransaction_Call(scard_call_context* smartcard,
                                          WINPR_ATTR_UNUSED wStream* out,
                                          SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };
	HCardAndDisposition_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.hCardAndDisposition;

	ret.ReturnCode = wrap(smartcard, SCardEndTransaction, operation->hCard, call->dwDisposition);
	scard_log_status_error_wlog(smartcard->log, "SCardEndTransaction", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "EndTransaction");
	return ret.ReturnCode;
}

static LONG smartcard_State_Call(scard_call_context* smartcard, wStream* out,
                                 SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	State_Return ret = { 0 };

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	ret.cbAtrLen = SCARD_ATR_LENGTH;
	ret.ReturnCode = wrap(smartcard, SCardState, operation->hCard, &ret.dwState, &ret.dwProtocol,
	                      (BYTE*)&ret.rgAtr, &ret.cbAtrLen);

	scard_log_status_error_wlog(smartcard->log, "SCardState", ret.ReturnCode);
	status = smartcard_pack_state_return(out, &ret);
	if (status != SCARD_S_SUCCESS)
		return status;

	return ret.ReturnCode;
}

static LONG smartcard_StatusA_Call(scard_call_context* smartcard, wStream* out,
                                   SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	Status_Return ret = { 0 };
	DWORD cchReaderLen = 0;
	DWORD cbAtrLen = 0;
	LPSTR mszReaderNames = NULL;
	Status_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.status;

	call->cbAtrLen = 32;
	cbAtrLen = call->cbAtrLen;

	if (call->fmszReaderNamesIsNULL)
		cchReaderLen = 0;
	else
		cchReaderLen = SCARD_AUTOALLOCATE;

	status = ret.ReturnCode =
	    wrap(smartcard, SCardStatusA, operation->hCard,
	         call->fmszReaderNamesIsNULL ? NULL : (LPSTR)&mszReaderNames, &cchReaderLen,
	         &ret.dwState, &ret.dwProtocol, cbAtrLen ? (BYTE*)&ret.pbAtr : NULL, &cbAtrLen);

	scard_log_status_error_wlog(smartcard->log, "SCardStatusA", status);
	if ((ret.ReturnCode == SCARD_S_SUCCESS) && (cchReaderLen == SCARD_AUTOALLOCATE))
		return SCARD_F_UNKNOWN_ERROR;

	if (status == SCARD_S_SUCCESS)
	{
		if (!call->fmszReaderNamesIsNULL)
			ret.mszReaderNames = (BYTE*)mszReaderNames;

		ret.cBytes = cchReaderLen;

		if (call->cbAtrLen)
			ret.cbAtrLen = cbAtrLen;
	}

	status = smartcard_pack_status_return(out, &ret, FALSE);

	if (mszReaderNames)
		wrap(smartcard, SCardFreeMemory, operation->hContext, mszReaderNames);

	if (status != SCARD_S_SUCCESS)
		return status;
	return ret.ReturnCode;
}

static LONG smartcard_StatusW_Call(scard_call_context* smartcard, wStream* out,
                                   SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	Status_Return ret = { 0 };
	LPWSTR mszReaderNames = NULL;
	Status_Call* call = NULL;
	DWORD cbAtrLen = 0;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.status;

	/**
	 * [MS-RDPESC]
	 * According to 2.2.2.18 Status_Call cbAtrLen is unused an must be ignored upon receipt.
	 */
	cbAtrLen = call->cbAtrLen = 32;

	if (call->fmszReaderNamesIsNULL)
		ret.cBytes = 0;
	else
		ret.cBytes = SCARD_AUTOALLOCATE;

	status = ret.ReturnCode =
	    wrap(smartcard, SCardStatusW, operation->hCard,
	         call->fmszReaderNamesIsNULL ? NULL : (LPWSTR)&mszReaderNames, &ret.cBytes,
	         &ret.dwState, &ret.dwProtocol, (BYTE*)&ret.pbAtr, &cbAtrLen);
	scard_log_status_error_wlog(smartcard->log, "SCardStatusW", status);
	if ((ret.ReturnCode == SCARD_S_SUCCESS) && (ret.cBytes == SCARD_AUTOALLOCATE))
		return SCARD_F_UNKNOWN_ERROR;

	size_t blen = 0;
	if (status == SCARD_S_SUCCESS)
	{
		if (!call->fmszReaderNamesIsNULL)
			ret.mszReaderNames = (BYTE*)mszReaderNames;

		ret.cbAtrLen = cbAtrLen;
	}

	if (ret.cBytes != SCARD_AUTOALLOCATE)
	{
		/* SCardStatusW returns number of characters, we need number of bytes */
		WINPR_ASSERT(ret.cBytes < SCARD_AUTOALLOCATE / sizeof(WCHAR));
		blen = sizeof(WCHAR) * ret.cBytes;
		WINPR_ASSERT(blen <= UINT32_MAX);
		ret.cBytes = (UINT32)blen;
	}

	status = smartcard_pack_status_return(out, &ret, TRUE);
	if (status != SCARD_S_SUCCESS)
		return status;

	if (mszReaderNames)
		wrap(smartcard, SCardFreeMemory, operation->hContext, mszReaderNames);

	return ret.ReturnCode;
}

static LONG smartcard_Transmit_Call(scard_call_context* smartcard, wStream* out,
                                    SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	Transmit_Return ret = { 0 };
	Transmit_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.transmit;
	ret.cbRecvLength = 0;
	ret.pbRecvBuffer = NULL;

	if (call->cbRecvLength && !call->fpbRecvBufferIsNULL)
	{
		if (call->cbRecvLength >= 66560)
			call->cbRecvLength = 66560;

		ret.cbRecvLength = call->cbRecvLength;
		ret.pbRecvBuffer = (BYTE*)malloc(ret.cbRecvLength);

		if (!ret.pbRecvBuffer)
			return STATUS_NO_MEMORY;
	}

	ret.pioRecvPci = call->pioRecvPci;
	ret.ReturnCode =
	    wrap(smartcard, SCardTransmit, operation->hCard, call->pioSendPci, call->pbSendBuffer,
	         call->cbSendLength, ret.pioRecvPci, ret.pbRecvBuffer, &(ret.cbRecvLength));

	scard_log_status_error_wlog(smartcard->log, "SCardTransmit", ret.ReturnCode);

	status = smartcard_pack_transmit_return(out, &ret);
	free(ret.pbRecvBuffer);

	if (status != SCARD_S_SUCCESS)
		return status;
	return ret.ReturnCode;
}

static LONG smartcard_Control_Call(scard_call_context* smartcard, wStream* out,
                                   SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	Control_Return ret = { 0 };
	Control_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.control;
	ret.cbOutBufferSize = call->cbOutBufferSize;
	ret.pvOutBuffer = (BYTE*)malloc(call->cbOutBufferSize);

	if (!ret.pvOutBuffer)
		return SCARD_E_NO_MEMORY;

	ret.ReturnCode =
	    wrap(smartcard, SCardControl, operation->hCard, call->dwControlCode, call->pvInBuffer,
	         call->cbInBufferSize, ret.pvOutBuffer, call->cbOutBufferSize, &ret.cbOutBufferSize);
	scard_log_status_error_wlog(smartcard->log, "SCardControl", ret.ReturnCode);
	status = smartcard_pack_control_return(out, &ret);

	free(ret.pvOutBuffer);
	if (status != SCARD_S_SUCCESS)
		return status;
	return ret.ReturnCode;
}

static LONG smartcard_GetAttrib_Call(scard_call_context* smartcard, wStream* out,
                                     SMARTCARD_OPERATION* operation)
{
	BOOL autoAllocate = FALSE;
	LONG status = 0;
	DWORD cbAttrLen = 0;
	LPBYTE pbAttr = NULL;
	GetAttrib_Return ret = { 0 };
	const GetAttrib_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(operation);

	call = &operation->call.getAttrib;

	if (!call->fpbAttrIsNULL)
	{
		autoAllocate = (call->cbAttrLen == SCARD_AUTOALLOCATE) ? TRUE : FALSE;
		cbAttrLen = call->cbAttrLen;
		if (cbAttrLen && !autoAllocate)
		{
			ret.pbAttr = (BYTE*)malloc(cbAttrLen);

			if (!ret.pbAttr)
				return SCARD_E_NO_MEMORY;
		}

		pbAttr = autoAllocate ? (LPBYTE) & (ret.pbAttr) : ret.pbAttr;
	}

	ret.ReturnCode =
	    wrap(smartcard, SCardGetAttrib, operation->hCard, call->dwAttrId, pbAttr, &cbAttrLen);
	scard_log_status_error_wlog(smartcard->log, "SCardGetAttrib", ret.ReturnCode);
	if ((ret.ReturnCode == SCARD_S_SUCCESS) && (cbAttrLen == SCARD_AUTOALLOCATE))
		return SCARD_F_UNKNOWN_ERROR;

	ret.cbAttrLen = cbAttrLen;

	status = smartcard_pack_get_attrib_return(out, &ret, call->dwAttrId, call->cbAttrLen);

	if (autoAllocate)
		wrap(smartcard, SCardFreeMemory, operation->hContext, ret.pbAttr);
	else
		free(ret.pbAttr);
	return status;
}

static LONG smartcard_SetAttrib_Call(scard_call_context* smartcard, WINPR_ATTR_UNUSED wStream* out,
                                     SMARTCARD_OPERATION* operation)
{
	Long_Return ret = { 0 };
	SetAttrib_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(operation);

	call = &operation->call.setAttrib;

	ret.ReturnCode = wrap(smartcard, SCardSetAttrib, operation->hCard, call->dwAttrId, call->pbAttr,
	                      call->cbAttrLen);
	scard_log_status_error_wlog(smartcard->log, "SCardSetAttrib", ret.ReturnCode);
	smartcard_trace_long_return_int(smartcard->log, &ret, "SetAttrib");

	return ret.ReturnCode;
}

static LONG smartcard_AccessStartedEvent_Call(scard_call_context* smartcard,
                                              WINPR_ATTR_UNUSED wStream* out,
                                              SMARTCARD_OPERATION* operation)
{
	LONG status = SCARD_S_SUCCESS;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_UNUSED(operation);

	if (!smartcard->StartedEvent)
		smartcard->StartedEvent = wrap_ptr(smartcard, SCardAccessStartedEvent);

	if (!smartcard->StartedEvent)
		status = SCARD_E_NO_SERVICE;

	return status;
}

static LONG smartcard_LocateCardsByATRA_Call(scard_call_context* smartcard, wStream* out,
                                             SMARTCARD_OPERATION* operation)
{
	LONG status = 0;
	GetStatusChange_Return ret = { 0 };
	LPSCARD_READERSTATEA states = NULL;
	LocateCardsByATRA_Call* call = NULL;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(operation);

	call = &operation->call.locateCardsByATRA;
	states = (LPSCARD_READERSTATEA)calloc(call->cReaders, sizeof(SCARD_READERSTATEA));

	if (!states)
		return STATUS_NO_MEMORY;

	for (UINT32 i = 0; i < call->cReaders; i++)
	{
		LPSCARD_READERSTATEA state = &states[i];
		state->szReader = call->rgReaderStates[i].szReader;
		state->dwCurrentState = call->rgReaderStates[i].dwCurrentState;
		state->dwEventState = call->rgReaderStates[i].dwEventState;
		state->cbAtr = call->rgReaderStates[i].cbAtr;
		CopyMemory(&(state->rgbAtr), &(call->rgReaderStates[i].rgbAtr), 36);
	}

	status = ret.ReturnCode = wrap(smartcard, SCardGetStatusChangeA, operation->hContext,
	                               0x000001F4, states, call->cReaders);

	scard_log_status_error_wlog(smartcard->log, "SCardGetStatusChangeA", status);
	for (UINT32 i = 0; i < call->cAtrs; i++)
	{
		for (UINT32 j = 0; j < call->cReaders; j++)
		{
			for (UINT32 k = 0; k < call->rgAtrMasks[i].cbAtr; k++)
			{
				if ((call->rgAtrMasks[i].rgbAtr[k] & call->rgAtrMasks[i].rgbMask[k]) !=
				    (states[j].rgbAtr[k] & call->rgAtrMasks[i].rgbMask[k]))
				{
					break;
				}

				states[j].dwEventState |= SCARD_STATE_ATRMATCH;
			}
		}
	}

	ret.cReaders = call->cReaders;
	ret.rgReaderStates = NULL;

	if (ret.cReaders > 0)
		ret.rgReaderStates = (ReaderState_Return*)calloc(ret.cReaders, sizeof(ReaderState_Return));

	if (!ret.rgReaderStates)
	{
		free(states);
		return STATUS_NO_MEMORY;
	}

	for (UINT32 i = 0; i < ret.cReaders; i++)
	{
		LPSCARD_READERSTATEA state = &states[i];
		ret.rgReaderStates[i].dwCurrentState = state->dwCurrentState;
		ret.rgReaderStates[i].dwEventState = state->dwEventState;
		ret.rgReaderStates[i].cbAtr = state->cbAtr;
		CopyMemory(&(ret.rgReaderStates[i].rgbAtr), &(state->rgbAtr),
		           sizeof(ret.rgReaderStates[i].rgbAtr));
	}

	free(states);

	status = smartcard_pack_get_status_change_return(out, &ret, FALSE);

	free(ret.rgReaderStates);
	if (status != SCARD_S_SUCCESS)
		return status;
	return ret.ReturnCode;
}

LONG smartcard_irp_device_control_call(scard_call_context* smartcard, wStream* out,
                                       NTSTATUS* pIoStatus, SMARTCARD_OPERATION* operation)
{
	LONG result = 0;
	UINT32 offset = 0;
	size_t objectBufferLength = 0;

	WINPR_ASSERT(smartcard);
	WINPR_ASSERT(out);
	WINPR_ASSERT(pIoStatus);
	WINPR_ASSERT(operation);

	const UINT32 ioControlCode = operation->ioControlCode;
	/**
	 * [MS-RDPESC] 3.2.5.1: Sending Outgoing Messages:
	 * the output buffer length SHOULD be set to 2048
	 *
	 * Since it's a SHOULD and not a MUST, we don't care
	 * about it, but we still reserve at least 2048 bytes.
	 */
	const size_t outMaxLen = MAX(2048, operation->outputBufferLength);
	if (!Stream_EnsureRemainingCapacity(out, outMaxLen))
		return SCARD_E_NO_MEMORY;

	/* Device Control Response */
	Stream_Write_UINT32(out, 0);                            /* OutputBufferLength (4 bytes) */
	Stream_Zero(out, SMARTCARD_COMMON_TYPE_HEADER_LENGTH);  /* CommonTypeHeader (8 bytes) */
	Stream_Zero(out, SMARTCARD_PRIVATE_TYPE_HEADER_LENGTH); /* PrivateTypeHeader (8 bytes) */
	Stream_Write_UINT32(out, 0);                            /* Result (4 bytes) */

	/* Call */
	switch (ioControlCode)
	{
		case SCARD_IOCTL_ESTABLISHCONTEXT:
			result = smartcard_EstablishContext_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_RELEASECONTEXT:
			result = smartcard_ReleaseContext_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_ISVALIDCONTEXT:
			result = smartcard_IsValidContext_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_LISTREADERGROUPSA:
			result = smartcard_ListReaderGroupsA_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_LISTREADERGROUPSW:
			result = smartcard_ListReaderGroupsW_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_LISTREADERSA:
			result = smartcard_ListReadersA_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_LISTREADERSW:
			result = smartcard_ListReadersW_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_INTRODUCEREADERGROUPA:
			result = smartcard_IntroduceReaderGroupA_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_INTRODUCEREADERGROUPW:
			result = smartcard_IntroduceReaderGroupW_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_FORGETREADERGROUPA:
			result = smartcard_ForgetReaderA_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_FORGETREADERGROUPW:
			result = smartcard_ForgetReaderW_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_INTRODUCEREADERA:
			result = smartcard_IntroduceReaderA_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_INTRODUCEREADERW:
			result = smartcard_IntroduceReaderW_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_FORGETREADERA:
			result = smartcard_ForgetReaderA_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_FORGETREADERW:
			result = smartcard_ForgetReaderW_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_ADDREADERTOGROUPA:
			result = smartcard_AddReaderToGroupA_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_ADDREADERTOGROUPW:
			result = smartcard_AddReaderToGroupW_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_REMOVEREADERFROMGROUPA:
			result = smartcard_RemoveReaderFromGroupA_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_REMOVEREADERFROMGROUPW:
			result = smartcard_RemoveReaderFromGroupW_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_LOCATECARDSA:
			result = smartcard_LocateCardsA_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_LOCATECARDSW:
			result = smartcard_LocateCardsW_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_GETSTATUSCHANGEA:
			result = smartcard_GetStatusChangeA_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_GETSTATUSCHANGEW:
			result = smartcard_GetStatusChangeW_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_CANCEL:
			result = smartcard_Cancel_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_CONNECTA:
			result = smartcard_ConnectA_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_CONNECTW:
			result = smartcard_ConnectW_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_RECONNECT:
			result = smartcard_Reconnect_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_DISCONNECT:
			result = smartcard_Disconnect_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_BEGINTRANSACTION:
			result = smartcard_BeginTransaction_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_ENDTRANSACTION:
			result = smartcard_EndTransaction_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_STATE:
			result = smartcard_State_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_STATUSA:
			result = smartcard_StatusA_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_STATUSW:
			result = smartcard_StatusW_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_TRANSMIT:
			result = smartcard_Transmit_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_CONTROL:
			result = smartcard_Control_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_GETATTRIB:
			result = smartcard_GetAttrib_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_SETATTRIB:
			result = smartcard_SetAttrib_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_ACCESSSTARTEDEVENT:
			result = smartcard_AccessStartedEvent_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_LOCATECARDSBYATRA:
			result = smartcard_LocateCardsByATRA_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_LOCATECARDSBYATRW:
			result = smartcard_LocateCardsW_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_READCACHEA:
			result = smartcard_ReadCacheA_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_READCACHEW:
			result = smartcard_ReadCacheW_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_WRITECACHEA:
			result = smartcard_WriteCacheA_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_WRITECACHEW:
			result = smartcard_WriteCacheW_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_GETTRANSMITCOUNT:
			result = smartcard_GetTransmitCount_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_RELEASETARTEDEVENT:
			result = smartcard_ReleaseStartedEvent_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_GETREADERICON:
			result = smartcard_GetReaderIcon_Call(smartcard, out, operation);
			break;

		case SCARD_IOCTL_GETDEVICETYPEID:
			result = smartcard_GetDeviceTypeId_Call(smartcard, out, operation);
			break;

		default:
			result = STATUS_UNSUCCESSFUL;
			break;
	}

	/**
	 * [MS-RPCE] 2.2.6.3 Primitive Type Serialization
	 * The type MUST be aligned on an 8-byte boundary. If the size of the
	 * primitive type is not a multiple of 8 bytes, the data MUST be padded.
	 */

	if ((ioControlCode != SCARD_IOCTL_ACCESSSTARTEDEVENT) &&
	    (ioControlCode != SCARD_IOCTL_RELEASETARTEDEVENT))
	{
		offset = (RDPDR_DEVICE_IO_RESPONSE_LENGTH + RDPDR_DEVICE_IO_CONTROL_RSP_HDR_LENGTH);
		smartcard_pack_write_size_align(out, Stream_GetPosition(out) - offset, 8);
	}

	if ((result != SCARD_S_SUCCESS) && (result != SCARD_E_TIMEOUT) &&
	    (result != SCARD_E_NO_READERS_AVAILABLE) && (result != SCARD_E_NO_SERVICE) &&
	    (result != SCARD_W_CACHE_ITEM_NOT_FOUND) && (result != SCARD_W_CACHE_ITEM_STALE))
	{
		WLog_Print(smartcard->log, WLOG_WARN,
		           "IRP failure: %s (0x%08" PRIX32 "), status: %s (0x%08" PRIX32 ")",
		           scard_get_ioctl_string(ioControlCode, TRUE), ioControlCode,
		           SCardGetErrorString(result), result);
	}

	*pIoStatus = STATUS_SUCCESS;

	if ((result & 0xC0000000L) == 0xC0000000L)
	{
		/* NTSTATUS error */
		*pIoStatus = result;
		WLog_Print(smartcard->log, WLOG_WARN,
		           "IRP failure: %s (0x%08" PRIX32 "), ntstatus: 0x%08" PRIX32 "",
		           scard_get_ioctl_string(ioControlCode, TRUE), ioControlCode, result);
	}

	Stream_SealLength(out);
	size_t outputBufferLength = Stream_Length(out);
	WINPR_ASSERT(outputBufferLength >= RDPDR_DEVICE_IO_RESPONSE_LENGTH + 4U);
	outputBufferLength -= (RDPDR_DEVICE_IO_RESPONSE_LENGTH + 4U);
	WINPR_ASSERT(outputBufferLength >= RDPDR_DEVICE_IO_RESPONSE_LENGTH);
	objectBufferLength = outputBufferLength - RDPDR_DEVICE_IO_RESPONSE_LENGTH;
	WINPR_ASSERT(outputBufferLength <= UINT32_MAX);
	WINPR_ASSERT(objectBufferLength <= UINT32_MAX);
	Stream_SetPosition(out, RDPDR_DEVICE_IO_RESPONSE_LENGTH);

	/* [MS-RDPESC] 3.2.5.2 Processing Incoming Replies
	 *
	 * if the output buffer is too small, reply with STATUS_BUFFER_TOO_SMALL
	 * and a outputBufferLength of 0.
	 * The message should then be retransmitted from the server with a doubled
	 * buffer size.
	 */
	if (outputBufferLength > operation->outputBufferLength)
	{
		WLog_Print(smartcard->log, WLOG_WARN,
		           "IRP warn: expected outputBufferLength %" PRIu32 ", but current limit %" PRIu32
		           ", respond with STATUS_BUFFER_TOO_SMALL",
		           operation->outputBufferLength, outputBufferLength);

		*pIoStatus = STATUS_BUFFER_TOO_SMALL;
		result = *pIoStatus;
		outputBufferLength = 0;
		objectBufferLength = 0;
	}

	/* Device Control Response */
	Stream_Write_UINT32(out, (UINT32)outputBufferLength); /* OutputBufferLength (4 bytes) */
	smartcard_pack_common_type_header(out);               /* CommonTypeHeader (8 bytes) */
	smartcard_pack_private_type_header(
	    out, (UINT32)objectBufferLength); /* PrivateTypeHeader (8 bytes) */
	Stream_Write_INT32(out, result);      /* Result (4 bytes) */
	Stream_SetPosition(out, Stream_Length(out));
	return SCARD_S_SUCCESS;
}

void context_free(void* arg)
{
	struct s_scard_context_element* element = arg;
	if (!arg)
		return;

	if (element->fn_free)
		element->fn_free(element->context);
	free(element);
}

scard_call_context* smartcard_call_context_new(const rdpSettings* settings)
{
	wObject* obj = NULL;
	scard_call_context* ctx = NULL;

	WINPR_ASSERT(settings);
	ctx = calloc(1, sizeof(scard_call_context));
	if (!ctx)
		goto fail;

	ctx->log = WLog_Get(SCARD_TAG);
	WINPR_ASSERT(ctx->log);

	ctx->stopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
	if (!ctx->stopEvent)
		goto fail;

	ctx->names = LinkedList_New();
	if (!ctx->names)
		goto fail;

#if defined(WITH_SMARTCARD_EMULATE)
	ctx->useEmulatedCard = freerdp_settings_get_bool(settings, FreeRDP_SmartcardEmulation);
#endif

	if (ctx->useEmulatedCard)
	{
#if defined(WITH_SMARTCARD_EMULATE)
		ctx->emulation = Emulate_New(settings);
		if (!ctx->emulation)
			goto fail;
#else
		WLog_Print(ctx->log, WLOG_ERROR, "Smartcard emulation requested, but not supported!");
		goto fail;
#endif
	}
	else
	{
		const char* WinSCardModule = freerdp_settings_get_string(settings, FreeRDP_WinSCardModule);
		if (WinSCardModule)
		{
			ctx->hWinSCardLibrary = LoadLibraryX(WinSCardModule);

			if (!ctx->hWinSCardLibrary)
			{
				WLog_Print(ctx->log, WLOG_ERROR, "Failed to load WinSCard library: '%s'",
				           WinSCardModule);
				goto fail;
			}

			if (!WinSCard_LoadApiTableFunctions(&ctx->WinSCardApi, ctx->hWinSCardLibrary))
				goto fail;
			ctx->pWinSCardApi = &ctx->WinSCardApi;
		}
		else
		{
			ctx->pWinSCardApi = WinPR_GetSCardApiFunctionTable();
		}

		if (!ctx->pWinSCardApi)
		{
			WLog_Print(ctx->log, WLOG_ERROR, "Failed to load WinSCard API!");
			goto fail;
		}
	}

	ctx->rgSCardContextList = HashTable_New(FALSE);
	if (!ctx->rgSCardContextList)
		goto fail;

	obj = HashTable_ValueObject(ctx->rgSCardContextList);
	WINPR_ASSERT(obj);
	obj->fnObjectFree = context_free;

	return ctx;
fail:
	WINPR_PRAGMA_DIAG_PUSH
	WINPR_PRAGMA_DIAG_IGNORED_MISMATCHED_DEALLOC
	smartcard_call_context_free(ctx);
	WINPR_PRAGMA_DIAG_POP
	return NULL;
}

void smartcard_call_context_free(scard_call_context* ctx)
{
	if (!ctx)
		return;

	smartcard_call_context_signal_stop(ctx, FALSE);

	LinkedList_Free(ctx->names);
	if (ctx->StartedEvent)
	{
		WINPR_ASSERT(ctx->useEmulatedCard || ctx->pWinSCardApi);
		wrap(ctx, SCardReleaseStartedEvent);
	}

	if (ctx->useEmulatedCard)
	{
#ifdef WITH_SMARTCARD_EMULATE
		if (ctx->emulation)
		{
			Emulate_Free(ctx->emulation);
			ctx->emulation = NULL;
		}
#endif
	}

	if (ctx->hWinSCardLibrary)
	{
		ZeroMemory(&ctx->WinSCardApi, sizeof(SCardApiFunctionTable));
		FreeLibrary(ctx->hWinSCardLibrary);
		ctx->hWinSCardLibrary = NULL;
	}

	ctx->pWinSCardApi = NULL;

	HashTable_Free(ctx->rgSCardContextList);
	(void)CloseHandle(ctx->stopEvent);
	free(ctx);
}

BOOL smartcard_call_context_add(scard_call_context* ctx, const char* name)
{
	WINPR_ASSERT(ctx);
	WINPR_ASSERT(name);
	return LinkedList_AddLast(ctx->names, name);
}

BOOL smartcard_call_cancel_context(scard_call_context* ctx, SCARDCONTEXT hContext)
{
	WINPR_ASSERT(ctx);
	if (wrap(ctx, SCardIsValidContext, hContext) == SCARD_S_SUCCESS)
	{
		wrap(ctx, SCardCancel, hContext);
	}
	return TRUE;
}

BOOL smartcard_call_release_context(scard_call_context* ctx, SCARDCONTEXT hContext)
{
	WINPR_ASSERT(ctx);
	wrap(ctx, SCardReleaseContext, hContext);
	return TRUE;
}

BOOL smartcard_call_cancel_all_context(scard_call_context* ctx)
{
	WINPR_ASSERT(ctx);

	HashTable_Clear(ctx->rgSCardContextList);
	return TRUE;
}

BOOL smarcard_call_set_callbacks(scard_call_context* ctx, void* userdata,
                                 void* (*fn_new)(void*, SCARDCONTEXT), void (*fn_free)(void*))
{
	WINPR_ASSERT(ctx);
	ctx->userdata = userdata;
	ctx->fn_new = fn_new;
	ctx->fn_free = fn_free;
	return TRUE;
}

void* smartcard_call_get_context(scard_call_context* ctx, SCARDCONTEXT hContext)
{
	struct s_scard_context_element* element = NULL;

	WINPR_ASSERT(ctx);
	element = HashTable_GetItemValue(ctx->rgSCardContextList, (void*)hContext);
	if (!element)
		return NULL;
	return element->context;
}

BOOL smartcard_call_is_configured(scard_call_context* ctx)
{
	WINPR_ASSERT(ctx);

#if defined(WITH_SMARTCARD_EMULATE)
	if (ctx->useEmulatedCard)
		return Emulate_IsConfigured(ctx->emulation);
#endif

	return FALSE;
}

BOOL smartcard_call_context_signal_stop(scard_call_context* ctx, BOOL reset)
{
	WINPR_ASSERT(ctx);
	if (!ctx->stopEvent)
		return TRUE;

	if (reset)
		return ResetEvent(ctx->stopEvent);
	else
		return SetEvent(ctx->stopEvent);
}
