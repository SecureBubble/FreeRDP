/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Audio Output Virtual Channel
 *
 * Copyright 2009-2011 Jay Sorg
 * Copyright 2010-2011 Vic Lee
 * Copyright 2012-2013 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 * Copyright 2015 Thincast Technologies GmbH
 * Copyright 2015 DI (FH) Martin Haimberger <martin.haimberger@thincast.com>
 * Copyright 2016 David PHAM-VAN <d.phamvan@inuvika.com>
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

#ifndef _WIN32
#include <sys/time.h>
#include <signal.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <winpr/crt.h>
#include <winpr/assert.h>
#include <winpr/wlog.h>
#include <winpr/stream.h>
#include <winpr/cmdline.h>
#include <winpr/sysinfo.h>
#include <winpr/collections.h>

#include <freerdp/types.h>
#include <freerdp/addin.h>
#include <freerdp/freerdp.h>
#include <freerdp/codec/dsp.h>
#include <freerdp/client/channels.h>

#include "rdpsnd_common.h"
#include "rdpsnd_main.h"

struct rdpsnd_plugin
{
	IWTSPlugin iface;
	IWTSListener* listener;
	GENERIC_LISTENER_CALLBACK* listener_callback;

	CHANNEL_DEF channelDef;
	CHANNEL_ENTRY_POINTS_FREERDP_EX channelEntryPoints;

	wStreamPool* pool;
	wStream* data_in;

	void* InitHandle;
	DWORD OpenHandle;

	wLog* log;

	BYTE cBlockNo;
	UINT16 wQualityMode;
	UINT16 wCurrentFormatNo;

	AUDIO_FORMAT* ServerFormats;
	UINT16 NumberOfServerFormats;

	AUDIO_FORMAT* ClientFormats;
	UINT16 NumberOfClientFormats;

	BOOL attached;
	BOOL connected;
	BOOL dynamic;

	BOOL expectingWave;
	BYTE waveData[4];
	UINT16 waveDataSize;
	UINT16 wTimeStamp;
	UINT64 wArrivalTime;

	UINT32 latency;
	BOOL isOpen;
	AUDIO_FORMAT* fixed_format;

	UINT32 startPlayTime;
	size_t totalPlaySize;

	char* subsystem;
	char* device_name;

	/* Device plugin */
	rdpsndDevicePlugin* device;
	rdpContext* rdpcontext;

	FREERDP_DSP_CONTEXT* dsp_context;

	HANDLE thread;
	wMessageQueue* queue;
	BOOL initialized;

	UINT16 wVersion;
	UINT32 volume;
	BOOL applyVolume;

	size_t references;
	BOOL OnOpenCalled;
	BOOL async;
};

static const char* rdpsnd_is_dyn_str(BOOL dynamic)
{
	if (dynamic)
		return "[dynamic]";
	return "[static]";
}

static void rdpsnd_virtual_channel_event_terminated(rdpsndPlugin* rdpsnd);

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_virtual_channel_write(rdpsndPlugin* rdpsnd, wStream* s);

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_send_quality_mode_pdu(rdpsndPlugin* rdpsnd)
{
	wStream* pdu = NULL;
	WINPR_ASSERT(rdpsnd);
	pdu = Stream_New(NULL, 8);

	if (!pdu)
	{
		WLog_ERR(TAG, "%s Stream_New failed!", rdpsnd_is_dyn_str(rdpsnd->dynamic));
		return CHANNEL_RC_NO_MEMORY;
	}

	Stream_Write_UINT8(pdu, SNDC_QUALITYMODE);      /* msgType */
	Stream_Write_UINT8(pdu, 0);                     /* bPad */
	Stream_Write_UINT16(pdu, 4);                    /* BodySize */
	Stream_Write_UINT16(pdu, rdpsnd->wQualityMode); /* wQualityMode */
	Stream_Write_UINT16(pdu, 0);                    /* Reserved */
	WLog_Print(rdpsnd->log, WLOG_DEBUG, "%s QualityMode: %" PRIu16 "",
	           rdpsnd_is_dyn_str(rdpsnd->dynamic), rdpsnd->wQualityMode);
	return rdpsnd_virtual_channel_write(rdpsnd, pdu);
}

static void rdpsnd_select_supported_audio_formats(rdpsndPlugin* rdpsnd)
{
	WINPR_ASSERT(rdpsnd);
	audio_formats_free(rdpsnd->ClientFormats, rdpsnd->NumberOfClientFormats);
	rdpsnd->NumberOfClientFormats = 0;
	rdpsnd->ClientFormats = NULL;

	if (!rdpsnd->NumberOfServerFormats)
		return;

	rdpsnd->ClientFormats = audio_formats_new(rdpsnd->NumberOfServerFormats);

	if (!rdpsnd->ClientFormats || !rdpsnd->device)
		return;

	for (UINT16 index = 0; index < rdpsnd->NumberOfServerFormats; index++)
	{
		const AUDIO_FORMAT* serverFormat = &rdpsnd->ServerFormats[index];

		if (!audio_format_compatible(rdpsnd->fixed_format, serverFormat))
			continue;

		WINPR_ASSERT(rdpsnd->device->FormatSupported);
		if (freerdp_dsp_supports_format(serverFormat, FALSE) ||
		    rdpsnd->device->FormatSupported(rdpsnd->device, serverFormat))
		{
			AUDIO_FORMAT* clientFormat = &rdpsnd->ClientFormats[rdpsnd->NumberOfClientFormats++];
			audio_format_copy(serverFormat, clientFormat);
		}
	}
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_send_client_audio_formats(rdpsndPlugin* rdpsnd)
{
	wStream* pdu = NULL;
	UINT16 length = 0;
	UINT32 dwVolume = 0;
	UINT16 wNumberOfFormats = 0;
	WINPR_ASSERT(rdpsnd);

	if (!rdpsnd->device || (!rdpsnd->dynamic && (rdpsnd->OpenHandle == 0)))
		return CHANNEL_RC_INITIALIZATION_ERROR;

	dwVolume = IFCALLRESULT(0, rdpsnd->device->GetVolume, rdpsnd->device);
	wNumberOfFormats = rdpsnd->NumberOfClientFormats;
	length = 4 + 20;

	for (UINT16 index = 0; index < wNumberOfFormats; index++)
		length += (18 + rdpsnd->ClientFormats[index].cbSize);

	pdu = Stream_New(NULL, length);

	if (!pdu)
	{
		WLog_ERR(TAG, "%s Stream_New failed!", rdpsnd_is_dyn_str(rdpsnd->dynamic));
		return CHANNEL_RC_NO_MEMORY;
	}

	Stream_Write_UINT8(pdu, SNDC_FORMATS);                        /* msgType */
	Stream_Write_UINT8(pdu, 0);                                   /* bPad */
	Stream_Write_UINT16(pdu, length - 4);                         /* BodySize */
	Stream_Write_UINT32(pdu, TSSNDCAPS_ALIVE | TSSNDCAPS_VOLUME); /* dwFlags */
	Stream_Write_UINT32(pdu, dwVolume);                           /* dwVolume */
	Stream_Write_UINT32(pdu, 0);                                  /* dwPitch */
	Stream_Write_UINT16(pdu, 0);                                  /* wDGramPort */
	Stream_Write_UINT16(pdu, wNumberOfFormats);                   /* wNumberOfFormats */
	Stream_Write_UINT8(pdu, 0);                                   /* cLastBlockConfirmed */
	Stream_Write_UINT16(pdu, CHANNEL_VERSION_WIN_MAX);            /* wVersion */
	Stream_Write_UINT8(pdu, 0);                                   /* bPad */

	for (UINT16 index = 0; index < wNumberOfFormats; index++)
	{
		const AUDIO_FORMAT* clientFormat = &rdpsnd->ClientFormats[index];

		if (!audio_format_write(pdu, clientFormat))
		{
			Stream_Free(pdu, TRUE);
			return ERROR_INTERNAL_ERROR;
		}
	}

	WLog_Print(rdpsnd->log, WLOG_DEBUG, "%s Client Audio Formats",
	           rdpsnd_is_dyn_str(rdpsnd->dynamic));
	return rdpsnd_virtual_channel_write(rdpsnd, pdu);
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_recv_server_audio_formats_pdu(rdpsndPlugin* rdpsnd, wStream* s)
{
	UINT16 wNumberOfFormats = 0;
	UINT ret = ERROR_BAD_LENGTH;

	WINPR_ASSERT(rdpsnd);
	audio_formats_free(rdpsnd->ServerFormats, rdpsnd->NumberOfServerFormats);
	rdpsnd->NumberOfServerFormats = 0;
	rdpsnd->ServerFormats = NULL;

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 30))
		return ERROR_BAD_LENGTH;

	/* http://msdn.microsoft.com/en-us/library/cc240956.aspx */
	Stream_Seek_UINT32(s); /* dwFlags */
	Stream_Seek_UINT32(s); /* dwVolume */
	Stream_Seek_UINT32(s); /* dwPitch */
	Stream_Seek_UINT16(s); /* wDGramPort */
	Stream_Read_UINT16(s, wNumberOfFormats);
	Stream_Read_UINT8(s, rdpsnd->cBlockNo);  /* cLastBlockConfirmed */
	Stream_Read_UINT16(s, rdpsnd->wVersion); /* wVersion */
	Stream_Seek_UINT8(s);                    /* bPad */
	rdpsnd->NumberOfServerFormats = wNumberOfFormats;

	if (!Stream_CheckAndLogRequiredLengthOfSize(TAG, s, wNumberOfFormats, 14ull))
		return ERROR_BAD_LENGTH;

	if (rdpsnd->NumberOfServerFormats > 0)
	{
		rdpsnd->ServerFormats = audio_formats_new(wNumberOfFormats);

		if (!rdpsnd->ServerFormats)
			return CHANNEL_RC_NO_MEMORY;

		for (UINT16 index = 0; index < wNumberOfFormats; index++)
		{
			AUDIO_FORMAT* format = &rdpsnd->ServerFormats[index];

			if (!audio_format_read(s, format))
				goto out_fail;
		}
	}

	WINPR_ASSERT(rdpsnd->device);
	ret = IFCALLRESULT(CHANNEL_RC_OK, rdpsnd->device->ServerFormatAnnounce, rdpsnd->device,
	                   rdpsnd->ServerFormats, rdpsnd->NumberOfServerFormats);
	if (ret != CHANNEL_RC_OK)
		goto out_fail;

	rdpsnd_select_supported_audio_formats(rdpsnd);
	WLog_Print(rdpsnd->log, WLOG_DEBUG, "%s Server Audio Formats",
	           rdpsnd_is_dyn_str(rdpsnd->dynamic));
	ret = rdpsnd_send_client_audio_formats(rdpsnd);

	if (ret == CHANNEL_RC_OK)
	{
		if (rdpsnd->wVersion >= CHANNEL_VERSION_WIN_7)
			ret = rdpsnd_send_quality_mode_pdu(rdpsnd);
	}

	return ret;
out_fail:
	audio_formats_free(rdpsnd->ServerFormats, rdpsnd->NumberOfServerFormats);
	rdpsnd->ServerFormats = NULL;
	rdpsnd->NumberOfServerFormats = 0;
	return ret;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_send_training_confirm_pdu(rdpsndPlugin* rdpsnd, UINT16 wTimeStamp,
                                             UINT16 wPackSize)
{
	wStream* pdu = NULL;
	WINPR_ASSERT(rdpsnd);
	pdu = Stream_New(NULL, 8);

	if (!pdu)
	{
		WLog_ERR(TAG, "%s Stream_New failed!", rdpsnd_is_dyn_str(rdpsnd->dynamic));
		return CHANNEL_RC_NO_MEMORY;
	}

	Stream_Write_UINT8(pdu, SNDC_TRAINING); /* msgType */
	Stream_Write_UINT8(pdu, 0);             /* bPad */
	Stream_Write_UINT16(pdu, 4);            /* BodySize */
	Stream_Write_UINT16(pdu, wTimeStamp);
	Stream_Write_UINT16(pdu, wPackSize);
	WLog_Print(rdpsnd->log, WLOG_DEBUG,
	           "%s Training Response: wTimeStamp: %" PRIu16 " wPackSize: %" PRIu16 "",
	           rdpsnd_is_dyn_str(rdpsnd->dynamic), wTimeStamp, wPackSize);
	return rdpsnd_virtual_channel_write(rdpsnd, pdu);
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_recv_training_pdu(rdpsndPlugin* rdpsnd, wStream* s)
{
	UINT16 wTimeStamp = 0;
	UINT16 wPackSize = 0;
	WINPR_ASSERT(rdpsnd);
	WINPR_ASSERT(s);

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 4))
		return ERROR_BAD_LENGTH;

	Stream_Read_UINT16(s, wTimeStamp);
	Stream_Read_UINT16(s, wPackSize);
	WLog_Print(rdpsnd->log, WLOG_DEBUG,
	           "%s Training Request: wTimeStamp: %" PRIu16 " wPackSize: %" PRIu16 "",
	           rdpsnd_is_dyn_str(rdpsnd->dynamic), wTimeStamp, wPackSize);
	return rdpsnd_send_training_confirm_pdu(rdpsnd, wTimeStamp, wPackSize);
}

static BOOL rdpsnd_apply_volume(rdpsndPlugin* rdpsnd)
{
	WINPR_ASSERT(rdpsnd);

	if (rdpsnd->isOpen && rdpsnd->applyVolume && rdpsnd->device)
	{
		BOOL rc = IFCALLRESULT(TRUE, rdpsnd->device->SetVolume, rdpsnd->device, rdpsnd->volume);
		if (!rc)
			return FALSE;
		rdpsnd->applyVolume = FALSE;
	}
	return TRUE;
}

static BOOL rdpsnd_ensure_device_is_open(rdpsndPlugin* rdpsnd, UINT16 wFormatNo,
                                         const AUDIO_FORMAT* format)
{
	if (!rdpsnd)
		return FALSE;
	WINPR_ASSERT(format);

	if (!rdpsnd->isOpen || (wFormatNo != rdpsnd->wCurrentFormatNo))
	{
		BOOL rc = 0;
		BOOL supported = 0;
		AUDIO_FORMAT deviceFormat = *format;

		IFCALL(rdpsnd->device->Close, rdpsnd->device);
		supported = IFCALLRESULT(FALSE, rdpsnd->device->FormatSupported, rdpsnd->device, format);

		if (!supported)
		{
			if (!IFCALLRESULT(FALSE, rdpsnd->device->DefaultFormat, rdpsnd->device, format,
			                  &deviceFormat))
			{
				deviceFormat.wFormatTag = WAVE_FORMAT_PCM;
				deviceFormat.wBitsPerSample = 16;
				deviceFormat.cbSize = 0;
			}
		}

		WLog_Print(rdpsnd->log, WLOG_DEBUG, "%s Opening device with format %s [backend %s]",
		           rdpsnd_is_dyn_str(rdpsnd->dynamic),
		           audio_format_get_tag_string(format->wFormatTag),
		           audio_format_get_tag_string(deviceFormat.wFormatTag));
		rc = IFCALLRESULT(FALSE, rdpsnd->device->Open, rdpsnd->device, &deviceFormat,
		                  rdpsnd->latency);

		if (!rc)
			return FALSE;

		if (!supported)
		{
			if (!freerdp_dsp_context_reset(rdpsnd->dsp_context, format, 0u))
				return FALSE;
		}

		rdpsnd->isOpen = TRUE;
		rdpsnd->wCurrentFormatNo = wFormatNo;
		rdpsnd->startPlayTime = 0;
		rdpsnd->totalPlaySize = 0;
	}

	return rdpsnd_apply_volume(rdpsnd);
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_recv_wave_info_pdu(rdpsndPlugin* rdpsnd, wStream* s, UINT16 BodySize)
{
	UINT16 wFormatNo = 0;
	const AUDIO_FORMAT* format = NULL;
	WINPR_ASSERT(rdpsnd);
	WINPR_ASSERT(s);

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 12))
		return ERROR_BAD_LENGTH;

	rdpsnd->wArrivalTime = GetTickCount64();
	Stream_Read_UINT16(s, rdpsnd->wTimeStamp);
	Stream_Read_UINT16(s, wFormatNo);

	if (wFormatNo >= rdpsnd->NumberOfClientFormats)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT8(s, rdpsnd->cBlockNo);
	Stream_Seek(s, 3); /* bPad */
	Stream_Read(s, rdpsnd->waveData, 4);
	rdpsnd->waveDataSize = BodySize - 8;
	format = &rdpsnd->ClientFormats[wFormatNo];
	WLog_Print(rdpsnd->log, WLOG_DEBUG,
	           "%s WaveInfo: cBlockNo: %" PRIu8 " wFormatNo: %" PRIu16 " [%s]",
	           rdpsnd_is_dyn_str(rdpsnd->dynamic), rdpsnd->cBlockNo, wFormatNo,
	           audio_format_get_tag_string(format->wFormatTag));

	if (!rdpsnd_ensure_device_is_open(rdpsnd, wFormatNo, format))
		return ERROR_INTERNAL_ERROR;

	rdpsnd->expectingWave = TRUE;
	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_send_wave_confirm_pdu(rdpsndPlugin* rdpsnd, UINT16 wTimeStamp,
                                         BYTE cConfirmedBlockNo)
{
	wStream* pdu = NULL;
	WINPR_ASSERT(rdpsnd);
	pdu = Stream_New(NULL, 8);

	if (!pdu)
	{
		WLog_ERR(TAG, "%s Stream_New failed!", rdpsnd_is_dyn_str(rdpsnd->dynamic));
		return CHANNEL_RC_NO_MEMORY;
	}

	Stream_Write_UINT8(pdu, SNDC_WAVECONFIRM);
	Stream_Write_UINT8(pdu, 0);
	Stream_Write_UINT16(pdu, 4);
	Stream_Write_UINT16(pdu, wTimeStamp);
	Stream_Write_UINT8(pdu, cConfirmedBlockNo); /* cConfirmedBlockNo */
	Stream_Write_UINT8(pdu, 0);                 /* bPad */
	return rdpsnd_virtual_channel_write(rdpsnd, pdu);
}

static BOOL rdpsnd_detect_overrun(rdpsndPlugin* rdpsnd, const AUDIO_FORMAT* format, size_t size)
{
	UINT32 bpf = 0;
	UINT32 now = 0;
	UINT32 duration = 0;
	UINT32 totalDuration = 0;
	UINT32 remainingDuration = 0;
	UINT32 maxDuration = 0;

	if (!rdpsnd || !format)
		return FALSE;

	/* Older windows RDP servers do not limit the send buffer, which can
	 * cause quite a large amount of sound data buffered client side.
	 * If e.g. sound is paused server side the client will keep playing
	 * for a long time instead of pausing playback.
	 *
	 * To avoid this we check:
	 *
	 * 1. Is the sound sample received from a known format these servers
	 *    support
	 * 2. If it is calculate the size of the client side sound buffer
	 * 3. If the buffer is too large silently drop the sample which will
	 *    trigger a retransmit later on.
	 *
	 * This check must only be applied to these known formats, because
	 * with newer and other formats the sample size can not be calculated
	 * without decompressing the sample first.
	 */
	switch (format->wFormatTag)
	{
		case WAVE_FORMAT_PCM:
		case WAVE_FORMAT_DVI_ADPCM:
		case WAVE_FORMAT_ADPCM:
		case WAVE_FORMAT_ALAW:
		case WAVE_FORMAT_MULAW:
			break;
		case WAVE_FORMAT_MSG723:
		case WAVE_FORMAT_GSM610:
		case WAVE_FORMAT_AAC_MS:
		default:
			return FALSE;
	}

	audio_format_print(WLog_Get(TAG), WLOG_DEBUG, format);
	bpf = format->nChannels * format->wBitsPerSample * format->nSamplesPerSec / 8;
	if (bpf == 0)
		return FALSE;

	duration = (UINT32)(1000 * size / bpf);
	totalDuration = (UINT32)(1000 * rdpsnd->totalPlaySize / bpf);
	now = GetTickCountPrecise();
	if (rdpsnd->startPlayTime == 0)
	{
		rdpsnd->startPlayTime = now;
		rdpsnd->totalPlaySize = size;
		return FALSE;
	}
	else if (now - rdpsnd->startPlayTime > totalDuration + 10)
	{
		/* Buffer underrun */
		WLog_Print(rdpsnd->log, WLOG_DEBUG, "%s Buffer underrun by %u ms",
		           rdpsnd_is_dyn_str(rdpsnd->dynamic),
		           (UINT)(now - rdpsnd->startPlayTime - totalDuration));
		rdpsnd->startPlayTime = now;
		rdpsnd->totalPlaySize = size;
		return FALSE;
	}
	else
	{
		/* Calculate remaining duration to be played */
		remainingDuration = totalDuration - (now - rdpsnd->startPlayTime);

		/* Maximum allow duration calculation */
		maxDuration = duration * 2 + rdpsnd->latency;

		if (remainingDuration + duration > maxDuration)
		{
			WLog_Print(rdpsnd->log, WLOG_DEBUG, "%s Buffer overrun pending %u ms dropping %u ms",
			           rdpsnd_is_dyn_str(rdpsnd->dynamic), remainingDuration, duration);
			return TRUE;
		}

		rdpsnd->totalPlaySize += size;
		return FALSE;
	}
}

static UINT rdpsnd_treat_wave(rdpsndPlugin* rdpsnd, wStream* s, size_t size)
{
	AUDIO_FORMAT* format = NULL;
	UINT64 end = 0;
	UINT64 diffMS = 0;
	UINT64 ts = 0;
	UINT latency = 0;
	UINT error = 0;

	if (!Stream_CheckAndLogRequiredLength(TAG, s, size))
		return ERROR_BAD_LENGTH;

	if (rdpsnd->wCurrentFormatNo >= rdpsnd->NumberOfClientFormats)
		return ERROR_INTERNAL_ERROR;

	/*
	 * Send the first WaveConfirm PDU. The server side uses this to determine the
	 * network latency.
	 * See also [MS-RDPEA] 2.2.3.8 Wave Confirm PDU
	 */
	error = rdpsnd_send_wave_confirm_pdu(rdpsnd, rdpsnd->wTimeStamp, rdpsnd->cBlockNo);
	if (error)
		return error;

	const BYTE* data = Stream_ConstPointer(s);
	format = &rdpsnd->ClientFormats[rdpsnd->wCurrentFormatNo];
	WLog_Print(rdpsnd->log, WLOG_DEBUG,
	           "%s Wave: cBlockNo: %" PRIu8 " wTimeStamp: %" PRIu16 ", size: %" PRIdz,
	           rdpsnd_is_dyn_str(rdpsnd->dynamic), rdpsnd->cBlockNo, rdpsnd->wTimeStamp, size);

	if (rdpsnd->device && rdpsnd->attached && !rdpsnd_detect_overrun(rdpsnd, format, size))
	{
		UINT status = CHANNEL_RC_OK;
		wStream* pcmData = StreamPool_Take(rdpsnd->pool, 4096);

		if (rdpsnd->device->FormatSupported(rdpsnd->device, format))
		{
			if (rdpsnd->device->PlayEx)
				latency = rdpsnd->device->PlayEx(rdpsnd->device, format, data, size);
			else
				latency = IFCALLRESULT(0, rdpsnd->device->Play, rdpsnd->device, data, size);
		}
		else if (freerdp_dsp_decode(rdpsnd->dsp_context, format, data, size, pcmData))
		{
			Stream_SealLength(pcmData);

			if (rdpsnd->device->PlayEx)
				latency = rdpsnd->device->PlayEx(rdpsnd->device, format, Stream_Buffer(pcmData),
				                                 Stream_Length(pcmData));
			else
				latency = IFCALLRESULT(0, rdpsnd->device->Play, rdpsnd->device,
				                       Stream_Buffer(pcmData), Stream_Length(pcmData));
		}
		else
			status = ERROR_INTERNAL_ERROR;

		Stream_Release(pcmData);

		if (status != CHANNEL_RC_OK)
			return status;
	}

	end = GetTickCount64();
	diffMS = end - rdpsnd->wArrivalTime + latency;
	ts = (rdpsnd->wTimeStamp + diffMS) % UINT16_MAX;

	/*
	 * Send the second WaveConfirm PDU. With the first WaveConfirm PDU,
	 * the server side uses this second WaveConfirm PDU to determine the actual
	 * render latency.
	 */
	return rdpsnd_send_wave_confirm_pdu(rdpsnd, (UINT16)ts, rdpsnd->cBlockNo);
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_recv_wave_pdu(rdpsndPlugin* rdpsnd, wStream* s)
{
	rdpsnd->expectingWave = FALSE;

	/**
	 * The Wave PDU is a special case: it is always sent after a Wave Info PDU,
	 * and we do not process its header. Instead, the header is pad that needs
	 * to be filled with the first four bytes of the audio sample data sent as
	 * part of the preceding Wave Info PDU.
	 */
	if (!Stream_CheckAndLogRequiredLength(TAG, s, 4))
		return ERROR_INVALID_DATA;

	CopyMemory(Stream_Buffer(s), rdpsnd->waveData, 4);
	return rdpsnd_treat_wave(rdpsnd, s, rdpsnd->waveDataSize);
}

static UINT rdpsnd_recv_wave2_pdu(rdpsndPlugin* rdpsnd, wStream* s, UINT16 BodySize)
{
	UINT16 wFormatNo = 0;
	AUDIO_FORMAT* format = NULL;
	UINT32 dwAudioTimeStamp = 0;

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 12))
		return ERROR_BAD_LENGTH;

	Stream_Read_UINT16(s, rdpsnd->wTimeStamp);
	Stream_Read_UINT16(s, wFormatNo);
	Stream_Read_UINT8(s, rdpsnd->cBlockNo);
	Stream_Seek(s, 3); /* bPad */
	Stream_Read_UINT32(s, dwAudioTimeStamp);
	if (wFormatNo >= rdpsnd->NumberOfClientFormats)
		return ERROR_INVALID_DATA;
	format = &rdpsnd->ClientFormats[wFormatNo];
	rdpsnd->waveDataSize = BodySize - 12;
	rdpsnd->wArrivalTime = GetTickCount64();
	WLog_Print(rdpsnd->log, WLOG_DEBUG,
	           "%s Wave2PDU: cBlockNo: %" PRIu8 " wFormatNo: %" PRIu16
	           " [%s] , align=%hu wTimeStamp=0x%04" PRIx16 ", dwAudioTimeStamp=0x%08" PRIx32,
	           rdpsnd_is_dyn_str(rdpsnd->dynamic), rdpsnd->cBlockNo, wFormatNo,
	           audio_format_get_tag_string(format->wFormatTag), format->nBlockAlign,
	           rdpsnd->wTimeStamp, dwAudioTimeStamp);

	if (!rdpsnd_ensure_device_is_open(rdpsnd, wFormatNo, format))
		return ERROR_INTERNAL_ERROR;

	return rdpsnd_treat_wave(rdpsnd, s, rdpsnd->waveDataSize);
}

static void rdpsnd_recv_close_pdu(rdpsndPlugin* rdpsnd)
{
	if (rdpsnd->isOpen)
	{
		WLog_Print(rdpsnd->log, WLOG_DEBUG, "%s Closing device",
		           rdpsnd_is_dyn_str(rdpsnd->dynamic));
	}
	else
		WLog_Print(rdpsnd->log, WLOG_DEBUG, "%s Device already closed",
		           rdpsnd_is_dyn_str(rdpsnd->dynamic));
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_recv_volume_pdu(rdpsndPlugin* rdpsnd, wStream* s)
{
	BOOL rc = TRUE;
	UINT32 dwVolume = 0;

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 4))
		return ERROR_BAD_LENGTH;

	Stream_Read_UINT32(s, dwVolume);
	WLog_Print(rdpsnd->log, WLOG_DEBUG, "%s Volume: 0x%08" PRIX32 "",
	           rdpsnd_is_dyn_str(rdpsnd->dynamic), dwVolume);

	rdpsnd->volume = dwVolume;
	rdpsnd->applyVolume = TRUE;
	rc = rdpsnd_apply_volume(rdpsnd);

	if (!rc)
	{
		WLog_ERR(TAG, "%s error setting volume", rdpsnd_is_dyn_str(rdpsnd->dynamic));
		return CHANNEL_RC_INITIALIZATION_ERROR;
	}

	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_recv_pdu(rdpsndPlugin* rdpsnd, wStream* s)
{
	BYTE msgType = 0;
	UINT16 BodySize = 0;
	UINT status = CHANNEL_RC_OK;

	if (rdpsnd->expectingWave)
	{
		status = rdpsnd_recv_wave_pdu(rdpsnd, s);
		goto out;
	}

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 4))
	{
		status = ERROR_BAD_LENGTH;
		goto out;
	}

	Stream_Read_UINT8(s, msgType); /* msgType */
	Stream_Seek_UINT8(s);          /* bPad */
	Stream_Read_UINT16(s, BodySize);

	switch (msgType)
	{
		case SNDC_FORMATS:
			status = rdpsnd_recv_server_audio_formats_pdu(rdpsnd, s);
			break;

		case SNDC_TRAINING:
			status = rdpsnd_recv_training_pdu(rdpsnd, s);
			break;

		case SNDC_WAVE:
			status = rdpsnd_recv_wave_info_pdu(rdpsnd, s, BodySize);
			break;

		case SNDC_CLOSE:
			rdpsnd_recv_close_pdu(rdpsnd);
			break;

		case SNDC_SETVOLUME:
			status = rdpsnd_recv_volume_pdu(rdpsnd, s);
			break;

		case SNDC_WAVE2:
			status = rdpsnd_recv_wave2_pdu(rdpsnd, s, BodySize);
			break;

		default:
			WLog_ERR(TAG, "%s unknown msgType %" PRIu8 "", rdpsnd_is_dyn_str(rdpsnd->dynamic),
			         msgType);
			break;
	}

out:
	Stream_Release(s);
	return status;
}

static void rdpsnd_register_device_plugin(rdpsndPlugin* rdpsnd, rdpsndDevicePlugin* device)
{
	if (rdpsnd->device)
	{
		WLog_ERR(TAG, "%s existing device, abort.", rdpsnd_is_dyn_str(FALSE));
		return;
	}

	rdpsnd->device = device;
	device->rdpsnd = rdpsnd;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_load_device_plugin(rdpsndPlugin* rdpsnd, const char* name,
                                      const ADDIN_ARGV* args)
{
	FREERDP_RDPSND_DEVICE_ENTRY_POINTS entryPoints = { 0 };
	UINT error = 0;
	DWORD flags = FREERDP_ADDIN_CHANNEL_STATIC | FREERDP_ADDIN_CHANNEL_ENTRYEX;
	if (rdpsnd->dynamic)
		flags = FREERDP_ADDIN_CHANNEL_DYNAMIC;
	PVIRTUALCHANNELENTRY pvce =
	    freerdp_load_channel_addin_entry(RDPSND_CHANNEL_NAME, name, NULL, flags);
	PFREERDP_RDPSND_DEVICE_ENTRY entry = WINPR_FUNC_PTR_CAST(pvce, PFREERDP_RDPSND_DEVICE_ENTRY);

	if (!entry)
		return ERROR_INTERNAL_ERROR;

	entryPoints.rdpsnd = rdpsnd;
	entryPoints.pRegisterRdpsndDevice = rdpsnd_register_device_plugin;
	entryPoints.args = args;

	error = entry(&entryPoints);
	if (error)
		WLog_ERR(TAG, "%s %s entry returns error %" PRIu32 "", rdpsnd_is_dyn_str(rdpsnd->dynamic),
		         name, error);

	WLog_INFO(TAG, "%s Loaded %s backend for rdpsnd", rdpsnd_is_dyn_str(rdpsnd->dynamic), name);
	return error;
}

static BOOL rdpsnd_set_subsystem(rdpsndPlugin* rdpsnd, const char* subsystem)
{
	free(rdpsnd->subsystem);
	rdpsnd->subsystem = _strdup(subsystem);
	return (rdpsnd->subsystem != NULL);
}

static BOOL rdpsnd_set_device_name(rdpsndPlugin* rdpsnd, const char* device_name)
{
	free(rdpsnd->device_name);
	rdpsnd->device_name = _strdup(device_name);
	return (rdpsnd->device_name != NULL);
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_process_addin_args(rdpsndPlugin* rdpsnd, const ADDIN_ARGV* args)
{
	int status = 0;
	DWORD flags = 0;
	const COMMAND_LINE_ARGUMENT_A* arg = NULL;
	COMMAND_LINE_ARGUMENT_A rdpsnd_args[] = {
		{ "sys", COMMAND_LINE_VALUE_REQUIRED, "<subsystem>", NULL, NULL, -1, NULL, "subsystem" },
		{ "dev", COMMAND_LINE_VALUE_REQUIRED, "<device>", NULL, NULL, -1, NULL, "device" },
		{ "format", COMMAND_LINE_VALUE_REQUIRED, "<format>", NULL, NULL, -1, NULL, "format" },
		{ "rate", COMMAND_LINE_VALUE_REQUIRED, "<rate>", NULL, NULL, -1, NULL, "rate" },
		{ "channel", COMMAND_LINE_VALUE_REQUIRED, "<channel>", NULL, NULL, -1, NULL, "channel" },
		{ "latency", COMMAND_LINE_VALUE_REQUIRED, "<latency>", NULL, NULL, -1, NULL, "latency" },
		{ "quality", COMMAND_LINE_VALUE_REQUIRED, "<quality mode>", NULL, NULL, -1, NULL,
		  "quality mode" },
		{ NULL, 0, NULL, NULL, NULL, -1, NULL, NULL }
	};
	rdpsnd->wQualityMode = HIGH_QUALITY; /* default quality mode */

	if (args->argc > 1)
	{
		flags = COMMAND_LINE_SIGIL_NONE | COMMAND_LINE_SEPARATOR_COLON;
		status = CommandLineParseArgumentsA(args->argc, args->argv, rdpsnd_args, flags, rdpsnd,
		                                    NULL, NULL);

		if (status < 0)
			return CHANNEL_RC_INITIALIZATION_ERROR;

		arg = rdpsnd_args;
		errno = 0;

		do
		{
			if (!(arg->Flags & COMMAND_LINE_VALUE_PRESENT))
				continue;

			CommandLineSwitchStart(arg) CommandLineSwitchCase(arg, "sys")
			{
				if (!rdpsnd_set_subsystem(rdpsnd, arg->Value))
					return CHANNEL_RC_NO_MEMORY;
			}
			CommandLineSwitchCase(arg, "dev")
			{
				if (!rdpsnd_set_device_name(rdpsnd, arg->Value))
					return CHANNEL_RC_NO_MEMORY;
			}
			CommandLineSwitchCase(arg, "format")
			{
				unsigned long val = strtoul(arg->Value, NULL, 0);

				if ((errno != 0) || (val > UINT16_MAX))
					return CHANNEL_RC_INITIALIZATION_ERROR;

				rdpsnd->fixed_format->wFormatTag = (UINT16)val;
			}
			CommandLineSwitchCase(arg, "rate")
			{
				unsigned long val = strtoul(arg->Value, NULL, 0);

				if ((errno != 0) || (val > UINT32_MAX))
					return CHANNEL_RC_INITIALIZATION_ERROR;

				rdpsnd->fixed_format->nSamplesPerSec = (UINT32)val;
			}
			CommandLineSwitchCase(arg, "channel")
			{
				unsigned long val = strtoul(arg->Value, NULL, 0);

				if ((errno != 0) || (val > UINT16_MAX))
					return CHANNEL_RC_INITIALIZATION_ERROR;

				rdpsnd->fixed_format->nChannels = (UINT16)val;
			}
			CommandLineSwitchCase(arg, "latency")
			{
				unsigned long val = strtoul(arg->Value, NULL, 0);

				if ((errno != 0) || (val > UINT32_MAX))
					return CHANNEL_RC_INITIALIZATION_ERROR;

				rdpsnd->latency = (UINT32)val;
			}
			CommandLineSwitchCase(arg, "quality")
			{
				long wQualityMode = DYNAMIC_QUALITY;

				if (_stricmp(arg->Value, "dynamic") == 0)
					wQualityMode = DYNAMIC_QUALITY;
				else if (_stricmp(arg->Value, "medium") == 0)
					wQualityMode = MEDIUM_QUALITY;
				else if (_stricmp(arg->Value, "high") == 0)
					wQualityMode = HIGH_QUALITY;
				else
				{
					wQualityMode = strtol(arg->Value, NULL, 0);

					if (errno != 0)
						return CHANNEL_RC_INITIALIZATION_ERROR;
				}

				if ((wQualityMode < 0) || (wQualityMode > 2))
					wQualityMode = DYNAMIC_QUALITY;

				rdpsnd->wQualityMode = (UINT16)wQualityMode;
			}
			CommandLineSwitchDefault(arg)
			{
			}
			CommandLineSwitchEnd(arg)
		} while ((arg = CommandLineFindNextArgumentA(arg)) != NULL);
	}

	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_process_connect(rdpsndPlugin* rdpsnd)
{
	const struct
	{
		const char* subsystem;
		const char* device;
	} backends[] = {
#if defined(WITH_IOSAUDIO)
		{ "ios", "" },
#endif
#if defined(WITH_OPENSLES)
		{ "opensles", "" },
#endif
#if defined(WITH_PULSE)
		{ "pulse", "" },
#endif
#if defined(WITH_ALSA)
		{ "alsa", "default" },
#endif
#if defined(WITH_OSS)
		{ "oss", "" },
#endif
#if defined(WITH_MACAUDIO)
		{ "mac", "default" },
#endif
#if defined(WITH_WINMM)
		{ "winmm", "" },
#endif
#if defined(WITH_SNDIO)
		{ "sndio", "" },
#endif
		{ "fake", "" }
	};
	const ADDIN_ARGV* args = NULL;
	UINT status = ERROR_INTERNAL_ERROR;
	WINPR_ASSERT(rdpsnd);
	rdpsnd->latency = 0;
	args = (const ADDIN_ARGV*)rdpsnd->channelEntryPoints.pExtendedData;

	if (args)
	{
		status = rdpsnd_process_addin_args(rdpsnd, args);

		if (status != CHANNEL_RC_OK)
			return status;
	}

	if (rdpsnd->subsystem)
	{
		if ((status = rdpsnd_load_device_plugin(rdpsnd, rdpsnd->subsystem, args)))
		{
			WLog_ERR(TAG,
			         "%s Unable to load sound playback subsystem %s because of error %" PRIu32 "",
			         rdpsnd_is_dyn_str(rdpsnd->dynamic), rdpsnd->subsystem, status);
			return status;
		}
	}
	else
	{
		for (size_t x = 0; x < ARRAYSIZE(backends); x++)
		{
			const char* subsystem_name = backends[x].subsystem;
			const char* device_name = backends[x].device;

			if ((status = rdpsnd_load_device_plugin(rdpsnd, subsystem_name, args)))
				WLog_ERR(TAG,
				         "%s Unable to load sound playback subsystem %s because of error %" PRIu32
				         "",
				         rdpsnd_is_dyn_str(rdpsnd->dynamic), subsystem_name, status);

			if (!rdpsnd->device)
				continue;

			if (!rdpsnd_set_subsystem(rdpsnd, subsystem_name) ||
			    !rdpsnd_set_device_name(rdpsnd, device_name))
				return CHANNEL_RC_NO_MEMORY;

			break;
		}

		if (!rdpsnd->device || status)
			return CHANNEL_RC_INITIALIZATION_ERROR;
	}

	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
UINT rdpsnd_virtual_channel_write(rdpsndPlugin* rdpsnd, wStream* s)
{
	UINT status = CHANNEL_RC_BAD_INIT_HANDLE;

	if (rdpsnd)
	{
		if (rdpsnd->dynamic)
		{
			IWTSVirtualChannel* channel = NULL;
			if (rdpsnd->listener_callback)
			{
				channel = rdpsnd->listener_callback->channel_callback->channel;
				status = channel->Write(channel, (UINT32)Stream_Length(s), Stream_Buffer(s), NULL);
			}
			Stream_Free(s, TRUE);
		}
		else
		{
			status = rdpsnd->channelEntryPoints.pVirtualChannelWriteEx(
			    rdpsnd->InitHandle, rdpsnd->OpenHandle, Stream_Buffer(s),
			    (UINT32)Stream_GetPosition(s), s);

			if (status != CHANNEL_RC_OK)
			{
				Stream_Free(s, TRUE);
				WLog_ERR(TAG, "%s pVirtualChannelWriteEx failed with %s [%08" PRIX32 "]",
				         rdpsnd_is_dyn_str(FALSE), WTSErrorToString(status), status);
			}
		}
	}

	return status;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_virtual_channel_event_data_received(rdpsndPlugin* plugin, void* pData,
                                                       UINT32 dataLength, UINT32 totalLength,
                                                       UINT32 dataFlags)
{
	if ((dataFlags & CHANNEL_FLAG_SUSPEND) || (dataFlags & CHANNEL_FLAG_RESUME))
		return CHANNEL_RC_OK;

	if (dataFlags & CHANNEL_FLAG_FIRST)
	{
		if (!plugin->data_in)
			plugin->data_in = StreamPool_Take(plugin->pool, totalLength);

		Stream_SetPosition(plugin->data_in, 0);
	}

	if (!Stream_EnsureRemainingCapacity(plugin->data_in, dataLength))
		return CHANNEL_RC_NO_MEMORY;

	Stream_Write(plugin->data_in, pData, dataLength);

	if (dataFlags & CHANNEL_FLAG_LAST)
	{
		Stream_SealLength(plugin->data_in);
		Stream_SetPosition(plugin->data_in, 0);

		if (plugin->async)
		{
			if (!MessageQueue_Post(plugin->queue, NULL, 0, plugin->data_in, NULL))
				return ERROR_INTERNAL_ERROR;
			plugin->data_in = NULL;
		}
		else
		{
			UINT error = rdpsnd_recv_pdu(plugin, plugin->data_in);
			plugin->data_in = NULL;
			if (error)
				return error;
		}
	}

	return CHANNEL_RC_OK;
}

static VOID VCAPITYPE rdpsnd_virtual_channel_open_event_ex(LPVOID lpUserParam, DWORD openHandle,
                                                           UINT event, LPVOID pData,
                                                           UINT32 dataLength, UINT32 totalLength,
                                                           UINT32 dataFlags)
{
	UINT error = CHANNEL_RC_OK;
	rdpsndPlugin* rdpsnd = (rdpsndPlugin*)lpUserParam;
	WINPR_ASSERT(rdpsnd);
	WINPR_ASSERT(!rdpsnd->dynamic);

	switch (event)
	{
		case CHANNEL_EVENT_DATA_RECEIVED:
			if (!rdpsnd)
				return;

			if (rdpsnd->OpenHandle != openHandle)
			{
				WLog_ERR(TAG, "%s error no match", rdpsnd_is_dyn_str(rdpsnd->dynamic));
				return;
			}
			if ((error = rdpsnd_virtual_channel_event_data_received(rdpsnd, pData, dataLength,
			                                                        totalLength, dataFlags)))
				WLog_ERR(TAG,
				         "%s rdpsnd_virtual_channel_event_data_received failed with error %" PRIu32
				         "",
				         rdpsnd_is_dyn_str(rdpsnd->dynamic), error);

			break;

		case CHANNEL_EVENT_WRITE_CANCELLED:
		case CHANNEL_EVENT_WRITE_COMPLETE:
		{
			wStream* s = (wStream*)pData;
			Stream_Free(s, TRUE);
		}
		break;

		case CHANNEL_EVENT_USER:
			break;
		default:
			break;
	}

	if (error && rdpsnd && rdpsnd->rdpcontext)
	{
		char buffer[8192];
		(void)_snprintf(buffer, sizeof(buffer),
		                "%s rdpsnd_virtual_channel_open_event_ex reported an error",
		                rdpsnd_is_dyn_str(rdpsnd->dynamic));
		setChannelError(rdpsnd->rdpcontext, error, buffer);
	}
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_virtual_channel_event_connected(rdpsndPlugin* rdpsnd, LPVOID pData,
                                                   UINT32 dataLength)
{
	UINT32 status = 0;
	DWORD opened = 0;
	WINPR_UNUSED(pData);
	WINPR_UNUSED(dataLength);

	WINPR_ASSERT(rdpsnd);
	WINPR_ASSERT(!rdpsnd->dynamic);

	status = rdpsnd->channelEntryPoints.pVirtualChannelOpenEx(
	    rdpsnd->InitHandle, &opened, rdpsnd->channelDef.name, rdpsnd_virtual_channel_open_event_ex);

	if (status != CHANNEL_RC_OK)
	{
		WLog_ERR(TAG, "%s pVirtualChannelOpenEx failed with %s [%08" PRIX32 "]",
		         rdpsnd_is_dyn_str(rdpsnd->dynamic), WTSErrorToString(status), status);
		goto fail;
	}

	if (rdpsnd_process_connect(rdpsnd) != CHANNEL_RC_OK)
		goto fail;

	rdpsnd->OpenHandle = opened;
	return CHANNEL_RC_OK;
fail:
	if (opened != 0)
		rdpsnd->channelEntryPoints.pVirtualChannelCloseEx(rdpsnd->InitHandle, opened);
	return CHANNEL_RC_NO_MEMORY;
}

static void cleanup_internals(rdpsndPlugin* rdpsnd)
{
	if (!rdpsnd)
		return;

	if (rdpsnd->pool)
		StreamPool_Return(rdpsnd->pool, rdpsnd->data_in);

	audio_formats_free(rdpsnd->ClientFormats, rdpsnd->NumberOfClientFormats);
	audio_formats_free(rdpsnd->ServerFormats, rdpsnd->NumberOfServerFormats);

	rdpsnd->NumberOfClientFormats = 0;
	rdpsnd->ClientFormats = NULL;
	rdpsnd->NumberOfServerFormats = 0;
	rdpsnd->ServerFormats = NULL;

	rdpsnd->data_in = NULL;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_virtual_channel_event_disconnected(rdpsndPlugin* rdpsnd)
{
	UINT error = 0;

	WINPR_ASSERT(rdpsnd);
	WINPR_ASSERT(!rdpsnd->dynamic);
	if (rdpsnd->OpenHandle != 0)
	{
		DWORD opened = rdpsnd->OpenHandle;
		rdpsnd->OpenHandle = 0;
		if (rdpsnd->device)
			IFCALL(rdpsnd->device->Close, rdpsnd->device);

		error = rdpsnd->channelEntryPoints.pVirtualChannelCloseEx(rdpsnd->InitHandle, opened);

		if (CHANNEL_RC_OK != error)
		{
			WLog_ERR(TAG, "%s pVirtualChannelCloseEx failed with %s [%08" PRIX32 "]",
			         rdpsnd_is_dyn_str(rdpsnd->dynamic), WTSErrorToString(error), error);
			return error;
		}
	}

	cleanup_internals(rdpsnd);

	if (rdpsnd->device)
	{
		IFCALL(rdpsnd->device->Free, rdpsnd->device);
		rdpsnd->device = NULL;
	}

	return CHANNEL_RC_OK;
}

static void queue_free(void* obj)
{
	wMessage* msg = obj;
	if (!msg)
		return;
	if (msg->id != 0)
		return;
	wStream* s = msg->wParam;
	Stream_Release(s);
}

static void free_internals(rdpsndPlugin* rdpsnd)
{
	if (!rdpsnd)
		return;

	if (rdpsnd->references > 0)
		rdpsnd->references--;

	if (rdpsnd->references > 0)
		return;

	freerdp_dsp_context_free(rdpsnd->dsp_context);
	StreamPool_Free(rdpsnd->pool);
	rdpsnd->pool = NULL;
	rdpsnd->dsp_context = NULL;
}

static BOOL allocate_internals(rdpsndPlugin* rdpsnd)
{
	WINPR_ASSERT(rdpsnd);

	if (!rdpsnd->pool)
	{
		rdpsnd->pool = StreamPool_New(TRUE, 4096);
		if (!rdpsnd->pool)
			return FALSE;
	}

	if (!rdpsnd->dsp_context)
	{
		rdpsnd->dsp_context = freerdp_dsp_context_new(FALSE);
		if (!rdpsnd->dsp_context)
			return FALSE;
	}
	rdpsnd->references++;

	return TRUE;
}

static DWORD WINAPI play_thread(LPVOID arg)
{
	UINT error = CHANNEL_RC_OK;
	rdpsndPlugin* rdpsnd = arg;

	if (!rdpsnd || !rdpsnd->queue)
		return ERROR_INVALID_PARAMETER;

	while (TRUE)
	{
		int rc = -1;
		wMessage message = { 0 };
		wStream* s = NULL;
		DWORD status = 0;
		DWORD nCount = 0;
		HANDLE handles[MAXIMUM_WAIT_OBJECTS] = { 0 };

		handles[nCount++] = MessageQueue_Event(rdpsnd->queue);
		handles[nCount++] = freerdp_abort_event(rdpsnd->rdpcontext);
		status = WaitForMultipleObjects(nCount, handles, FALSE, INFINITE);
		switch (status)
		{
			case WAIT_OBJECT_0:
				break;
			default:
				return ERROR_TIMEOUT;
		}

		rc = MessageQueue_Peek(rdpsnd->queue, &message, TRUE);
		if (rc < 1)
			continue;

		if (message.id == WMQ_QUIT)
			break;

		s = message.wParam;
		error = rdpsnd_recv_pdu(rdpsnd, s);

		if (error)
			return error;
	}

	return CHANNEL_RC_OK;
}

static UINT rdpsnd_virtual_channel_event_initialized(rdpsndPlugin* rdpsnd)
{
	if (!rdpsnd)
		return ERROR_INVALID_PARAMETER;

	if (rdpsnd->async)
	{
		wObject obj = { 0 };

		obj.fnObjectFree = queue_free;
		rdpsnd->queue = MessageQueue_New(&obj);
		if (!rdpsnd->queue)
			return CHANNEL_RC_NO_MEMORY;

		rdpsnd->thread = CreateThread(NULL, 0, play_thread, rdpsnd, 0, NULL);
		if (!rdpsnd->thread)
			return CHANNEL_RC_INITIALIZATION_ERROR;
	}

	if (!allocate_internals(rdpsnd))
		return CHANNEL_RC_NO_MEMORY;

	return CHANNEL_RC_OK;
}

void rdpsnd_virtual_channel_event_terminated(rdpsndPlugin* rdpsnd)
{
	if (rdpsnd)
	{
		if (rdpsnd->queue)
			MessageQueue_PostQuit(rdpsnd->queue, 0);

		if (rdpsnd->thread)
		{
			(void)WaitForSingleObject(rdpsnd->thread, INFINITE);
			(void)CloseHandle(rdpsnd->thread);
		}
		MessageQueue_Free(rdpsnd->queue);

		free_internals(rdpsnd);
		audio_formats_free(rdpsnd->fixed_format, 1);
		free(rdpsnd->subsystem);
		free(rdpsnd->device_name);
		rdpsnd->InitHandle = 0;
	}

	free(rdpsnd);
}

static VOID VCAPITYPE rdpsnd_virtual_channel_init_event_ex(LPVOID lpUserParam, LPVOID pInitHandle,
                                                           UINT event, LPVOID pData,
                                                           UINT dataLength)
{
	UINT error = CHANNEL_RC_OK;
	rdpsndPlugin* plugin = (rdpsndPlugin*)lpUserParam;

	if (!plugin)
		return;

	if (plugin->InitHandle != pInitHandle)
	{
		WLog_ERR(TAG, "%s error no match", rdpsnd_is_dyn_str(plugin->dynamic));
		return;
	}

	switch (event)
	{
		case CHANNEL_EVENT_INITIALIZED:
			error = rdpsnd_virtual_channel_event_initialized(plugin);
			break;

		case CHANNEL_EVENT_CONNECTED:
			error = rdpsnd_virtual_channel_event_connected(plugin, pData, dataLength);
			break;

		case CHANNEL_EVENT_DISCONNECTED:
			error = rdpsnd_virtual_channel_event_disconnected(plugin);
			break;

		case CHANNEL_EVENT_TERMINATED:
			rdpsnd_virtual_channel_event_terminated(plugin);
			plugin = NULL;
			break;

		case CHANNEL_EVENT_ATTACHED:
			plugin->attached = TRUE;
			break;

		case CHANNEL_EVENT_DETACHED:
			plugin->attached = FALSE;
			break;

		default:
			break;
	}

	if (error && plugin && plugin->rdpcontext)
	{
		char buffer[8192];
		(void)_snprintf(buffer, sizeof(buffer), "%s reported an error",
		                rdpsnd_is_dyn_str(plugin->dynamic));
		setChannelError(plugin->rdpcontext, error, buffer);
	}
}

rdpContext* freerdp_rdpsnd_get_context(rdpsndPlugin* plugin)
{
	if (!plugin)
		return NULL;

	return plugin->rdpcontext;
}

static rdpsndPlugin* allocatePlugin(void)
{
	rdpsndPlugin* rdpsnd = (rdpsndPlugin*)calloc(1, sizeof(rdpsndPlugin));
	if (!rdpsnd)
		goto fail;

	rdpsnd->fixed_format = audio_format_new();
	if (!rdpsnd->fixed_format)
		goto fail;
	rdpsnd->log = WLog_Get("com.freerdp.channels.rdpsnd.client");
	if (!rdpsnd->log)
		goto fail;

	rdpsnd->attached = TRUE;
	return rdpsnd;

fail:
	if (rdpsnd)
		audio_formats_free(rdpsnd->fixed_format, 1);
	free(rdpsnd);
	return NULL;
}
/* rdpsnd is always built-in */
FREERDP_ENTRY_POINT(BOOL VCAPITYPE rdpsnd_VirtualChannelEntryEx(PCHANNEL_ENTRY_POINTS pEntryPoints,
                                                                PVOID pInitHandle))
{
	UINT rc = 0;
	rdpsndPlugin* rdpsnd = NULL;
	CHANNEL_ENTRY_POINTS_FREERDP_EX* pEntryPointsEx = NULL;

	if (!pEntryPoints)
		return FALSE;

	rdpsnd = allocatePlugin();

	if (!rdpsnd)
		return FALSE;

	rdpsnd->channelDef.options = CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_ENCRYPT_RDP;
	(void)sprintf_s(rdpsnd->channelDef.name, ARRAYSIZE(rdpsnd->channelDef.name),
	                RDPSND_CHANNEL_NAME);
	pEntryPointsEx = (CHANNEL_ENTRY_POINTS_FREERDP_EX*)pEntryPoints;

	if ((pEntryPointsEx->cbSize >= sizeof(CHANNEL_ENTRY_POINTS_FREERDP_EX)) &&
	    (pEntryPointsEx->MagicNumber == FREERDP_CHANNEL_MAGIC_NUMBER))
	{
		rdpsnd->rdpcontext = pEntryPointsEx->context;
		if (!freerdp_settings_get_bool(rdpsnd->rdpcontext->settings,
		                               FreeRDP_SynchronousStaticChannels))
			rdpsnd->async = TRUE;
	}

	CopyMemory(&(rdpsnd->channelEntryPoints), pEntryPoints,
	           sizeof(CHANNEL_ENTRY_POINTS_FREERDP_EX));
	rdpsnd->InitHandle = pInitHandle;

	WINPR_ASSERT(rdpsnd->channelEntryPoints.pVirtualChannelInitEx);
	rc = rdpsnd->channelEntryPoints.pVirtualChannelInitEx(
	    rdpsnd, NULL, pInitHandle, &rdpsnd->channelDef, 1, VIRTUAL_CHANNEL_VERSION_WIN2000,
	    rdpsnd_virtual_channel_init_event_ex);

	if (CHANNEL_RC_OK != rc)
	{
		WLog_ERR(TAG, "%s pVirtualChannelInitEx failed with %s [%08" PRIX32 "]",
		         rdpsnd_is_dyn_str(FALSE), WTSErrorToString(rc), rc);
		rdpsnd_virtual_channel_event_terminated(rdpsnd);
		return FALSE;
	}

	return TRUE;
}

static UINT rdpsnd_on_open(IWTSVirtualChannelCallback* pChannelCallback)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)pChannelCallback;
	rdpsndPlugin* rdpsnd = NULL;

	WINPR_ASSERT(callback);

	rdpsnd = (rdpsndPlugin*)callback->plugin;
	WINPR_ASSERT(rdpsnd);

	if (rdpsnd->OnOpenCalled)
		return CHANNEL_RC_OK;
	rdpsnd->OnOpenCalled = TRUE;

	if (!allocate_internals(rdpsnd))
		return ERROR_OUTOFMEMORY;

	return rdpsnd_process_connect(rdpsnd);
}

static UINT rdpsnd_on_data_received(IWTSVirtualChannelCallback* pChannelCallback, wStream* data)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)pChannelCallback;
	rdpsndPlugin* plugin = NULL;
	wStream* copy = NULL;
	size_t len = 0;

	len = Stream_GetRemainingLength(data);

	if (!callback || !callback->plugin)
		return ERROR_INVALID_PARAMETER;
	plugin = (rdpsndPlugin*)callback->plugin;
	WINPR_ASSERT(plugin);

	copy = StreamPool_Take(plugin->pool, len);
	if (!copy)
		return ERROR_OUTOFMEMORY;
	Stream_Copy(data, copy, len);
	Stream_SealLength(copy);
	Stream_SetPosition(copy, 0);

	if (plugin->async)
	{
		if (!MessageQueue_Post(plugin->queue, NULL, 0, copy, NULL))
		{
			Stream_Release(copy);
			return ERROR_INTERNAL_ERROR;
		}
	}
	else
	{
		UINT error = rdpsnd_recv_pdu(plugin, copy);
		if (error)
			return error;
	}

	return CHANNEL_RC_OK;
}

static UINT rdpsnd_on_close(IWTSVirtualChannelCallback* pChannelCallback)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)pChannelCallback;
	rdpsndPlugin* rdpsnd = NULL;

	WINPR_ASSERT(callback);

	rdpsnd = (rdpsndPlugin*)callback->plugin;
	WINPR_ASSERT(rdpsnd);

	rdpsnd->OnOpenCalled = FALSE;
	if (rdpsnd->device)
		IFCALL(rdpsnd->device->Close, rdpsnd->device);

	cleanup_internals(rdpsnd);

	if (rdpsnd->device)
	{
		IFCALL(rdpsnd->device->Free, rdpsnd->device);
		rdpsnd->device = NULL;
	}

	free_internals(rdpsnd);
	free(pChannelCallback);
	return CHANNEL_RC_OK;
}

// NOLINTBEGIN(readability-non-const-parameter)
static UINT rdpsnd_on_new_channel_connection(IWTSListenerCallback* pListenerCallback,
                                             IWTSVirtualChannel* pChannel, BYTE* Data,
                                             BOOL* pbAccept,
                                             IWTSVirtualChannelCallback** ppCallback)
// NOLINTEND(readability-non-const-parameter)
{
	GENERIC_CHANNEL_CALLBACK* callback = NULL;
	GENERIC_LISTENER_CALLBACK* listener_callback = (GENERIC_LISTENER_CALLBACK*)pListenerCallback;
	WINPR_ASSERT(listener_callback);
	WINPR_ASSERT(pChannel);
	WINPR_ASSERT(ppCallback);
	callback = (GENERIC_CHANNEL_CALLBACK*)calloc(1, sizeof(GENERIC_CHANNEL_CALLBACK));

	WINPR_UNUSED(Data);
	WINPR_UNUSED(pbAccept);

	if (!callback)
	{
		WLog_ERR(TAG, "%s calloc failed!", rdpsnd_is_dyn_str(TRUE));
		return CHANNEL_RC_NO_MEMORY;
	}

	callback->iface.OnOpen = rdpsnd_on_open;
	callback->iface.OnDataReceived = rdpsnd_on_data_received;
	callback->iface.OnClose = rdpsnd_on_close;
	callback->plugin = listener_callback->plugin;
	callback->channel_mgr = listener_callback->channel_mgr;
	callback->channel = pChannel;
	listener_callback->channel_callback = callback;
	*ppCallback = &callback->iface;
	return CHANNEL_RC_OK;
}

static UINT rdpsnd_plugin_initialize(IWTSPlugin* pPlugin, IWTSVirtualChannelManager* pChannelMgr)
{
	UINT status = 0;
	rdpsndPlugin* rdpsnd = (rdpsndPlugin*)pPlugin;
	WINPR_ASSERT(rdpsnd);
	WINPR_ASSERT(pChannelMgr);
	if (rdpsnd->initialized)
	{
		WLog_ERR(TAG, "[%s] channel initialized twice, aborting", RDPSND_DVC_CHANNEL_NAME);
		return ERROR_INVALID_DATA;
	}
	rdpsnd->listener_callback =
	    (GENERIC_LISTENER_CALLBACK*)calloc(1, sizeof(GENERIC_LISTENER_CALLBACK));

	if (!rdpsnd->listener_callback)
	{
		WLog_ERR(TAG, "%s calloc failed!", rdpsnd_is_dyn_str(TRUE));
		return CHANNEL_RC_NO_MEMORY;
	}

	rdpsnd->listener_callback->iface.OnNewChannelConnection = rdpsnd_on_new_channel_connection;
	rdpsnd->listener_callback->plugin = pPlugin;
	rdpsnd->listener_callback->channel_mgr = pChannelMgr;
	status = pChannelMgr->CreateListener(pChannelMgr, RDPSND_DVC_CHANNEL_NAME, 0,
	                                     &rdpsnd->listener_callback->iface, &(rdpsnd->listener));
	if (status != CHANNEL_RC_OK)
	{
		WLog_ERR(TAG, "%s CreateListener failed!", rdpsnd_is_dyn_str(TRUE));
		return status;
	}

	rdpsnd->listener->pInterface = rdpsnd->iface.pInterface;
	status = rdpsnd_virtual_channel_event_initialized(rdpsnd);

	rdpsnd->initialized = status == CHANNEL_RC_OK;
	return status;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpsnd_plugin_terminated(IWTSPlugin* pPlugin)
{
	rdpsndPlugin* rdpsnd = (rdpsndPlugin*)pPlugin;
	if (rdpsnd)
	{
		if (rdpsnd->listener_callback)
		{
			IWTSVirtualChannelManager* mgr = rdpsnd->listener_callback->channel_mgr;
			if (mgr)
				IFCALL(mgr->DestroyListener, mgr, rdpsnd->listener);
		}
		free(rdpsnd->listener_callback);
		free(rdpsnd->iface.pInterface);
	}
	rdpsnd_virtual_channel_event_terminated(rdpsnd);
	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
FREERDP_ENTRY_POINT(UINT VCAPITYPE rdpsnd_DVCPluginEntry(IDRDYNVC_ENTRY_POINTS* pEntryPoints))
{
	UINT error = CHANNEL_RC_OK;
	rdpsndPlugin* rdpsnd = NULL;

	WINPR_ASSERT(pEntryPoints);
	WINPR_ASSERT(pEntryPoints->GetPlugin);

	rdpsnd = (rdpsndPlugin*)pEntryPoints->GetPlugin(pEntryPoints, RDPSND_CHANNEL_NAME);

	if (!rdpsnd)
	{
		IWTSPlugin* iface = NULL;
		union
		{
			const void* cev;
			void* ev;
		} cnv;

		rdpsnd = allocatePlugin();
		if (!rdpsnd)
		{
			WLog_ERR(TAG, "%s calloc failed!", rdpsnd_is_dyn_str(TRUE));
			return CHANNEL_RC_NO_MEMORY;
		}

		iface = &rdpsnd->iface;
		iface->Initialize = rdpsnd_plugin_initialize;
		iface->Connected = NULL;
		iface->Disconnected = NULL;
		iface->Terminated = rdpsnd_plugin_terminated;

		rdpsnd->dynamic = TRUE;

		WINPR_ASSERT(pEntryPoints->GetRdpContext);
		rdpsnd->rdpcontext = pEntryPoints->GetRdpContext(pEntryPoints);

		if (!freerdp_settings_get_bool(rdpsnd->rdpcontext->settings,
		                               FreeRDP_SynchronousDynamicChannels))
			rdpsnd->async = TRUE;

		/* user data pointer is not const, cast to avoid warning. */
		cnv.cev = pEntryPoints->GetPluginData(pEntryPoints);
		WINPR_ASSERT(pEntryPoints->GetPluginData);
		rdpsnd->channelEntryPoints.pExtendedData = cnv.ev;

		error = pEntryPoints->RegisterPlugin(pEntryPoints, RDPSND_CHANNEL_NAME, iface);
	}
	else
	{
		WLog_ERR(TAG, "%s could not get rdpsnd Plugin.", rdpsnd_is_dyn_str(TRUE));
		return CHANNEL_RC_BAD_CHANNEL;
	}

	return error;
}
