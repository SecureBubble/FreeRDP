/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Progressive Codec Bitmap Compression
 *
 * Copyright 2014 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 * Copyright 2019 Armin Novak <armin.novak@thincast.com>
 * Copyright 2019 Thincast Technologies GmbH
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
#include <winpr/cast.h>
#include <winpr/crt.h>
#include <winpr/print.h>
#include <winpr/bitstream.h>

#include <freerdp/primitives.h>
#include <freerdp/codec/color.h>
#include <freerdp/codec/progressive.h>
#include <freerdp/codec/region.h>
#include <freerdp/log.h>

#include "rfx_differential.h"
#include "rfx_quantization.h"
#include "rfx_dwt.h"
#include "rfx_rlgr.h"
#include "rfx_constants.h"
#include "rfx_types.h"
#include "progressive.h"

#define TAG FREERDP_TAG("codec.progressive")

typedef struct
{
	BOOL nonLL;
	wBitStream* srl;
	wBitStream* raw;

	/* SRL state */

	UINT32 kp;
	int nz;
	BOOL mode;
} RFX_PROGRESSIVE_UPGRADE_STATE;

static INLINE void
progressive_component_codec_quant_read(wStream* WINPR_RESTRICT s,
                                       RFX_COMPONENT_CODEC_QUANT* WINPR_RESTRICT quantVal)
{
	BYTE b = 0;
	Stream_Read_UINT8(s, b);
	quantVal->LL3 = b & 0x0F;
	quantVal->HL3 = b >> 4;
	Stream_Read_UINT8(s, b);
	quantVal->LH3 = b & 0x0F;
	quantVal->HH3 = b >> 4;
	Stream_Read_UINT8(s, b);
	quantVal->HL2 = b & 0x0F;
	quantVal->LH2 = b >> 4;
	Stream_Read_UINT8(s, b);
	quantVal->HH2 = b & 0x0F;
	quantVal->HL1 = b >> 4;
	Stream_Read_UINT8(s, b);
	quantVal->LH1 = b & 0x0F;
	quantVal->HH1 = b >> 4;
}

static INLINE void progressive_rfx_quant_add(const RFX_COMPONENT_CODEC_QUANT* WINPR_RESTRICT q1,
                                             const RFX_COMPONENT_CODEC_QUANT* WINPR_RESTRICT q2,
                                             RFX_COMPONENT_CODEC_QUANT* dst)
{
	dst->HL1 = q1->HL1 + q2->HL1; /* HL1 */
	dst->LH1 = q1->LH1 + q2->LH1; /* LH1 */
	dst->HH1 = q1->HH1 + q2->HH1; /* HH1 */
	dst->HL2 = q1->HL2 + q2->HL2; /* HL2 */
	dst->LH2 = q1->LH2 + q2->LH2; /* LH2 */
	dst->HH2 = q1->HH2 + q2->HH2; /* HH2 */
	dst->HL3 = q1->HL3 + q2->HL3; /* HL3 */
	dst->LH3 = q1->LH3 + q2->LH3; /* LH3 */
	dst->HH3 = q1->HH3 + q2->HH3; /* HH3 */
	dst->LL3 = q1->LL3 + q2->LL3; /* LL3 */
}

static INLINE void progressive_rfx_quant_lsub(RFX_COMPONENT_CODEC_QUANT* WINPR_RESTRICT q, int val)
{
	q->HL1 -= val; /* HL1 */
	q->LH1 -= val; /* LH1 */
	q->HH1 -= val; /* HH1 */
	q->HL2 -= val; /* HL2 */
	q->LH2 -= val; /* LH2 */
	q->HH2 -= val; /* HH2 */
	q->HL3 -= val; /* HL3 */
	q->LH3 -= val; /* LH3 */
	q->HH3 -= val; /* HH3 */
	q->LL3 -= val; /* LL3 */
}

static INLINE void progressive_rfx_quant_sub(const RFX_COMPONENT_CODEC_QUANT* WINPR_RESTRICT q1,
                                             const RFX_COMPONENT_CODEC_QUANT* WINPR_RESTRICT q2,
                                             RFX_COMPONENT_CODEC_QUANT* dst)
{
	dst->HL1 = q1->HL1 - q2->HL1; /* HL1 */
	dst->LH1 = q1->LH1 - q2->LH1; /* LH1 */
	dst->HH1 = q1->HH1 - q2->HH1; /* HH1 */
	dst->HL2 = q1->HL2 - q2->HL2; /* HL2 */
	dst->LH2 = q1->LH2 - q2->LH2; /* LH2 */
	dst->HH2 = q1->HH2 - q2->HH2; /* HH2 */
	dst->HL3 = q1->HL3 - q2->HL3; /* HL3 */
	dst->LH3 = q1->LH3 - q2->LH3; /* LH3 */
	dst->HH3 = q1->HH3 - q2->HH3; /* HH3 */
	dst->LL3 = q1->LL3 - q2->LL3; /* LL3 */
}

static INLINE BOOL
progressive_rfx_quant_lcmp_less_equal(const RFX_COMPONENT_CODEC_QUANT* WINPR_RESTRICT q, int val)
{
	if (q->HL1 > val)
		return FALSE; /* HL1 */

	if (q->LH1 > val)
		return FALSE; /* LH1 */

	if (q->HH1 > val)
		return FALSE; /* HH1 */

	if (q->HL2 > val)
		return FALSE; /* HL2 */

	if (q->LH2 > val)
		return FALSE; /* LH2 */

	if (q->HH2 > val)
		return FALSE; /* HH2 */

	if (q->HL3 > val)
		return FALSE; /* HL3 */

	if (q->LH3 > val)
		return FALSE; /* LH3 */

	if (q->HH3 > val)
		return FALSE; /* HH3 */

	if (q->LL3 > val)
		return FALSE; /* LL3 */

	return TRUE;
}

static INLINE BOOL
progressive_rfx_quant_lcmp_greater_equal(const RFX_COMPONENT_CODEC_QUANT* WINPR_RESTRICT q, int val)
{
	if (q->HL1 < val)
		return FALSE; /* HL1 */

	if (q->LH1 < val)
		return FALSE; /* LH1 */

	if (q->HH1 < val)
		return FALSE; /* HH1 */

	if (q->HL2 < val)
		return FALSE; /* HL2 */

	if (q->LH2 < val)
		return FALSE; /* LH2 */

	if (q->HH2 < val)
		return FALSE; /* HH2 */

	if (q->HL3 < val)
		return FALSE; /* HL3 */

	if (q->LH3 < val)
		return FALSE; /* LH3 */

	if (q->HH3 < val)
		return FALSE; /* HH3 */

	if (q->LL3 < val)
		return FALSE; /* LL3 */

	return TRUE;
}

static INLINE BOOL
progressive_rfx_quant_cmp_equal(const RFX_COMPONENT_CODEC_QUANT* WINPR_RESTRICT q1,
                                const RFX_COMPONENT_CODEC_QUANT* WINPR_RESTRICT q2)
{
	if (q1->HL1 != q2->HL1)
		return FALSE; /* HL1 */

	if (q1->LH1 != q2->LH1)
		return FALSE; /* LH1 */

	if (q1->HH1 != q2->HH1)
		return FALSE; /* HH1 */

	if (q1->HL2 != q2->HL2)
		return FALSE; /* HL2 */

	if (q1->LH2 != q2->LH2)
		return FALSE; /* LH2 */

	if (q1->HH2 != q2->HH2)
		return FALSE; /* HH2 */

	if (q1->HL3 != q2->HL3)
		return FALSE; /* HL3 */

	if (q1->LH3 != q2->LH3)
		return FALSE; /* LH3 */

	if (q1->HH3 != q2->HH3)
		return FALSE; /* HH3 */

	if (q1->LL3 != q2->LL3)
		return FALSE; /* LL3 */

	return TRUE;
}

static INLINE BOOL progressive_set_surface_data(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                                                UINT16 surfaceId,
                                                PROGRESSIVE_SURFACE_CONTEXT* WINPR_RESTRICT pData)
{
	ULONG_PTR key = 0;
	key = ((ULONG_PTR)surfaceId) + 1;

	if (pData)
		return HashTable_Insert(progressive->SurfaceContexts, (void*)key, pData);

	HashTable_Remove(progressive->SurfaceContexts, (void*)key);
	return TRUE;
}

static INLINE PROGRESSIVE_SURFACE_CONTEXT*
progressive_get_surface_data(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive, UINT16 surfaceId)
{
	void* key = (void*)(((ULONG_PTR)surfaceId) + 1);

	if (!progressive)
		return NULL;

	return HashTable_GetItemValue(progressive->SurfaceContexts, key);
}

static void progressive_tile_free(RFX_PROGRESSIVE_TILE* WINPR_RESTRICT tile)
{
	if (tile)
	{
		winpr_aligned_free(tile->sign);
		winpr_aligned_free(tile->current);
		winpr_aligned_free(tile->data);
		winpr_aligned_free(tile);
	}
}

static void progressive_surface_context_free(void* ptr)
{
	PROGRESSIVE_SURFACE_CONTEXT* surface = ptr;

	if (!surface)
		return;

	if (surface->tiles)
	{
		for (size_t index = 0; index < surface->tilesSize; index++)
		{
			RFX_PROGRESSIVE_TILE* tile = surface->tiles[index];
			progressive_tile_free(tile);
		}
	}

	winpr_aligned_free((void*)surface->tiles);
	winpr_aligned_free(surface->updatedTileIndices);
	winpr_aligned_free(surface);
}

static INLINE RFX_PROGRESSIVE_TILE* progressive_tile_new(void)
{
	RFX_PROGRESSIVE_TILE* tile = winpr_aligned_calloc(1, sizeof(RFX_PROGRESSIVE_TILE), 32);
	if (!tile)
		goto fail;

	tile->width = 64;
	tile->height = 64;
	tile->stride = 4 * tile->width;

	size_t dataLen = 1ull * tile->stride * tile->height;
	tile->data = (BYTE*)winpr_aligned_malloc(dataLen, 16);
	if (!tile->data)
		goto fail;
	memset(tile->data, 0xFF, dataLen);

	size_t signLen = (8192ULL + 32ULL) * 3ULL;
	tile->sign = (BYTE*)winpr_aligned_malloc(signLen, 16);
	if (!tile->sign)
		goto fail;

	size_t currentLen = (8192ULL + 32ULL) * 3ULL;
	tile->current = (BYTE*)winpr_aligned_malloc(currentLen, 16);
	if (!tile->current)
		goto fail;

	return tile;

fail:
	progressive_tile_free(tile);
	return NULL;
}

static INLINE BOOL
progressive_allocate_tile_cache(PROGRESSIVE_SURFACE_CONTEXT* WINPR_RESTRICT surface, size_t min)
{
	size_t oldIndex = 0;

	WINPR_ASSERT(surface);
	WINPR_ASSERT(surface->gridSize > 0);

	if (surface->tiles)
	{
		oldIndex = surface->gridSize;
		while (surface->gridSize < min)
			surface->gridSize += 1024;
	}

	void* tmp = winpr_aligned_recalloc((void*)surface->tiles, surface->gridSize,
	                                   sizeof(RFX_PROGRESSIVE_TILE*), 32);
	if (!tmp)
		return FALSE;
	surface->tilesSize = surface->gridSize;
	surface->tiles = (RFX_PROGRESSIVE_TILE**)tmp;

	for (size_t x = oldIndex; x < surface->tilesSize; x++)
	{
		surface->tiles[x] = progressive_tile_new();
		if (!surface->tiles[x])
			return FALSE;
	}

	tmp =
	    winpr_aligned_recalloc(surface->updatedTileIndices, surface->gridSize, sizeof(UINT32), 32);
	if (!tmp)
		return FALSE;

	surface->updatedTileIndices = tmp;

	return TRUE;
}

static PROGRESSIVE_SURFACE_CONTEXT* progressive_surface_context_new(UINT16 surfaceId, UINT32 width,
                                                                    UINT32 height)
{
	PROGRESSIVE_SURFACE_CONTEXT* surface = (PROGRESSIVE_SURFACE_CONTEXT*)winpr_aligned_calloc(
	    1, sizeof(PROGRESSIVE_SURFACE_CONTEXT), 32);

	if (!surface)
		return NULL;

	surface->id = surfaceId;
	surface->width = width;
	surface->height = height;
	surface->gridWidth = (width + (64 - width % 64)) / 64;
	surface->gridHeight = (height + (64 - height % 64)) / 64;
	surface->gridSize = surface->gridWidth * surface->gridHeight;

	if (!progressive_allocate_tile_cache(surface, surface->gridSize))
	{
		progressive_surface_context_free(surface);
		return NULL;
	}

	return surface;
}

static INLINE BOOL
progressive_surface_tile_replace(PROGRESSIVE_SURFACE_CONTEXT* WINPR_RESTRICT surface,
                                 PROGRESSIVE_BLOCK_REGION* WINPR_RESTRICT region,
                                 const RFX_PROGRESSIVE_TILE* WINPR_RESTRICT tile, BOOL upgrade)
{
	RFX_PROGRESSIVE_TILE* t = NULL;

	size_t zIdx = 0;
	if (!surface || !tile)
		return FALSE;

	zIdx = (tile->yIdx * surface->gridWidth) + tile->xIdx;

	if (zIdx >= surface->tilesSize)
	{
		WLog_ERR(TAG, "Invalid zIndex %" PRIuz, zIdx);
		return FALSE;
	}

	t = surface->tiles[zIdx];

	t->blockType = tile->blockType;
	t->blockLen = tile->blockLen;
	t->quantIdxY = tile->quantIdxY;
	t->quantIdxCb = tile->quantIdxCb;
	t->quantIdxCr = tile->quantIdxCr;
	t->xIdx = tile->xIdx;
	t->yIdx = tile->yIdx;
	t->flags = tile->flags;
	t->quality = tile->quality;
	t->x = tile->xIdx * t->width;
	t->y = tile->yIdx * t->height;

	if (upgrade)
	{
		t->ySrlLen = tile->ySrlLen;
		t->yRawLen = tile->yRawLen;
		t->cbSrlLen = tile->cbSrlLen;
		t->cbRawLen = tile->cbRawLen;
		t->crSrlLen = tile->crSrlLen;
		t->crRawLen = tile->crRawLen;
		t->ySrlData = tile->ySrlData;
		t->yRawData = tile->yRawData;
		t->cbSrlData = tile->cbSrlData;
		t->cbRawData = tile->cbRawData;
		t->crSrlData = tile->crSrlData;
		t->crRawData = tile->crRawData;
	}
	else
	{
		t->yLen = tile->yLen;
		t->cbLen = tile->cbLen;
		t->crLen = tile->crLen;
		t->tailLen = tile->tailLen;
		t->yData = tile->yData;
		t->cbData = tile->cbData;
		t->crData = tile->crData;
		t->tailData = tile->tailData;
	}

	if (region->usedTiles >= region->numTiles)
	{
		WLog_ERR(TAG, "Invalid tile count, only expected %" PRIu16 ", got %" PRIu16,
		         region->numTiles, region->usedTiles);
		return FALSE;
	}

	region->tiles[region->usedTiles++] = t;
	if (!t->dirty)
	{
		if (surface->numUpdatedTiles >= surface->gridSize)
		{
			if (!progressive_allocate_tile_cache(surface, surface->numUpdatedTiles + 1))
				return FALSE;
		}

		surface->updatedTileIndices[surface->numUpdatedTiles++] = (UINT32)zIdx;
	}

	t->dirty = TRUE;
	return TRUE;
}

INT32 progressive_create_surface_context(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                                         UINT16 surfaceId, UINT32 width, UINT32 height)
{
	PROGRESSIVE_SURFACE_CONTEXT* surface = progressive_get_surface_data(progressive, surfaceId);

	if (!surface)
	{
		surface = progressive_surface_context_new(surfaceId, width, height);

		if (!surface)
			return -1;

		if (!progressive_set_surface_data(progressive, surfaceId, (void*)surface))
		{
			progressive_surface_context_free(surface);
			return -1;
		}
	}

	return 1;
}

int progressive_delete_surface_context(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                                       UINT16 surfaceId)
{
	progressive_set_surface_data(progressive, surfaceId, NULL);

	return 1;
}

/*
 * Band	    Offset      Dimensions  Size
 *
 * HL1      0           31x33       1023
 * LH1      1023        33x31       1023
 * HH1      2046        31x31       961
 *
 * HL2      3007        16x17       272
 * LH2      3279        17x16       272
 * HH2      3551        16x16       256
 *
 * HL3      3807        8x9         72
 * LH3      3879        9x8         72
 * HH3      3951        8x8         64
 *
 * LL3      4015        9x9         81
 */

static int16_t clampi16(int val)
{
	if (val < INT16_MIN)
		return INT16_MIN;
	if (val > INT16_MAX)
		return INT16_MAX;
	return (int16_t)val;
}

static INLINE void progressive_rfx_idwt_x(const INT16* WINPR_RESTRICT pLowBand, size_t nLowStep,
                                          const INT16* WINPR_RESTRICT pHighBand, size_t nHighStep,
                                          INT16* WINPR_RESTRICT pDstBand, size_t nDstStep,
                                          size_t nLowCount, size_t nHighCount, size_t nDstCount)
{
	INT16 H1 = 0;
	INT16 X1 = 0;

	for (size_t i = 0; i < nDstCount; i++)
	{
		const INT16* pL = pLowBand;
		const INT16* pH = pHighBand;
		INT16* pX = pDstBand;
		INT16 H0 = *pH++;
		INT16 L0 = *pL++;
		INT16 X0 = clampi16((int32_t)L0 - H0);
		INT16 X2 = clampi16((int32_t)L0 - H0);

		for (size_t j = 0; j < (nHighCount - 1); j++)
		{
			H1 = *pH;
			pH++;
			L0 = *pL;
			pL++;
			X2 = clampi16((int32_t)L0 - ((H0 + H1) / 2));
			X1 = clampi16((int32_t)((X0 + X2) / 2) + (2 * H0));
			pX[0] = X0;
			pX[1] = X1;
			pX += 2;
			X0 = X2;
			H0 = H1;
		}

		if (nLowCount <= (nHighCount + 1))
		{
			if (nLowCount <= nHighCount)
			{
				pX[0] = X2;
				pX[1] = clampi16((int32_t)X2 + (2 * H0));
			}
			else
			{
				L0 = *pL;
				pL++;
				X0 = clampi16((int32_t)L0 - H0);
				pX[0] = X2;
				pX[1] = clampi16((int32_t)((X0 + X2) / 2) + (2 * H0));
				pX[2] = X0;
			}
		}
		else
		{
			L0 = *pL;
			pL++;
			X0 = clampi16((int32_t)L0 - (H0 / 2));
			pX[0] = X2;
			pX[1] = clampi16((int32_t)((X0 + X2) / 2) + (2 * H0));
			pX[2] = X0;
			L0 = *pL;
			pL++;
			pX[3] = clampi16((int32_t)(X0 + L0) / 2);
		}

		pLowBand += nLowStep;
		pHighBand += nHighStep;
		pDstBand += nDstStep;
	}
}

static INLINE void progressive_rfx_idwt_y(const INT16* WINPR_RESTRICT pLowBand, size_t nLowStep,
                                          const INT16* WINPR_RESTRICT pHighBand, size_t nHighStep,
                                          INT16* WINPR_RESTRICT pDstBand, size_t nDstStep,
                                          size_t nLowCount, size_t nHighCount, size_t nDstCount)
{
	for (size_t i = 0; i < nDstCount; i++)
	{
		INT16 H1 = 0;
		INT16 X1 = 0;
		const INT16* pL = pLowBand;
		const INT16* pH = pHighBand;
		INT16* pX = pDstBand;
		INT16 H0 = *pH;
		pH += nHighStep;
		INT16 L0 = *pL;
		pL += nLowStep;
		int16_t X0 = clampi16((int32_t)L0 - H0);
		int16_t X2 = clampi16((int32_t)L0 - H0);

		for (size_t j = 0; j < (nHighCount - 1); j++)
		{
			H1 = *pH;
			pH += nHighStep;
			L0 = *pL;
			pL += nLowStep;
			X2 = clampi16((int32_t)L0 - ((H0 + H1) / 2));
			X1 = clampi16((int32_t)((X0 + X2) / 2) + (2 * H0));
			*pX = X0;
			pX += nDstStep;
			*pX = X1;
			pX += nDstStep;
			X0 = X2;
			H0 = H1;
		}

		if (nLowCount <= (nHighCount + 1))
		{
			if (nLowCount <= nHighCount)
			{
				*pX = X2;
				pX += nDstStep;
				*pX = clampi16((int32_t)X2 + (2 * H0));
			}
			else
			{
				L0 = *pL;
				X0 = clampi16((int32_t)L0 - H0);
				*pX = X2;
				pX += nDstStep;
				*pX = clampi16((int32_t)((X0 + X2) / 2) + (2 * H0));
				pX += nDstStep;
				*pX = X0;
			}
		}
		else
		{
			L0 = *pL;
			pL += nLowStep;
			X0 = clampi16((int32_t)L0 - (H0 / 2));
			*pX = X2;
			pX += nDstStep;
			*pX = clampi16((int32_t)((X0 + X2) / 2) + (2 * H0));
			pX += nDstStep;
			*pX = X0;
			pX += nDstStep;
			L0 = *pL;
			*pX = clampi16((int32_t)(X0 + L0) / 2);
		}

		pLowBand++;
		pHighBand++;
		pDstBand++;
	}
}

static INLINE size_t progressive_rfx_get_band_l_count(size_t level)
{
	return (64 >> level) + 1;
}

static INLINE size_t progressive_rfx_get_band_h_count(size_t level)
{
	if (level == 1)
		return (64 >> 1) - 1;
	else
		return (64 + (1 << (level - 1))) >> level;
}

static INLINE void progressive_rfx_dwt_2d_decode_block(INT16* WINPR_RESTRICT buffer,
                                                       INT16* WINPR_RESTRICT temp, size_t level)
{
	size_t nDstStepX = 0;
	size_t nDstStepY = 0;
	const INT16* WINPR_RESTRICT HL = NULL;
	const INT16* WINPR_RESTRICT LH = NULL;
	const INT16* WINPR_RESTRICT HH = NULL;
	INT16* WINPR_RESTRICT LL = NULL;
	INT16* WINPR_RESTRICT L = NULL;
	INT16* WINPR_RESTRICT H = NULL;
	INT16* WINPR_RESTRICT LLx = NULL;

	const size_t nBandL = progressive_rfx_get_band_l_count(level);
	const size_t nBandH = progressive_rfx_get_band_h_count(level);
	size_t offset = 0;

	HL = &buffer[offset];
	offset += (nBandH * nBandL);
	LH = &buffer[offset];
	offset += (nBandL * nBandH);
	HH = &buffer[offset];
	offset += (nBandH * nBandH);
	LL = &buffer[offset];
	nDstStepX = (nBandL + nBandH);
	nDstStepY = (nBandL + nBandH);
	offset = 0;
	L = &temp[offset];
	offset += (nBandL * nDstStepX);
	H = &temp[offset];
	LLx = &buffer[0];

	/* horizontal (LL + HL -> L) */
	progressive_rfx_idwt_x(LL, nBandL, HL, nBandH, L, nDstStepX, nBandL, nBandH, nBandL);

	/* horizontal (LH + HH -> H) */
	progressive_rfx_idwt_x(LH, nBandL, HH, nBandH, H, nDstStepX, nBandL, nBandH, nBandH);

	/* vertical (L + H -> LL) */
	progressive_rfx_idwt_y(L, nDstStepX, H, nDstStepX, LLx, nDstStepY, nBandL, nBandH,
	                       nBandL + nBandH);
}

void rfx_dwt_2d_extrapolate_decode(INT16* WINPR_RESTRICT buffer, INT16* WINPR_RESTRICT temp)
{
	WINPR_ASSERT(buffer);
	WINPR_ASSERT(temp);
	progressive_rfx_dwt_2d_decode_block(&buffer[3807], temp, 3);
	progressive_rfx_dwt_2d_decode_block(&buffer[3007], temp, 2);
	progressive_rfx_dwt_2d_decode_block(&buffer[0], temp, 1);
}

static INLINE int progressive_rfx_dwt_2d_decode(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                                                INT16* WINPR_RESTRICT buffer,
                                                INT16* WINPR_RESTRICT current, BOOL coeffDiff,
                                                BOOL extrapolate, BOOL reverse)
{
	const primitives_t* prims = primitives_get();

	if (!progressive || !buffer || !current)
		return -1;

	const uint32_t belements = 4096;
	const uint32_t bsize = belements * sizeof(INT16);
	if (reverse)
		memcpy(buffer, current, bsize);
	else if (!coeffDiff)
		memcpy(current, buffer, bsize);
	else
		prims->add_16s_inplace(buffer, current, belements);

	INT16* temp = (INT16*)BufferPool_Take(progressive->bufferPool, -1); /* DWT buffer */

	if (!temp)
		return -2;

	if (!extrapolate)
	{
		progressive->rfx_context->dwt_2d_decode(buffer, temp);
	}
	else
	{
		WINPR_ASSERT(progressive->rfx_context->dwt_2d_extrapolate_decode);
		progressive->rfx_context->dwt_2d_extrapolate_decode(buffer, temp);
	}
	BufferPool_Return(progressive->bufferPool, temp);
	return 1;
}

static INLINE void progressive_rfx_decode_block(const primitives_t* prims,
                                                INT16* WINPR_RESTRICT buffer, UINT32 length,
                                                UINT32 shift)
{
	if (!shift)
		return;

	prims->lShiftC_16s_inplace(buffer, shift, length);
}

static INLINE int
progressive_rfx_decode_component(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                                 const RFX_COMPONENT_CODEC_QUANT* WINPR_RESTRICT shift,
                                 const BYTE* WINPR_RESTRICT data, UINT32 length,
                                 INT16* WINPR_RESTRICT buffer, INT16* WINPR_RESTRICT current,
                                 INT16* WINPR_RESTRICT sign, BOOL coeffDiff,
                                 WINPR_ATTR_UNUSED BOOL subbandDiff, BOOL extrapolate)
{
	int status = 0;
	const primitives_t* prims = primitives_get();

	status = progressive->rfx_context->rlgr_decode(RLGR1, data, length, buffer, 4096);

	if (status < 0)
		return status;

	CopyMemory(sign, buffer, 4096ULL * 2ULL);
	if (!extrapolate)
	{
		rfx_differential_decode(buffer + 4032, 64);
		progressive_rfx_decode_block(prims, &buffer[0], 1024, shift->HL1);    /* HL1 */
		progressive_rfx_decode_block(prims, &buffer[1024], 1024, shift->LH1); /* LH1 */
		progressive_rfx_decode_block(prims, &buffer[2048], 1024, shift->HH1); /* HH1 */
		progressive_rfx_decode_block(prims, &buffer[3072], 256, shift->HL2);  /* HL2 */
		progressive_rfx_decode_block(prims, &buffer[3328], 256, shift->LH2);  /* LH2 */
		progressive_rfx_decode_block(prims, &buffer[3584], 256, shift->HH2);  /* HH2 */
		progressive_rfx_decode_block(prims, &buffer[3840], 64, shift->HL3);   /* HL3 */
		progressive_rfx_decode_block(prims, &buffer[3904], 64, shift->LH3);   /* LH3 */
		progressive_rfx_decode_block(prims, &buffer[3968], 64, shift->HH3);   /* HH3 */
		progressive_rfx_decode_block(prims, &buffer[4032], 64, shift->LL3);   /* LL3 */
	}
	else
	{
		progressive_rfx_decode_block(prims, &buffer[0], 1023, shift->HL1);    /* HL1 */
		progressive_rfx_decode_block(prims, &buffer[1023], 1023, shift->LH1); /* LH1 */
		progressive_rfx_decode_block(prims, &buffer[2046], 961, shift->HH1);  /* HH1 */
		progressive_rfx_decode_block(prims, &buffer[3007], 272, shift->HL2);  /* HL2 */
		progressive_rfx_decode_block(prims, &buffer[3279], 272, shift->LH2);  /* LH2 */
		progressive_rfx_decode_block(prims, &buffer[3551], 256, shift->HH2);  /* HH2 */
		progressive_rfx_decode_block(prims, &buffer[3807], 72, shift->HL3);   /* HL3 */
		progressive_rfx_decode_block(prims, &buffer[3879], 72, shift->LH3);   /* LH3 */
		progressive_rfx_decode_block(prims, &buffer[3951], 64, shift->HH3);   /* HH3 */
		rfx_differential_decode(&buffer[4015], 81);                           /* LL3 */
		progressive_rfx_decode_block(prims, &buffer[4015], 81, shift->LL3);   /* LL3 */
	}
	return progressive_rfx_dwt_2d_decode(progressive, buffer, current, coeffDiff, extrapolate,
	                                     FALSE);
}

static INLINE int
progressive_decompress_tile_first(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                                  RFX_PROGRESSIVE_TILE* WINPR_RESTRICT tile,
                                  PROGRESSIVE_BLOCK_REGION* WINPR_RESTRICT region,
                                  const PROGRESSIVE_BLOCK_CONTEXT* WINPR_RESTRICT context)
{
	int rc = 0;
	BOOL diff = 0;
	BOOL sub = 0;
	BOOL extrapolate = 0;
	BYTE* pBuffer = NULL;
	INT16* pSign[3];
	INT16* pSrcDst[3];
	INT16* pCurrent[3];
	RFX_COMPONENT_CODEC_QUANT shiftY = { 0 };
	RFX_COMPONENT_CODEC_QUANT shiftCb = { 0 };
	RFX_COMPONENT_CODEC_QUANT shiftCr = { 0 };
	RFX_COMPONENT_CODEC_QUANT* quantY = NULL;
	RFX_COMPONENT_CODEC_QUANT* quantCb = NULL;
	RFX_COMPONENT_CODEC_QUANT* quantCr = NULL;
	RFX_COMPONENT_CODEC_QUANT* quantProgY = NULL;
	RFX_COMPONENT_CODEC_QUANT* quantProgCb = NULL;
	RFX_COMPONENT_CODEC_QUANT* quantProgCr = NULL;
	RFX_PROGRESSIVE_CODEC_QUANT* quantProgVal = NULL;
	static const prim_size_t roi_64x64 = { 64, 64 };
	const primitives_t* prims = primitives_get();

	tile->pass = 1;
	diff = tile->flags & RFX_TILE_DIFFERENCE;
	sub = context->flags & RFX_SUBBAND_DIFFING;
	extrapolate = region->flags & RFX_DWT_REDUCE_EXTRAPOLATE;

#if defined(WITH_DEBUG_CODECS)
	WLog_Print(progressive->log, WLOG_DEBUG,
	           "ProgressiveTile%s: quantIdx Y: %" PRIu8 " Cb: %" PRIu8 " Cr: %" PRIu8
	           " xIdx: %" PRIu16 " yIdx: %" PRIu16 " flags: 0x%02" PRIX8 " quality: %" PRIu8
	           " yLen: %" PRIu16 " cbLen: %" PRIu16 " crLen: %" PRIu16 " tailLen: %" PRIu16 "",
	           (tile->blockType == PROGRESSIVE_WBT_TILE_FIRST) ? "First" : "Simple",
	           tile->quantIdxY, tile->quantIdxCb, tile->quantIdxCr, tile->xIdx, tile->yIdx,
	           tile->flags, tile->quality, tile->yLen, tile->cbLen, tile->crLen, tile->tailLen);
#endif

	if (tile->quantIdxY >= region->numQuant)
	{
		WLog_ERR(TAG, "quantIdxY %" PRIu8 " > numQuant %" PRIu8, tile->quantIdxY, region->numQuant);
		return -1;
	}

	quantY = &(region->quantVals[tile->quantIdxY]);

	if (tile->quantIdxCb >= region->numQuant)
	{
		WLog_ERR(TAG, "quantIdxCb %" PRIu8 " > numQuant %" PRIu8, tile->quantIdxCb,
		         region->numQuant);
		return -1;
	}

	quantCb = &(region->quantVals[tile->quantIdxCb]);

	if (tile->quantIdxCr >= region->numQuant)
	{
		WLog_ERR(TAG, "quantIdxCr %" PRIu8 " > numQuant %" PRIu8, tile->quantIdxCr,
		         region->numQuant);
		return -1;
	}

	quantCr = &(region->quantVals[tile->quantIdxCr]);

	if (tile->quality == 0xFF)
	{
		quantProgVal = &(progressive->quantProgValFull);
	}
	else
	{
		if (tile->quality >= region->numProgQuant)
		{
			WLog_ERR(TAG, "quality %" PRIu8 " > numProgQuant %" PRIu8, tile->quality,
			         region->numProgQuant);
			return -1;
		}

		quantProgVal = &(region->quantProgVals[tile->quality]);
	}

	quantProgY = &(quantProgVal->yQuantValues);
	quantProgCb = &(quantProgVal->cbQuantValues);
	quantProgCr = &(quantProgVal->crQuantValues);

	tile->yQuant = *quantY;
	tile->cbQuant = *quantCb;
	tile->crQuant = *quantCr;
	tile->yProgQuant = *quantProgY;
	tile->cbProgQuant = *quantProgCb;
	tile->crProgQuant = *quantProgCr;

	progressive_rfx_quant_add(quantY, quantProgY, &(tile->yBitPos));
	progressive_rfx_quant_add(quantCb, quantProgCb, &(tile->cbBitPos));
	progressive_rfx_quant_add(quantCr, quantProgCr, &(tile->crBitPos));
	progressive_rfx_quant_add(quantY, quantProgY, &shiftY);
	progressive_rfx_quant_lsub(&shiftY, 1); /* -6 + 5 = -1 */
	progressive_rfx_quant_add(quantCb, quantProgCb, &shiftCb);
	progressive_rfx_quant_lsub(&shiftCb, 1); /* -6 + 5 = -1 */
	progressive_rfx_quant_add(quantCr, quantProgCr, &shiftCr);
	progressive_rfx_quant_lsub(&shiftCr, 1); /* -6 + 5 = -1 */

	pSign[0] = (INT16*)((&tile->sign[((8192 + 32) * 0) + 16])); /* Y/R buffer */
	pSign[1] = (INT16*)((&tile->sign[((8192 + 32) * 1) + 16])); /* Cb/G buffer */
	pSign[2] = (INT16*)((&tile->sign[((8192 + 32) * 2) + 16])); /* Cr/B buffer */

	pCurrent[0] = (INT16*)((&tile->current[((8192 + 32) * 0) + 16])); /* Y/R buffer */
	pCurrent[1] = (INT16*)((&tile->current[((8192 + 32) * 1) + 16])); /* Cb/G buffer */
	pCurrent[2] = (INT16*)((&tile->current[((8192 + 32) * 2) + 16])); /* Cr/B buffer */

	pBuffer = (BYTE*)BufferPool_Take(progressive->bufferPool, -1);
	pSrcDst[0] = (INT16*)((&pBuffer[((8192 + 32) * 0) + 16])); /* Y/R buffer */
	pSrcDst[1] = (INT16*)((&pBuffer[((8192 + 32) * 1) + 16])); /* Cb/G buffer */
	pSrcDst[2] = (INT16*)((&pBuffer[((8192 + 32) * 2) + 16])); /* Cr/B buffer */

	rc = progressive_rfx_decode_component(progressive, &shiftY, tile->yData, tile->yLen, pSrcDst[0],
	                                      pCurrent[0], pSign[0], diff, sub, extrapolate); /* Y */
	if (rc < 0)
		goto fail;
	rc = progressive_rfx_decode_component(progressive, &shiftCb, tile->cbData, tile->cbLen,
	                                      pSrcDst[1], pCurrent[1], pSign[1], diff, sub,
	                                      extrapolate); /* Cb */
	if (rc < 0)
		goto fail;
	rc = progressive_rfx_decode_component(progressive, &shiftCr, tile->crData, tile->crLen,
	                                      pSrcDst[2], pCurrent[2], pSign[2], diff, sub,
	                                      extrapolate); /* Cr */
	if (rc < 0)
		goto fail;

	const INT16** ptr = WINPR_REINTERPRET_CAST(pSrcDst, INT16**, const INT16**);
	rc = prims->yCbCrToRGB_16s8u_P3AC4R(ptr, 64 * 2, tile->data, tile->stride, progressive->format,
	                                    &roi_64x64);
fail:
	BufferPool_Return(progressive->bufferPool, pBuffer);
	return rc;
}

static INLINE INT16 progressive_rfx_srl_read(RFX_PROGRESSIVE_UPGRADE_STATE* WINPR_RESTRICT state,
                                             UINT32 numBits)
{
	WINPR_ASSERT(state);

	wBitStream* bs = state->srl;
	WINPR_ASSERT(bs);

	if (state->nz)
	{
		state->nz--;
		return 0;
	}

	const UINT32 k = state->kp / 8;

	if (!state->mode)
	{
		/* zero encoding */
		const UINT32 bit = (bs->accumulator & 0x80000000) ? 1 : 0;
		BitStream_Shift(bs, 1);

		if (!bit)
		{
			/* '0' bit, nz >= (1 << k), nz = (1 << k) */
			state->nz = (1 << k);
			state->kp += 4;

			if (state->kp > 80)
				state->kp = 80;

			state->nz--;
			return 0;
		}
		else
		{
			/* '1' bit, nz < (1 << k), nz = next k bits */
			state->nz = 0;
			state->mode = 1; /* unary encoding is next */

			if (k)
			{
				bs->mask = ((1 << k) - 1);
				state->nz =
				    WINPR_ASSERTING_INT_CAST(int16_t, ((bs->accumulator >> (32u - k)) & bs->mask));
				BitStream_Shift(bs, k);
			}

			if (state->nz)
			{
				state->nz--;
				return 0;
			}
		}
	}

	state->mode = 0; /* zero encoding is next */
	/* unary encoding */
	/* read sign bit */
	const UINT32 sign = (bs->accumulator & 0x80000000) ? 1 : 0;
	BitStream_Shift(bs, 1);

	if (state->kp < 6)
		state->kp = 0;
	else
		state->kp -= 6;

	if (numBits == 1)
		return sign ? -1 : 1;

	UINT32 mag = 1;
	const UINT32 max = (1 << numBits) - 1;

	while (mag < max)
	{
		const UINT32 bit = (bs->accumulator & 0x80000000) ? 1 : 0;
		BitStream_Shift(bs, 1);

		if (bit)
			break;

		mag++;
	}

	if (mag > INT16_MAX)
		mag = INT16_MAX;
	return (INT16)(sign ? -1 * (int)mag : (INT16)mag);
}

static INLINE int
progressive_rfx_upgrade_state_finish(RFX_PROGRESSIVE_UPGRADE_STATE* WINPR_RESTRICT state)
{
	UINT32 pad = 0;
	wBitStream* srl = NULL;
	wBitStream* raw = NULL;
	if (!state)
		return -1;

	srl = state->srl;
	raw = state->raw;
	/* Read trailing bits from RAW/SRL bit streams */
	pad = (raw->position % 8) ? (8 - (raw->position % 8)) : 0;

	if (pad)
		BitStream_Shift(raw, pad);

	pad = (srl->position % 8) ? (8 - (srl->position % 8)) : 0;

	if (pad)
		BitStream_Shift(srl, pad);

	if (BitStream_GetRemainingLength(srl) == 8)
		BitStream_Shift(srl, 8);

	return 1;
}

static INLINE int progressive_rfx_upgrade_block(RFX_PROGRESSIVE_UPGRADE_STATE* WINPR_RESTRICT state,
                                                INT16* WINPR_RESTRICT buffer,
                                                INT16* WINPR_RESTRICT sign, UINT32 length,
                                                UINT32 shift, WINPR_ATTR_UNUSED UINT32 bitPos,
                                                UINT32 numBits)
{
	if (!numBits)
		return 1;

	wBitStream* raw = state->raw;
	int32_t input = 0;

	if (!state->nonLL)
	{
		for (UINT32 index = 0; index < length; index++)
		{
			raw->mask = ((1 << numBits) - 1);
			input = (INT16)((raw->accumulator >> (32 - numBits)) & raw->mask);
			BitStream_Shift(raw, numBits);

			const int32_t shifted = input << shift;
			const int32_t val = buffer[index] + shifted;
			const int16_t ival = WINPR_ASSERTING_INT_CAST(int16_t, val);
			buffer[index] = ival;
		}

		return 1;
	}

	for (UINT32 index = 0; index < length; index++)
	{
		if (sign[index] > 0)
		{
			/* sign > 0, read from raw */
			raw->mask = ((1 << numBits) - 1);
			input = (INT16)((raw->accumulator >> (32 - numBits)) & raw->mask);
			BitStream_Shift(raw, numBits);
		}
		else if (sign[index] < 0)
		{
			/* sign < 0, read from raw */
			raw->mask = ((1 << numBits) - 1);
			input = (INT16)((raw->accumulator >> (32 - numBits)) & raw->mask);
			BitStream_Shift(raw, numBits);
			input *= -1;
		}
		else
		{
			/* sign == 0, read from srl */
			input = progressive_rfx_srl_read(state, numBits);
			sign[index] = WINPR_ASSERTING_INT_CAST(int16_t, input);
		}

		const int32_t val = input << shift;
		const int32_t ival = buffer[index] + val;
		buffer[index] = WINPR_ASSERTING_INT_CAST(INT16, ival);
	}

	return 1;
}

static INLINE int progressive_rfx_upgrade_component(
    PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
    const RFX_COMPONENT_CODEC_QUANT* WINPR_RESTRICT shift,
    const RFX_COMPONENT_CODEC_QUANT* WINPR_RESTRICT bitPos,
    const RFX_COMPONENT_CODEC_QUANT* WINPR_RESTRICT numBits, INT16* WINPR_RESTRICT buffer,
    INT16* WINPR_RESTRICT current, INT16* WINPR_RESTRICT sign, const BYTE* WINPR_RESTRICT srlData,
    UINT32 srlLen, const BYTE* WINPR_RESTRICT rawData, UINT32 rawLen, BOOL coeffDiff,
    WINPR_ATTR_UNUSED BOOL subbandDiff, BOOL extrapolate)
{
	int rc = 0;
	UINT32 aRawLen = 0;
	UINT32 aSrlLen = 0;
	wBitStream s_srl = { 0 };
	wBitStream s_raw = { 0 };
	RFX_PROGRESSIVE_UPGRADE_STATE state = { 0 };

	state.kp = 8;
	state.mode = 0;
	state.srl = &s_srl;
	state.raw = &s_raw;
	BitStream_Attach(state.srl, srlData, srlLen);
	BitStream_Fetch(state.srl);
	BitStream_Attach(state.raw, rawData, rawLen);
	BitStream_Fetch(state.raw);

	state.nonLL = TRUE;
	rc = progressive_rfx_upgrade_block(&state, &current[0], &sign[0], 1023, shift->HL1, bitPos->HL1,
	                                   numBits->HL1); /* HL1 */
	if (rc < 0)
		return rc;
	rc = progressive_rfx_upgrade_block(&state, &current[1023], &sign[1023], 1023, shift->LH1,
	                                   bitPos->LH1, numBits->LH1); /* LH1 */
	if (rc < 0)
		return rc;
	rc = progressive_rfx_upgrade_block(&state, &current[2046], &sign[2046], 961, shift->HH1,
	                                   bitPos->HH1, numBits->HH1); /* HH1 */
	if (rc < 0)
		return rc;
	rc = progressive_rfx_upgrade_block(&state, &current[3007], &sign[3007], 272, shift->HL2,
	                                   bitPos->HL2, numBits->HL2); /* HL2 */
	if (rc < 0)
		return rc;
	rc = progressive_rfx_upgrade_block(&state, &current[3279], &sign[3279], 272, shift->LH2,
	                                   bitPos->LH2, numBits->LH2); /* LH2 */
	if (rc < 0)
		return rc;
	rc = progressive_rfx_upgrade_block(&state, &current[3551], &sign[3551], 256, shift->HH2,
	                                   bitPos->HH2, numBits->HH2); /* HH2 */
	if (rc < 0)
		return rc;
	rc = progressive_rfx_upgrade_block(&state, &current[3807], &sign[3807], 72, shift->HL3,
	                                   bitPos->HL3, numBits->HL3); /* HL3 */
	if (rc < 0)
		return rc;
	rc = progressive_rfx_upgrade_block(&state, &current[3879], &sign[3879], 72, shift->LH3,
	                                   bitPos->LH3, numBits->LH3); /* LH3 */
	if (rc < 0)
		return rc;
	rc = progressive_rfx_upgrade_block(&state, &current[3951], &sign[3951], 64, shift->HH3,
	                                   bitPos->HH3, numBits->HH3); /* HH3 */
	if (rc < 0)
		return rc;

	state.nonLL = FALSE;
	rc = progressive_rfx_upgrade_block(&state, &current[4015], &sign[4015], 81, shift->LL3,
	                                   bitPos->LL3, numBits->LL3); /* LL3 */
	if (rc < 0)
		return rc;
	rc = progressive_rfx_upgrade_state_finish(&state);
	if (rc < 0)
		return rc;
	aRawLen = (state.raw->position + 7) / 8;
	aSrlLen = (state.srl->position + 7) / 8;

	if ((aRawLen != rawLen) || (aSrlLen != srlLen))
	{
		int pRawLen = 0;
		int pSrlLen = 0;

		if (rawLen)
			pRawLen = (int)((((float)aRawLen) / ((float)rawLen)) * 100.0f);

		if (srlLen)
			pSrlLen = (int)((((float)aSrlLen) / ((float)srlLen)) * 100.0f);

		WLog_Print(progressive->log, WLOG_WARN,
		           "RAW: %" PRIu32 "/%" PRIu32 " %d%% (%" PRIu32 "/%" PRIu32 ":%" PRIu32
		           ")\tSRL: %" PRIu32 "/%" PRIu32 " %d%% (%" PRIu32 "/%" PRIu32 ":%" PRIu32 ")",
		           aRawLen, rawLen, pRawLen, state.raw->position, rawLen * 8,
		           (rawLen * 8) - state.raw->position, aSrlLen, srlLen, pSrlLen,
		           state.srl->position, srlLen * 8, (srlLen * 8) - state.srl->position);
		return -1;
	}

	return progressive_rfx_dwt_2d_decode(progressive, buffer, current, coeffDiff, extrapolate,
	                                     TRUE);
}

static INLINE int
progressive_decompress_tile_upgrade(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                                    RFX_PROGRESSIVE_TILE* WINPR_RESTRICT tile,
                                    PROGRESSIVE_BLOCK_REGION* WINPR_RESTRICT region,
                                    const PROGRESSIVE_BLOCK_CONTEXT* WINPR_RESTRICT context)
{
	int status = 0;
	BOOL coeffDiff = 0;
	BOOL sub = 0;
	BOOL extrapolate = 0;
	BYTE* pBuffer = NULL;
	INT16* pSign[3] = { 0 };
	INT16* pSrcDst[3] = { 0 };
	INT16* pCurrent[3] = { 0 };
	RFX_COMPONENT_CODEC_QUANT shiftY = { 0 };
	RFX_COMPONENT_CODEC_QUANT shiftCb = { 0 };
	RFX_COMPONENT_CODEC_QUANT shiftCr = { 0 };
	RFX_COMPONENT_CODEC_QUANT yBitPos = { 0 };
	RFX_COMPONENT_CODEC_QUANT cbBitPos = { 0 };
	RFX_COMPONENT_CODEC_QUANT crBitPos = { 0 };
	RFX_COMPONENT_CODEC_QUANT yNumBits = { 0 };
	RFX_COMPONENT_CODEC_QUANT cbNumBits = { 0 };
	RFX_COMPONENT_CODEC_QUANT crNumBits = { 0 };
	RFX_COMPONENT_CODEC_QUANT* quantY = NULL;
	RFX_COMPONENT_CODEC_QUANT* quantCb = NULL;
	RFX_COMPONENT_CODEC_QUANT* quantCr = NULL;
	RFX_COMPONENT_CODEC_QUANT* quantProgY = NULL;
	RFX_COMPONENT_CODEC_QUANT* quantProgCb = NULL;
	RFX_COMPONENT_CODEC_QUANT* quantProgCr = NULL;
	RFX_PROGRESSIVE_CODEC_QUANT* quantProg = NULL;
	static const prim_size_t roi_64x64 = { 64, 64 };
	const primitives_t* prims = primitives_get();

	coeffDiff = tile->flags & RFX_TILE_DIFFERENCE;
	sub = context->flags & RFX_SUBBAND_DIFFING;
	extrapolate = region->flags & RFX_DWT_REDUCE_EXTRAPOLATE;

	tile->pass++;

#if defined(WITH_DEBUG_CODECS)
	WLog_Print(progressive->log, WLOG_DEBUG,
	           "ProgressiveTileUpgrade: pass: %" PRIu16 " quantIdx Y: %" PRIu8 " Cb: %" PRIu8
	           " Cr: %" PRIu8 " xIdx: %" PRIu16 " yIdx: %" PRIu16 " quality: %" PRIu8
	           " ySrlLen: %" PRIu16 " yRawLen: %" PRIu16 " cbSrlLen: %" PRIu16 " cbRawLen: %" PRIu16
	           " crSrlLen: %" PRIu16 " crRawLen: %" PRIu16 "",
	           tile->pass, tile->quantIdxY, tile->quantIdxCb, tile->quantIdxCr, tile->xIdx,
	           tile->yIdx, tile->quality, tile->ySrlLen, tile->yRawLen, tile->cbSrlLen,
	           tile->cbRawLen, tile->crSrlLen, tile->crRawLen);
#endif

	if (tile->quantIdxY >= region->numQuant)
	{
		WLog_ERR(TAG, "quantIdxY %" PRIu8 " > numQuant %" PRIu8, tile->quantIdxY, region->numQuant);
		return -1;
	}

	quantY = &(region->quantVals[tile->quantIdxY]);

	if (tile->quantIdxCb >= region->numQuant)
	{
		WLog_ERR(TAG, "quantIdxCb %" PRIu8 " > numQuant %" PRIu8, tile->quantIdxCb,
		         region->numQuant);
		return -1;
	}

	quantCb = &(region->quantVals[tile->quantIdxCb]);

	if (tile->quantIdxCr >= region->numQuant)
	{
		WLog_ERR(TAG, "quantIdxCr %" PRIu8 " > numQuant %" PRIu8, tile->quantIdxCr,
		         region->numQuant);
		return -1;
	}

	quantCr = &(region->quantVals[tile->quantIdxCr]);

	if (tile->quality == 0xFF)
	{
		quantProg = &(progressive->quantProgValFull);
	}
	else
	{
		if (tile->quality >= region->numProgQuant)
		{
			WLog_ERR(TAG, "quality %" PRIu8 " > numProgQuant %" PRIu8, tile->quality,
			         region->numProgQuant);
			return -1;
		}

		quantProg = &(region->quantProgVals[tile->quality]);
	}

	quantProgY = &(quantProg->yQuantValues);
	quantProgCb = &(quantProg->cbQuantValues);
	quantProgCr = &(quantProg->crQuantValues);

	if (!progressive_rfx_quant_cmp_equal(quantY, &(tile->yQuant)))
		WLog_Print(progressive->log, WLOG_WARN, "non-progressive quantY has changed!");

	if (!progressive_rfx_quant_cmp_equal(quantCb, &(tile->cbQuant)))
		WLog_Print(progressive->log, WLOG_WARN, "non-progressive quantCb has changed!");

	if (!progressive_rfx_quant_cmp_equal(quantCr, &(tile->crQuant)))
		WLog_Print(progressive->log, WLOG_WARN, "non-progressive quantCr has changed!");

	if (!(context->flags & RFX_SUBBAND_DIFFING))
		WLog_WARN(TAG, "PROGRESSIVE_BLOCK_CONTEXT::flags & RFX_SUBBAND_DIFFING not set");

	progressive_rfx_quant_add(quantY, quantProgY, &yBitPos);
	progressive_rfx_quant_add(quantCb, quantProgCb, &cbBitPos);
	progressive_rfx_quant_add(quantCr, quantProgCr, &crBitPos);
	progressive_rfx_quant_sub(&(tile->yBitPos), &yBitPos, &yNumBits);
	progressive_rfx_quant_sub(&(tile->cbBitPos), &cbBitPos, &cbNumBits);
	progressive_rfx_quant_sub(&(tile->crBitPos), &crBitPos, &crNumBits);
	progressive_rfx_quant_add(quantY, quantProgY, &shiftY);
	progressive_rfx_quant_lsub(&shiftY, 1); /* -6 + 5 = -1 */
	progressive_rfx_quant_add(quantCb, quantProgCb, &shiftCb);
	progressive_rfx_quant_lsub(&shiftCb, 1); /* -6 + 5 = -1 */
	progressive_rfx_quant_add(quantCr, quantProgCr, &shiftCr);
	progressive_rfx_quant_lsub(&shiftCr, 1); /* -6 + 5 = -1 */

	tile->yBitPos = yBitPos;
	tile->cbBitPos = cbBitPos;
	tile->crBitPos = crBitPos;
	tile->yQuant = *quantY;
	tile->cbQuant = *quantCb;
	tile->crQuant = *quantCr;
	tile->yProgQuant = *quantProgY;
	tile->cbProgQuant = *quantProgCb;
	tile->crProgQuant = *quantProgCr;

	pSign[0] = (INT16*)((&tile->sign[((8192 + 32) * 0) + 16])); /* Y/R buffer */
	pSign[1] = (INT16*)((&tile->sign[((8192 + 32) * 1) + 16])); /* Cb/G buffer */
	pSign[2] = (INT16*)((&tile->sign[((8192 + 32) * 2) + 16])); /* Cr/B buffer */

	pCurrent[0] = (INT16*)((&tile->current[((8192 + 32) * 0) + 16])); /* Y/R buffer */
	pCurrent[1] = (INT16*)((&tile->current[((8192 + 32) * 1) + 16])); /* Cb/G buffer */
	pCurrent[2] = (INT16*)((&tile->current[((8192 + 32) * 2) + 16])); /* Cr/B buffer */

	pBuffer = (BYTE*)BufferPool_Take(progressive->bufferPool, -1);
	pSrcDst[0] = (INT16*)((&pBuffer[((8192 + 32) * 0) + 16])); /* Y/R buffer */
	pSrcDst[1] = (INT16*)((&pBuffer[((8192 + 32) * 1) + 16])); /* Cb/G buffer */
	pSrcDst[2] = (INT16*)((&pBuffer[((8192 + 32) * 2) + 16])); /* Cr/B buffer */

	status = progressive_rfx_upgrade_component(progressive, &shiftY, quantProgY, &yNumBits,
	                                           pSrcDst[0], pCurrent[0], pSign[0], tile->ySrlData,
	                                           tile->ySrlLen, tile->yRawData, tile->yRawLen,
	                                           coeffDiff, sub, extrapolate); /* Y */

	if (status < 0)
		goto fail;

	status = progressive_rfx_upgrade_component(progressive, &shiftCb, quantProgCb, &cbNumBits,
	                                           pSrcDst[1], pCurrent[1], pSign[1], tile->cbSrlData,
	                                           tile->cbSrlLen, tile->cbRawData, tile->cbRawLen,
	                                           coeffDiff, sub, extrapolate); /* Cb */

	if (status < 0)
		goto fail;

	status = progressive_rfx_upgrade_component(progressive, &shiftCr, quantProgCr, &crNumBits,
	                                           pSrcDst[2], pCurrent[2], pSign[2], tile->crSrlData,
	                                           tile->crSrlLen, tile->crRawData, tile->crRawLen,
	                                           coeffDiff, sub, extrapolate); /* Cr */

	if (status < 0)
		goto fail;

	const INT16** ptr = WINPR_REINTERPRET_CAST(pSrcDst, INT16**, const INT16**);
	status = prims->yCbCrToRGB_16s8u_P3AC4R(ptr, 64 * 2, tile->data, tile->stride,
	                                        progressive->format, &roi_64x64);
fail:
	BufferPool_Return(progressive->bufferPool, pBuffer);
	return status;
}

static INLINE BOOL progressive_tile_read_upgrade(
    PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive, wStream* WINPR_RESTRICT s, UINT16 blockType,
    UINT32 blockLen, PROGRESSIVE_SURFACE_CONTEXT* WINPR_RESTRICT surface,
    PROGRESSIVE_BLOCK_REGION* WINPR_RESTRICT region,
    WINPR_ATTR_UNUSED const PROGRESSIVE_BLOCK_CONTEXT* WINPR_RESTRICT context)
{
	RFX_PROGRESSIVE_TILE tile = { 0 };
	const size_t expect = 20;

	if (!Stream_CheckAndLogRequiredLength(TAG, s, expect))
		return FALSE;

	tile.blockType = blockType;
	tile.blockLen = blockLen;
	tile.flags = 0;

	Stream_Read_UINT8(s, tile.quantIdxY);
	Stream_Read_UINT8(s, tile.quantIdxCb);
	Stream_Read_UINT8(s, tile.quantIdxCr);
	Stream_Read_UINT16(s, tile.xIdx);
	Stream_Read_UINT16(s, tile.yIdx);
	Stream_Read_UINT8(s, tile.quality);
	Stream_Read_UINT16(s, tile.ySrlLen);
	Stream_Read_UINT16(s, tile.yRawLen);
	Stream_Read_UINT16(s, tile.cbSrlLen);
	Stream_Read_UINT16(s, tile.cbRawLen);
	Stream_Read_UINT16(s, tile.crSrlLen);
	Stream_Read_UINT16(s, tile.crRawLen);

	tile.ySrlData = Stream_Pointer(s);
	if (!Stream_SafeSeek(s, tile.ySrlLen))
	{
		WLog_Print(progressive->log, WLOG_ERROR, " Failed to seek %" PRIu32 " bytes", tile.ySrlLen);
		return FALSE;
	}

	tile.yRawData = Stream_Pointer(s);
	if (!Stream_SafeSeek(s, tile.yRawLen))
	{
		WLog_Print(progressive->log, WLOG_ERROR, " Failed to seek %" PRIu32 " bytes", tile.yRawLen);
		return FALSE;
	}

	tile.cbSrlData = Stream_Pointer(s);
	if (!Stream_SafeSeek(s, tile.cbSrlLen))
	{
		WLog_Print(progressive->log, WLOG_ERROR, " Failed to seek %" PRIu32 " bytes",
		           tile.cbSrlLen);
		return FALSE;
	}

	tile.cbRawData = Stream_Pointer(s);
	if (!Stream_SafeSeek(s, tile.cbRawLen))
	{
		WLog_Print(progressive->log, WLOG_ERROR, " Failed to seek %" PRIu32 " bytes",
		           tile.cbRawLen);
		return FALSE;
	}

	tile.crSrlData = Stream_Pointer(s);
	if (!Stream_SafeSeek(s, tile.crSrlLen))
	{
		WLog_Print(progressive->log, WLOG_ERROR, " Failed to seek %" PRIu32 " bytes",
		           tile.crSrlLen);
		return FALSE;
	}

	tile.crRawData = Stream_Pointer(s);
	if (!Stream_SafeSeek(s, tile.crRawLen))
	{
		WLog_Print(progressive->log, WLOG_ERROR, " Failed to seek %" PRIu32 " bytes",
		           tile.crRawLen);
		return FALSE;
	}

	return progressive_surface_tile_replace(surface, region, &tile, TRUE);
}

static INLINE BOOL progressive_tile_read(
    PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive, BOOL simple, wStream* WINPR_RESTRICT s,
    UINT16 blockType, UINT32 blockLen, PROGRESSIVE_SURFACE_CONTEXT* WINPR_RESTRICT surface,
    PROGRESSIVE_BLOCK_REGION* WINPR_RESTRICT region,
    WINPR_ATTR_UNUSED const PROGRESSIVE_BLOCK_CONTEXT* WINPR_RESTRICT context)
{
	RFX_PROGRESSIVE_TILE tile = { 0 };
	size_t expect = simple ? 16 : 17;

	if (!Stream_CheckAndLogRequiredLength(TAG, s, expect))
		return FALSE;

	tile.blockType = blockType;
	tile.blockLen = blockLen;

	Stream_Read_UINT8(s, tile.quantIdxY);
	Stream_Read_UINT8(s, tile.quantIdxCb);
	Stream_Read_UINT8(s, tile.quantIdxCr);
	Stream_Read_UINT16(s, tile.xIdx);
	Stream_Read_UINT16(s, tile.yIdx);
	Stream_Read_UINT8(s, tile.flags);

	if (!simple)
		Stream_Read_UINT8(s, tile.quality);
	else
		tile.quality = 0xFF;
	Stream_Read_UINT16(s, tile.yLen);
	Stream_Read_UINT16(s, tile.cbLen);
	Stream_Read_UINT16(s, tile.crLen);
	Stream_Read_UINT16(s, tile.tailLen);

	tile.yData = Stream_Pointer(s);
	if (!Stream_SafeSeek(s, tile.yLen))
	{
		WLog_Print(progressive->log, WLOG_ERROR, " Failed to seek %" PRIu32 " bytes", tile.yLen);
		return FALSE;
	}

	tile.cbData = Stream_Pointer(s);
	if (!Stream_SafeSeek(s, tile.cbLen))
	{
		WLog_Print(progressive->log, WLOG_ERROR, " Failed to seek %" PRIu32 " bytes", tile.cbLen);
		return FALSE;
	}

	tile.crData = Stream_Pointer(s);
	if (!Stream_SafeSeek(s, tile.crLen))
	{
		WLog_Print(progressive->log, WLOG_ERROR, " Failed to seek %" PRIu32 " bytes", tile.crLen);
		return FALSE;
	}

	tile.tailData = Stream_Pointer(s);
	if (!Stream_SafeSeek(s, tile.tailLen))
	{
		WLog_Print(progressive->log, WLOG_ERROR, " Failed to seek %" PRIu32 " bytes", tile.tailLen);
		return FALSE;
	}

	return progressive_surface_tile_replace(surface, region, &tile, FALSE);
}

static void CALLBACK progressive_process_tiles_tile_work_callback(PTP_CALLBACK_INSTANCE instance,
                                                                  void* context, PTP_WORK work)
{
	PROGRESSIVE_TILE_PROCESS_WORK_PARAM* param = (PROGRESSIVE_TILE_PROCESS_WORK_PARAM*)context;

	WINPR_UNUSED(instance);
	WINPR_UNUSED(work);

	switch (param->tile->blockType)
	{
		case PROGRESSIVE_WBT_TILE_SIMPLE:
		case PROGRESSIVE_WBT_TILE_FIRST:
			progressive_decompress_tile_first(param->progressive, param->tile, param->region,
			                                  param->context);
			break;

		case PROGRESSIVE_WBT_TILE_UPGRADE:
			progressive_decompress_tile_upgrade(param->progressive, param->tile, param->region,
			                                    param->context);
			break;
		default:
			WLog_Print(param->progressive->log, WLOG_ERROR, "Invalid block type %04" PRIx16 " (%s)",
			           param->tile->blockType,
			           rfx_get_progressive_block_type_string(param->tile->blockType));
			break;
	}
}

static INLINE SSIZE_T progressive_process_tiles(
    PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive, wStream* WINPR_RESTRICT s,
    PROGRESSIVE_BLOCK_REGION* WINPR_RESTRICT region,
    PROGRESSIVE_SURFACE_CONTEXT* WINPR_RESTRICT surface,
    const PROGRESSIVE_BLOCK_CONTEXT* WINPR_RESTRICT context)
{
	int status = 0;
	size_t end = 0;
	const size_t start = Stream_GetPosition(s);
	UINT16 blockType = 0;
	UINT32 blockLen = 0;
	UINT32 count = 0;
	UINT16 close_cnt = 0;

	WINPR_ASSERT(progressive);
	WINPR_ASSERT(region);

	if (!Stream_CheckAndLogRequiredLength(TAG, s, region->tileDataSize))
		return -1;

	while ((Stream_GetRemainingLength(s) >= 6) &&
	       (region->tileDataSize > (Stream_GetPosition(s) - start)))
	{
		const size_t pos = Stream_GetPosition(s);

		Stream_Read_UINT16(s, blockType);
		Stream_Read_UINT32(s, blockLen);

#if defined(WITH_DEBUG_CODECS)
		WLog_Print(progressive->log, WLOG_DEBUG, "%s",
		           rfx_get_progressive_block_type_string(blockType));
#endif

		if (blockLen < 6)
		{
			WLog_Print(progressive->log, WLOG_ERROR, "Expected >= %" PRIu32 " remaining %" PRIuz, 6,
			           blockLen);
			return -1003;
		}
		if (!Stream_CheckAndLogRequiredLength(TAG, s, blockLen - 6))
			return -1003;

		switch (blockType)
		{
			case PROGRESSIVE_WBT_TILE_SIMPLE:
				if (!progressive_tile_read(progressive, TRUE, s, blockType, blockLen, surface,
				                           region, context))
					return -1022;
				break;

			case PROGRESSIVE_WBT_TILE_FIRST:
				if (!progressive_tile_read(progressive, FALSE, s, blockType, blockLen, surface,
				                           region, context))
					return -1027;
				break;

			case PROGRESSIVE_WBT_TILE_UPGRADE:
				if (!progressive_tile_read_upgrade(progressive, s, blockType, blockLen, surface,
				                                   region, context))
					return -1032;
				break;
			default:
				WLog_ERR(TAG, "Invalid block type %04" PRIx16 " (%s)", blockType,
				         rfx_get_progressive_block_type_string(blockType));
				return -1039;
		}

		size_t rem = Stream_GetPosition(s);
		if ((rem - pos) != blockLen)
		{
			WLog_Print(progressive->log, WLOG_ERROR,
			           "Actual block read %" PRIuz " but expected %" PRIu32, rem - pos, blockLen);
			return -1040;
		}
		count++;
	}

	end = Stream_GetPosition(s);
	if ((end - start) != region->tileDataSize)
	{
		WLog_Print(progressive->log, WLOG_ERROR,
		           "Actual total blocks read %" PRIuz " but expected %" PRIu32, end - start,
		           region->tileDataSize);
		return -1041;
	}

	if (count != region->numTiles)
	{
		WLog_Print(progressive->log, WLOG_WARN,
		           "numTiles inconsistency: actual: %" PRIu32 ", expected: %" PRIu16 "\n", count,
		           region->numTiles);
		return -1044;
	}

	for (UINT32 idx = 0; idx < region->numTiles; idx++)
	{
		RFX_PROGRESSIVE_TILE* tile = region->tiles[idx];
		PROGRESSIVE_TILE_PROCESS_WORK_PARAM* param = &progressive->params[idx];
		param->progressive = progressive;
		param->region = region;
		param->context = context;
		param->tile = tile;

		if (progressive->rfx_context->priv->UseThreads)
		{
			progressive->work_objects[idx] =
			    CreateThreadpoolWork(progressive_process_tiles_tile_work_callback, (void*)param,
			                         &progressive->rfx_context->priv->ThreadPoolEnv);
			if (!progressive->work_objects[idx])
			{
				WLog_Print(progressive->log, WLOG_ERROR,
				           "Failed to create ThreadpoolWork for tile %" PRIu32, idx);
				status = -1;
				break;
			}

			SubmitThreadpoolWork(progressive->work_objects[idx]);

			close_cnt = WINPR_ASSERTING_INT_CAST(UINT16, idx + 1);
		}
		else
		{
			progressive_process_tiles_tile_work_callback(0, param, 0);
		}

		if (status < 0)
		{
			WLog_Print(progressive->log, WLOG_ERROR, "Failed to decompress %s at %" PRIu16,
			           rfx_get_progressive_block_type_string(tile->blockType), idx);
			goto fail;
		}
	}

	if (progressive->rfx_context->priv->UseThreads)
	{
		for (UINT32 idx = 0; idx < close_cnt; idx++)
		{
			WaitForThreadpoolWorkCallbacks(progressive->work_objects[idx], FALSE);
			CloseThreadpoolWork(progressive->work_objects[idx]);
		}
	}

fail:

	if (status < 0)
		return -1;

	return (SSIZE_T)(end - start);
}

static INLINE SSIZE_T progressive_wb_sync(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                                          wStream* WINPR_RESTRICT s, UINT16 blockType,
                                          UINT32 blockLen)
{
	const UINT32 magic = 0xCACCACCA;
	const UINT16 version = 0x0100;
	PROGRESSIVE_BLOCK_SYNC sync = { 0 };

	sync.blockType = blockType;
	sync.blockLen = blockLen;

	if (sync.blockLen != 12)
	{
		WLog_Print(progressive->log, WLOG_ERROR,
		           "PROGRESSIVE_BLOCK_SYNC::blockLen = 0x%08" PRIx32 " != 0x%08" PRIx32,
		           sync.blockLen, 12);
		return -1005;
	}

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 6))
		return -1004;

#if defined(WITH_DEBUG_CODECS)
	WLog_Print(progressive->log, WLOG_DEBUG, "ProgressiveSync");
#endif

	Stream_Read_UINT32(s, sync.magic);
	Stream_Read_UINT16(s, sync.version);

	if (sync.magic != magic)
	{
		WLog_Print(progressive->log, WLOG_ERROR,
		           "PROGRESSIVE_BLOCK_SYNC::magic = 0x%08" PRIx32 " != 0x%08" PRIx32, sync.magic,
		           magic);
		return -1005;
	}

	if (sync.version != 0x0100)
	{
		WLog_Print(progressive->log, WLOG_ERROR,
		           "PROGRESSIVE_BLOCK_SYNC::version = 0x%04" PRIx16 " != 0x%04" PRIu16,
		           sync.version, version);
		return -1006;
	}

	if ((progressive->state & FLAG_WBT_SYNC) != 0)
		WLog_WARN(TAG, "Duplicate PROGRESSIVE_BLOCK_SYNC, ignoring");

	progressive->state |= FLAG_WBT_SYNC;
	return 0;
}

static INLINE SSIZE_T progressive_wb_frame_begin(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                                                 wStream* WINPR_RESTRICT s, UINT16 blockType,
                                                 UINT32 blockLen)
{
	PROGRESSIVE_BLOCK_FRAME_BEGIN frameBegin = { 0 };

	frameBegin.blockType = blockType;
	frameBegin.blockLen = blockLen;

	if (frameBegin.blockLen != 12)
	{
		WLog_Print(progressive->log, WLOG_ERROR,
		           " RFX_PROGRESSIVE_FRAME_BEGIN::blockLen = 0x%08" PRIx32 " != 0x%08" PRIx32,
		           frameBegin.blockLen, 12);
		return -1005;
	}

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 6))
		return -1007;

	Stream_Read_UINT32(s, frameBegin.frameIndex);
	Stream_Read_UINT16(s, frameBegin.regionCount);

#if defined(WITH_DEBUG_CODECS)
	WLog_Print(progressive->log, WLOG_DEBUG,
	           "ProgressiveFrameBegin: frameIndex: %" PRIu32 " regionCount: %" PRIu16 "",
	           frameBegin.frameIndex, frameBegin.regionCount);
#endif

	/**
	 * If the number of elements specified by the regionCount field is
	 * larger than the actual number of elements in the regions field,
	 * the decoder SHOULD ignore this inconsistency.
	 */

	if ((progressive->state & FLAG_WBT_FRAME_BEGIN) != 0)
	{
		WLog_ERR(TAG, "Duplicate RFX_PROGRESSIVE_FRAME_BEGIN in stream, this is not allowed!");
		return -1008;
	}

	if ((progressive->state & FLAG_WBT_FRAME_END) != 0)
	{
		WLog_ERR(TAG, "RFX_PROGRESSIVE_FRAME_BEGIN after RFX_PROGRESSIVE_FRAME_END in stream, this "
		              "is not allowed!");
		return -1008;
	}

	progressive->state |= FLAG_WBT_FRAME_BEGIN;
	return 0;
}

static INLINE SSIZE_T progressive_wb_frame_end(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                                               wStream* WINPR_RESTRICT s, UINT16 blockType,
                                               UINT32 blockLen)
{
	PROGRESSIVE_BLOCK_FRAME_END frameEnd = { 0 };

	frameEnd.blockType = blockType;
	frameEnd.blockLen = blockLen;

	if (frameEnd.blockLen != 6)
	{
		WLog_Print(progressive->log, WLOG_ERROR,
		           " RFX_PROGRESSIVE_FRAME_END::blockLen = 0x%08" PRIx32 " != 0x%08" PRIx32,
		           frameEnd.blockLen, 6);
		return -1005;
	}

	if (Stream_GetRemainingLength(s) != 0)
	{
		WLog_Print(progressive->log, WLOG_ERROR,
		           "ProgressiveFrameEnd short %" PRIuz ", expected %" PRIuz,
		           Stream_GetRemainingLength(s), 0);
		return -1008;
	}

#if defined(WITH_DEBUG_CODECS)
	WLog_Print(progressive->log, WLOG_DEBUG, "ProgressiveFrameEnd");
#endif

	if ((progressive->state & FLAG_WBT_FRAME_BEGIN) == 0)
		WLog_WARN(TAG, "RFX_PROGRESSIVE_FRAME_END before RFX_PROGRESSIVE_FRAME_BEGIN, ignoring");
	if ((progressive->state & FLAG_WBT_FRAME_END) != 0)
		WLog_WARN(TAG, "Duplicate RFX_PROGRESSIVE_FRAME_END, ignoring");

	progressive->state |= FLAG_WBT_FRAME_END;
	return 0;
}

static INLINE SSIZE_T progressive_wb_context(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                                             wStream* WINPR_RESTRICT s, UINT16 blockType,
                                             UINT32 blockLen)
{
	PROGRESSIVE_BLOCK_CONTEXT* context = &progressive->context;
	context->blockType = blockType;
	context->blockLen = blockLen;

	if (context->blockLen != 10)
	{
		WLog_Print(progressive->log, WLOG_ERROR,
		           "RFX_PROGRESSIVE_CONTEXT::blockLen = 0x%08" PRIx32 " != 0x%08" PRIx32,
		           context->blockLen, 10);
		return -1005;
	}

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 4))
		return -1009;

	Stream_Read_UINT8(s, context->ctxId);
	Stream_Read_UINT16(s, context->tileSize);
	Stream_Read_UINT8(s, context->flags);

	if (context->ctxId != 0x00)
		WLog_WARN(TAG, "RFX_PROGRESSIVE_CONTEXT::ctxId != 0x00: %" PRIu8, context->ctxId);

	if (context->tileSize != 64)
	{
		WLog_ERR(TAG, "RFX_PROGRESSIVE_CONTEXT::tileSize != 0x40: %" PRIu16, context->tileSize);
		return -1010;
	}

	if ((progressive->state & FLAG_WBT_FRAME_BEGIN) != 0)
		WLog_WARN(TAG, "RFX_PROGRESSIVE_CONTEXT received after RFX_PROGRESSIVE_FRAME_BEGIN");
	if ((progressive->state & FLAG_WBT_FRAME_END) != 0)
		WLog_WARN(TAG, "RFX_PROGRESSIVE_CONTEXT received after RFX_PROGRESSIVE_FRAME_END");
	if ((progressive->state & FLAG_WBT_CONTEXT) != 0)
		WLog_WARN(TAG, "Duplicate RFX_PROGRESSIVE_CONTEXT received, ignoring.");

#if defined(WITH_DEBUG_CODECS)
	WLog_Print(progressive->log, WLOG_DEBUG, "ProgressiveContext: flags: 0x%02" PRIX8 "",
	           context->flags);
#endif

	progressive->state |= FLAG_WBT_CONTEXT;
	return 0;
}

static INLINE SSIZE_T progressive_wb_read_region_header(
    PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive, wStream* WINPR_RESTRICT s, UINT16 blockType,
    UINT32 blockLen, PROGRESSIVE_BLOCK_REGION* WINPR_RESTRICT region)
{
	region->usedTiles = 0;

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 12))
		return -1011;

	region->blockType = blockType;
	region->blockLen = blockLen;
	Stream_Read_UINT8(s, region->tileSize);
	Stream_Read_UINT16(s, region->numRects);
	Stream_Read_UINT8(s, region->numQuant);
	Stream_Read_UINT8(s, region->numProgQuant);
	Stream_Read_UINT8(s, region->flags);
	Stream_Read_UINT16(s, region->numTiles);
	Stream_Read_UINT32(s, region->tileDataSize);

	if (region->tileSize != 64)
	{
		WLog_Print(progressive->log, WLOG_ERROR,
		           "ProgressiveRegion tile size %" PRIu8 ", expected %" PRIuz, region->tileSize,
		           64);
		return -1012;
	}

	if (region->numRects < 1)
	{
		WLog_Print(progressive->log, WLOG_ERROR, "ProgressiveRegion missing rect count %" PRIu16,
		           region->numRects);
		return -1013;
	}

	if (region->numQuant > 7)
	{
		WLog_Print(progressive->log, WLOG_ERROR,
		           "ProgressiveRegion quant count too high %" PRIu8 ", expected < %" PRIuz,
		           region->numQuant, 7);
		return -1014;
	}

	const SSIZE_T rc = WINPR_ASSERTING_INT_CAST(SSIZE_T, Stream_GetRemainingLength(s));
	const SSIZE_T expect = region->numRects * 8ll + region->numQuant * 5ll +
	                       region->numProgQuant * 16ll + region->tileDataSize;
	SSIZE_T len = rc;
	if (expect != rc)
	{
		if (len / 8LL < region->numRects)
		{
			WLog_Print(progressive->log, WLOG_ERROR,
			           "ProgressiveRegion data short for region->rects");
			return -1015;
		}
		len -= region->numRects * 8LL;

		if (len / 5LL < region->numQuant)
		{
			WLog_Print(progressive->log, WLOG_ERROR,
			           "ProgressiveRegion data short for region->cQuant");
			return -1018;
		}
		len -= region->numQuant * 5LL;

		if (len / 16LL < region->numProgQuant)
		{
			WLog_Print(progressive->log, WLOG_ERROR,
			           "ProgressiveRegion data short for region->cProgQuant");
			return -1021;
		}
		len -= region->numProgQuant * 16LL;

		if (len < region->tileDataSize * 1ll)
		{
			WLog_Print(progressive->log, WLOG_ERROR,
			           "ProgressiveRegion data short for region->tiles");
			return -1024;
		}
		len -= region->tileDataSize;

		if (len > 0)
			WLog_Print(progressive->log, WLOG_WARN,
			           "Unused bytes detected, %" PRIdz " bytes not processed", len);
	}

	return rc;
}

static INLINE SSIZE_T progressive_wb_skip_region(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                                                 wStream* WINPR_RESTRICT s, UINT16 blockType,
                                                 UINT32 blockLen)
{
	PROGRESSIVE_BLOCK_REGION* WINPR_RESTRICT region = &progressive->region;

	const SSIZE_T rc =
	    progressive_wb_read_region_header(progressive, s, blockType, blockLen, region);
	if (rc < 0)
		return rc;

	if (!Stream_SafeSeek(s, WINPR_ASSERTING_INT_CAST(size_t, rc)))
		return -1111;

	return rc;
}

static INLINE SSIZE_T progressive_wb_region(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                                            wStream* WINPR_RESTRICT s, UINT16 blockType,
                                            UINT32 blockLen,
                                            PROGRESSIVE_SURFACE_CONTEXT* WINPR_RESTRICT surface,
                                            PROGRESSIVE_BLOCK_REGION* WINPR_RESTRICT region)
{
	SSIZE_T rc = -1;
	UINT16 boxLeft = 0;
	UINT16 boxTop = 0;
	UINT16 boxRight = 0;
	UINT16 boxBottom = 0;
	UINT16 idxLeft = 0;
	UINT16 idxTop = 0;
	UINT16 idxRight = 0;
	UINT16 idxBottom = 0;
	const PROGRESSIVE_BLOCK_CONTEXT* context = &progressive->context;

	if ((progressive->state & FLAG_WBT_FRAME_BEGIN) == 0)
	{
		WLog_WARN(TAG, "RFX_PROGRESSIVE_REGION before RFX_PROGRESSIVE_FRAME_BEGIN, ignoring");
		return progressive_wb_skip_region(progressive, s, blockType, blockLen);
	}
	if ((progressive->state & FLAG_WBT_FRAME_END) != 0)
	{
		WLog_WARN(TAG, "RFX_PROGRESSIVE_REGION after RFX_PROGRESSIVE_FRAME_END, ignoring");
		return progressive_wb_skip_region(progressive, s, blockType, blockLen);
	}

	progressive->state |= FLAG_WBT_REGION;

	rc = progressive_wb_read_region_header(progressive, s, blockType, blockLen, region);
	if (rc < 0)
		return rc;

	for (UINT16 index = 0; index < region->numRects; index++)
	{
		RFX_RECT* rect = &(region->rects[index]);
		Stream_Read_UINT16(s, rect->x);
		Stream_Read_UINT16(s, rect->y);
		Stream_Read_UINT16(s, rect->width);
		Stream_Read_UINT16(s, rect->height);
	}

	for (BYTE index = 0; index < region->numQuant; index++)
	{
		RFX_COMPONENT_CODEC_QUANT* quantVal = &(region->quantVals[index]);
		progressive_component_codec_quant_read(s, quantVal);

		if (!progressive_rfx_quant_lcmp_greater_equal(quantVal, 6))
		{
			WLog_Print(progressive->log, WLOG_ERROR,
			           "ProgressiveRegion region->cQuant[%" PRIu32 "] < 6", index);
			return -1;
		}

		if (!progressive_rfx_quant_lcmp_less_equal(quantVal, 15))
		{
			WLog_Print(progressive->log, WLOG_ERROR,
			           "ProgressiveRegion region->cQuant[%" PRIu32 "] > 15", index);
			return -1;
		}
	}

	for (BYTE index = 0; index < region->numProgQuant; index++)
	{
		RFX_PROGRESSIVE_CODEC_QUANT* quantProgVal = &(region->quantProgVals[index]);

		Stream_Read_UINT8(s, quantProgVal->quality);

		progressive_component_codec_quant_read(s, &(quantProgVal->yQuantValues));
		progressive_component_codec_quant_read(s, &(quantProgVal->cbQuantValues));
		progressive_component_codec_quant_read(s, &(quantProgVal->crQuantValues));
	}

#if defined(WITH_DEBUG_CODECS)
	WLog_Print(progressive->log, WLOG_DEBUG,
	           "ProgressiveRegion: numRects: %" PRIu16 " numTiles: %" PRIu16
	           " tileDataSize: %" PRIu32 " flags: 0x%02" PRIX8 " numQuant: %" PRIu8
	           " numProgQuant: %" PRIu8 "",
	           region->numRects, region->numTiles, region->tileDataSize, region->flags,
	           region->numQuant, region->numProgQuant);
#endif

	boxLeft = WINPR_ASSERTING_INT_CAST(UINT16, surface->gridWidth);
	boxTop = WINPR_ASSERTING_INT_CAST(UINT16, surface->gridHeight);
	boxRight = 0;
	boxBottom = 0;

	for (UINT16 index = 0; index < region->numRects; index++)
	{
		RFX_RECT* rect = &(region->rects[index]);
		idxLeft = rect->x / 64;
		idxTop = rect->y / 64;
		idxRight = (rect->x + rect->width + 63) / 64;
		idxBottom = (rect->y + rect->height + 63) / 64;

		if (idxLeft < boxLeft)
			boxLeft = idxLeft;

		if (idxTop < boxTop)
			boxTop = idxTop;

		if (idxRight > boxRight)
			boxRight = idxRight;

		if (idxBottom > boxBottom)
			boxBottom = idxBottom;

#if defined(WITH_DEBUG_CODECS)
		WLog_Print(progressive->log, WLOG_DEBUG,
		           "rect[%" PRIu16 "]: x: %" PRIu16 " y: %" PRIu16 " w: %" PRIu16 " h: %" PRIu16 "",
		           index, rect->x, rect->y, rect->width, rect->height);
#endif
	}

	const SSIZE_T res = progressive_process_tiles(progressive, s, region, surface, context);
	if (res < 0)
		return -1;
	return rc;
}

static INLINE SSIZE_T progressive_parse_block(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                                              wStream* WINPR_RESTRICT s,
                                              PROGRESSIVE_SURFACE_CONTEXT* WINPR_RESTRICT surface,
                                              PROGRESSIVE_BLOCK_REGION* WINPR_RESTRICT region)
{
	UINT16 blockType = 0;
	UINT32 blockLen = 0;
	SSIZE_T rc = -1;
	wStream sub = { 0 };

	WINPR_ASSERT(progressive);

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 6))
		return -1;

	Stream_Read_UINT16(s, blockType);
	Stream_Read_UINT32(s, blockLen);

	if (blockLen < 6)
	{
		WLog_WARN(TAG, "Invalid blockLen %" PRIu32 ", expected >= 6", blockLen);
		return -1;
	}
	if (!Stream_CheckAndLogRequiredLength(TAG, s, blockLen - 6))
		return -1;
	Stream_StaticConstInit(&sub, Stream_Pointer(s), blockLen - 6);
	Stream_Seek(s, blockLen - 6);

	switch (blockType)
	{
		case PROGRESSIVE_WBT_SYNC:
			rc = progressive_wb_sync(progressive, &sub, blockType, blockLen);
			break;

		case PROGRESSIVE_WBT_FRAME_BEGIN:
			rc = progressive_wb_frame_begin(progressive, &sub, blockType, blockLen);
			break;

		case PROGRESSIVE_WBT_FRAME_END:
			rc = progressive_wb_frame_end(progressive, &sub, blockType, blockLen);
			break;

		case PROGRESSIVE_WBT_CONTEXT:
			rc = progressive_wb_context(progressive, &sub, blockType, blockLen);
			break;

		case PROGRESSIVE_WBT_REGION:
			rc = progressive_wb_region(progressive, &sub, blockType, blockLen, surface, region);
			break;

		default:
			WLog_Print(progressive->log, WLOG_ERROR, "Invalid block type %04" PRIx16, blockType);
			return -1;
	}

	if (rc < 0)
		return -1;

	if (Stream_GetRemainingLength(&sub) > 0)
	{
		WLog_Print(progressive->log, WLOG_ERROR,
		           "block len %" PRIu32 " does not match read data %" PRIuz, blockLen,
		           blockLen - Stream_GetRemainingLength(&sub));
		return -1;
	}

	return rc;
}

static INLINE BOOL update_tiles(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                                PROGRESSIVE_SURFACE_CONTEXT* WINPR_RESTRICT surface,
                                BYTE* WINPR_RESTRICT pDstData, UINT32 DstFormat, UINT32 nDstStep,
                                UINT32 nXDst, UINT32 nYDst,
                                PROGRESSIVE_BLOCK_REGION* WINPR_RESTRICT region,
                                REGION16* WINPR_RESTRICT invalidRegion)
{
	BOOL rc = TRUE;
	REGION16 clippingRects = { 0 };
	region16_init(&clippingRects);

	for (UINT32 i = 0; i < region->numRects; i++)
	{
		RECTANGLE_16 clippingRect = { 0 };
		const RFX_RECT* rect = &(region->rects[i]);

		clippingRect.left = (UINT16)nXDst + rect->x;
		clippingRect.top = (UINT16)nYDst + rect->y;
		clippingRect.right = clippingRect.left + rect->width;
		clippingRect.bottom = clippingRect.top + rect->height;
		region16_union_rect(&clippingRects, &clippingRects, &clippingRect);
	}

	for (UINT32 i = 0; i < surface->numUpdatedTiles; i++)
	{
		UINT32 nbUpdateRects = 0;
		const RECTANGLE_16* updateRects = NULL;
		RECTANGLE_16 updateRect = { 0 };

		WINPR_ASSERT(surface->updatedTileIndices);
		const UINT32 index = surface->updatedTileIndices[i];

		WINPR_ASSERT(index < surface->tilesSize);
		RFX_PROGRESSIVE_TILE* tile = surface->tiles[index];
		WINPR_ASSERT(tile);

		const UINT32 dl = nXDst + tile->x;
		updateRect.left = WINPR_ASSERTING_INT_CAST(UINT16, dl);

		const UINT32 dt = nYDst + tile->y;
		updateRect.top = WINPR_ASSERTING_INT_CAST(UINT16, dt);
		updateRect.right = updateRect.left + 64;
		updateRect.bottom = updateRect.top + 64;

		REGION16 updateRegion = { 0 };
		region16_init(&updateRegion);
		region16_intersect_rect(&updateRegion, &clippingRects, &updateRect);
		updateRects = region16_rects(&updateRegion, &nbUpdateRects);

		for (UINT32 j = 0; j < nbUpdateRects; j++)
		{
			rc = FALSE;
			const RECTANGLE_16* rect = &updateRects[j];
			if (rect->left < updateRect.left)
				break;
			const UINT32 nXSrc = rect->left - updateRect.left;
			const UINT32 nYSrc = rect->top - updateRect.top;
			const UINT32 width = rect->right - rect->left;
			const UINT32 height = rect->bottom - rect->top;

			if (rect->left + width > surface->width)
				break;
			if (rect->top + height > surface->height)
				break;
			rc = freerdp_image_copy_no_overlap(
			    pDstData, DstFormat, nDstStep, rect->left, rect->top, width, height, tile->data,
			    progressive->format, tile->stride, nXSrc, nYSrc, NULL, FREERDP_KEEP_DST_ALPHA);
			if (!rc)
				break;

			if (invalidRegion)
				region16_union_rect(invalidRegion, invalidRegion, rect);
		}

		region16_uninit(&updateRegion);
		if (!rc)
			goto fail;
		tile->dirty = FALSE;
	}

fail:
	region16_uninit(&clippingRects);
	return rc;
}

INT32 progressive_decompress(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                             const BYTE* WINPR_RESTRICT pSrcData, UINT32 SrcSize,
                             BYTE* WINPR_RESTRICT pDstData, UINT32 DstFormat, UINT32 nDstStep,
                             UINT32 nXDst, UINT32 nYDst, REGION16* WINPR_RESTRICT invalidRegion,
                             UINT16 surfaceId, UINT32 frameId)
{
	INT32 rc = 1;

	WINPR_ASSERT(progressive);
	PROGRESSIVE_SURFACE_CONTEXT* surface = progressive_get_surface_data(progressive, surfaceId);

	if (!surface)
	{
		WLog_Print(progressive->log, WLOG_ERROR, "ProgressiveRegion no surface for %" PRIu16,
		           surfaceId);
		return -1001;
	}

	PROGRESSIVE_BLOCK_REGION* WINPR_RESTRICT region = &progressive->region;
	WINPR_ASSERT(region);

	if (surface->frameId != frameId)
	{
		surface->frameId = frameId;
		surface->numUpdatedTiles = 0;
	}

	wStream ss = { 0 };
	wStream* s = Stream_StaticConstInit(&ss, pSrcData, SrcSize);
	WINPR_ASSERT(s);

	switch (DstFormat)
	{
		case PIXEL_FORMAT_RGBA32:
		case PIXEL_FORMAT_RGBX32:
		case PIXEL_FORMAT_BGRA32:
		case PIXEL_FORMAT_BGRX32:
			progressive->format = DstFormat;
			break;
		default:
			progressive->format = PIXEL_FORMAT_XRGB32;
			break;
	}

	const size_t start = Stream_GetPosition(s);
	progressive->state = 0; /* Set state to not initialized */
	while (Stream_GetRemainingLength(s) > 0)
	{
		if (progressive_parse_block(progressive, s, surface, region) < 0)
			goto fail;
	}

	const size_t end = Stream_GetPosition(s);
	if ((end - start) != SrcSize)
	{
		WLog_Print(progressive->log, WLOG_ERROR,
		           "total block len %" PRIuz " does not match read data %" PRIu32, end - start,
		           SrcSize);
		rc = -1041;
		goto fail;
	}

	if (!update_tiles(progressive, surface, pDstData, DstFormat, nDstStep, nXDst, nYDst, region,
	                  invalidRegion))
		return -2002;
fail:
	return rc;
}

BOOL progressive_rfx_write_message_progressive_simple(
    PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive, wStream* WINPR_RESTRICT s,
    const RFX_MESSAGE* WINPR_RESTRICT msg)
{
	RFX_CONTEXT* context = NULL;

	WINPR_ASSERT(progressive);
	WINPR_ASSERT(s);
	WINPR_ASSERT(msg);
	context = progressive->rfx_context;
	return rfx_write_message_progressive_simple(context, s, msg);
}

int progressive_compress(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive,
                         const BYTE* WINPR_RESTRICT pSrcData, UINT32 SrcSize, UINT32 SrcFormat,
                         UINT32 Width, UINT32 Height, UINT32 ScanLine,
                         const REGION16* WINPR_RESTRICT invalidRegion,
                         BYTE** WINPR_RESTRICT ppDstData, UINT32* WINPR_RESTRICT pDstSize)
{
	BOOL rc = FALSE;
	int res = -6;
	wStream* s = NULL;
	UINT32 numRects = 0;
	RFX_RECT* rects = NULL;
	RFX_MESSAGE* message = NULL;

	if (!progressive || !pSrcData || !ppDstData || !pDstSize)
	{
		return -1;
	}

	if (ScanLine == 0)
	{
		switch (SrcFormat)
		{
			case PIXEL_FORMAT_ABGR32:
			case PIXEL_FORMAT_ARGB32:
			case PIXEL_FORMAT_XBGR32:
			case PIXEL_FORMAT_XRGB32:
			case PIXEL_FORMAT_BGRA32:
			case PIXEL_FORMAT_BGRX32:
			case PIXEL_FORMAT_RGBA32:
			case PIXEL_FORMAT_RGBX32:
				ScanLine = Width * 4;
				break;
			default:
				return -2;
		}
	}

	if (SrcSize < Height * ScanLine)
		return -4;

	if (!invalidRegion)
	{
		numRects = (Width + 63) / 64;
		numRects *= (Height + 63) / 64;
	}
	else
	{
		const int nr = region16_n_rects(invalidRegion);
		numRects = WINPR_ASSERTING_INT_CAST(uint32_t, nr);
	}

	if (numRects == 0)
		return 0;

	if (!Stream_EnsureRemainingCapacity(progressive->rects, numRects * sizeof(RFX_RECT)))
		return -5;
	rects = Stream_BufferAs(progressive->rects, RFX_RECT);
	if (invalidRegion)
	{
		const RECTANGLE_16* region_rects = region16_rects(invalidRegion, NULL);
		for (UINT32 idx = 0; idx < numRects; idx++)
		{
			const RECTANGLE_16* r = &region_rects[idx];
			RFX_RECT* rect = &rects[idx];

			rect->x = r->left;
			rect->y = r->top;
			rect->width = r->right - r->left;
			rect->height = r->bottom - r->top;
		}
	}
	else
	{
		UINT16 x = 0;
		UINT16 y = 0;

		for (UINT32 i = 0; i < numRects; i++)
		{
			RFX_RECT* r = &rects[i];
			r->x = x;
			r->y = y;

			WINPR_ASSERT(Width >= x);
			WINPR_ASSERT(Height >= y);
			r->width = MIN(64, WINPR_ASSERTING_INT_CAST(UINT16, Width - x));
			r->height = MIN(64, WINPR_ASSERTING_INT_CAST(UINT16, Height - y));

			if (x + 64UL >= Width)
			{
				y += 64;
				x = 0;
			}
			else
				x += 64;

			WINPR_ASSERT(r->x % 64 == 0);
			WINPR_ASSERT(r->y % 64 == 0);
			WINPR_ASSERT(r->width <= 64);
			WINPR_ASSERT(r->height <= 64);
		}
	}
	s = progressive->buffer;
	Stream_SetPosition(s, 0);

	progressive->rfx_context->mode = RLGR1;

	progressive->rfx_context->width = WINPR_ASSERTING_INT_CAST(UINT16, Width);
	progressive->rfx_context->height = WINPR_ASSERTING_INT_CAST(UINT16, Height);
	rfx_context_set_pixel_format(progressive->rfx_context, SrcFormat);
	message = rfx_encode_message(progressive->rfx_context, rects, numRects, pSrcData, Width, Height,
	                             ScanLine);
	if (!message)
	{
		WLog_ERR(TAG, "failed to encode rfx message");
		goto fail;
	}

	rc = progressive_rfx_write_message_progressive_simple(progressive, s, message);
	rfx_message_free(progressive->rfx_context, message);
	if (!rc)
		goto fail;

	const size_t pos = Stream_GetPosition(s);
	WINPR_ASSERT(pos <= UINT32_MAX);
	*pDstSize = (UINT32)pos;
	*ppDstData = Stream_Buffer(s);
	res = 1;
fail:
	return res;
}

BOOL progressive_context_reset(PROGRESSIVE_CONTEXT* WINPR_RESTRICT progressive)
{
	if (!progressive)
		return FALSE;

	return TRUE;
}

PROGRESSIVE_CONTEXT* progressive_context_new(BOOL Compressor)
{
	return progressive_context_new_ex(Compressor, 0);
}

PROGRESSIVE_CONTEXT* progressive_context_new_ex(BOOL Compressor, UINT32 ThreadingFlags)
{
	PROGRESSIVE_CONTEXT* progressive =
	    (PROGRESSIVE_CONTEXT*)winpr_aligned_calloc(1, sizeof(PROGRESSIVE_CONTEXT), 32);

	if (!progressive)
		return NULL;

	progressive->Compressor = Compressor;
	progressive->quantProgValFull.quality = 100;
	progressive->log = WLog_Get(TAG);
	if (!progressive->log)
		goto fail;
	progressive->rfx_context = rfx_context_new_ex(Compressor, ThreadingFlags);
	if (!progressive->rfx_context)
		goto fail;
	progressive->buffer = Stream_New(NULL, 1024);
	if (!progressive->buffer)
		goto fail;
	progressive->rects = Stream_New(NULL, 1024);
	if (!progressive->rects)
		goto fail;
	progressive->bufferPool = BufferPool_New(TRUE, (8192LL + 32LL) * 3LL, 16);
	if (!progressive->bufferPool)
		goto fail;
	progressive->SurfaceContexts = HashTable_New(TRUE);
	if (!progressive->SurfaceContexts)
		goto fail;

	{
		wObject* obj = HashTable_ValueObject(progressive->SurfaceContexts);
		WINPR_ASSERT(obj);
		obj->fnObjectFree = progressive_surface_context_free;
	}
	return progressive;
fail:
	WINPR_PRAGMA_DIAG_PUSH
	WINPR_PRAGMA_DIAG_IGNORED_MISMATCHED_DEALLOC
	progressive_context_free(progressive);
	WINPR_PRAGMA_DIAG_POP
	return NULL;
}

void progressive_context_free(PROGRESSIVE_CONTEXT* progressive)
{
	if (!progressive)
		return;

	Stream_Free(progressive->buffer, TRUE);
	Stream_Free(progressive->rects, TRUE);
	rfx_context_free(progressive->rfx_context);

	BufferPool_Free(progressive->bufferPool);
	HashTable_Free(progressive->SurfaceContexts);

	winpr_aligned_free(progressive);
}
