/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * RemoteFX Codec Library - RLGR
 *
 * Copyright 2011 Vic Lee
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

/**
 * This implementation of RLGR refers to
 * [MS-RDPRFX] 3.1.8.1.7.3 RLGR1/RLGR3 Pseudocode
 */

#include <freerdp/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winpr/assert.h>
#include <winpr/cast.h>
#include <winpr/crt.h>
#include <winpr/print.h>
#include <winpr/sysinfo.h>
#include <winpr/bitstream.h>
#include <winpr/intrin.h>

#include "rfx_bitstream.h"

#include "rfx_rlgr.h"

/* Constants used in RLGR1/RLGR3 algorithm */
#define KPMAX (80) /* max value for kp or krp */
#define LSGR (3)   /* shift count to convert kp to k */
#define UP_GR (4)  /* increase in kp after a zero run in RL mode */
#define DN_GR (6)  /* decrease in kp after a nonzero symbol in RL mode */
#define UQ_GR (3)  /* increase in kp after nonzero symbol in GR mode */
#define DQ_GR (3)  /* decrease in kp after zero symbol in GR mode */

/* Returns the least number of bits required to represent a given value */
#define GetMinBits(_val, _nbits) \
	do                           \
	{                            \
		UINT32 _v = (_val);      \
		(_nbits) = 0;            \
		while (_v)               \
		{                        \
			_v >>= 1;            \
			(_nbits)++;          \
		}                        \
	} while (0)

/*
 * Update the passed parameter and clamp it to the range [0, KPMAX]
 * Return the value of parameter right-shifted by LSGR
 */
static inline uint32_t UpdateParam(uint32_t* param, int32_t deltaP)
{
	WINPR_ASSERT(param);
	if (deltaP < 0)
	{
		const uint32_t udeltaP = WINPR_ASSERTING_INT_CAST(uint32_t, -deltaP);
		if (udeltaP > *param)
			*param = 0;
		else
			*param -= udeltaP;
	}
	else
		*param += WINPR_ASSERTING_INT_CAST(uint32_t, deltaP);

	if ((*param) > KPMAX)
		(*param) = KPMAX;
	return (*param) >> LSGR;
}

static BOOL g_LZCNT = FALSE;

static INIT_ONCE rfx_rlgr_init_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK rfx_rlgr_init(PINIT_ONCE once, PVOID param, PVOID* context)
{
	WINPR_UNUSED(once);
	WINPR_UNUSED(param);
	WINPR_UNUSED(context);

	g_LZCNT = IsProcessorFeaturePresentEx(PF_EX_LZCNT);
	return TRUE;
}

static INLINE UINT32 lzcnt_s(UINT32 x)
{
	if (!x)
		return 32;

	if (!g_LZCNT)
	{
		UINT32 y = 0;
		UINT32 n = 32;
		y = x >> 16;
		if (y != 0)
		{
			WINPR_ASSERT(n >= 16);
			n = n - 16;
			x = y;
		}
		y = x >> 8;
		if (y != 0)
		{
			WINPR_ASSERT(n >= 8);
			n = n - 8;
			x = y;
		}
		y = x >> 4;
		if (y != 0)
		{
			WINPR_ASSERT(n >= 4);
			n = n - 4;
			x = y;
		}
		y = x >> 2;
		if (y != 0)
		{
			WINPR_ASSERT(n >= 2);
			n = n - 2;
			x = y;
		}
		y = x >> 1;
		if (y != 0)
		{
			WINPR_ASSERT(n >= 2);
			return n - 2;
		}

		WINPR_ASSERT(n >= x);
		return n - x;
	}

	return __lzcnt(x);
}

int rfx_rlgr_decode(RLGR_MODE mode, const BYTE* WINPR_RESTRICT pSrcData, UINT32 SrcSize,
                    INT16* WINPR_RESTRICT pDstData, UINT32 rDstSize)
{
	uint32_t vk = 0;
	size_t run = 0;
	size_t cnt = 0;
	size_t size = 0;
	size_t offset = 0;
	INT16 mag = 0;
	UINT32 k = 0;
	UINT32 kp = 0;
	UINT32 kr = 0;
	UINT32 krp = 0;
	UINT16 code = 0;
	UINT32 sign = 0;
	UINT32 nIdx = 0;
	UINT32 val1 = 0;
	UINT32 val2 = 0;
	INT16* pOutput = NULL;
	wBitStream* bs = NULL;
	wBitStream s_bs = { 0 };
	const SSIZE_T DstSize = rDstSize;

	InitOnceExecuteOnce(&rfx_rlgr_init_once, rfx_rlgr_init, NULL, NULL);

	k = 1;
	kp = k << LSGR;

	kr = 1;
	krp = kr << LSGR;

	if ((mode != RLGR1) && (mode != RLGR3))
		mode = RLGR1;

	if (!pSrcData || !SrcSize)
		return -1;

	if (!pDstData || !DstSize)
		return -1;

	pOutput = pDstData;

	bs = &s_bs;

	BitStream_Attach(bs, pSrcData, SrcSize);
	BitStream_Fetch(bs);

	while ((BitStream_GetRemainingLength(bs) > 0) && ((pOutput - pDstData) < DstSize))
	{
		if (k)
		{
			/* Run-Length (RL) Mode */

			run = 0;

			/* count number of leading 0s */

			cnt = lzcnt_s(bs->accumulator);

			size_t nbits = BitStream_GetRemainingLength(bs);

			if (cnt > nbits)
				cnt = WINPR_ASSERTING_INT_CAST(uint32_t, nbits);

			vk = WINPR_ASSERTING_INT_CAST(uint32_t, cnt);

			while ((cnt == 32) && (BitStream_GetRemainingLength(bs) > 0))
			{
				BitStream_Shift32(bs);

				cnt = lzcnt_s(bs->accumulator);

				nbits = BitStream_GetRemainingLength(bs);

				if (cnt > nbits)
					cnt = nbits;

				WINPR_ASSERT(cnt + vk <= UINT32_MAX);
				vk += WINPR_ASSERTING_INT_CAST(uint32_t, cnt);
			}

			BitStream_Shift(bs, (vk % 32));

			if (BitStream_GetRemainingLength(bs) < 1)
				break;

			BitStream_Shift(bs, 1);

			while (vk--)
			{
				const UINT32 add = (1 << k); /* add (1 << k) to run length */
				run += add;

				/* update k, kp params */

				kp += UP_GR;

				if (kp > KPMAX)
					kp = KPMAX;

				k = kp >> LSGR;
			}

			/* next k bits contain run length remainder */

			if (BitStream_GetRemainingLength(bs) < k)
				break;

			bs->mask = ((1 << k) - 1);
			run += ((bs->accumulator >> (32 - k)) & bs->mask);
			BitStream_Shift(bs, k);

			/* read sign bit */

			if (BitStream_GetRemainingLength(bs) < 1)
				break;

			sign = (bs->accumulator & 0x80000000) ? 1 : 0;
			BitStream_Shift(bs, 1);

			/* count number of leading 1s */

			cnt = lzcnt_s(~(bs->accumulator));

			nbits = BitStream_GetRemainingLength(bs);

			if (cnt > nbits)
				cnt = nbits;

			vk = WINPR_ASSERTING_INT_CAST(uint32_t, cnt);

			while ((cnt == 32) && (BitStream_GetRemainingLength(bs) > 0))
			{
				BitStream_Shift32(bs);

				cnt = lzcnt_s(~(bs->accumulator));

				nbits = BitStream_GetRemainingLength(bs);

				if (cnt > nbits)
					cnt = nbits;

				WINPR_ASSERT(cnt + vk <= UINT32_MAX);
				vk += WINPR_ASSERTING_INT_CAST(uint32_t, cnt);
			}

			BitStream_Shift(bs, (vk % 32));

			if (BitStream_GetRemainingLength(bs) < 1)
				break;

			BitStream_Shift(bs, 1);

			/* next kr bits contain code remainder */

			if (BitStream_GetRemainingLength(bs) < kr)
				break;

			bs->mask = ((1 << kr) - 1);
			if (kr > 0)
				code = (UINT16)((bs->accumulator >> (32 - kr)) & bs->mask);
			else
				code = 0;
			BitStream_Shift(bs, kr);

			/* add (vk << kr) to code */

			code |= (vk << kr);

			if (!vk)
			{
				/* update kr, krp params */

				if (krp > 2)
					krp -= 2;
				else
					krp = 0;

				kr = krp >> LSGR;
			}
			else if (vk != 1)
			{
				/* update kr, krp params */

				krp += vk;

				if (krp > KPMAX)
					krp = KPMAX;

				kr = krp >> LSGR;
			}

			/* update k, kp params */

			if (kp > DN_GR)
				kp -= DN_GR;
			else
				kp = 0;

			k = kp >> LSGR;

			/* compute magnitude from code */

			if (sign)
				mag = WINPR_ASSERTING_INT_CAST(int16_t, (code + 1)) * -1;
			else
				mag = WINPR_ASSERTING_INT_CAST(int16_t, code + 1);

			/* write to output stream */

			offset = WINPR_ASSERTING_INT_CAST(size_t, (pOutput)-pDstData);
			size = run;

			if ((offset + size) > rDstSize)
				size = WINPR_ASSERTING_INT_CAST(size_t, DstSize) - offset;

			if (size)
			{
				ZeroMemory(pOutput, size * sizeof(INT16));
				pOutput += size;
			}

			if ((pOutput - pDstData) < DstSize)
			{
				*pOutput = mag;
				pOutput++;
			}
		}
		else
		{
			/* Golomb-Rice (GR) Mode */

			/* count number of leading 1s */

			cnt = lzcnt_s(~(bs->accumulator));

			size_t nbits = BitStream_GetRemainingLength(bs);

			if (cnt > nbits)
				cnt = nbits;

			vk = WINPR_ASSERTING_INT_CAST(uint32_t, cnt);

			while ((cnt == 32) && (BitStream_GetRemainingLength(bs) > 0))
			{
				BitStream_Shift32(bs);

				cnt = lzcnt_s(~(bs->accumulator));

				nbits = BitStream_GetRemainingLength(bs);

				if (cnt > nbits)
					cnt = nbits;

				WINPR_ASSERT(cnt + vk <= UINT32_MAX);
				vk += WINPR_ASSERTING_INT_CAST(uint32_t, cnt);
			}

			BitStream_Shift(bs, (vk % 32));

			if (BitStream_GetRemainingLength(bs) < 1)
				break;

			BitStream_Shift(bs, 1);

			/* next kr bits contain code remainder */

			if (BitStream_GetRemainingLength(bs) < kr)
				break;

			bs->mask = ((1 << kr) - 1);
			if (kr > 0)
				code = (UINT16)((bs->accumulator >> (32 - kr)) & bs->mask);
			else
				code = 0;
			BitStream_Shift(bs, kr);

			/* add (vk << kr) to code */

			code |= (vk << kr);

			if (!vk)
			{
				/* update kr, krp params */

				if (krp > 2)
					krp -= 2;
				else
					krp = 0;

				kr = (krp >> LSGR) & UINT32_MAX;
			}
			else if (vk != 1)
			{
				/* update kr, krp params */

				krp += vk;

				if (krp > KPMAX)
					krp = KPMAX;

				kr = krp >> LSGR;
			}

			if (mode == RLGR1) /* RLGR1 */
			{
				if (!code)
				{
					/* update k, kp params */

					kp += UQ_GR;

					if (kp > KPMAX)
						kp = KPMAX;

					k = kp >> LSGR;

					mag = 0;
				}
				else
				{
					/* update k, kp params */

					if (kp > DQ_GR)
						kp -= DQ_GR;
					else
						kp = 0;

					k = kp >> LSGR;

					/*
					 * code = 2 * mag - sign
					 * sign + code = 2 * mag
					 */

					if (code & 1)
						mag = WINPR_ASSERTING_INT_CAST(INT16, (code + 1) >> 1) * -1;
					else
						mag = WINPR_ASSERTING_INT_CAST(INT16, code >> 1);
				}

				if ((pOutput - pDstData) < DstSize)
				{
					*pOutput = mag;
					pOutput++;
				}
			}
			else if (mode == RLGR3) /* RLGR3 */
			{
				nIdx = 0;

				if (code)
				{
					mag = WINPR_ASSERTING_INT_CAST(int16_t, code);
					nIdx = 32 - lzcnt_s(WINPR_ASSERTING_INT_CAST(uint32_t, mag));
				}

				if (BitStream_GetRemainingLength(bs) < nIdx)
					break;

				bs->mask = ((1 << nIdx) - 1);
				if (nIdx > 0)
					val1 = ((bs->accumulator >> (32 - nIdx)) & bs->mask);
				else
					val1 = 0;
				BitStream_Shift(bs, nIdx);

				val2 = code - val1;

				if (val1 && val2)
				{
					/* update k, kp params */

					if (kp > 2 * DQ_GR)
						kp -= (2 * DQ_GR);
					else
						kp = 0;

					k = kp >> LSGR;
				}
				else if (!val1 && !val2)
				{
					/* update k, kp params */

					kp += (2 * UQ_GR);

					if (kp > KPMAX)
						kp = KPMAX;

					k = kp >> LSGR;
				}

				if (val1 & 1)
					mag = WINPR_ASSERTING_INT_CAST(int16_t, (val1 + 1) >> 1) * -1;
				else
					mag = WINPR_ASSERTING_INT_CAST(int16_t, val1 >> 1);

				if ((pOutput - pDstData) < DstSize)
				{
					*pOutput = mag;
					pOutput++;
				}

				if (val2 & 1)
					mag = WINPR_ASSERTING_INT_CAST(int16_t, (val2 + 1) >> 1) * -1;
				else
					mag = WINPR_ASSERTING_INT_CAST(int16_t, val2 >> 1);

				if ((pOutput - pDstData) < DstSize)
				{
					*pOutput = WINPR_ASSERTING_INT_CAST(int16_t, mag);
					pOutput++;
				}
			}
		}
	}

	offset = WINPR_ASSERTING_INT_CAST(size_t, (pOutput - pDstData));

	if (offset < rDstSize)
	{
		size = WINPR_ASSERTING_INT_CAST(size_t, DstSize) - offset;
		ZeroMemory(pOutput, size * 2);
		pOutput += size;
	}

	offset = WINPR_ASSERTING_INT_CAST(size_t, (pOutput - pDstData));

	if ((DstSize < 0) || (offset != (size_t)DstSize))
		return -1;

	return 1;
}

/* Returns the next coefficient (a signed int) to encode, from the input stream */
#define GetNextInput(_n)    \
	do                      \
	{                       \
		if (data_size > 0)  \
		{                   \
			(_n) = *data++; \
			data_size--;    \
		}                   \
		else                \
		{                   \
			(_n) = 0;       \
		}                   \
	} while (0)

/* Emit bitPattern to the output bitstream */
#define OutputBits(numBits, bitPattern) rfx_bitstream_put_bits(bs, bitPattern, numBits)

/* Emit a bit (0 or 1), count number of times, to the output bitstream */
static inline void OutputBit(RFX_BITSTREAM* bs, uint32_t count, UINT8 bit)
{
	UINT16 _b = ((bit) ? 0xFFFF : 0);
	const uint32_t rem = count % 16;
	for (uint32_t x = 0; x < count - rem; x += 16)
		rfx_bitstream_put_bits(bs, _b, 16);

	if (rem > 0)
		rfx_bitstream_put_bits(bs, _b, rem);
}

/* Converts the input value to (2 * abs(input) - sign(input)), where sign(input) = (input < 0 ? 1 :
 * 0) and returns it */
static inline UINT32 Get2MagSign(INT32 input)
{
	if (input >= 0)
		return WINPR_ASSERTING_INT_CAST(UINT32, 2 * input);
	return WINPR_ASSERTING_INT_CAST(UINT32, -2 * input - 1);
}

/* Outputs the Golomb/Rice encoding of a non-negative integer */
#define CodeGR(krp, val) rfx_rlgr_code_gr(bs, krp, val)

static void rfx_rlgr_code_gr(RFX_BITSTREAM* bs, uint32_t* krp, UINT32 val)
{
	uint32_t kr = *krp >> LSGR;

	/* unary part of GR code */

	const uint32_t vk = val >> kr;
	OutputBit(bs, vk, 1);
	OutputBit(bs, 1, 0);

	/* remainder part of GR code, if needed */
	if (kr)
	{
		OutputBits(kr, val & ((1 << kr) - 1));
	}

	/* update krp, only if it is not equal to 1 */
	if (vk == 0)
	{
		(void)UpdateParam(krp, -2);
	}
	else if (vk > 1)
	{
		(void)UpdateParam(krp, WINPR_CXX_COMPAT_CAST(int32_t, vk));
	}
}

int rfx_rlgr_encode(RLGR_MODE mode, const INT16* WINPR_RESTRICT data, UINT32 data_size,
                    BYTE* WINPR_RESTRICT buffer, UINT32 buffer_size)
{
	uint32_t k = 0;
	uint32_t kp = 0;
	uint32_t krp = 0;
	RFX_BITSTREAM* bs = NULL;

	if (!(bs = (RFX_BITSTREAM*)winpr_aligned_calloc(1, sizeof(RFX_BITSTREAM), 32)))
		return 0;

	rfx_bitstream_attach(bs, buffer, buffer_size);

	/* initialize the parameters */
	k = 1;
	kp = 1 << LSGR;
	krp = 1 << LSGR;

	/* process all the input coefficients */
	while (data_size > 0)
	{
		int input = 0;

		if (k)
		{
			uint32_t numZeros = 0;
			uint32_t runmax = 0;
			BYTE sign = 0;

			/* RUN-LENGTH MODE */

			/* collect the run of zeros in the input stream */
			numZeros = 0;
			GetNextInput(input);
			while (input == 0 && data_size > 0)
			{
				numZeros++;
				GetNextInput(input);
			}

			// emit output zeros
			runmax = 1 << k;
			while (numZeros >= runmax)
			{
				OutputBit(bs, 1, 0); /* output a zero bit */
				numZeros -= runmax;
				k = UpdateParam(&kp, UP_GR); /* update kp, k */
				runmax = 1 << k;
			}

			/* output a 1 to terminate runs */
			OutputBit(bs, 1, 1);

			/* output the remaining run length using k bits */
			OutputBits(k, numZeros);

			/* note: when we reach here and the last byte being encoded is 0, we still
			   need to output the last two bits, otherwise mstsc will crash */

			/* encode the nonzero value using GR coding */
			const UINT32 mag =
			    (UINT32)(input < 0 ? -input : input); /* absolute value of input coefficient */
			sign = (input < 0 ? 1 : 0);         /* sign of input coefficient */

			OutputBit(bs, 1, sign);          /* output the sign bit */
			CodeGR(&krp, mag ? mag - 1 : 0); /* output GR code for (mag - 1) */

			k = UpdateParam(&kp, -DN_GR);
		}
		else
		{
			/* GOLOMB-RICE MODE */

			if (mode == RLGR1)
			{
				UINT32 twoMs = 0;

				/* RLGR1 variant */

				/* convert input to (2*magnitude - sign), encode using GR code */
				GetNextInput(input);
				twoMs = Get2MagSign(input);
				CodeGR(&krp, twoMs);

				/* update k, kp */
				/* NOTE: as of Aug 2011, the algorithm is still wrongly documented
				   and the update direction is reversed */
				if (twoMs)
				{
					k = UpdateParam(&kp, -DQ_GR);
				}
				else
				{
					k = UpdateParam(&kp, UQ_GR);
				}
			}
			else /* mode == RLGR3 */
			{
				UINT32 twoMs1 = 0;
				UINT32 twoMs2 = 0;
				UINT32 sum2Ms = 0;
				UINT32 nIdx = 0;

				/* RLGR3 variant */

				/* convert the next two input values to (2*magnitude - sign) and */
				/* encode their sum using GR code */

				GetNextInput(input);
				twoMs1 = Get2MagSign(input);
				GetNextInput(input);
				twoMs2 = Get2MagSign(input);
				sum2Ms = twoMs1 + twoMs2;

				CodeGR(&krp, sum2Ms);

				/* encode binary representation of the first input (twoMs1). */
				GetMinBits(sum2Ms, nIdx);
				OutputBits(nIdx, twoMs1);

				/* update k,kp for the two input values */

				if (twoMs1 && twoMs2)
				{
					k = UpdateParam(&kp, -2 * DQ_GR);
				}
				else if (!twoMs1 && !twoMs2)
				{
					k = UpdateParam(&kp, 2 * UQ_GR);
				}
			}
		}
	}

	rfx_bitstream_flush(bs);
	uint32_t processed_size = rfx_bitstream_get_processed_bytes(bs);
	winpr_aligned_free(bs);

	return WINPR_ASSERTING_INT_CAST(int, processed_size);
}
