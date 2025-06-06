/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * GDI Shape Functions
 *
 * Copyright 2010-2011 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 * Copyright 2016 Armin Novak <armin.novak@thincast.com>
 * Copyright 2016 Thincast Technologies GmbH
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <freerdp/freerdp.h>
#include <freerdp/gdi/gdi.h>

#include <freerdp/gdi/bitmap.h>
#include <freerdp/gdi/region.h>
#include <freerdp/gdi/shape.h>

#include <freerdp/log.h>

#include "clipping.h"
#include "../gdi/gdi.h"

#define TAG FREERDP_TAG("gdi.shape")

static void Ellipse_Bresenham(HGDI_DC hdc, int x1, int y1, int x2, int y2)
{
	INT32 e = 0;
	INT32 e2 = 0;
	INT32 dx = 0;
	INT32 dy = 0;
	INT32 a = 0;
	INT32 b = 0;
	INT32 c = 0;
	a = (x1 < x2) ? x2 - x1 : x1 - x2;
	b = (y1 < y2) ? y2 - y1 : y1 - y2;
	c = b & 1;
	dx = 4 * (1 - a) * b * b;
	dy = 4 * (c + 1) * a * a;
	e = dx + dy + c * a * a;

	if (x1 > x2)
	{
		x1 = x2;
		x2 += a;
	}

	if (y1 > y2)
		y1 = y2;

	y1 += (b + 1) / 2;
	y2 = y1 - c;
	a *= 8 * a;
	c = 8 * b * b;

	do
	{
		gdi_SetPixel(hdc, WINPR_ASSERTING_INT_CAST(UINT32, x2),
		             WINPR_ASSERTING_INT_CAST(UINT32, y1), 0);
		gdi_SetPixel(hdc, WINPR_ASSERTING_INT_CAST(UINT32, x1),
		             WINPR_ASSERTING_INT_CAST(UINT32, y1), 0);
		gdi_SetPixel(hdc, WINPR_ASSERTING_INT_CAST(UINT32, x1),
		             WINPR_ASSERTING_INT_CAST(UINT32, y2), 0);
		gdi_SetPixel(hdc, WINPR_ASSERTING_INT_CAST(UINT32, x2),
		             WINPR_ASSERTING_INT_CAST(UINT32, y2), 0);
		e2 = 2 * e;

		if (e2 >= dx)
		{
			x1++;
			x2--;
			e += dx += c;
		}

		if (e2 <= dy)
		{
			y1++;
			y2--;
			e += dy += a;
		}
	} while (x1 <= x2);

	while (y1 - y2 < b)
	{
		y1++;
		y2--;

		gdi_SetPixel(hdc, WINPR_ASSERTING_INT_CAST(uint32_t, x1 - 1),
		             WINPR_ASSERTING_INT_CAST(uint32_t, y1), 0);
		gdi_SetPixel(hdc, WINPR_ASSERTING_INT_CAST(uint32_t, x1 - 1),
		             WINPR_ASSERTING_INT_CAST(uint32_t, y2), 0);
	}
}

/**
 * Draw an ellipse
 * msdn{dd162510}
 *
 * @param hdc device context
 * @param nLeftRect x1
 * @param nTopRect y1
 * @param nRightRect x2
 * @param nBottomRect y2
 *
 * @return nonzero if successful, 0 otherwise
 */
BOOL gdi_Ellipse(HGDI_DC hdc, int nLeftRect, int nTopRect, int nRightRect, int nBottomRect)
{
	Ellipse_Bresenham(hdc, nLeftRect, nTopRect, nRightRect, nBottomRect);
	return TRUE;
}

/**
 * Fill a rectangle with the given brush.
 * msdn{dd162719}
 *
 * @param hdc device context
 * @param rect rectangle
 * @param hbr brush
 *
 * @return nonzero if successful, 0 otherwise
 */

BOOL gdi_FillRect(HGDI_DC hdc, const GDI_RECT* rect, HGDI_BRUSH hbr)
{
	UINT32 color = 0;
	UINT32 dstColor = 0;
	BOOL monochrome = FALSE;
	INT32 nXDest = 0;
	INT32 nYDest = 0;
	INT32 nWidth = 0;
	INT32 nHeight = 0;
	const BYTE* srcp = NULL;
	DWORD formatSize = 0;
	gdi_RectToCRgn(rect, &nXDest, &nYDest, &nWidth, &nHeight);

	if (!hdc || !hbr)
		return FALSE;

	if (!gdi_ClipCoords(hdc, &nXDest, &nYDest, &nWidth, &nHeight, NULL, NULL))
		return TRUE;

	switch (hbr->style)
	{
		case GDI_BS_SOLID:
			color = hbr->color;

			for (INT32 x = 0; x < nWidth; x++)
			{
				BYTE* dstp = gdi_get_bitmap_pointer(hdc, nXDest + x, nYDest);

				if (dstp)
					FreeRDPWriteColor(dstp, hdc->format, color);
			}

			srcp = gdi_get_bitmap_pointer(hdc, nXDest, nYDest);
			formatSize = FreeRDPGetBytesPerPixel(hdc->format);

			for (INT32 y = 1; y < nHeight; y++)
			{
				BYTE* dstp = gdi_get_bitmap_pointer(hdc, nXDest, nYDest + y);
				memcpy(dstp, srcp, 1ull * WINPR_ASSERTING_INT_CAST(size_t, nWidth) * formatSize);
			}

			break;

		case GDI_BS_HATCHED:
		case GDI_BS_PATTERN:
			monochrome = (hbr->pattern->format == PIXEL_FORMAT_MONO);
			formatSize = FreeRDPGetBytesPerPixel(hbr->pattern->format);

			for (INT32 y = 0; y < nHeight; y++)
			{
				for (INT32 x = 0; x < nWidth; x++)
				{
					const size_t yOffset =
					    ((1ULL * WINPR_ASSERTING_INT_CAST(size_t, nYDest) +
					      WINPR_ASSERTING_INT_CAST(size_t, y)) *
					     WINPR_ASSERTING_INT_CAST(size_t, hbr->pattern->width) %
					     WINPR_ASSERTING_INT_CAST(size_t, hbr->pattern->height)) *
					    formatSize;
					const size_t xOffset = ((1ULL * WINPR_ASSERTING_INT_CAST(size_t, nXDest) +
					                         WINPR_ASSERTING_INT_CAST(size_t, x)) %
					                        WINPR_ASSERTING_INT_CAST(size_t, hbr->pattern->width)) *
					                       formatSize;
					const BYTE* patp = &hbr->pattern->data[yOffset + xOffset];

					if (monochrome)
					{
						if (*patp == 0)
							dstColor = hdc->bkColor;
						else
							dstColor = hdc->textColor;
					}
					else
					{
						dstColor = FreeRDPReadColor(patp, hbr->pattern->format);
						dstColor =
						    FreeRDPConvertColor(dstColor, hbr->pattern->format, hdc->format, NULL);
					}

					BYTE* dstp = gdi_get_bitmap_pointer(hdc, nXDest + x, nYDest + y);
					if (dstp)
						FreeRDPWriteColor(dstp, hdc->format, dstColor);
				}
			}

			break;

		default:
			break;
	}

	if (!gdi_InvalidateRegion(hdc, nXDest, nYDest, nWidth, nHeight))
		return FALSE;

	return TRUE;
}

/**
 * Draw a polygon
 * msdn{dd162814}
 * @param hdc device context
 * @param lpPoints array of points
 * @param nCount number of points
 * @return nonzero if successful, 0 otherwise
 */
BOOL gdi_Polygon(WINPR_ATTR_UNUSED HGDI_DC hdc, WINPR_ATTR_UNUSED GDI_POINT* lpPoints,
                 WINPR_ATTR_UNUSED int nCount)
{
	WLog_ERR(TAG, "Not implemented!");
	return FALSE;
}

/**
 * Draw a series of closed polygons
 * msdn{dd162818}
 * @param hdc device context
 * @param lpPoints array of series of points
 * @param lpPolyCounts array of number of points in each series
 * @param nCount count of number of points in lpPolyCounts
 * @return nonzero if successful, 0 otherwise
 */
BOOL gdi_PolyPolygon(WINPR_ATTR_UNUSED HGDI_DC hdc, WINPR_ATTR_UNUSED GDI_POINT* lpPoints,
                     WINPR_ATTR_UNUSED int* lpPolyCounts, WINPR_ATTR_UNUSED int nCount)
{
	WLog_ERR(TAG, "Not implemented!");
	return FALSE;
}

BOOL gdi_Rectangle(HGDI_DC hdc, INT32 nXDst, INT32 nYDst, INT32 nWidth, INT32 nHeight)
{
	UINT32 color = 0;

	if (!gdi_ClipCoords(hdc, &nXDst, &nYDst, &nWidth, &nHeight, NULL, NULL))
		return TRUE;

	color = hdc->textColor;

	for (INT32 y = 0; y < nHeight; y++)
	{
		BYTE* dstLeft = gdi_get_bitmap_pointer(hdc, nXDst, nYDst + y);
		BYTE* dstRight = gdi_get_bitmap_pointer(hdc, nXDst + nWidth - 1, nYDst + y);

		if (dstLeft)
			FreeRDPWriteColor(dstLeft, hdc->format, color);

		if (dstRight)
			FreeRDPWriteColor(dstRight, hdc->format, color);
	}

	for (INT32 x = 0; x < nWidth; x++)
	{
		BYTE* dstTop = gdi_get_bitmap_pointer(hdc, nXDst + x, nYDst);
		BYTE* dstBottom = gdi_get_bitmap_pointer(hdc, nXDst + x, nYDst + nHeight - 1);

		if (dstTop)
			FreeRDPWriteColor(dstTop, hdc->format, color);

		if (dstBottom)
			FreeRDPWriteColor(dstBottom, hdc->format, color);
	}

	return FALSE;
}
