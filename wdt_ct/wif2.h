/*
 * Copyright (C) 2022 Randy Lai
 * Copyright (C) 2022 Weida Hi-Tech
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef		__wif2_H__
#define		__wif2_H__

#include "wdt_dev_api.h"


#define	FOURCC_ID_WIF2	0x32464957
#define	FOURCC_ID_FBIN	0x4e494246
#define	FOURCC_ID_FSUM	0x4d555346
#define	FOURCC_ID_FCRC  0x43524336
#define	FOURCC_ID_INFO	0x4f464e49


typedef struct WIF2ChunkHeader
{
	UINT32 FourCC;
	UINT32 Size; // payload size
}WIF2_Chunk_Header;

typedef struct WIF2FlashSpace
{
	UINT32 Address;
	UINT32 Size;
}WIF2_Flash_Space;


typedef struct WIF2FlashBinaryChunk {
	WIF2_Chunk_Header Header;
	WIF2_Flash_Space SpaceToErase;
	WIF2_Flash_Space Binary;
	BYTE*  BinaryData;
}WIF2_FlashBinary_Chunk;

typedef struct WIF2InfoChunk {
	WIF2_Chunk_Header Header;
	BYTE* BinaryData;
}WIF2_Info_Chunk;


struct WIF2FlashNode {
	WIF2_Flash_Space Space;
	struct WIF2FlashNode* Next;
};


typedef struct WIF2FlashChecksumChunk {
	WIF2_Chunk_Header Header;
	UINT32 InitSum;
	UINT32 ExpectedSum;
	WIF2FlashNode* Spaces;

}WIF2_Flash_Checksum_Chunk;

typedef	struct WifFile2 {
	BYTE* pdata;
	UINT32	data_len;
} WIF_FILE2;

int update_fw_by_wif2(WDT_DEV *pdev, char *path);
int show_wif2_info(char *path);

#endif
