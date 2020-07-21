/*
 * Copyright (C) 2017 Chen Hung-Nien
 * Copyright (C) 2017 Weida Hi-Tech
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

#ifndef		__WHIFF_H__
#define		__WHIFF_H__

typedef		void*	WH_HANDLE;

/* since long is 4bytes on windows64, but is 8bytes on linux 64 */
typedef unsigned char 	BYTE; 
typedef unsigned short 	UINT16;
typedef unsigned int	UINT32;

/* Four-character code */
typedef UINT32 FOUR_CC;

/* Header
 * 4bytes: the fixed data RIFF.
 * 4bytes: little-endian 32-bit UINT32eger, size of entire file
 * 4bytes: file type WHIF
 */
typedef struct ChunkHeader{ 
	FOUR_CC riffID;
	UINT32 fileSize;
	FOUR_CC formType;
} CHUNK_HEADER; 


/*
 * Chunks : a block data 
 * 4bytes : the valid keywords of chunk are as following, FRMT, FRWR, CNFG, HDRS, FSBT, BINF, EXT1, EXT2
 *		FRMT: format chuck, store the parameters for using this file, it is a chunk muse be existed
 *		FRWR: firmware chunk, chunk id : 0x01
 *  		CNFG: config(parameters) chunk, chunk id: 0x02
 *		HDRS: header chunk, chunk id: 0x04
 *		FSBT: fastboot chunk, chunk id: 0x08
 *		BINF: bin chunk, if the bin chunk is existed, then other chunks will be ignored, chunk id: 0x10
 *		EXT1: external chunk 1, user defined chunk data, chunk id: 0x20
 *		EXT2: external chunk 2, user defined chunk data, chunk id: 0x40	
 *
 * 4bytes¡Glittle-endian 32-bit UINT32¡Ait means the size of this chunk,
 *		not include the header part.
 * Chunk data: the data of this block, align 4 bytes.
 *
 * 
 * versionNumber:  id1 | (id2 << 16)
 * attribute: 		0x01: AES encoded, 0x02: config_id
 */
typedef struct ChunkInfo{
	UINT32	targetStartAddr;
	UINT32	length;
	UINT32	sourceStartAddr;
	UINT32 	versionNumber;		
	UINT32	attribute;			
	UINT32	temp;
} CHUNK_INFO;

typedef struct ChunkData{ 
	FOUR_CC		ckID;
	UINT32		ckSize;
	CHUNK_INFO  chunkInfo;
	BYTE*		pChunkData;
} CHUNK_DATA; 

/* 
 * FRMT Format Chunk data format 
 *
 * ckID:			FRMT
 * ckSize:		the size of field <ckData> 
 * numberChunk:	the number of the chunk
 * enableFlag:		enable flag for chunks
 * checksum: 		checksum for all file
 * temp1:		for the feature used	
 * temp2: 		for the feature used
 */
typedef struct FormatChunk{ 
	FOUR_CC ckID;
	UINT32 ckSize;
	UINT32 numberChunk;
	UINT32 enableFlag;
	UINT32 checksum;
	UINT32 temp1;
	UINT32 temp2;
} FORMAT_CHUNK; 

typedef struct ChunkInfoEx{
	CHUNK_INFO	chuckInfo;
	BYTE*	pData;
  	UINT32 	length;
} CHUNK_INFO_EX;

#define		FOURCC_ID_RIFF		0x46464952
#define		FOURCC_ID_WHIF		0x46494857
#define		FOURCC_ID_FRMT		0x544D5246
#define		FOURCC_ID_FRWR		0x52575246
#define		FOURCC_ID_CNFG		0x47464E43
#define		FOURCC_ID_HDRS		0x53524448
#define		FOURCC_ID_FSBT		0x54425346
#define		FOURCC_ID_BINF		0x464E4942
#define		FOURCC_ID_RCVY		0x52435659
#define		FOURCC_ID_TSTB		0x54535442
#define		FOURCC_ID_EXTB		0x45585442

#define		CHUNK_ID_FRMT		0x00
#define		CHUNK_ID_FRWR		0x01
#define		CHUNK_ID_CNFG		0x02
#define		CHUNK_ID_HDRS		0x04
#define		CHUNK_ID_FSBT		0x08
#define		CHUNK_ID_BINF		0x10
#define		CHUNK_ID_RCVY		0x20
#define		CHUNK_ID_TSTB		0x40	
#define		CHUNK_ID_EXTB		0x80

typedef	struct WifFile {
	BYTE	*pdata;
	UINT32	data_len;
	FORMAT_CHUNK*	pformat_chunk;
} WIF_FILE;

/* __WHIFF_H__  */
#endif
