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




#ifndef	__WDT8790_DEF_H__
#define	__WDT8790_DEF_H__



// device working modes
// This mode only exists during ROM and fastboot. It cannot be set as the target mode.
#define W8790_MODE_INIT						0		
// Normal sensing
#define W8790_MODE_SENSING					1		
// Device sleeps most time and does sensing in longer period.
#define W8790_MODE_DOZE						2		
// The device is waiting for memory access or flash parameter read/write commands. Especially from GUI tools.
#define W8790_MODE_COMMAND					0x90	
// The device is handling flash firmware erase/program commands. This mode has no return until reboot.
#define W8790_MODE_FLASH_PROGRAM				0x96	

// Command 1-byte ID + 9 bytes payload
#define W8790_COMMAND9 			0x06		
// Command 1-byte ID + 63 bytes payload
#define W8790_COMMAND63			0x07
// Block Access 1-byte ID + 63 bytes payload
#define W8790_BLOCK63			0x0B
// 1-byte ID + 9 bytes payload

#define W8790_FLASH_SIZE 		(256 * 1024)
#define W8790_FLASH_PAGE_SIZE 	(256)
#define W8790_FLASH_SECTOR_SIZE (4 * 1024)
#define W8790_FLASH_SBLOCK_SIZE (32 * 1024)
#define W8790_FLASH_LBLOCK_SIZE (64 * 1024)


#define W8790_USB_MAX_PAYLOAD_SIZE			63


enum W8790_IspCommandType
{
	W8790_SET_MEMORY_ADDRESS = 0xC0,
	W8790_READ_WORDS = 0xC1,
	W8790_READ_HALFWORDS = 0xC2,
	W8790_READ_BYTES = 0xC3,
	W8790_WRITE_WORDS = 0xC4,
	W8790_WRITE_HALFWORDS = 0xC5,
	W8790_WRITE_BYTES = 0xC6,
	W8790_READ_BUFFERED_RESPONSE = 0xC7,
	W8790_GET_DEVICE_INFO = 0xC8,
	W8790_GET_DEVICE_STATUS = 0xC9,
	W8790_SET_DEVICE_MODE = 0xCA,
	W8790_PING = 0xCB,
	W8790_CALL_FUNCTION = 0xCC,
	W8790_READ_PARAMETER_TABLE_INFO = 0xCD,
	W8790_REBOOT = 0xCE,

	W8790_SET_FLASH_ADDRESS = 0xD0,
	W8790_READ_FLASH = 0xD1,
	W8790_ERASE_FLASH = 0xD2,
	W8790_WRITE_FLASH = 0xD3,
	W8790_PROTECT_FLASH = 0xD4,
	W8790_CALCULATE_FLASH_CHECKSUM = 0xD5,

	W8790_SET_BLOCK_ACCESS = 0xE0,
	W8790_BLOCK_READ = 0xE1,
	W8790_BLOCK_WRITE = 0xE2,
	W8790_BLOCK_CHECKSUM = 0xE3,
	W8790_READ_PIPE = 0xE4,
	W8790_RUN_PROGRAM_FROM_BACKGROUND = 0xE5,
	W8790_ESCAPE_FROM_FLASH_MODE = 0xE6,
	W8790_BATCH_WRITE_FLASH = 0xE7,
};

enum W8790_MainCommandType
{
	W8790_CAPTURE_TOUCH_SIGNAL = 0xB0,
	W8790_STORE_PARAMETERS = 0xB1,
	W8790_APPLY_PARAMETERS = 0xB2,
	W8790_MODIFY_BUFFERED_PARAMETERS = 0xB3,
	W8790_READ_PARAMETER_PAGE = 0xB4,

};



enum W8790_DeviceStatusBits
{
	W8790_COMMAND_BUSY = 0x01,
	W8790_SOFT_RESET = 0x02,
};

enum W8790_BlockAccessDataType
{
	W8790_ParameterMap = 0x00,
	W8790_FirmwareBinary = 0x01,
	W8790_SRamBuffer = 0x02,
	W8790_Image = 0x03,
	W8790_Regions = 0x04,

	W8790_PrimaryParameter = 0x08,
	W8790_ExtendedParameter = 0x09,
	W8790_MeasurementResult = 0x10,

	W8790_FlashBatchWrite = 0x20,    
	W8790_Ram = 0x21,    // Supported in ROM code only
	W8790_Flash = 0x22,   // Supported in ROM code only


};



enum W8790_ParameterTableType
{
	W8790_Primary = 0,
	W8790_Temporary = 1,
	W8790_Current = 0xFF,
};





enum W8790_FlashProtect
{
	// All 512kB unprotected
	W8790_ProtectNone = 0,
	W8790_UnprotectAll512k = 0,

	// 0x000000 - 0x03FFFF : lower 256kB protected, higher 256kB unprotected
	W8790_ProtectLower256k = 0x002C,
	W8790_UnprotectUpper256k = 0x002C,

	// 0x040000 - 0x07FFFF : lower 256kB unprotected, higher 256kB protected
	W8790_ProtectUpper256k = 0x000C,
	W8790_UnprotectLower256k = 0x000C,

	// 0x020000 - 0x07FFFF : lower 128kB unprotected, higher 384kB protected
	W8790_ProtectUpper384k = 0x4028,
	W8790_UnprotectLower128k = 0x4028,

	// 0x060000 - 0x07FFFF	: lower 384kB unprotected, higher 128kB protected
	W8790_ProtectUpper128k = 0x0008,
	W8790_UnprotectLower384k = 0x0008,

	// 0x07F000 - 0x07FFFF	: lower 508kB unprotected, higher 4kB protected
	W8790_ProtectUpper4k = 0x0044,
	W8790_UnprotectLower508k = 0x0044,

	// 0x000000 - 0x07FFFF : All 512kB protected
	W8790_ProtectAll512k = 0x007C,
	W8790_UnprotectNone = 0x007C,
};

typedef	struct DevInfo_8790_t
{
	UINT32		firmware_version;
	UINT32		hardware_version;
	UINT32		serial_number;
	BYTE		max_touches;
	BYTE		firmware_revision_ext;
	BYTE		partition;
	BYTE		partition_format_revision;

	BYTE		part_number[16];
	BYTE		rom_signature[8];
	BYTE		program_name_fourcc[4];
	BYTE		tracking_id[8];

} W8790_DEV_INFO;




typedef struct FlashSectionHeader_8790_t
{
	// for payload
	UINT16		Checksum;
	// only for header
	UINT16		HeaderChecksum;
	UINT32		PayloadSize;
	UINT32		Param0;
	UINT32		Param1;
} W8790_FLASH_SECTION_HEADER;

 
typedef struct FlashMapAddr_8790_t
{
	UINT32 		ParameterMap;
	UINT32 		MainLoader;
	UINT32		ParameterPrimary;
	UINT32 		ParameterExtended;        
	UINT32 		ParameterPrivate;
} W8790_FLASH_MAP;


typedef struct ParameterTableInfo_8790_t
{
	UINT16 PMapID;
	UINT16 PrimarySector;
	UINT16 PrimarySize;
	UINT16 ExtendedSector;
	UINT16 ExtendedSize;
}W8790_PARAMETER_INFO;




typedef struct ParameterCoordinatePage_8790_t
{
	BYTE revision;
	BYTE n_cd;
	BYTE n_cs;
	BYTE transform_flags;
	BYTE x1;
	BYTE xn;
	BYTE y1;
	BYTE yn;
	BYTE width;    // in unit of 0.1mm
	BYTE height;   // in unit of 0.1mm
}W8790_PCT;



#endif		// __WDT8790_DEF_H__
