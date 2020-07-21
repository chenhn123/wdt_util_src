/*
 * Copyright (C) 2020 Chen Hung-Nien
 * Copyright (C) 2020 Weida Hi-Tech
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

#ifndef	__WDT8760_DEF_H__
#define	__WDT8760_DEF_H__

/* 
 * device working modes 
 * W8760_MODE_INIT: This mode only exists during ROM and fastboot. It cannot be set as the target mode.
 * W8760_MODE_SENSING: Normal sensing
 * W8760_MODE_DOZE: Device sleeps most time and does sensing in longer period.
 * W8760_MODE_SLEEP: Both device and sensor are in sleep.
 * W8760_MODE_ISP: The device is in ISP mode. Unable to switch to other mode.
 * W8760_MODE_COMMAND: The device is waiting for memory access or flash parameter read/write commands. Especially from GUI tools.
 * W8760_MODE_FLASH_PROGRAM: The device is handling flash firmware erase/program commands. This mode has no return until reboot.
 * W8760_MODE_PARAMETER_PROGRAM: For executing parameter erase/program commands from host.
 * W8760_MODE_MEASUREMENT: Do factory MP testing/noise detection/TP RC measurement.
 * W8760_MODE_ATE: The device is in ATE mode. This mode has no return until reboot.
 * W8760_MODE_NOISE_DETECTION: A special in a special noise-detection firmware
 */
#define W8760_MODE_INIT						0		
#define W8760_MODE_SENSING					1
#define W8760_MODE_DOZE						2
#define W8760_MODE_SLEEP					3
#define W8760_MODE_ISP						0x10
#define W8760_MODE_COMMAND					0x90
#define W8760_MODE_FLASH_PROGRAM			0x96
#define W8760_MODE_PARAMETER_PROGRAM		0x99
#define W8760_MODE_MEASUREMENT				0x9F
#define W8760_MODE_ATE						0xA0
#define W8760_MODE_NOISE_DETECTION			0xB0
#define W8760_MODE_UNDEFINED				0xFF	

#define W8760_DEVICE_INFO 		0xF2
#define W8760_COMMAND9 			0x06
#define W8760_COMMAND63			0x07
#define W8760_BLOCK63			0x0B
#define W8760_PIPE9 			0x0D
#define W8760_PIPE63			0x0E

#define W8760_FLASH_SIZE 		(256 * 1024)
#define W8760_FLASH_PAGE_SIZE 	(256)
#define W8760_FLASH_SECTOR_SIZE (4 * 1024)
#define W8760_FLASH_SBLOCK_SIZE (32 * 1024)
#define W8760_FLASH_LBLOCK_SIZE (64 * 1024)


#define W8760_USB_MAX_PAYLOAD_SIZE			63
#define W8760_USB_SHORT_PIPE_PAYLOAD_SIZE	9
#define W8760_USB_LONG_PIPE_PAYLOAD_SIZE	63

#define	W8760_MP_STATUS_BUSY	0xFE
#define W8760_MP_STATUS_OK		0x80

#define W8760_MIN(a,b) (((a)<(b))?(a):(b))
#define W8760_MAX(a,b) (((a)>(b))?(a):(b))


#pragma pack(push, 1)
typedef struct PctData
{
	BYTE revision;
	BYTE n_cd;
	BYTE n_cs;
	BYTE transform_flags;
	BYTE x1;
	BYTE xn;
	BYTE y1;
	BYTE yn;
	UINT16 width;	
	UINT16 height;	
} W8760_PCT_DATA;

typedef	struct ReportFeatureDevInfo
{
	UINT32		firmware_id;
	UINT32		hardware_id;
	UINT32		serial_no;
	BYTE		n_touches_usb;
	BYTE		n_bytes_touch;
	BYTE		reserved0;
	BYTE		platform_id[8];
	BYTE		rom_signature[8];

	BYTE 		protocol_version;
	BYTE		firmware_rev_ext;
	UINT16 		parameter_section_size;
	UINT16 		parameter_mapid;

	BYTE 		program_name_fourcc[4];
	BYTE		trackingid_or_old_part_num[8];
	BYTE		part_number_ext[8];
	
} W8760_REPORT_FEATURE_DEVINFO;

typedef struct SectionMapAddr
{
	UINT32 		ParameterMap;
	UINT32 		MainLoader;
	UINT32		Parameter;
	UINT32 		Descriptors; 
	UINT32 		PowerOnReference;
	UINT32 		ParameterBackup;
	UINT32		DescriptorsBackup;
	UINT32		TemporaryParameter;
} W8760_SECTION_MAP_ADDR;

typedef struct FlashSectionHeader
{
	UINT16		Checksum;		
	UINT16		HeaderChecksum;	
	UINT32		PayloadSize;
	UINT32		Param0;
	UINT32		Param1;
} W8760_FLASH_SECTION_HEADER;
#pragma pack(pop)

enum W8760_IspCommandType 
{
	W8760_SET_MEMORY_ADDRESS = 0xC0,
	W8760_READ_WORDS = 0xC1,
	W8760_READ_HALFWORDS = 0xC2,
	W8760_READ_BYTES = 0xC3,
	W8760_WRITE_WORDS = 0xC4,
	W8760_WRITE_HALFWORDS = 0xC5,
	W8760_WRITE_BYTES = 0xC6,
	W8760_READ_BUFFERED_RESPONSE = 0xC7,
	W8760_GET_DEVICE_INFO = 0xC8,
	W8760_GET_DEVICE_STATUS = 0xC9,
	W8760_SET_DEVICE_MODE = 0xCA,
	W8760_REBOOT = 0xCE,
	W8760_GET_HID_DESCRIPTOR_REGISTER = 0xCF,
	
	W8760_SET_FLASH_ADDRESS = 0xD0,
	W8760_ERASE_FLASH = 0xD2,
	W8760_WRITE_FLASH = 0xD3,
	W8760_PROTECT_FLASH = 0xD4,
	W8760_CALCULATE_FLASH_CHECKSUM = 0xD5,
	W8760_SET_BLOCK_ACCESS = 0xE0,
	W8760_BLOCK_READ = 0xE1,
	W8760_BLOCK_WRITE = 0xE2,
	W8760_BLOCK_CHECKSUM = 0xE3,
	W8760_READ_PIPE = 0xE4,
};

enum W8760_MainCommandType 
{
	W8760_READ_PARAMETER_PAGE = 0xB4,
};

enum W8760_DeviceStatusBits
{
	W8760_COMMAND_BUSY = 0x01,
	W8760_SOFT_RESET = 0x02,
};

enum W8760_FlashProtect
{
	W8760_ProtectNone = 0, 					  
	W8760_UnprotectAll512k = 0,

	W8760_ProtectLower256k = 0x002C,			
	W8760_UnprotectUpper256k = 0x002C,

	W8760_ProtectUpper256k = 0x000C,			
	W8760_UnprotectLower256k = 0x000C,

	W8760_ProtectUpper384k = 0x4028,			
	W8760_UnprotectLower128k = 0x4028,

	W8760_ProtectUpper128k = 0x0008,			
	W8760_UnprotectLower384k = 0x0008,

	W8760_ProtectUpper4k = 0x0044, 		
	W8760_UnprotectLower508k = 0x0044,

	W8760_ProtectAll512k = 0x007C, 		
	W8760_UnprotectNone = 0x007C,
};

typedef	union
{
	struct {
		BYTE	rpt_id;
		BYTE	type;
		union
		{
			UINT16 size;
			UINT16 offset;
		};
		BYTE	data[60];	
	} DD;
	BYTE	buffer[64];
} W8760_WRITE_DATA;

typedef	union
{
	struct {
		BYTE	rpt_id;
		BYTE	type;
		UINT16	size;
		UINT32	reserved;	
	} DD;
	BYTE	buffer[8];
} W8760_REQ_READ;

typedef	union
{
	struct {
		BYTE	rpt_id;
		BYTE	type;
		UINT16	checksum;
		BYTE	data[60];	
	} DD;
	BYTE	buffer[64];
} W8760_READ_DATA;

/* __WDT8760_DEF_H__ */
#endif
