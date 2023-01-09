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

#ifndef	__W8755_DEF_H__
#define	__W8755_DEF_H__


#define		EXEC_I2C_NO_REPEAT_START	0x100
#define		EXEC_I2C_REDUNDANT		0x200




typedef struct WeidaDeviceInfoNew
{
	UINT32		protocol_version;
	UINT32		firmware_id;
	UINT32 		status;
	int		config_size;
	UINT32		parameter_map_sum;
	UINT32		firmware_revision;
	int		max_points;
	int		bytes_per_point;
	UINT32		customer_config_id;
} W8755_DEV_INFO_NEW;

typedef	struct WeidaDeviceInfo
{
	UINT32		firmware_id;
	UINT32		hardware_id;
	UINT32		serial_number;
	UINT32		max_points;
	UINT32		bytes_per_point;
	UINT32		protocol_id;
 } W8755_DEV_INFO;

typedef struct WeidaDeviceStatus
{
	UINT32		flash_id;
	UINT32		dummy;
	UINT32		status0;
	UINT32		status1;
	UINT32		flash_address;
	UINT32		mem_address;
	UINT32		flash_buff_size;
	UINT32		flash_buff_address;
} W8755_DEV_STATUS; 

typedef struct SectionAddressType
{
	UINT32		fastboot_addr;
	UINT32		library_addr;
	UINT32		firmware_image_addr;
	UINT32		parameter_addr;
	UINT32		ate_firmware_addr;
	UINT32		recovery_addr;
	UINT32		param_clone_addr;
	UINT32		reserved2_addr;
	UINT32		firmware_addr;
	UINT32		overlay_addr;
	UINT32		parameter_map_addr;
	char 		device_id[10];
	char 		tracking_info[16];
} W8755_SEC_ADDR_TYPE;

typedef struct SectionHeader
{
	UINT32		checksum;
	int		size;
	int		parameter0;
	int		parameter1;
} W8755_SEC_HEADER;


/*
 * spec from GigaDevice MD25D40 
 * W8755_FLASH_CHIP_DELAY: 3000ms typical, 7500ms max
 * W8755_FLASH_64K_DELAY: 500ms typical, 3000ms max
 * W8755_FLASH_32K_DELAY: 300ms typical, 2500ms max
 * W8755_FLASH_4K_DELAY: 100ms typical, 500ms max
 */
#define 	W8755_FLASH_CHIP_DELAY		7500
#define 	W8755_FLASH_64K_DELAY		3000
#define 	W8755_FLASH_32K_DELAY		2500
#define 	W8755_FLASH_4K_DELAY		500

/* 
 * definition of Device Mode 
 * W8755_DM_BOOTLOADER: this mode only exists during ROM and fastboot. It cannot be set as the target mode.
 * W8755_DM_SENSING: normal sensing
 * W8755_DM_DOZE: device sleeps most time and does sensing in longer period.
 * W8755_DM_SLEEP: both device and sensor are in sleep.
 * W8755_DM_FACTORY: for MP testing. The device cannot switch to other modes unless reboot it.
 * W8755_DM_COMMAND: STANDBY mode will be renamed to COMMAND mode.
 * W8755_DM_ATE: a special mode for IC production
 */
#define		W8755_DM_BOOTLOADER 		0
#define		W8755_DM_SENSING		1
#define		W8755_DM_DOZE			2
#define 	W8755_DM_SLEEP			3
#define		W8755_DM_FACTORY 		0x80
#define		W8755_DM_COMMAND		0x90
#define		W8755_DM_ATE			0xA0


/* definition of Flash Memory Block */
#define		W8755_FMB_FLS_SEC		0
#define		W8755_FMB_FLS_BLK32		1
#define		W8755_FMB_FLS_BLK64		2
#define		W8755_FMB_FLS_DEV		3

#define		FLS_SZ 				512 * 1024
#define		FLS_BLK32_SZ			32 * 1024
#define		FLS_BLK64_SZ			64 * 1024
#define		FLS_SEC_SZ 			4 * 1024

#define		TYPE_READ_OFFSET_SET		0x10000
#define		W8755_PACKET_SIZE		60

#define		DELAY_REAL_SLEEP		0x100000
#define		DELAY_REAL_SLEEP_MASK		0xFFFFF

enum W8755_VendorCommandId
{
	 W8755_RPTID_DEV_STATUS = 0xf0,
	 W8755_RPTID_DEV_INFO = 0xf2,
	 W8755_RPTID_REQ_READ = 0x06,
	 W8755_RPTID_READ_DATA = 0x07,
	 W8755_RPTID_WRITE_DATA = 0x08,
};

/* Data transfer type for VendorCommandId.REQ_READ command */
enum W8755_ReqReadType
{
	/* isp support also */
	W8755_ISP_GET_MEM_BYTE = 0x60,
	W8755_ISP_GET_MEM_HALFWORD = 0x61,
	W8755_ISP_GET_MEM_WORD = 0x62,
	W8755_ISP_GET_FLASH = 0x63,
	W8755_ISP_GET_FLASH_STATUS = 0x64,
	W8755_ISP_GET_CHECKSUM = 0x65,

	W8755_FW_GET_DEVICE_INFO = 0x73, 	
};

enum W8755_WriteType
{	
	/* support in isp also */
	W8755_ISP_SET_FLASH = 0x83,
	W8755_ISP_SET_FLASH_STATUS = 0x84,
	W8755_ISP_SET_COMMAND = 0x85,
	W8755_ISP_SET_FLASH_ADDRESS = 0x87,
	W8755_ISP_SET_CHECKSUM_CALC = 0x88,
 
	/* support in FW only */
    W8755_FW_SET_COMMAND = 0x91,	
};

enum W8755_WDTCommand
{
 	/* support in isp also */
	W8755_SET_CMD_SFLOCK = 0x00,
	W8755_SET_CMD_SFUNLOCK = 0x01,
	W8755_SET_CMD_RESET = 0x02,
	W8755_SET_CMD_ERASE4K = 0x03,
	W8755_SET_CMD_ERASE32K = 0x04,
	W8755_SET_CMD_ERASE64K = 0x05,
	W8755_SET_CMD_ERASEALL = 0x06,

	/* support in FW only */
	W8755_SET_CMD_IMAGE_CAPTURE = 0x80,
    	W8755_SET_CMD_IMAGE_SOURCE = 0x81,
	W8755_SET_CMD_DEVICE_MODE = 0x82,
};

typedef	union
{
	struct {
		BYTE 	rpt_id;
		BYTE	type;
		UINT16 	size;
		BYTE	cmd;
		BYTE	param1;
		UINT16	param2;
	} DD;
	BYTE	buffer[64];
} W8755_CMD_DATA;

typedef	union
{
	struct {
		BYTE	rpt_id;
		BYTE	type;
		UINT16	size;
		BYTE	data[60];
	} DD;
	BYTE	buffer[64];
} W8755_WRITE_DATA;

typedef	union
{
	struct {
		BYTE	rpt_id;
		BYTE	type;
		UINT16	size;
		UINT32	reserved;
	} DD;
	BYTE	buffer[8];
} W8755_REQ_READ;

typedef	union
{
	struct {
		BYTE	rpt_id;
		BYTE	type;
		UINT16	checksum;
		BYTE	data[60];
	} DD;
	BYTE	buffer[64];
} W8755_READ_DATA;

enum W8755_ISP_I2C_RESPONSE
{
	W8755_ISP_RSP_OK = 0x80,
	W8755_ISP_RSP_BUSY = 0xFE
};

/* __W8755_DEF_H__ */
#endif
