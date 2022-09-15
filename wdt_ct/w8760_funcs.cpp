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

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>

#include "wdt_dev_api.h"
#include "wdt_ct.h"
#include "dev_def.h"
#include "w8760_funcs.h"

#define	IS_ADDR_PAGE_ALIGNED(__ADDR__)		((__ADDR__ & (unsigned int)(W8760_FLASH_PAGE_SIZE - 1)) == 0)
#define	IS_ADDR_SECTOR_ALIGNED(__ADDR__)	((__ADDR__ & (unsigned int)(W8760_FLASH_SECTOR_SIZE - 1)) == 0)
#define	IS_ADDR_BLK64_ALIGNED(__ADDR__) 	((__ADDR__ & (unsigned int)(W8760_FLASH_LBLOCK_SIZE - 1)) == 0)
#define	IS_ADDR_BLK32_ALIGNED(__ADDR__)		((__ADDR__ & (unsigned int)(W8760_FLASH_SBLOCK_SIZE - 1)) == 0)  

static FUNC_PTR_STRUCT_DEV_BASIC	g_func_dev_basic = { 0, 0, 0, 0 };

static BYTE W8760_RomSignatureVerB[8] = { 0xa6, 0x97, 0x53, 0x11, 0xde, 0x7f, 0x2e, 0xd7, };
static BYTE W8762_RomSignatureVerA[8] = { 0x7F, 0xD0, 0x20, 0x00, 0xB8, 0x1D, 0xCA, 0x54, };
static BYTE W8762_RomSignatureVerC[8] = { 0x6B, 0x6B, 0xA2, 0x08, 0xC6, 0x4C, 0x4D, 0xDD, };

int check_is_all_ff(BYTE* data, int length)
{
	if (data == 0)
		return 0;

	int idx;

	for (idx=0; idx<length; idx++)
		if (data[idx] != 0xFF)
			return 0;
	return 1;
}

int  wh_w8760_get_feature_devinfo(W8760_REPORT_FEATURE_DEVINFO* report_feature_devinfo, BYTE* buf)
{
	if (!report_feature_devinfo || !buf)
		return 0;

	report_feature_devinfo->firmware_id = get_unaligned_le32(&buf[1]);	
	report_feature_devinfo->hardware_id = get_unaligned_le32(&buf[5]);
	report_feature_devinfo->serial_no = get_unaligned_le32(&buf[9]);
	report_feature_devinfo->n_touches_usb = buf[13];
	report_feature_devinfo->n_bytes_touch = buf[14];
	memcpy(report_feature_devinfo->platform_id, &buf[16], 8);
	memcpy(report_feature_devinfo->rom_signature, &buf[24], 8);

	report_feature_devinfo->protocol_version = buf[32];	
	report_feature_devinfo->firmware_rev_ext = buf[33];	
	report_feature_devinfo->parameter_section_size = get_unaligned_le16(&buf[34]);	
	report_feature_devinfo->parameter_mapid = get_unaligned_le16(&buf[36]);	
	memcpy(report_feature_devinfo->program_name_fourcc, &buf[38], 4);	
	memcpy(report_feature_devinfo->trackingid_or_old_part_num, &buf[42], 8);	
	
	return 1;
}

int wh_w8760_dev_read_report(WDT_DEV* pdev, BYTE* buf, UINT32 buf_size)
{
	if (!pdev)
		return 0;
	
	if (pdev->intf_index == INTERFACE_I2C)
		return wh_i2c_read(pdev, buf, buf_size);	
	
	return 0;
}
int wh_w8760_dev_get_indexed_string(WDT_DEV* pdev, UINT32 index, BYTE* buf, UINT32 buf_size)
{
	if (!pdev)
		return 0;

	if (pdev->intf_index == INTERFACE_I2C)
		return wh_i2c_get_indexed_string(pdev, index, buf, buf_size);	
	
	return 0;
}

int wh_w8760_dev_set_feature(WDT_DEV* pdev, BYTE* buf, UINT32 buf_size)
{
	if (!pdev)
		return 0;

	if (buf[0] == W8760_COMMAND9 || buf[0] == W8760_PIPE9)
		buf_size = 10;
	else if (buf[0] == W8760_COMMAND63 || buf[0] == W8760_PIPE63 || 
		buf[0] == W8760_BLOCK63 || buf[0] ==  W8760_DEVICE_INFO)
		buf_size = 64;
	else {
		printf("Feature id is not supported! (%d)\n", buf[0]);
		return 0;
	}
	
	if (pdev->intf_index == INTERFACE_I2C)
		return wh_i2c_set_feature(pdev, buf, buf_size);	

	return 0;
}

int wh_w8760_dev_get_feature(WDT_DEV* pdev, BYTE* buf, UINT32 buf_size)
{
	if (!pdev)
		return 0;

	if (buf[0] == W8760_COMMAND9 || buf[0] == W8760_PIPE9)
		buf_size = 10;
	else if (buf[0] == W8760_COMMAND63 || buf[0] == W8760_PIPE63 || 
		buf[0] == W8760_BLOCK63 || buf[0] == W8760_DEVICE_INFO)
		buf_size = 64;
	else {
		printf("Feature id is not supported! (%d)\n", buf[0]);
		return 0;
	}
			
	if (pdev->intf_index == INTERFACE_I2C)
		return wh_i2c_get_feature(pdev, buf, buf_size);	

	return 0;
}
int wh_w8760_dev_set_basic_op(WDT_DEV *pdev)
{
	if (!pdev)
		return 0;

	g_func_dev_basic.p_wh_get_feature = wh_w8760_dev_get_feature;
	g_func_dev_basic.p_wh_set_feature = wh_w8760_dev_set_feature;
	g_func_dev_basic.p_wh_get_index_string = wh_w8760_dev_get_indexed_string;
	g_func_dev_basic.p_wh_read_report = wh_w8760_dev_read_report;

	return 1;
}


int wh_w8760_dev_command_write(WDT_DEV *pdev, BYTE* data, int start, int size)
{
	return wh_w8760_dev_set_feature(pdev, &data[start], size);
}

int wh_w8760_dev_command_read(WDT_DEV *pdev, BYTE* cmd, int cmd_size, BYTE* data, int start, int size)
{
	BYTE	buf[64];
	if (wh_w8760_dev_command_write(pdev, cmd, 0, cmd_size) > 0) {
		if (size > 9)
			buf[0] = W8760_COMMAND63;
		else 
			buf[0] = W8760_COMMAND9;

		if (wh_w8760_dev_get_feature(pdev, buf, size) > 0) {
			memcpy(&data[start], &buf[1], size);
			return 1;
		}
	}
		  
	return 0;
}

int  wh_w8760_dev_read_items(WDT_DEV *pdev, int cmd_id, BYTE* buffer, int start, int item_size, int item_count)
{
	int size = item_size * item_count;
	BYTE cmd[] = { W8760_COMMAND9, (BYTE) cmd_id, (BYTE) item_count };
	
	return wh_w8760_dev_command_read(pdev, cmd, 2, buffer, start, size);
}

int wh_w8760_dev_write_items(WDT_DEV *pdev, int cmd_id, BYTE* buffer, int start, int item_size, int item_count)
{
	int size = item_count * item_size;
	BYTE cmd[64];

	cmd[0] = W8760_COMMAND9;
	cmd[1] = cmd_id;
	cmd[2] = item_count;
	memcpy(&cmd[3], &buffer[start], size);

	return wh_w8760_dev_command_write(pdev, cmd, 0, size + 3);
}

int wh_w8760_dev_write_array(WDT_DEV *pdev, int cmd_id, BYTE* buffer, int start, int item_size, int item_count)
{
	int max_write_batch = (W8760_USB_MAX_PAYLOAD_SIZE - 2) / item_size;
	int i = start;

	while (item_count >= max_write_batch) {
		if (wh_w8760_dev_write_items(pdev, cmd_id, buffer, i, item_size, max_write_batch) <= 0)
			return 0;

		i += max_write_batch * item_size;
		item_count -= max_write_batch;
	}

	if (item_count > 0) 
		return wh_w8760_dev_write_items(pdev, cmd_id, buffer, i, item_size, item_count);

	return 1;
}

/* Since the flash chip erase time at most is 3 seconds, so timeout limit here is 5 seconds. */
int wh_w8760_dev_wait_cmd_end(WDT_DEV* pdev, int timeout_ms, int invt_ms)
{
	int polling_timeout_ms = 5000;
	int polling_intv_ms = 5;
	int status;
	BYTE	status_buf[4];

	if (timeout_ms)
		polling_timeout_ms = timeout_ms;
	if (invt_ms)
		polling_intv_ms = invt_ms;	
	
	do
	{
		if (wh_w8760_dev_get_device_status(pdev, &status_buf[0], 0, 1) <= 0)
			return 0;
		
		status = status_buf[0];
		if ((status & W8760_COMMAND_BUSY) == 0) {			
			return 1;
		}

		wh_sleep(polling_intv_ms);
		polling_timeout_ms -= polling_intv_ms;		
	} while (polling_timeout_ms > 0);

	printf("%s: timeout occured (%d)!\n", __func__, polling_timeout_ms * polling_intv_ms);	
	return 0;
}

int wh_w8760_dev_reboot(WDT_DEV* pdev)
{
	BYTE cmd[] = { W8760_COMMAND9, W8760_REBOOT, 0xB9, 0x0C, 0x8A, 0x24 };
	
	return wh_w8760_dev_command_write(pdev, cmd, 0, sizeof(cmd));	
}

int wh_w8760_dev_run_program_from_background(WDT_DEV* pdev, UINT32 program_address)
{
    BYTE cmd[2 + 4 + 4];
	cmd[0] = W8760_COMMAND63;
	cmd[1] = W8760_RUN_PROGRAM_FORM_BACKGROUND;
	put_unaligned_le32(program_address, &cmd[2]);
	put_unaligned_le32(0, &cmd[6]);
	return wh_w8760_dev_command_write(pdev, cmd, 0, sizeof(cmd));	
}

int wh_w8760_dev_get_hid_descriptor_register(WDT_DEV* pdev, UINT16* pvalue)
{
	BYTE cmd[] = { W8760_COMMAND9, W8760_GET_HID_DESCRIPTOR_REGISTER };
	BYTE buf[4];

	*pvalue = 0x20;
	if (wh_w8760_dev_command_read(pdev, cmd, sizeof(cmd), buf, 0, 2) <= 0)
		return 0;

	*pvalue = get_unaligned_le16(buf);
	return 1;
}

int wh_w8760_dev_read_buf_response(WDT_DEV* pdev, BYTE* data, int size)
{
	return wh_w8760_dev_read_items(pdev, W8760_READ_BUFFERED_RESPONSE, data, 0, sizeof(BYTE), size);
}

int wh_w8760_dev_set_device_mode(WDT_DEV* pdev, BYTE mode)
{
	BYTE cmd[3];

	cmd[0] = W8760_COMMAND9;
	cmd[1] = W8760_SET_DEVICE_MODE;
	cmd[2] = mode;
	
	return wh_w8760_dev_command_write(pdev, cmd, 0, 3);
}

int wh_w8760_dev_get_device_mode(WDT_DEV* pdev)
{
	BYTE	status[4];
	if (!pdev)
		return 0;

	if (wh_w8760_dev_get_device_status(pdev, status, 4, 1))
		return status[0];

	return 0;
}

int wh_w8760_dev_set_n_check_device_mode(WDT_DEV* pdev, BYTE mode, int timeout_ms, int intv_ms)
{
	int polling_timeout_ms = 100;
	int polling_intv_ms = 5;

	/* if device in isp mode, just return */
	if (pdev->board_info.dev_type & FW_WDT8760_2_ISP)
		return 1;

	if (timeout_ms)
		polling_timeout_ms = timeout_ms;
	if (intv_ms)
		polling_intv_ms = intv_ms;

	do {
		wh_w8760_dev_set_device_mode(pdev, mode);

		if (wh_w8760_dev_get_device_mode(pdev) == mode)
			return 1;

		wh_sleep(polling_intv_ms);
		polling_timeout_ms -= polling_intv_ms;
	} while (polling_timeout_ms > 0);
	
	return 0;
}

int wh_w8760_dev_set_address(WDT_DEV* pdev, BYTE type, UINT32 address)
{
	BYTE cmd[8];

	memset(&cmd, 0, sizeof(cmd));

	if (!(type == W8760_SET_MEMORY_ADDRESS || type == W8760_SET_FLASH_ADDRESS))
		return 0;
	
	cmd[0] = W8760_COMMAND9;
	cmd[1] = type;
	put_unaligned_le32(address, &cmd[2]);
	if (type != W8760_SET_MEMORY_ADDRESS)
		cmd[5] = 0;

	return wh_w8760_dev_command_write(pdev, cmd, 0, 6);
}

int wh_w8760_dev_write_men_halfword(WDT_DEV* pdev, UINT16 hwords)
{
	BYTE buf[2];
	put_unaligned_le16(hwords, &buf[0]);

	return wh_w8760_dev_write_array(pdev, W8760_WRITE_HALFWORDS, buf, 0, sizeof(BYTE), 2);
}

int wh_w8760_dev_set_men_address(WDT_DEV* pdev, UINT32 address)
{
	return wh_w8760_dev_set_address(pdev, W8760_SET_MEMORY_ADDRESS, address);
}

int wh_w8760_dev_set_flash_address(WDT_DEV* pdev, UINT32 address)
{
	return wh_w8760_dev_set_address(pdev, W8760_SET_FLASH_ADDRESS, address);
}

int wh_w8760_dev_identify_platform(WDT_DEV* pdev, BOARD_INFO* pboardInfo)
{
	if (!pdev || !pboardInfo)
		return 0;

	if (memcmp(W8760_RomSignatureVerB, pdev->board_info.dev_info.w8760_feature_devinfo.rom_signature, 8) == 0) {
		pboardInfo->dev_type = FW_WDT8760;
		if (pdev->pparam->argus & OPTION_INFO)		
			printf("WDT8760_VerB\n");
		return 1;
	}

	if (memcmp(W8762_RomSignatureVerA, pdev->board_info.dev_info.w8760_feature_devinfo.rom_signature, 8) == 0) {
		pboardInfo->dev_type = FW_WDT8762;
		if (pdev->pparam->argus & OPTION_INFO)		
			printf("WDT8762_VerA\n");
		return 1;
	}

	if (memcmp(W8762_RomSignatureVerC, pdev->board_info.dev_info.w8760_feature_devinfo.rom_signature, 8) == 0) {
		pboardInfo->dev_type = FW_WDT8762;
		if (pdev->pparam->argus & OPTION_INFO)		
			printf("WDT8762_VerC\n");
		return 1;
	}
	
	return 0;
}

int wh_w8760_dev_erase_flash(WDT_DEV* pdev, UINT32 address, UINT32 size)
{
	BYTE cmd[4];

	cmd[0] = W8760_COMMAND9;
	cmd[1] = (BYTE) W8760_ERASE_FLASH;
	cmd[2] = (BYTE) (address >> 12);
	cmd[3] = (BYTE)(((address & 0x0FFF) + size + 4095) >> 12);

    if (wh_w8760_dev_command_write(pdev, cmd, 0, sizeof(cmd)) > 0)
		return wh_w8760_dev_wait_cmd_end(pdev, 0, 0);

	return 0;
}

int wh_w8760_dev_batch_write_flash(WDT_DEV* pdev, BYTE* buf, int start, int size)
{
	if (size > W8760_USB_MAX_PAYLOAD_SIZE - 2) {
		printf("%s: payload data overrun\n", __func__);
		return 0;
	}

	BYTE cmd[W8760_USB_MAX_PAYLOAD_SIZE+1];

	cmd[0] = W8760_COMMAND63;
	cmd[1] = (BYTE) W8760_WRITE_FLASH;
	cmd[2] = (BYTE) size;
	memcpy(&cmd[3], &buf[start], size);

	if (wh_w8760_dev_command_write(pdev, cmd, 0, size + 3) > 0)
		return wh_w8760_dev_wait_cmd_end(pdev, 0, 0);
			
	return 0;
}

int wh_w8760_dev_write_flash(WDT_DEV* pdev, int addr, BYTE* buf, int start, int size)
{
	int byte_count = size;
	int offset = start;
	int max_payload_size = W8760_USB_MAX_PAYLOAD_SIZE - 2;
	int cur_addr = 0xFFFFFFFF;
	
	while (byte_count >= max_payload_size) {
		if (!check_is_all_ff(&buf[offset], max_payload_size)) {
			if (cur_addr != addr) {
				if (!wh_w8760_dev_set_flash_address(pdev, addr))
					return 0;
			}

			if (wh_w8760_dev_batch_write_flash(pdev, buf, offset, max_payload_size) <= 0)
				return 0;
			cur_addr = addr + max_payload_size;
		} else 
			wh_printf("Already ff, no need to set: 0x%x\n", addr);			
		offset += max_payload_size;
		byte_count -= max_payload_size;
		addr += max_payload_size;
	}

	if (cur_addr != addr) {
		if (!wh_w8760_dev_set_flash_address(pdev, addr))
			return 0;
	}

	if (byte_count > 0) 
		return wh_w8760_dev_batch_write_flash(pdev, buf, offset, byte_count);

	return 1;
}

int wh_w8760_dev_write_flash_page(WDT_DEV* pdev, int addr, BYTE* buf, int size)
{
	int retval = 0;
	unsigned int	write_base;
	unsigned int	write_size;

	write_base = W8760_FLASH_PAGE_SIZE;

	if (addr & 0xFF) {
		unsigned int 	size_partial;
		size_partial = write_base - (addr & 0xFF);
		
		if (size > (int) size_partial) {				
			write_size = size_partial;				
			size = size - size_partial;				
		} else {											
			write_size = size;								
			size = 0;										
		}													
		retval = wh_w8760_dev_write_flash(pdev, addr, (BYTE*) buf, 0, write_size);	
		if (!retval)										
			return retval;									
		buf = buf + size_partial;				
		addr = addr + size_partial;	
	}

	while (size)
	{
		if ((addr & 0xfff) == 0)
			printf("base addr: 0x%x\n", addr);
		if (size > (int) write_base) {				
			write_size = write_base;				
			size = size - write_base;				
		} else {											
			write_size = size;								
			size = 0;										
		}													
		retval = wh_w8760_dev_write_flash(pdev, addr, (BYTE*) buf, 0, write_size);	
		if (!retval)										
			return retval;									
		buf = buf + write_base;				
		addr = addr + write_base;			
	}

	return 1;
}

int wh_w8760_dev_protect_flash(WDT_DEV* pdev, UINT16 protect_mask)
{
	UINT16 mask = protect_mask;
	
	BYTE cmd[] = { W8760_COMMAND9, (BYTE) W8760_PROTECT_FLASH, 0, 0, 0, 0 };
	put_unaligned_le16(mask, &cmd[2]);
	put_unaligned_le16((UINT16)~mask, &cmd[4]);

	return wh_w8760_dev_command_write(pdev, cmd, 0, sizeof(cmd));
}
        
int wh_w8760_dev_checksum_flash(WDT_DEV* pdev, UINT32* pchksum, UINT32 flash_address,
	int size, UINT32 init_sum)
{
	BYTE cmd[10];
	BYTE buf[4];		

	*pchksum = 0;

	cmd[0] = W8760_COMMAND9;
	cmd[1] = (BYTE) W8760_CALCULATE_FLASH_CHECKSUM;
	put_unaligned_le32(flash_address, &cmd[2]);
	put_unaligned_le32(size, &cmd[5]);	
	put_unaligned_le16(init_sum, &cmd[8]);	

	if (wh_w8760_dev_command_write(pdev, cmd, 0, sizeof(cmd)) <= 0) 
		return 0;
	
	if (wh_w8760_dev_wait_cmd_end(pdev, 0, 0) <= 0)
		return 0;

	if (wh_w8760_dev_read_buf_response (pdev, buf, 2) <= 0)
		return 0;

	*pchksum = get_unaligned_le16(buf);
	return 1;
}

int wh_w8760_dev_send_commands(WDT_DEV* pdev, int cmd, UINT32 value)
{
	switch(cmd)
	{
		case 	WH_CMD_ENTER_FACTORY: {
			return wh_w8760_dev_set_n_check_device_mode(pdev, W8760_MODE_MEASUREMENT, 0, 0);
		}
		break;
		case 	WH_CMD_ALGO_STOP: {
			return wh_w8760_dev_set_n_check_device_mode(pdev, W8760_MODE_COMMAND, 0, 0);
		}
		break;
		case 	WH_CMD_ALGO_START: 
		case 	WH_CMD_ALGO_RESTART: {	
			return wh_w8760_dev_set_n_check_device_mode(pdev, W8760_MODE_SENSING, 0, 0);
		}
		break;
		case 	WH_CMD_SET_DEV_MODE: {
			return wh_w8760_dev_set_n_check_device_mode(pdev, value, 0, 0);
		}
		break;
		case 	WH_CMD_RESET: {	
			return wh_w8760_dev_reboot(pdev);
		}
		break;
		case	WH_CMD_FLASH_ERASEALL:	{
			printf("FLASH_ERASEALL: not implemented!");		
			return 0;
		}
		break;
		case	WH_CMD_FLASH_ERASE4K:	{
			return wh_w8760_dev_flash_erase(pdev, value, 0x1000);
		}
		break;
		case	WH_CMD_FLASH_ERASE32K:	{
			return wh_w8760_dev_flash_erase(pdev, value, 0x8000);
		}
		break;
		case	WH_CMD_FLASH_ERASE64K:	{
			return wh_w8760_dev_flash_erase(pdev, value, 0x10000);
		}
		break;
		case	WH_CMD_FLASH_LOCK:	
		case	WH_CMD_FLASH_PROTECTION_ON: 
		{
			return wh_w8760_dev_protect_flash(pdev, W8760_ProtectAll512k);
		}
		break;
		case	WH_CMD_FLASH_UNLOCK: 
		case	WH_CMD_FLASH_PROTECTION_OFF: 
		{
			/* address align to 0x100 */
			UINT32 addr = (value & 0xFFFF0000) >> 8;
			/*  size align to 0x100 */
			UINT32 size = (value & 0xFFFF) << 8; 	
			int ret = 0;
			
			if (addr < 128 * 1024 && addr + size <= 128 * 1024)
				ret = wh_w8760_dev_protect_flash(pdev, W8760_UnprotectLower128k);
            		else if (addr < 256 * 1024 && addr + size <= 256 * 1024)
				ret = wh_w8760_dev_protect_flash(pdev, W8760_UnprotectLower256k);
			else if (addr < 384 * 1024 && addr + size <= 384 * 1024)
				ret = wh_w8760_dev_protect_flash(pdev, W8760_UnprotectLower384k);
	  		else if (addr < 508 * 1024 && addr + size <= 508 * 1024)
				ret = wh_w8760_dev_protect_flash(pdev, W8760_UnprotectLower508k);
          		else if (addr == 0 && addr + size > 508 * 1024 && addr + size <= 512*1024)
				ret = wh_w8760_dev_protect_flash(pdev, W8760_UnprotectAll512k);

			return ret;
		}
		break;		
 	
		default: {
			return 0;
		}
	}

	return 0;
}

int wh_w8760_dev_flash_write_data(WDT_DEV* pdev, BYTE* data, UINT32 address, int length)
{
	if (!pdev || !data)
		return 0;

	if ((address & 0x3) != 0)	
		return 0;

	if (!wh_w8760_dev_set_flash_address(pdev, address))
		return 0;

	return wh_w8760_dev_write_flash_page(pdev, address, data, length);
}

int wh_w8760_dev_flash_get_checksum(WDT_DEV* pdev, UINT32* pchecksum, UINT32 address, int size)
{
	return wh_w8760_dev_checksum_flash(pdev, pchecksum, address, size, 0 /*default initial value*/);
}

int wh_w8760_dev_verify_chunk_by_read_checksum(WDT_DEV* pdev, CHUNK_INFO_EX* pChunk)
{
	int retval = 0, result = 1;
	UINT32	bin_checksum;
	UINT32	read_checksum;
	
	retval = wh_w8760_dev_set_n_check_device_mode(pdev, W8760_MODE_COMMAND, 0, 0);
	if (!retval)
		return retval;
		
	printf("Calculating checksum...\n");
	
	bin_checksum = misr_for_bytes(0, pChunk->pData, 0, pChunk->chuckInfo.length);

	retval = wh_w8760_dev_flash_get_checksum(pdev, &read_checksum, pChunk->chuckInfo.targetStartAddr, pChunk->chuckInfo.length);
	if (!retval)
		return retval;

	if (bin_checksum != read_checksum) {
		printf("Checksum mismatch!!! Original=0x%x, Flash checksum=0x%x\n", bin_checksum, read_checksum);
		result = 0;
	}
	
	retval = wh_w8760_dev_set_n_check_device_mode(pdev, W8760_MODE_SENSING, 0, 0);
	if (!retval)
		return retval;
		
	return result;
}

int wh_w8760_dev_verify_chunk(WDT_DEV* pdev, CHUNK_INFO_EX* pChunk)
{
	if (!pdev)
		return 0;

	return wh_w8760_dev_verify_chunk_by_read_checksum(pdev, pChunk);
}

int wh_w8760_dev_get_device_data(WDT_DEV* pdev, BYTE type, int offset, BYTE *buf, int size)
{
	BYTE cmd[] = { (BYTE) W8760_COMMAND9, type, (BYTE) offset, (BYTE) size };

	if (type != W8760_GET_DEVICE_INFO && type != W8760_GET_DEVICE_STATUS)
		return 0;

	return wh_w8760_dev_command_read(pdev, cmd, sizeof(cmd), buf, 0,  size);
}

int wh_w8760_dev_get_device_status(WDT_DEV* pdev, BYTE* buf, int offset, int size)
{
	return wh_w8760_dev_get_device_data(pdev, W8760_GET_DEVICE_STATUS, offset, buf, size);
}

int wh_w8760_dev_read_parameter_page(WDT_DEV* pdev, BYTE* buf, int page_index)
{
	BYTE cmd[] = { W8760_COMMAND9, W8760_READ_PARAMETER_PAGE, (BYTE) page_index };

	return wh_w8760_dev_command_read(pdev, cmd, sizeof(cmd), buf, 0, W8760_USB_MAX_PAYLOAD_SIZE);
}

int wh_w8760_dev_get_context(WDT_DEV* pdev, W8760_PCT_DATA* pPct)
{
	BYTE  buf[64];

	if (!pdev || !pPct)	
		return 0;
	
	if (wh_w8760_dev_read_parameter_page(pdev, buf, 1) <= 0)
		return 0;

	memcpy(pPct, &buf[0], sizeof(W8760_PCT_DATA));

	return 1;
}

int	wh_w8760_prepare_data(WDT_DEV* pdev, BOARD_INFO* p_out_board_info)
{
	if (!pdev || !p_out_board_info)
		return 0;

	W8760_PCT_DATA	pct_data;

	/* initialize the basic function for handling the following operations */
	wh_w8760_dev_set_basic_op(pdev);

	if (!wh_w8760_dev_identify_platform(pdev, p_out_board_info))  {
		printf("Can't get platform identify!\n");
		return 0;
	}
	
	if (p_out_board_info->dev_type & FW_WDT8760_2_ISP)
		return 1;

	if (wh_w8760_dev_get_context(pdev, &pct_data)) {
		/* set the default values */
		p_out_board_info->sys_param.Phy_Frmbuf_W= pct_data.n_cs;
		p_out_board_info->sys_param.Phy_X0= pct_data.x1;
		p_out_board_info->sys_param.Phy_X1= pct_data.xn;

		p_out_board_info->sys_param.Phy_Frmbuf_H= pct_data.n_cd;
		p_out_board_info->sys_param.Phy_Y0= pct_data.y1;
		p_out_board_info->sys_param.Phy_Y1= pct_data.yn;
		
		p_out_board_info->sys_param.xmls_id1 = 0;
		p_out_board_info->sys_param.xmls_id2 = 0;

		return 1;
	}

	return 1;
}

int wh_w8760_dev_flash_erase(WDT_DEV* pdev, unsigned int address, int size)
{
	int ret = wh_w8760_dev_erase_flash(pdev, address, size);

	if (ret <= 0)
		printf("%s: addr: %x, size: %x\n", __func__, address, size);
	
	return ret;
}

int wh_w8760_dev_program_4k_chunk_verify(WDT_DEV* pdev, CHUNK_INFO_EX* pInputChunk, int option)
{
	int retval = 0;
	int size;
	int start_addr = 0;
	int page_size;
	int	retry_count = 0;
	int is_first_page = 0;
	char*	pdata;
	UINT32	calc_checksum, read_checksum;
	CHUNK_INFO_EX	*pChunk = pInputChunk;
	FUNC_PTR_STRUCT_DEV_OPERATION funcs;

	memset(&funcs, 0, sizeof(FUNC_PTR_STRUCT_DEV_OPERATION));
	
	printf("start 4k chunk program ...\n");
	pdev->dev_state = DS_PROGRAM;

	retval = wh_w8760_dev_set_n_check_device_mode(pdev, W8760_MODE_FLASH_PROGRAM, 0, 0);
	if (!retval)
		return retval;
		
	UINT32 value = (pInputChunk->length + 255) >> 8;
	value |= (((pChunk->chuckInfo.targetStartAddr >> 8) << 16) & 0xFFFF0000);
	retval = wh_w8760_dev_send_commands(pdev, WH_CMD_FLASH_UNLOCK, value);
	if (!retval)
		return retval;
	if(pdev->board_info.dev_type == FW_WDT8762)
	{
		if(pChunk->chuckInfo.targetStartAddr == 0x5d000)
		{
			printf("Erase Sector 0x0000 \n");
			retval = wh_w8760_dev_flash_erase(pdev, 0x0000, 0x1000);
			if (!retval)
		        return retval;
		}
	}

	size = pChunk->chuckInfo.length;	
	start_addr = pChunk->chuckInfo.targetStartAddr;
	pdata =	(char*) pChunk->pData;

	if (size > WDT_PAGE_SIZE) {
		is_first_page = 1;
		size = size - WDT_PAGE_SIZE;
		start_addr = start_addr + WDT_PAGE_SIZE;
		pdata = pdata + WDT_PAGE_SIZE;
	}

	while (size) {
		if (size > (int) WDT_PAGE_SIZE)	{
			page_size = WDT_PAGE_SIZE;
			size = size - WDT_PAGE_SIZE;
		} else	{
			page_size = size;
			size = 0;
		}

		for (retry_count = 0; retry_count < RETRY_COUNT; retry_count ++) {		
			retval = wh_w8760_dev_send_commands(pdev, WH_CMD_FLASH_ERASE4K, start_addr);
			
			if (!retval)
				continue;

			retval = wh_w8760_dev_flash_write_data(pdev, (BYTE*) pdata, start_addr, page_size);
			if (!retval)
				continue;

			calc_checksum = misr_for_bytes(0, (BYTE*) pdata, 0, page_size);

			retval = wh_w8760_dev_flash_get_checksum(pdev, &read_checksum, start_addr, page_size);

			if (read_checksum == calc_checksum)
				break;
			else
				printf("checksum failed (%d): %d <> %d\n", retry_count, read_checksum, calc_checksum);
		}

		if (retry_count == RETRY_COUNT)	{
			printf("***** retry failed *****\n");
			break;
		}

		start_addr = start_addr + page_size;
		pdata =	pdata + page_size;

		/* keep the first page to write to the flash in the last loop */
		if (size == 0 && is_first_page) {		
			size = WDT_PAGE_SIZE;
			start_addr = pChunk->chuckInfo.targetStartAddr;
			pdata = (char*) pChunk->pData;
			is_first_page = 0;		
		}
		
	}

	retval = wh_w8760_dev_send_commands(pdev, WH_CMD_FLASH_LOCK, 0);
	if (!retval)
		return retval;
	
	if (retry_count == RETRY_COUNT) {
		printf("stop 4k chunk program : fail \n");
		return 0;
	}

	return 1;
}

int wh_w8760_dev_program_chunk_verify(WDT_DEV* pdev, CHUNK_INFO_EX* pInputChunk, int option)
{
	int retval = 0;

	CHUNK_INFO_EX	*pChunk = pInputChunk;
	FUNC_PTR_STRUCT_DEV_OPERATION funcs;
	UINT32	calc_checksum, read_checksum;

	memset(&funcs, 0, sizeof(FUNC_PTR_STRUCT_DEV_OPERATION));
	
	retval = wh_w8760_dev_set_n_check_device_mode(pdev, W8760_MODE_FLASH_PROGRAM, 0, 0);
	if (!retval)
		return retval;
		
	retval = wh_w8760_dev_send_commands(pdev, WH_CMD_FLASH_UNLOCK, 0);
	if (!retval)
		return retval;
	
	if(pdev->board_info.dev_type == FW_WDT8762)
	{
		if(pChunk->chuckInfo.targetStartAddr == 0x5d000)
		{
			printf("Erase Sector 0x0000 \n");
			retval = wh_w8760_dev_flash_erase(pdev, 0x0000, 0x1000);
			if (!retval)
		        return retval;
		}
	}

	retval = wh_w8760_dev_flash_erase(pdev, pChunk->chuckInfo.targetStartAddr, pChunk->chuckInfo.length);
	if (!retval)
		return retval;
		
	printf("Chunk program start...\n");
	retval = wh_w8760_dev_flash_write_data(pdev, pChunk->pData, pChunk->chuckInfo.targetStartAddr, pChunk->chuckInfo.length);
	if (!retval)
		return retval;
		
	printf("Chunk program end ...\n");

	calc_checksum = misr_for_bytes(0, (BYTE*) pChunk->pData, 0,  pChunk->chuckInfo.length);
	retval = wh_w8760_dev_flash_get_checksum(pdev, &read_checksum, pChunk->chuckInfo.targetStartAddr, pChunk->chuckInfo.length);
	
	if (read_checksum != calc_checksum) {
		printf("checksum failed : %d <> %d\n", read_checksum, calc_checksum);
		retval = 0;
	}
	
	wh_w8760_dev_send_commands(pdev, WH_CMD_FLASH_LOCK, 0);
	if (!retval)
		return retval;
	return 1;
}

int wh_w8760_dev_program_chunk(WDT_DEV* pdev, CHUNK_INFO_EX* pInputChunk, int option)
{
	if (!pdev)
		return 0;
	
	if (pdev->pparam->argus & OPTION_BLOCK)
		return wh_w8760_dev_program_chunk_verify(pdev, pInputChunk, option);
	else
		return wh_w8760_dev_program_4k_chunk_verify(pdev, pInputChunk, option);

	return 1;
}

int wh_w8760_get_rom_signature(int type, BYTE* buf)
{
	if(type == 0)
	{
		memcpy(buf, W8760_RomSignatureVerB, sizeof(W8760_RomSignatureVerB));
		return 1;
	}
	else if(type == 1)
	{
		memcpy(buf, W8762_RomSignatureVerA, sizeof(W8762_RomSignatureVerA));
		return 1;
	}
	else if(type == 2)
	{
		memcpy(buf, W8762_RomSignatureVerC, sizeof(W8762_RomSignatureVerC));
		return 1;
	}
	else
	{
		return 0;
	}


}


