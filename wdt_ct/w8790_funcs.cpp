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


#include "wdt_dev_api.h"
#include <stdio.h>
#include <malloc.h>
#include <string.h>

#include "wdt_ct.h"
#include "w8790_funcs.h"
#include "w8790_def.h"
#include <unistd.h>



static FUNC_PTR_STRUCT_DEV_BASIC	g_func_dev_basic = { 0, 0, 0, 0 };



#define		IS_ADDR_PAGE_ALIGNED(__ADDR__)		((__ADDR__ & (unsigned int)(W8790_FLASH_PAGE_SIZE - 1)) == 0)
#define		IS_ADDR_SECTOR_ALIGNED(__ADDR__)	((__ADDR__ & (unsigned int)(W8790_FLASH_SECTOR_SIZE - 1)) == 0)
#define		IS_ADDR_BLK64_ALIGNED(__ADDR__) 	((__ADDR__ & (unsigned int)(W8790_FLASH_LBLOCK_SIZE - 1)) == 0)
#define		IS_ADDR_BLK32_ALIGNED(__ADDR__)		((__ADDR__ & (unsigned int)(W8790_FLASH_SBLOCK_SIZE - 1)) == 0)  


	
BYTE W8790_RomSignatureVerA[8] = { 0xab, 0x85, 0xc0, 0xe8, 0x2b, 0x20, 0xe8, 0x11 };
BYTE W8790_RomSignatureVerB[8] = { 0xe2, 0x82, 0xeb, 0x48, 0x34, 0xdb, 0xdb, 0x7b };

int wh_w8790_dev_read_report(WDT_DEV* pdev, BYTE* buf, UINT32 buf_size)
{
	if (!pdev)
		return 0;

	if (pdev->intf_index == INTERFACE_I2C)
		return wh_i2c_read(pdev, buf, buf_size);



	return 0;
}
int wh_w8790_dev_get_indexed_string(WDT_DEV* pdev, UINT32 index, BYTE* buf, UINT32 buf_size)
{
	if (!pdev)
		return 0;

	if (pdev->intf_index == INTERFACE_I2C)
		return wh_i2c_get_indexed_string(pdev, index, buf, buf_size);


	return 0;
}


int wh_w8790_dev_set_feature(WDT_DEV* pdev, BYTE* buf, UINT32 buf_size)
{
	if (!pdev)
		return 0;

	if (buf[0] == W8790_COMMAND9)
		buf_size = 10;
	else if (buf[0] == W8790_COMMAND63 || buf[0] == W8790_BLOCK63)
		buf_size = 64;
	else {
		printf("Feature id is not supported! (%d)\n", buf[0]);
		return 0;
	}
	if (pdev->intf_index == INTERFACE_I2C)
		return wh_i2c_set_feature(pdev, buf, buf_size);


	return 0;
}

int wh_w8790_dev_get_feature(WDT_DEV* pdev, BYTE* buf, UINT32 buf_size)
{
	if (!pdev)
		return 0;

	if (buf[0] == W8790_COMMAND9)
		buf_size = 10;
	else if (buf[0] == W8790_COMMAND63 || buf[0] == W8790_BLOCK63)
		buf_size = 64;
	else {
		printf("Feature id is not supported! (%d)\n", buf[0]);
		return 0;
	}
	if (pdev->intf_index == INTERFACE_I2C)
		return wh_i2c_get_feature(pdev, buf, buf_size);




	return 0;
}
int wh_w8790_dev_set_basic_op(WDT_DEV* pdev)
{
	if (!pdev)
		return 0;

	g_func_dev_basic.p_wh_get_feature = wh_w8790_dev_get_feature;
	g_func_dev_basic.p_wh_set_feature = wh_w8790_dev_set_feature;
	g_func_dev_basic.p_wh_get_index_string = wh_w8790_dev_get_indexed_string;
	g_func_dev_basic.p_wh_read_report = wh_w8790_dev_read_report;

	return 1;
}


int wh_w8790_dev_command_write(WDT_DEV* pdev, BYTE* data, int start, int size)
{
	return wh_w8790_dev_set_feature(pdev, &data[start], size);
}

int  wh_w8790_parse_device_info(W8790_DEV_INFO* report_feature_devinfo, BYTE* buf)
{
	if (!report_feature_devinfo || !buf)
		return 0;

	report_feature_devinfo->firmware_version = get_unaligned_le32(&buf[1]);
	report_feature_devinfo->hardware_version = get_unaligned_le32(&buf[5]);
	report_feature_devinfo->serial_number = get_unaligned_le32(&buf[9]);
	report_feature_devinfo->max_touches = buf[13];
	report_feature_devinfo->firmware_revision_ext = buf[14];
	report_feature_devinfo->partition = buf[15];
	report_feature_devinfo->partition_format_revision = buf[16];


	memcpy(report_feature_devinfo->part_number, &buf[17], 16);
	memcpy(report_feature_devinfo->rom_signature, &buf[33], 8);
	memcpy(report_feature_devinfo->program_name_fourcc, &buf[41], 4);
	memcpy(report_feature_devinfo->tracking_id, &buf[45], 8);

	return 1;
}

int wh_w8790_dev_identify_platform(WDT_DEV* pdev)
{
	// identify chip by reading its ROM.
	if (!pdev )
		return 0;

	if (memcmp(W8790_RomSignatureVerA, pdev->board_info.dev_info.w8790_feature_devinfo.rom_signature, 8) == 0) {
		if (pdev->pparam->argus & OPTION_INFO)		
			printf("WDT8790_VerA\n");

		return 1;
	}
	if (memcmp(W8790_RomSignatureVerB, pdev->board_info.dev_info.w8760_feature_devinfo.rom_signature, 8) == 0) {
                if (pdev->pparam->argus & OPTION_INFO)	
			printf("WDT8790_VerB\n");
		return 1;
	}


	return 0;
}

int wh_w8790_dev_get_context(WDT_DEV* pdev, W8790_PCT* pPct)
{
	BYTE  buf[64] = { 0 };

	if (!pdev || !pPct)
		return 0;

	if (wh_w8790_dev_read_parameter_page(pdev, buf, 1) <= 0)
		return 0;

	memcpy(pPct, &buf[0], sizeof(W8790_PCT));

	return 1;
}

int wh_w8790_dev_command_read(WDT_DEV* pdev, BYTE* cmd, int cmd_size, BYTE* data, int start, int size)
{
	if (wh_w8790_dev_command_write(pdev, cmd, 0, cmd_size) > 0) {

		BYTE	buf[64] = { 0 };
		if (size > 9)
			buf[0] = W8790_COMMAND63;
		else
			buf[0] = W8790_COMMAND9;

		if (wh_w8790_dev_get_feature(pdev, buf, size) > 0) {
			memcpy(&data[start], &buf[1], size);
			return 1;
		}
	}

	return 0;
}
int  wh_w8790_dev_read_items(WDT_DEV* pdev, int cmd_id, BYTE* buffer, int start, int item_size, int item_count)
{
	int size = item_size * item_count;
	BYTE cmd[10] = { W8790_COMMAND9, (BYTE)cmd_id, (BYTE)item_count };

	return wh_w8790_dev_command_read(pdev, cmd, 2, buffer, start, size);
}

int wh_w8790_dev_read_array(WDT_DEV* pdev, int cmd_id, BYTE* buffer, int start, int item_size, int item_count)
{
	int max_read_batch = W8790_USB_MAX_PAYLOAD_SIZE / item_size;
	int i = start;

	while (item_count >= max_read_batch) {
		if (wh_w8790_dev_read_items(pdev, cmd_id, buffer, i, item_size, max_read_batch) <= 0)
			return 0;
		i += max_read_batch * item_size;
		item_count -= max_read_batch;
	}
	if (item_count > 0)
		return wh_w8790_dev_read_items(pdev, cmd_id, buffer, i, item_size, item_count);
	return 1;
}

int wh_w8790_dev_read_flash(WDT_DEV* pdev, BYTE* buf, int size)
{
	return wh_w8790_dev_read_array(pdev, W8790_READ_FLASH, buf, 0, sizeof(BYTE), size);
}

int wh_w8790_dev_get_device_mode(WDT_DEV* pdev)
{
	BYTE	status[4] = { 0 };
	if (!pdev)
		return 0;

	if (wh_w8790_dev_get_device_status(pdev, status, 8, 1))
		return status[0];

	return 0;
}




int wh_w8790_dev_set_mem_address(WDT_DEV* pdev, UINT32 address)
{
	BYTE cmd[10] = { 0 };

	cmd[0] = W8790_COMMAND9;
	cmd[1] = W8790_SET_MEMORY_ADDRESS;
	put_unaligned_le32(address, &cmd[2]);

	return wh_w8790_dev_command_write(pdev, cmd, 0, sizeof(cmd));

}

int wh_w8790_dev_set_flash_address(WDT_DEV* pdev, UINT32 address)
{
	BYTE cmd[10] = { 0 };

	cmd[0] = W8790_COMMAND9;
	cmd[1] = W8790_SET_FLASH_ADDRESS;
	put_unaligned_le32(address, &cmd[2]);

	return wh_w8790_dev_command_write(pdev, cmd, 0, sizeof(cmd));

}


int wh_w8790_section_header_valid(W8790_FLASH_SECTION_HEADER* psec_header)
{
	if (!psec_header)
		return 0;

	UINT16 sum = 0;
	sum = misr_for_bytes(sum, (BYTE*)&psec_header->PayloadSize, 0, 12);

	return (sum == psec_header->HeaderChecksum);
}

int wh_w8790_dev_get_section_addr_map(WDT_DEV* pdev, W8790_FLASH_MAP* psec_map)
{
	UINT32 firmware_map_table_addr = 0x000010;
	W8790_FLASH_SECTION_HEADER	sec_header;

	if (!psec_map)
		return 0;

	if (wh_w8790_dev_set_flash_address(pdev, firmware_map_table_addr) <= 0)
		return 0;

	if (wh_w8790_dev_read_flash(pdev, (BYTE*)&sec_header, sizeof(W8790_FLASH_SECTION_HEADER)) <= 0)
		return 0;

	if (wh_w8790_section_header_valid(&sec_header) && sec_header.PayloadSize >= 32 && sec_header.PayloadSize < 1024) {
		if (wh_w8790_dev_set_flash_address(pdev, firmware_map_table_addr + sizeof(W8760_FLASH_SECTION_HEADER)) <= 0)
			return 0;
		size_t padata_buffer = sec_header.PayloadSize + 16;
		BYTE* pdata = (BYTE*)malloc(padata_buffer);
		if (!pdata) {
			printf("pdata malloc fail \n");
			return 0;
		}
		int ret = wh_w8790_dev_read_flash(pdev, (BYTE*)pdata, sec_header.PayloadSize);


		if (ret > 0) {
			psec_map->ParameterMap = get_unaligned_le32(&pdata[0]);
			psec_map->MainLoader = get_unaligned_le32(&pdata[4]);
			psec_map->ParameterPrimary = get_unaligned_le32(&pdata[8]);
			psec_map->ParameterExtended = get_unaligned_le32(&pdata[12]);
			psec_map->ParameterPrivate = get_unaligned_le32(&pdata[16]);

		}
		free(pdata);
		return ret;
	}
	return 0;
}

int wh_w8790_dev_set_n_check_device_mode(WDT_DEV* pdev, BYTE mode, int timeout_ms, int intv_ms)
{
	int polling_timeout_ms = 100;
	int polling_intv_ms = 5;

	// if device in isp mode, we don't check mode
	if (pdev->board_info.dev_type & FW_MAYBE_ISP)
		return 1;

	if (timeout_ms)
		polling_timeout_ms = timeout_ms;
	if (intv_ms)
		polling_intv_ms = intv_ms;

	do {
		wh_w8790_dev_set_device_mode(pdev, mode);

		if (wh_w8790_dev_get_device_mode(pdev) == mode)
			return 1;

		usleep(polling_intv_ms*1000);
		polling_timeout_ms -= polling_intv_ms;
	} while (polling_timeout_ms > 0);

	return 0;
}

int wh_w8760_dev_get_parameter_chksum_by_sec_header(WDT_DEV* pdev, W8790_FLASH_MAP param_addr, UINT16* chksum)
{
	UINT32 checksum = 0;
	W8760_FLASH_SECTION_HEADER	sec_header;

	if (wh_w8790_dev_set_flash_address(pdev, param_addr.ParameterPrimary) <= 0)
		return 0;

	if (wh_w8790_dev_read_flash(pdev, (BYTE*)&sec_header, sizeof(W8760_FLASH_SECTION_HEADER)) <= 0)
		return 0;

	if (wh_w8790_dev_flash_get_checksum(pdev, &checksum, param_addr.ParameterPrimary, sec_header.PayloadSize + sizeof(W8760_FLASH_SECTION_HEADER), 0) <= 0)
		return 0;
	if (wh_w8790_dev_set_flash_address(pdev, param_addr.ParameterExtended) <= 0)
		return 0;

	if (wh_w8790_dev_flash_get_checksum(pdev, &checksum, param_addr.ParameterExtended, sec_header.PayloadSize + sizeof(W8760_FLASH_SECTION_HEADER), checksum) <= 0)
		return 0;

	*chksum = checksum;
	return 1;
}

int  wh_w8790_dev_read_parameter_table_info(WDT_DEV* pdev, W8790_PARAMETER_INFO* p_out_parameter_info)
{
	BYTE cmd[10] = { 0 };

	cmd[0] = W8790_COMMAND9;
	cmd[1] = W8790_READ_PARAMETER_TABLE_INFO;
	BYTE buf[64];
	

	if (wh_w8790_dev_command_read(pdev, cmd, sizeof(cmd), buf, 0, sizeof(W8790_PARAMETER_INFO))) {
		p_out_parameter_info->PMapID = get_unaligned_le16(&buf[0]);
		p_out_parameter_info->PrimarySector = get_unaligned_le16(&buf[2]);
		p_out_parameter_info->PrimarySize = get_unaligned_le16(&buf[4]);
		p_out_parameter_info->ExtendedSector = get_unaligned_le16(&buf[6]);
		p_out_parameter_info->ExtendedSize = get_unaligned_le16(&buf[8]);
		return 1;
	}
	
	
	return 0;

}





int wh_w8790_dev_one_block_fast_write(WDT_DEV* pdev, BYTE* data, int start, int size)
{
	BYTE cmd[64] = { 0 };
	int write_size = size;

	if (size > W8790_USB_MAX_PAYLOAD_SIZE)
		write_size = W8790_USB_MAX_PAYLOAD_SIZE;

	cmd[0] = W8790_BLOCK63;
	memcpy(&cmd[1], &data[start], write_size);

	return wh_w8790_dev_set_feature(pdev, cmd, write_size);
}

int wh_w8790_dev_block_fast_write(WDT_DEV* pdev, BYTE* data, int start, int size)
{
	int payload_size = W8790_USB_MAX_PAYLOAD_SIZE;
	while (size > payload_size) {
		if (wh_w8790_dev_one_block_fast_write(pdev, data, start, payload_size) <= 0)
			return 0;
		start += payload_size;
		size -= payload_size;
	}
	if (size > 0)
		return wh_w8790_dev_one_block_fast_write(pdev, data, start, size);
	return 1;
}

int wh_w8790_dev_one_block_fast_read(WDT_DEV* pdev, BYTE* data, int start, int size)
{
	BYTE cmd[64] = { 0 };
	int read_size = size;

	if (size > W8790_USB_MAX_PAYLOAD_SIZE)
		read_size = W8790_USB_MAX_PAYLOAD_SIZE;

	cmd[0] = W8790_BLOCK63;

	if (wh_w8790_dev_get_feature(pdev, cmd, read_size) > 0) {
		memcpy(&data[start], &cmd[1], read_size);
		return 1;
	}

	return 0;
}

int wh_w8790_dev_block_fast_read(WDT_DEV* pdev, BYTE* data, int start, int size)
{
	int payload_size = W8790_USB_MAX_PAYLOAD_SIZE;

	while (size > payload_size) {
		if (wh_w8790_dev_one_block_fast_read(pdev, data, start, payload_size) <= 0)
			return 0;
		start += payload_size;
		size -= payload_size;
	}

	if (size > 0)
		return wh_w8790_dev_one_block_fast_read(pdev, data, start, size);

	return 1;
}






int wh_w8790_dev_write_items(WDT_DEV* pdev, int cmd_id, BYTE* buffer, int start, int item_size, int item_count)
{
	int size = item_count * item_size;
	BYTE cmd[64] = { 0 };

	cmd[0] = W8790_COMMAND9;
	cmd[1] = cmd_id;
	cmd[2] = item_count;
	memcpy(&cmd[3], &buffer[start], size);

	return wh_w8790_dev_command_write(pdev, cmd, 0, size + 3);
}

int wh_w8790_dev_write_array(WDT_DEV* pdev, int cmd_id, BYTE* buffer, int start, int item_size, int item_count)
{
	int max_write_batch = (W8790_USB_MAX_PAYLOAD_SIZE - 2) / item_size;
	int i = start;

	while (item_count >= max_write_batch) {
		if (wh_w8790_dev_write_items(pdev, cmd_id, buffer, i, item_size, max_write_batch) <= 0)
			return 0;

		i += max_write_batch * item_size;
		item_count -= max_write_batch;
	}

	if (item_count > 0)
		return wh_w8790_dev_write_items(pdev, cmd_id, buffer, i, item_size, item_count);

	return 1;
}





// Longest time to earse the flash chip is 3 seconds. So timeout limit here is 5 seconds.
int wh_w8790_dev_wait_cmd_end(WDT_DEV* pdev, int timeout_ms, int invt_ms)
{
	int polling_timeout_ms = 5000;
	int polling_intv_ms = 10;
	int status;
	BYTE	status_buf[4] = { 0 };

	unsigned long 	start_tick = get_current_ms();
	unsigned long 	time_period;

	if (timeout_ms)
		polling_timeout_ms = timeout_ms;
	if (invt_ms)
		polling_intv_ms = invt_ms;

	do
	{
		if (wh_w8790_dev_get_device_status(pdev, &status_buf[0], 0, 1) <= 0)
			return 0;

		status = status_buf[0];
		if ((status & W8790_COMMAND_BUSY) == 0) {
			time_period = (get_current_ms() - start_tick);
			if (time_period)
				wh_printf("leave %s : %dms\n", __FUNCTION__, time_period);

			return 1;
		}

		wh_sleep(polling_intv_ms);
		polling_timeout_ms -= polling_intv_ms;
	} while (polling_timeout_ms > 0);

	printf("%s: timeout occured (%d)!\n", __FUNCTION__, polling_timeout_ms * polling_intv_ms);
	return 0;
}



int wh_w8790_dev_escape_from_flash_mode(WDT_DEV* pdev, UINT32 mode_id)
{
	BYTE cmd[10] = { W8790_COMMAND9, W8790_ESCAPE_FROM_FLASH_MODE, (BYTE)mode_id, 0xFA, 0xEC };

	if (wh_w8790_dev_command_write(pdev, cmd, 0, sizeof(cmd)) <= 0)
		return 0;

	return 1;
}

int wh_w8790_dev_call_function(WDT_DEV* pdev, UINT32 function_address, UINT32 arg0,
	UINT32 arg1, UINT32 arg2, UINT32 arg3)
{
	BYTE cmd[64] = { 0 };

	cmd[0] = W8790_COMMAND63;
	cmd[1] = W8790_CALL_FUNCTION;
	put_unaligned_le32(function_address, &cmd[2]);
	put_unaligned_le32(arg0, &cmd[6]);
	put_unaligned_le32(arg1, &cmd[10]);
	put_unaligned_le32(arg2, &cmd[14]);
	put_unaligned_le32(arg3, &cmd[18]);

	return wh_w8790_dev_command_write(pdev, cmd, 0, sizeof(cmd));
}

int wh_w8790_dev_get_function_return_value(WDT_DEV* pdev, UINT32* pvalue)
{
	BYTE return_bytes[4] = { 0 };

	int ret = wh_w8790_dev_read_buf_response(pdev, return_bytes, 4);
	if (ret > 0)
		*pvalue = get_unaligned_le32(return_bytes);
	else
		*pvalue = 0;

	return ret;
}



int wh_w8790_dev_run_program_from_background(WDT_DEV* pdev, UINT32 program_address, UINT32 loader_stack)
{
	BYTE cmd[10] = { 0 };

	cmd[0] = W8790_COMMAND63;
	cmd[1] = W8790_RUN_PROGRAM_FROM_BACKGROUND;
	put_unaligned_le32(program_address, &cmd[2]);
	put_unaligned_le32(loader_stack, &cmd[6]);

	return wh_w8790_dev_command_write(pdev, cmd, 0, sizeof(cmd));

}



int wh_w8790_dev_reboot(WDT_DEV* pdev)
{
	BYTE cmd[10] = { W8790_COMMAND9, W8790_REBOOT, 0xB9, 0x0C, 0x8A, 0x24 };

	return wh_w8790_dev_command_write(pdev, cmd, 0, sizeof(cmd));
}


int wh_w8790_dev_read_buf_response(WDT_DEV* pdev, BYTE* data, int size)
{
	return wh_w8790_dev_read_items(pdev, W8790_READ_BUFFERED_RESPONSE, data, 0, sizeof(BYTE), size);
}

int wh_w8790_dev_set_device_mode(WDT_DEV* pdev, BYTE mode)
{
	BYTE cmd[10] = { 0 };

	cmd[0] = W8790_COMMAND9;
	cmd[1] = W8790_SET_DEVICE_MODE;
	cmd[2] = mode;

	return wh_w8790_dev_command_write(pdev, cmd, 0, 3);
}






int wh_w8790_dev_flash_erase_cmd(WDT_DEV* pdev, UINT32 address, UINT32 size)
{
	BYTE cmd[10] = { 0 };

	cmd[0] = W8790_COMMAND9;
	cmd[1] = (BYTE)W8790_ERASE_FLASH;
	cmd[2] = (BYTE)(address >> 12);
	cmd[3] = (BYTE)(((address & 0x0FFF) + size + 4095) >> 12);

	if (wh_w8790_dev_command_write(pdev, cmd, 0, sizeof(cmd)) > 0)
		return wh_w8790_dev_wait_cmd_end(pdev, 6000, 0);

	return 0;
}

int wh_w8790_dev_write_flash_cmd(WDT_DEV* pdev, BYTE* buf, int start, int size)
{
	if (size > W8790_USB_MAX_PAYLOAD_SIZE - 2) {
		printf("%s: payload data overrun\n", __FUNCTION__);
		return 0;
	}

	BYTE cmd[W8790_USB_MAX_PAYLOAD_SIZE + 1] = { 0 };

	cmd[0] = W8790_COMMAND63;
	cmd[1] = (BYTE)W8790_WRITE_FLASH;
	cmd[2] = (BYTE)size;
	memcpy(&cmd[3], &buf[start], size);

	if (wh_w8790_dev_command_write(pdev, cmd, 0, size + 3) > 0)
		return wh_w8790_dev_wait_cmd_end(pdev, 0, 0);

	return 0;
}




int wh_w8790_dev_write_flash(WDT_DEV* pdev, int addr, BYTE* buf, int start, int size)
{
	int byte_count = size;
	int offset = start;
	int max_payload_size = W8760_USB_MAX_PAYLOAD_SIZE - 2;
	int cur_addr = 0xFFFFFFFF;

	while (byte_count >= max_payload_size) {
		if ((addr & 0xfff) == 0)
			wh_printf("base addr: 0x%x\n", addr);
		if (!check_is_all_ff(&buf[offset], max_payload_size)) {
			if (cur_addr != addr) {
				if (!wh_w8790_dev_set_flash_address(pdev, addr))
					return 0;
			}
			if (wh_w8790_dev_write_flash_cmd(pdev, buf, offset, max_payload_size) <= 0)
				return 0;
			cur_addr = addr + max_payload_size;
		}
		else
			wh_printf("Already ff, no need to set: 0x%x\n", addr);
		offset += max_payload_size;
		byte_count -= max_payload_size;
		addr += max_payload_size;
	}

	if (cur_addr != addr) {
		if (!wh_w8790_dev_set_flash_address(pdev, addr))
			return 0;
	}
	if (byte_count > 0) {
		if ((addr & 0xfff) == 0)
			wh_printf("base addr: 0x%x\n", addr);
		return wh_w8790_dev_write_flash_cmd(pdev, buf, offset, byte_count);

	}

	return 1;
}

int wh_w8790_dev_write_flash_page(WDT_DEV* pdev, BYTE* buf, int addr, int size)
{
	int retval = 0;
	unsigned int	write_base;
	unsigned int	write_size;

	write_base = W8790_FLASH_PAGE_SIZE;

	if (addr & 0xFF) {
		unsigned int 	size_partial;
		size_partial = write_base - (addr & 0xFF);

		if (size > (int)size_partial) {
			write_size = size_partial;
			size = size - size_partial;
		}
		else {
			write_size = size;
			size = 0;
		}
		retval = wh_w8790_dev_write_flash(pdev, addr, (BYTE*)buf, 0/*offset*/, write_size);
		if (!retval)
			return retval;
		buf = buf + size_partial;
		addr = addr + size_partial;
	}

	while (size)
	{
		if (size > (int)write_base) {
			write_size = write_base;
			size = size - write_base;
		}
		else {
			write_size = size;
			size = 0;
		}
		retval = wh_w8790_dev_write_flash(pdev, addr, (BYTE*)buf, 0/*offset*/, write_size);
		if (!retval)
			return retval;
		buf = buf + write_base;
		addr = addr + write_base;
	}

	return 1;
}


int wh_w8790_dev_protect_flash(WDT_DEV* pdev, UINT16 protect_mask)
{
	UINT16 mask = protect_mask;

	BYTE cmd[10] = { W8790_COMMAND9, (BYTE)W8790_PROTECT_FLASH, 0, 0, 0, 0 };
	put_unaligned_le16(mask, &cmd[2]);
	put_unaligned_le16((UINT16)~mask, &cmd[4]);

	return wh_w8790_dev_command_write(pdev, cmd, 0, sizeof(cmd));
}

int wh_w8790_dev_flash_get_checksum(WDT_DEV* pdev, UINT32* pchksum, UINT32 flash_address,
	int size, UINT32 init_sum)
{
	BYTE cmd[10] = { 0 };
	BYTE buf[2] = { 0 };

	*pchksum = 0;

	cmd[0] = W8790_COMMAND9;
	cmd[1] = (BYTE)W8790_CALCULATE_FLASH_CHECKSUM;
	put_unaligned_le32(flash_address, &cmd[2]);
	put_unaligned_le32(size, &cmd[5]);
	put_unaligned_le16(init_sum, &cmd[8]);

	if (wh_w8790_dev_command_write(pdev, cmd, 0, sizeof(cmd)) <= 0)
		return 0;

	if (wh_w8790_dev_wait_cmd_end(pdev, 0, 0) <= 0)
		return 0;

	if (wh_w8790_dev_read_buf_response(pdev, buf, 2) <= 0)
		return 0;

	*pchksum = get_unaligned_le16(buf);
	return 1;
}








/*
 * Block access
 */
int wh_w8790_dev_set_block_access(WDT_DEV* pdev, BYTE type, UINT32 offset, UINT32* pblk_size)
{
	BYTE response[4] = { 0 };
	BYTE cmd[10] = { 0 };
	int block_size = 0;

	*pblk_size = 0;

	cmd[0] = W8790_COMMAND9;
	cmd[1] = (BYTE)W8790_SET_BLOCK_ACCESS;
	cmd[2] = type;
	cmd[3] = (BYTE)(offset >> 0);
	cmd[4] = (BYTE)(offset >> 8);
	cmd[5] = (BYTE)(offset >> 16);

	if (wh_w8790_dev_command_read(pdev, cmd, sizeof(cmd), response, 0, 4) <= 0)
	{
		printf("%s: Failed !\n", __FUNCTION__);
		return 0;
	}
		

	block_size = response[1] | (response[2] << 8) | (response[3] << 16);

	if (response[0] == (BYTE)type && block_size != 0x00FFFFFF)
		*pblk_size = block_size;

	return 1;
}

int wh_w8790_dev_block_read(WDT_DEV* pdev, BYTE* data, int start, int size)
{
	return wh_w8790_dev_block_fast_read(pdev, data, start, size);
}

int wh_w8790_dev_block_write(WDT_DEV* pdev, BYTE* data, int start, int size)
{
	return wh_w8790_dev_block_fast_write(pdev, data, start, size);
}

int wh_w8790_dev_block_checksum(WDT_DEV* pdev, UINT32* pchksum, UINT32 size, UINT32 init_value)
{
	BYTE cmd[10] = { 0 };
	BYTE buf[8] = { 0 };

	cmd[0] = W8790_COMMAND9;
	cmd[1] = W8790_BLOCK_CHECKSUM;
	put_unaligned_le32(size, &cmd[2]);
	put_unaligned_le16(init_value, &cmd[5]);

	if (wh_w8790_dev_command_write(pdev, cmd, 0, sizeof(cmd)) <= 0)
		return 0;

	if (wh_w8790_dev_wait_cmd_end(pdev, 0, 0) <= 0)
		return 0;

	if (wh_w8790_dev_read_buf_response(pdev, buf, 2) <= 0)
		return 0;

	*pchksum = get_unaligned_le16(buf);
	return 1;
}








int	wh_w8790_dev_flash_read_data(WDT_DEV* pdev, BYTE* data, UINT32 address, int length)
{
	if (!pdev || !data)
		return 0;

	// address and length should be align to 4
	if ((address & 0x3) != 0 || (length & 0x3) != 0)
		return 0;


	if (!wh_w8790_dev_set_flash_address(pdev, address))
		return 0;

	return wh_w8790_dev_read_flash(pdev, data, length);
}

int	wh_w8790_dev_flash_write_data(WDT_DEV* pdev, BYTE* data, UINT32 address, int length)
{

	return wh_w8790_dev_write_flash_page(pdev,  data, address, length);
}



int wh_w8790_dev_batch_write_flash_cmd(WDT_DEV* pdev,  UINT32 address, UINT32 size, UINT16 misr)
{
	BYTE cmd[10] = { 0 };

	cmd[0] = W8790_COMMAND9;
	cmd[1] = (BYTE)W8790_BATCH_WRITE_FLASH;
	put_unaligned_le32(address, &cmd[2]);
	put_unaligned_le32(size, &cmd[5]);
	UINT16 orig_data_misr = misr;
	misr = misr_for_bytes(misr, cmd, 1, 6);
	put_unaligned_le16(misr, &cmd[7]);

	if (wh_w8790_dev_command_write(pdev, cmd, 0, sizeof(cmd)) <= 0)
		return 0;

	if (wh_w8790_dev_wait_cmd_end(pdev, 0, 0) <= 0)
		return 0;
	BYTE buf[4] = { 0 };

	if (wh_w8790_dev_read_buf_response(pdev, buf, 4) <= 0)
		return 0;
	UINT16 total_misr_sum = get_unaligned_le16(&buf[0]);
	UINT16 data_misr_sum = get_unaligned_le16(&buf[2]);
	if (total_misr_sum != misr && data_misr_sum == orig_data_misr)
	{
		printf("Flash batch write command transmission error. \n");
	}
	if (total_misr_sum != misr && data_misr_sum != orig_data_misr)
	{

		printf("Flash batch write data transmission error. \n");

	}

	printf("base addr: 0x%x\n", address);

	return total_misr_sum == misr;

}



int wh_w8790_dev_batch_write_flash(WDT_DEV* pdev, BYTE* data, UINT32 address, UINT32 start, UINT32 size)
{

	int batch_length = 2048;
	while (size >= (UINT32)batch_length)
	{
		UINT32 batch_buf_size;
		if (!wh_w8790_dev_set_block_access(pdev, W8790_FlashBatchWrite, 0, &batch_buf_size))
			return 0;

		if (batch_buf_size <= 0)
			return 0;
		if (!wh_w8790_dev_block_fast_write(pdev, data, start, batch_length))
			return 0;
		UINT16 misr = misr_for_bytes(0, data, start, batch_length);
		if (wh_w8790_dev_batch_write_flash_cmd(pdev, address, batch_length, misr) == 0)
			return 0;
		address += batch_length;
		start += batch_length;
		size -= batch_length;
	}
	if (size > 0)
	{
		UINT32 batch_buf_size;
		if (!wh_w8790_dev_set_block_access(pdev, W8790_FlashBatchWrite, 0, &batch_buf_size))
			return 0;
		if (!wh_w8790_dev_block_fast_write(pdev, data, start, size))
			return 0;


		UINT16 misr = misr_for_bytes(0, data, start, size);

		if (wh_w8790_dev_batch_write_flash_cmd(pdev, address, size, misr) == 0)
			return 0;

	}
	return 1;




}



int	wh_w8790_dev_flash_block_write(WDT_DEV* pdev, BYTE* data, UINT32 address, int size)
{
	int ret = 1;
	int start = 0;
	UINT32 batch_buf_size = 0;

	if (!wh_w8790_dev_set_block_access(pdev, W8790_FlashBatchWrite, 0, &batch_buf_size))
		return 0;
	if (batch_buf_size <= 0)
		return 0;

	// handle the 1st page if not page aligned
	if (IS_ADDR_PAGE_ALIGNED(address) != 1)
	{
		UINT32 next_page_address = ((address / W8790_FLASH_PAGE_SIZE) + 1) * W8790_FLASH_PAGE_SIZE;
		int first_page_size = (int)(next_page_address - address);
		int retry = 5;
		while ((wh_w8790_dev_batch_write_flash(pdev,  data, address, start, first_page_size) == false) && --retry > 0);
		if (retry == 0)
			return false;
		start += first_page_size;
		size -= first_page_size;
		address += first_page_size;
		if (size <= 0)
			return 1;
	}
	int page_size = W8790_FLASH_PAGE_SIZE;
	unsigned int  page_addr_mask = ~(unsigned int)(page_size - 1);
	UINT32 page_aligned_start = address;
	unsigned int page_aligned_end = (address + (unsigned int)size + (unsigned int)page_size - 1u) & page_addr_mask;
	int num_pages = (int)(page_aligned_end - page_aligned_start) / page_size;

	bool* page_map;
	page_map = (bool*)calloc(num_pages, sizeof(bool));
	if (!page_map)
		return 0;

	int source_size = size;
	int source_start = start;
	int i = 0;
	while (source_size > 0)
	{
		int write_size;
		if (page_size > source_size)
			write_size = source_size;
		else
			write_size = page_size;

		page_map[i] =(count_ff_bytes(data, source_start, write_size) != write_size);
		i++;
		source_start += page_size;
		source_size -= page_size;
	}
	i = 0;
	while (1)
	{
		while (i < num_pages && (page_map[i] == false))
			i++;
		if (i >= num_pages)
			break;
		int num_write_pages;
		if (num_pages - i > 8)
			num_write_pages = 8;
		else
			num_write_pages = num_pages - i;

		while (page_map[i + num_write_pages - 1] == false)
			num_write_pages--;
		int offset = i * page_size;
		int write_size;
		if (num_write_pages * page_size > size - offset)
			write_size = size - offset;
		else
			write_size = num_write_pages * page_size;
		int retry = 5;

		while ((wh_w8790_dev_batch_write_flash(pdev, data, (address + offset), start + offset, write_size) == 0) && --retry > 0);
		if (retry == 0) {
			ret = 0;
		    goto finish;
		}
		i += num_write_pages;
	}

finish: 

	if (page_map) {
		free(page_map);
	}

	return ret;



}



int wh_w8790_dev_get_device_info(WDT_DEV* pdev, BYTE* buf, int offset, int size)
{
	BYTE cmd[10] = { 0 };
	cmd[0] = (BYTE)W8790_COMMAND9;// , type, (BYTE)offset, (BYTE)size
	cmd[1] = W8790_GET_DEVICE_INFO;
	cmd[2] = (BYTE)offset;
	cmd[3] = (BYTE)size;

	return wh_w8790_dev_command_read(pdev, cmd, sizeof(cmd), buf, 0, size);

}

int wh_w8790_dev_get_device_status(WDT_DEV* pdev, BYTE* buf, int offset, int size)
{
	BYTE cmd[10] = { 0 };
	cmd[0] = (BYTE)W8790_COMMAND9;// , type, (BYTE)offset, (BYTE)size
	cmd[1] = W8790_GET_DEVICE_STATUS;
	cmd[2] = (BYTE)offset;
	cmd[3] = (BYTE)size;

	return wh_w8790_dev_command_read(pdev, cmd, sizeof(cmd), buf, 0, size);

}


int wh_w8790_dev_apply_parameters(WDT_DEV* pdev, BYTE table_type)
{
	BYTE cmd[10] = { W8790_COMMAND9, W8790_APPLY_PARAMETERS, (BYTE)table_type };

	if (wh_w8790_dev_command_write(pdev, cmd, 0, sizeof(cmd)) <= 0) {
		printf("Fail to do get store parameter \n");
		return 0;
	}

	if (wh_w8790_dev_wait_cmd_end(pdev, 0, 0) <= 0) {
		printf("Cd Cs open test time out \n");
		return 0;
	}

	return 1;
}

int wh_w8790_dev_read_parameter_page(WDT_DEV* pdev, BYTE* buf, int page_index)
{
	BYTE cmd[10] = { W8790_COMMAND9, W8790_READ_PARAMETER_PAGE, (BYTE)page_index };

	return wh_w8790_dev_command_read(pdev, cmd, sizeof(cmd), buf, 0, W8790_USB_MAX_PAYLOAD_SIZE);
}



int wh_w8790_dev_get_parameter_chksum_by_blk_xfer(WDT_DEV* pdev, UINT16* chksum)
{
	int ret = 0;
	UINT32 parameter_size = 0;
	BYTE* pdata = 0;

	if (!wh_w8790_dev_set_block_access(pdev, W8790_PrimaryParameter, 0, &parameter_size))
		return 0;

	if (parameter_size > 16) {
		pdata = (BYTE*)malloc(parameter_size + 16);
		ret = wh_w8790_dev_block_read(pdev, pdata, 0, parameter_size);

		if (ret)
			*chksum = misr_for_bytes(0, pdata, 0, parameter_size);
		free(pdata);
		return ret;
	}
	return 0;
}






int wh_w8790_dev_flash_erase(WDT_DEV* pdev, UINT32 address, int size)
{

	int ret = wh_w8790_dev_flash_erase_cmd(pdev, address, size);

	if (ret <= 0)
		printf("%s: addr: %x, size: %x\n", __FUNCTION__, address, size);

	return ret;
}







int wh_w8790_dev_program_chunk(WDT_DEV* pdev, CHUNK_INFO_EX* pInputChunk, int option)
{
	printf("%s: not implemented !\n", __FUNCTION__);
	return 0;

}



int wh_w8790_dev_verify_chunk(WDT_DEV* pdev, CHUNK_INFO_EX* pChunk)
{
	printf("%s: not implemented !\n", __FUNCTION__);
	return 0;

}







int	wh_w8790_dev_send_commands(WDT_DEV* pdev, int cmd, UINT32 value)
{
	int ret = 0;
	switch (cmd)
	{
	case 	WH_CMD_RESET:
		ret = wh_w8790_dev_reboot(pdev);
		break;
	case 	WH_CMD_SET_DEV_MODE: {
		ret =  wh_w8790_dev_set_n_check_device_mode(pdev, value, 0, 0);
		break;
	}
	case	WH_CMD_FLASH_ERASE4K:
		ret = wh_w8790_dev_flash_erase(pdev, value, 0x1000);
		break;
	case	WH_CMD_FLASH_ERASE32K:
		ret = wh_w8790_dev_flash_erase(pdev, value, 0x8000);
		break;
	case	WH_CMD_FLASH_ERASE64K:
		ret = wh_w8790_dev_flash_erase(pdev, value, 0x10000);
		break;

	case	WH_CMD_FLASH_LOCK:
	case	WH_CMD_FLASH_PROTECTION_ON:
		ret = wh_w8790_dev_protect_flash(pdev, W8760_ProtectAll512k);
		break;
	case	WH_CMD_FLASH_UNLOCK: {
		ret = wh_w8790_dev_set_n_check_device_mode(pdev, W8790_MODE_FLASH_PROGRAM, 0, 0);
		break;
	}
	case	WH_CMD_FLASH_PROTECTION_OFF:
	{
		// address align to 0x100
		UINT32 addr = ((value & 0xFFFF0000) >> 8);

		// size align to 0x100
		UINT32 size = ((value & 0xFFFF) << 8) + 0x100;
		if (addr < 128 * 1024 && addr + size <= 128 * 1024)
			ret = wh_w8790_dev_protect_flash(pdev, W8760_UnprotectLower128k);
		else if (addr < 256 * 1024 && addr + size <= 256 * 1024)
			ret = wh_w8790_dev_protect_flash(pdev, W8760_UnprotectLower256k);
		else if (addr < 384 * 1024 && addr + size <= 384 * 1024)
			ret = wh_w8790_dev_protect_flash(pdev, W8760_UnprotectLower384k);
		else if (addr < 508 * 1024 && addr + size <= 508 * 1024)
			ret = wh_w8790_dev_protect_flash(pdev, W8760_UnprotectLower508k);
		else if (addr == 0 && addr + size > 508 * 1024 && addr + size <= 512 * 1024)
			ret = wh_w8790_dev_protect_flash(pdev, W8760_UnprotectAll512k);
	}
	break;
	case 	WH_CMD_ALGO_STOP: 
		ret =  wh_w8790_dev_set_n_check_device_mode(pdev, W8790_MODE_COMMAND, 0, 0);
		break;
	case 	WH_CMD_ALGO_START:
		ret = wh_w8790_dev_set_n_check_device_mode(pdev, W8790_MODE_SENSING, 0, 0);
		break;
	default:
		ret = 0;
		break;
	}
	return ret;

}





UINT16 wh_w8790_flash_section_header_checksum(W8790_FLASH_SECTION_HEADER header)
{
	UINT16 sum = 0;
	sum = misr_32b(sum, header.PayloadSize);
	sum = misr_32b(sum, header.Param0);
	sum = misr_32b(sum, header.Param1);
	return sum;
}
int  wh_w8790_flash_section_validate(BYTE* data, UINT32 datalength, int start = 0)
{
	int ret = 0;
	W8790_FLASH_SECTION_HEADER header;

	header.Param1 = get_unaligned_le32(&data[12]);
	header.Param0 = get_unaligned_le32(&data[8]);
	header.PayloadSize = get_unaligned_le32(&data[4]);
	header.HeaderChecksum = get_unaligned_le16(&data[2]);
	header.Checksum = get_unaligned_le16(&data[0]);
	if (header.HeaderChecksum != wh_w8790_flash_section_header_checksum(header))
	{
		printf("Invalid section header. \n");
		return 0;
	}
	if (start + sizeof(header) + header.PayloadSize > datalength)
	{
		printf("Invalid section length. \n");
		return 0;
	}
	BYTE* payload;
	payload = (BYTE*)calloc(header.PayloadSize, sizeof(BYTE));
	if (!payload) {
		printf("calloc fail !\n");
		return 0;
	}
	memcpy(payload, &data[16], header.PayloadSize);

	if (header.Checksum != misr_for_bytes(header.HeaderChecksum, payload, 0, header.PayloadSize / sizeof(BYTE))) {
		ret = 0;
		printf("Payload checksum error.\n");
	}
	else 
	{
		ret = 1;
	}
		
	if (payload)
		free(payload);
	return ret;
}




int wh_w8790_dev_read_parameters_get_checksum(WDT_DEV* pdev, W8790_PARAMETER_INFO parameter_info, UINT32* sum)
{
	int ret = 0;

	UINT32 primary_parameter_size;
	ret = wh_w8790_dev_set_block_access(pdev, W8790_PrimaryParameter, 0, &primary_parameter_size);
	if (!ret) {
		return 0;
	}

	if (primary_parameter_size != parameter_info.PrimarySize) {
		printf("Invalid primary parameter. ({ %d }) \n", primary_parameter_size);
		ret = 0;
		return 0;

	}
	BYTE* primary_bin;

	primary_bin = (BYTE*)calloc(primary_parameter_size, sizeof(BYTE));
	if (!primary_bin)
	{
		printf("calloc fail ! \n");
		ret = 0;
		goto exit_fun;
	}

	if (wh_w8790_dev_block_read(pdev, primary_bin, 0, primary_parameter_size) <= 0)
	{
		ret = 0;
		goto exit_fun;
	}
	W8790_FLASH_SECTION_HEADER primary_header;

	primary_header.Param1 = get_unaligned_le32(&primary_bin[12]);
	primary_header.Param0 = get_unaligned_le32(&primary_bin[8]);
	primary_header.PayloadSize = get_unaligned_le32(&primary_bin[4]);
	primary_header.HeaderChecksum = get_unaligned_le16(&primary_bin[2]);
	primary_header.Checksum = get_unaligned_le16(&primary_bin[0]);

	*sum = misr_for_bytes(0, primary_bin, 0, primary_parameter_size);

	if (primary_header.Checksum == 0x0000 && primary_header.HeaderChecksum == 0x0000) // for the built-in parameter table in firmware
	{
		ret = wh_w8790_dev_set_block_access(pdev, W8790_PrimaryParameter, 0, &primary_parameter_size);
		if (!ret) {
			goto exit_fun;
		}
		UINT32 expected_sum;
		ret = wh_w8790_dev_block_checksum(pdev, &expected_sum, primary_parameter_size, 0);

		if (*sum != expected_sum) {
			printf("Primary parameter checksum mismatch. \n");
			ret = 0;
			goto exit_fun;
		}

	}
	else
	{
		if (primary_header.HeaderChecksum != wh_w8790_flash_section_header_checksum(primary_header))
			printf("Primary parameter section header checksum failed.\n");

		if(wh_w8790_flash_section_validate(primary_bin, primary_parameter_size) == 0)
			printf("Invalid primary parameter section.\n");

	}

	
	if (parameter_info.ExtendedSize > 0)
	{
		BYTE* extended_bin;
		UINT32 extent_parameter_size;
		ret = wh_w8790_dev_set_block_access(pdev, W8790_ExtendedParameter, 0, &extent_parameter_size);
		if (!ret) {
			goto exit_fun;
		}
		if (extent_parameter_size > 0)
		{
			extended_bin = (BYTE*)calloc(extent_parameter_size, sizeof(BYTE));
			if (!extended_bin)
			{
				printf("calloc fail !");

				ret = 0;
				goto exit_fun;
			}

			if (wh_w8790_dev_block_read(pdev, extended_bin, 0, extent_parameter_size) <= 0)
			{
				ret = 0;
				if (extended_bin)
					free(extended_bin);
				goto exit_fun;
			}
			W8790_FLASH_SECTION_HEADER extended_header;

			extended_header.Param1 = get_unaligned_le32(&extended_bin[12]);
			extended_header.Param0 = get_unaligned_le32(&extended_bin[8]);
			extended_header.PayloadSize = get_unaligned_le32(&extended_bin[4]);
			extended_header.HeaderChecksum = get_unaligned_le16(&extended_bin[2]);
			extended_header.Checksum = get_unaligned_le16(&extended_bin[0]);

			if (extended_header.HeaderChecksum != wh_w8790_flash_section_header_checksum(extended_header))
				printf("Extended parameter section header checksum failed.\n");

			if (wh_w8790_flash_section_validate(extended_bin, extent_parameter_size) == 0)
				printf("Invalid extended parameter section.\n");
		}
		else
		{
			extended_bin = (BYTE*)calloc(parameter_info.ExtendedSize, sizeof(BYTE));
		}
		*sum = misr_for_bytes(*sum, extended_bin, 0, extent_parameter_size);

		if (extended_bin)
			free(extended_bin);

	}


exit_fun:
	if (primary_bin)
		free(primary_bin);

	
	return ret; 

}

int	wh_w8790_prepare_data(WDT_DEV* pdev, BOARD_INFO* p_out_board_info)
{
	if (!pdev || !p_out_board_info)
		return 0;
	wh_w8790_dev_set_basic_op(pdev);



	if (!wh_w8790_dev_identify_platform(pdev)) {
		printf("can't get platform identify!\n");
		return 0;
	}
	//I:0x49 S:0x53 P:0x50 
	if (pdev->board_info.dev_info.w8790_feature_devinfo.program_name_fourcc[0] == 'I' &&
		pdev->board_info.dev_info.w8790_feature_devinfo.program_name_fourcc[1] == 'S' &&
		pdev->board_info.dev_info.w8790_feature_devinfo.program_name_fourcc[2] == 'P')
	{
		p_out_board_info->dev_type = FW_WDT8790_ISP;
		printf("It is ISP mode!\n");


		return 1;

	}


	W8790_PCT	pct_data;


	if (wh_w8790_dev_get_context(pdev, &pct_data)) {
		// set the default values
		p_out_board_info->sys_param.Phy_Frmbuf_W = pct_data.n_cs;
		p_out_board_info->sys_param.Phy_X0 = pct_data.x1;
		p_out_board_info->sys_param.Phy_X1 = pct_data.xn;

		p_out_board_info->sys_param.Phy_Frmbuf_H = pct_data.n_cd;
		p_out_board_info->sys_param.Phy_Y0 = pct_data.y1;
		p_out_board_info->sys_param.Phy_Y1 = pct_data.yn;

		p_out_board_info->sys_param.xmls_id2 = 0;

		W8790_PARAMETER_INFO parameter_info;
		wh_w8790_dev_read_parameter_table_info(pdev, &parameter_info);
		UINT32 cksum;
		wh_w8790_dev_read_parameters_get_checksum(pdev, parameter_info, &cksum);
		p_out_board_info->sys_param.xmls_id1 = cksum;



		return 1;
	}




	return 0;
}



