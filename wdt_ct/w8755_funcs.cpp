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
#include "w8755_funcs.h"


#define		WRITE_FLASH_PAGE(__WRITE_BASE_SIZE__)	\
	if (size > (int) __WRITE_BASE_SIZE__) {		\
		write_size = __WRITE_BASE_SIZE__;	\
		size = size - __WRITE_BASE_SIZE__;	\
	} else {					\
		write_size = size;			\
		size = 0;				\
	}						\
	retval = wh_w8755_dev_flash_write_data_page(pdev, (BYTE*) pdata, start_addr, write_size);	\
	if (!retval)					\
		return retval;				\
	pdata = pdata + __WRITE_BASE_SIZE__;		\
	start_addr = start_addr + __WRITE_BASE_SIZE__;	

#define		IS_ADDR_SECTOR_ALIGNED(__ADDR__)	((__ADDR__ & (unsigned int)(FLS_SEC_SZ - 1)) == 0)
#define		IS_ADDR_BLK64_ALIGNED(__ADDR__) 	((__ADDR__ & (unsigned int)(FLS_BLK64_SZ - 1)) == 0)
#define		IS_ADDR_BLK32_ALIGNED(__ADDR__)		((__ADDR__ & (unsigned int)(FLS_BLK32_SZ - 1)) == 0)  


int     wh_w8755_dev_set_device_mode(WDT_DEV* pdev, BYTE mode);
BYTE 	wh_w8755_dev_get_device_mode(WDT_DEV* pdev);
int 	wh_w8755_dev_enable_spi_flash_protection(WDT_DEV* pdev, int protect);
int 	wh_w8755_i2c_delay(WDT_DEV* pdev, unsigned long delay);

static const int DataPayloadSize = 60;
static FUNC_PTR_STRUCT_DEV_BASIC	g_func_dev_basic = { 0, 0, 0, 0 };

int wh_w8755_dev_exec_report_type_write(WDT_DEV* pdev, BYTE type, BYTE *pbuf, int size)
{
	W8755_WRITE_DATA	write_data;

	if (!pdev || !pbuf)
		return 0;

	memset(&write_data, 0, sizeof(write_data));

	write_data.DD.rpt_id = W8755_RPTID_WRITE_DATA;
	write_data.DD.type = type;
	write_data.DD.size = size;

	memcpy(&write_data.DD.data[0], pbuf, size);

	if (g_func_dev_basic.p_wh_set_feature)
		return g_func_dev_basic.p_wh_set_feature(pdev, write_data.buffer, 4 + write_data.DD.size);		

	return 0;
}


int wh_w8755_dev_exec_set_report_read(WDT_DEV* pdev, BYTE type, BYTE *pbuf, int size)
{
	W8755_WRITE_DATA	write_data;

	if (!pdev || !pbuf || !g_func_dev_basic.p_wh_set_feature)
		return 0;

	write_data.DD.rpt_id = W8755_RPTID_REQ_READ;	
	write_data.DD.type = type;
	write_data.DD.size = size;
	
	return g_func_dev_basic.p_wh_set_feature(pdev, write_data.buffer, 4);	
}

int wh_w8755_dev_exec_get_report_read(WDT_DEV* pdev, BYTE type, BYTE *pbuf, int size)
{
	W8755_READ_DATA 	read_data;
	int 				retval;
	UINT32				read_checksum, calc_checksum;
	
	if (!pdev || !pbuf || !g_func_dev_basic.p_wh_get_feature)
		return 0;

	memset(&read_data.buffer[0], 0xff, 4);
	memset(&read_data.buffer[4], 0, 60);
			
	read_data.DD.rpt_id = W8755_RPTID_READ_DATA;
	read_data.DD.type = type;
	retval = g_func_dev_basic.p_wh_get_feature(pdev, read_data.buffer, 64);
	if (!retval)
		return 0;

	if (read_data.DD.rpt_id != W8755_RPTID_READ_DATA) {
		wh_printf("%s: wrong rpt_id\n", __func__);
		return 0;
	}
		
	read_checksum = read_data.DD.checksum;
	calc_checksum = 0;
	for (int i=0; i<60; i++)
		calc_checksum += read_data.DD.data[i];
		
	if (read_checksum != calc_checksum) {
		wh_printf("%s: wrong chksum\n", __func__);
		return 0;
	}
	
	memcpy(pbuf, read_data.DD.data, size);
	return 1;
}


int wh_w8755_dev_exec_report_type_read(WDT_DEV* pdev, BYTE type, BYTE *pbuf, int size, int offset)
{
	int	retval;
	int	i_size;

	if (offset & TYPE_READ_OFFSET_SET)
		i_size = offset & 0xFF;
	else
		i_size = size;

	retval = wh_w8755_dev_exec_set_report_read(pdev, type, pbuf, i_size);
	if (!retval)
		return 0;

	return wh_w8755_dev_exec_get_report_read(pdev, type, pbuf, size);
}


int wh_w8755_dev_get_new_device_info(WDT_DEV* pdev, BYTE *pbuf, int offset, int size)
{
	BYTE	buf[64];
	
	if (wh_w8755_dev_exec_report_type_read(pdev, W8755_FW_GET_DEVICE_INFO, buf, 32, TYPE_READ_OFFSET_SET | offset)) {
		memcpy(pbuf, &buf[0], size);
		return 1;
	}

	return 0;
}

int wh_w8755_dev_flash_write_data_page(WDT_DEV* pdev, BYTE* data, UINT32 address, int length)
{
	int	addr_start, data_len, packet_size;
	BYTE*	psource_data = 0;
	int	count = 0;
	int	retval = 1;

	if (!data)
		return 0;

	/* address and length should be align to 4 */
	if ((address & 0x3) != 0 || (length & 0x3) != 0)
		return 0;

	/* to make sure the data not exceed a sector */
	if ((address >> 8) != ((address + length - 1) >> 8))		
		return 0;

	data_len = length;
	addr_start = address;
	psource_data = data;

	packet_size = W8755_PACKET_SIZE;
	
	/* set the address to the device first */
	retval = wh_w8755_dev_exec_report_type_write(pdev, W8755_ISP_SET_FLASH_ADDRESS,
						     (BYTE *) &addr_start, 4);
	if (!retval)
		return 0;

	/* since the address is incremental, the following step just keep writting the flash data */
	while(data_len)	{		
		if (data_len < W8755_PACKET_SIZE)
			packet_size = data_len;

		if (!wh_w8755_dev_exec_report_type_write(pdev, W8755_ISP_SET_FLASH,
							 psource_data, packet_size)) {
			printf("can't set flash: 0x%x\n", addr_start);
			retval = 0;
			break;			
		}

		data_len = data_len - packet_size;
		psource_data = psource_data + packet_size;
		addr_start = addr_start + packet_size;


		wh_udelay(FLASH_PAGE_WRITE_DELAY_US);
		count++;
	}

	return retval; 
}

int wh_w8755_dev_flash_write_data(WDT_DEV* pdev, BYTE* pdata, UINT32 start_addr, int size)
{
	int retval = 0;
	unsigned int	write_base;
	unsigned int	write_size;

	write_base = 0x100;

	if (start_addr & 0xFF) {
		unsigned int 	size_partial;
		size_partial = write_base - (start_addr & 0xFF);
		
		WRITE_FLASH_PAGE(size_partial);			
	}

	while (size) {
		if ((start_addr & 0xfff) == 0)
			printf("base addr: 0x%x\n", start_addr);
	
		WRITE_FLASH_PAGE(write_base);			
	}

	return 1;
}



int wh_w8755_dev_send_commands(WDT_DEV* pdev, int cmd, UINT32 value)
{
	W8755_CMD_DATA	cmd_data;
	unsigned long 	delay = 0;
	int				result = 0;

	memset(&cmd_data, 0, sizeof(cmd_data));

	cmd_data.DD.rpt_id = W8755_RPTID_WRITE_DATA;

	switch(cmd)
	{
		case 	WH_CMD_ALGO_STOP: {
			int count = 20;
			do {
				wh_w8755_dev_set_device_mode(pdev, W8755_DM_COMMAND);
				wh_sleep(5);
			} while (wh_w8755_dev_get_device_mode(pdev) != W8755_DM_COMMAND && count-- > 0);
			
			return 1;
		}
		break;
		case 	WH_CMD_ALGO_START: {
			int count = 20;
			do {
				wh_w8755_dev_set_device_mode(pdev, W8755_DM_SENSING);
				wh_sleep(5);
			} while (wh_w8755_dev_get_device_mode(pdev) != W8755_DM_SENSING && count--> 0);

			return 1;
		}
		break;
		case 	WH_CMD_SET_DEV_MODE: {
			cmd_data.DD.type = W8755_FW_SET_COMMAND;
			cmd_data.DD.size = 2;
			cmd_data.DD.cmd = W8755_SET_CMD_DEVICE_MODE; 
			cmd_data.DD.param1 = (BYTE) value;			
		}
		break;
		case 	WH_CMD_RESET: {							
			cmd_data.DD.type = W8755_ISP_SET_COMMAND;			
			cmd_data.DD.size = 1;
			cmd_data.DD.cmd = W8755_SET_CMD_RESET;		
		}
		break;
		case	WH_CMD_FLASH_ERASEALL:	{
			cmd_data.DD.type = W8755_ISP_SET_COMMAND;			
			cmd_data.DD.size = 5;
			cmd_data.DD.cmd = W8755_SET_CMD_ERASEALL;
			put_unaligned_le32(value, &cmd_data.buffer[5]);
			
			delay = W8755_FLASH_CHIP_DELAY;			
		}
		break;
		case	WH_CMD_FLASH_ERASE4K:	{
			cmd_data.DD.type = W8755_ISP_SET_COMMAND;			
			cmd_data.DD.size = 5;
			cmd_data.DD.cmd = W8755_SET_CMD_ERASE4K;
			put_unaligned_le32(value, &cmd_data.buffer[5]);

			delay = W8755_FLASH_4K_DELAY;			
		}
		break;
		case	WH_CMD_FLASH_ERASE32K:	{
			cmd_data.DD.type = W8755_ISP_SET_COMMAND;						
			cmd_data.DD.size = 5;
			cmd_data.DD.cmd = W8755_SET_CMD_ERASE32K;
			put_unaligned_le32(value, &cmd_data.buffer[5]);

			delay = W8755_FLASH_32K_DELAY;				
		}
		break;
		case	WH_CMD_FLASH_ERASE64K:	{
			cmd_data.DD.type = W8755_ISP_SET_COMMAND;						
			cmd_data.DD.size = 5;
			cmd_data.DD.cmd = W8755_SET_CMD_ERASE64K;
			put_unaligned_le32(value, &cmd_data.buffer[5]);

			delay = W8755_FLASH_64K_DELAY;				
		}
		break;
		case WH_CMD_FLASH_PROTECTION_ON: {
			cmd_data.DD.type = W8755_ISP_SET_COMMAND;						
			cmd_data.DD.size = 2;
			cmd_data.DD.cmd = W8755_SET_CMD_SFLOCK; 
			cmd_data.DD.param1 = 0x9B;

			/* to wait read flash status */
			delay = 20 | DELAY_REAL_SLEEP;
		}
		break;
		case WH_CMD_FLASH_PROTECTION_OFF: {
			cmd_data.DD.type = W8755_ISP_SET_COMMAND;						
			cmd_data.DD.size = 2;
			cmd_data.DD.cmd = W8755_SET_CMD_SFUNLOCK; 
			cmd_data.DD.param1 = 0xDA;		
			
			/* to wait read flash status */
			delay = 20 | DELAY_REAL_SLEEP;
		}
		break;		
		case	WH_CMD_FLASH_LOCK:	{		
			return wh_w8755_dev_enable_spi_flash_protection(pdev, 1);
		}
		case	WH_CMD_FLASH_UNLOCK: {		
			return wh_w8755_dev_enable_spi_flash_protection(pdev, 0);
		}
		break;

		default: {
			cmd_data.DD.rpt_id = 0;
			return 0;
		}
	}

	if (g_func_dev_basic.p_wh_set_feature) {
		result = g_func_dev_basic.p_wh_set_feature(pdev, &cmd_data.buffer[0], 4 + cmd_data.DD.size);

		if (delay) {
			if (delay & DELAY_REAL_SLEEP) 
				wh_sleep(delay & DELAY_REAL_SLEEP_MASK);
			else {
				delay = wh_w8755_i2c_delay(pdev, delay);
				wh_printf("cmd delay: %d ms\n", (int) delay);
			}
		}

		return result;
	} else
		printf("set feature ptr is null\n");

	return 0;
}

int wh_w8755_dev_set_device_mode(WDT_DEV* pdev, BYTE mode)
{
	return wh_w8755_dev_send_commands(pdev, WH_CMD_SET_DEV_MODE, mode);
}

BYTE wh_w8755_dev_get_device_mode(WDT_DEV* pdev)
{
	BYTE	buffer[4];

	if (wh_w8755_dev_get_new_device_info(pdev, buffer, 0x0C, 4))
		return buffer[0];

	return 0;
}

unsigned int wh_w8755_dev_read_flash_status_register(WDT_DEV* pdev, unsigned int *pdata)
{
	BYTE				buf[64];

	*pdata = 0xff;

 	if (!wh_w8755_dev_exec_report_type_read(pdev, W8755_ISP_GET_FLASH_STATUS, buf, DataPayloadSize, 0)) {
		wh_printf("%s: report type read error\n", __func__);
		return 0;
	}

	*pdata = (unsigned int) buf[0];

	return 1;
}

unsigned int wh_w8755_dev_write_flash_status_register(WDT_DEV* pdev, unsigned int r)
{
	BYTE				data;
	unsigned int		result;
	int					timeout_count = 0;
	
	data = (BYTE) (r & 0xff);

	if (!wh_w8755_dev_exec_report_type_write(pdev, W8755_ISP_SET_FLASH_STATUS, &data, 1)) {
		wh_printf("%s: report type write error\n", __func__);
		return 0;
	}

	/* timeout should be limit to 1 second */
	result = 0xFF;
	while ((result & 0x01) && (timeout_count < 100) ) {
		wh_w8755_dev_read_flash_status_register(pdev, &result);
		wh_printf("count: %d, (%d)\n", timeout_count, result);
		wh_sleep(10);
		timeout_count ++;
	}

	if (timeout_count >= 100)
		printf("%s: error in timeout !\n", __func__);

	return 1;
}

int wh_w8755_dev_enable_spi_flash_protection(WDT_DEV* pdev, int protect)
{
	if (protect) {
		int retval = wh_w8755_dev_send_commands(pdev, WH_CMD_FLASH_PROTECTION_ON, 0);
			
		wh_sleep(20);
		return retval;
	}	
	else
	{
		if (wh_w8755_dev_send_commands(pdev, WH_CMD_FLASH_PROTECTION_OFF, 0)) {
			wh_sleep(20);

			return 1;
		}
	}
	return 0;
}


int wh_w8755_dev_flash_erase(WDT_DEV* pdev, unsigned int address, int size)
{
	if (address == 0 && size == FLS_SZ) {
		if (!wh_w8755_dev_send_commands(pdev, WH_CMD_FLASH_ERASEALL, 0)) {			
			printf("Flash chip erase fails\n");
			return 0;
		}

		return 1;
	} else {
		if (!IS_ADDR_SECTOR_ALIGNED(address))
			return 0;
		
		while (size > 0)
		{
			if (IS_ADDR_BLK64_ALIGNED(address) && size >= FLS_BLK64_SZ) {
				if (!wh_w8755_dev_send_commands(pdev, WH_CMD_FLASH_ERASE64K, address)) {
					printf("Flash 64k block erase fails: 0x%x\n", address);
					break;
				}			
				
				address += FLS_BLK64_SZ;
				size -= FLS_BLK64_SZ;
			} else if (IS_ADDR_BLK64_ALIGNED(address) && size >= FLS_BLK32_SZ) {
				if (!wh_w8755_dev_send_commands(pdev, WH_CMD_FLASH_ERASE32K, address)) {
					printf("Flash 32k block erase fails: 0x%x\n", address);
					break;
				}
				
				address += FLS_BLK32_SZ;
				size -= FLS_BLK32_SZ;
			} else	{
				if (!wh_w8755_dev_send_commands(pdev, WH_CMD_FLASH_ERASE4K, address)) {
					printf("Flash 4k block erase fails: 0x%x\n", address);
					break;
				}
		
				address += FLS_SEC_SZ;
				size -= FLS_SEC_SZ;
			}
		}
	}
	
	return (size <= 0);
}

int wh_w8755_dev_flash_get_checksum(WDT_DEV* pdev, UINT32* pchecksum, UINT32 address, int size)
{
	BYTE			buf[64];
	unsigned int	checksum;
	int				delay;	

	put_unaligned_le32(address, &buf[0]);
	put_unaligned_le32(size, &buf[4]);
	
	if (!wh_w8755_dev_exec_report_type_write(pdev, W8755_ISP_SET_CHECKSUM_CALC, buf, 8)) {
		printf("%s: report type write error!\n", __func__);
		return 0;
	}

	delay = (size + 1023) / 1024;
	delay = wh_w8755_i2c_delay(pdev, delay * 4);
	wh_printf("chksum delay: %d ms\n", delay);

	if (!wh_w8755_dev_exec_report_type_read(pdev, W8755_ISP_GET_CHECKSUM, buf, DataPayloadSize, 0)) {
		printf("%s: report type read chksum error!\n", __func__);
		return 0;
	}

	checksum = get_unaligned_le16(buf);
	*pchecksum = checksum;

	return 1;
}

int wh_w8755_dev_parse_new_dev_info(WDT_DEV* pdev, W8755_DEV_INFO_NEW *pdev_info_new)
{
	BYTE	buffer[32];
	int		retval;

	retval = wh_w8755_dev_get_new_device_info(pdev, buffer, 0, 32);
	if (!retval)
		return 0;
	
	pdev_info_new->protocol_version = get_unaligned_le32(&buffer[0x00]);
	pdev_info_new->firmware_id = get_unaligned_le32(&buffer[0x04]);
	pdev_info_new->status = get_unaligned_le32(&buffer[0x08]);
	pdev_info_new->config_size = get_unaligned_le16(&buffer[0x10]);
	pdev_info_new->parameter_map_sum = get_unaligned_le16(&buffer[0x12]);
	pdev_info_new->firmware_revision = get_unaligned_le16(&buffer[0x14]);
	pdev_info_new->max_points = buffer[0x16];
	pdev_info_new->bytes_per_point = buffer[0x16];
	pdev_info_new->customer_config_id = get_unaligned_le32(&buffer[0x18]);

	pdev_info_new->boot_partition = W8755_BP_DEFAULT;
	if (pdev_info_new->protocol_version >= 0x01010000) {
		if (buffer[0x001E] == 0xB1)
			pdev_info_new->boot_partition = W8755_BP_PRIMARY;
		else if (buffer[0x001E] == 0xB2)
            pdev_info_new->boot_partition = W8755_BP_SECONDARY;
	}	



	return true;
}

int wh_w8755_dev_program_4k_chunk_verify(WDT_DEV* pdev, CHUNK_INFO_EX* pInputChunk, int option)
{
	int retval = 0;
	int size;
	int start_addr = 0;
	int page_size;
	int retry_count = 0;
	int is_first_page = 0;
	char*	pdata;
	UINT32	calc_checksum, read_checksum;
	CHUNK_INFO_EX	*pChunk = pInputChunk;

	printf("start 4k chunk program ...\n");
	pdev->dev_state = DS_PROGRAM;

	retval = wh_w8755_dev_send_commands(pdev, WH_CMD_ALGO_STOP, 0);
	if (!retval)
		return retval;	
	
	retval = wh_w8755_dev_send_commands(pdev, WH_CMD_FLASH_UNLOCK, 0);
	if (!retval)
		return retval;

	if (option & OPTION_FASTBOOT)	{
		printf("not supported !\n");
		return 0;
	} 

	if (option & OPTION_ERASE_TEMP) {
		retval = wh_w8755_dev_send_commands(pdev, WH_CMD_FLASH_ERASE4K, pInputChunk->chuckInfo.temp);
		if (!retval) {
			printf("erase temp addr failed !\n");
			return 0;
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
			retval = wh_w8755_dev_send_commands(pdev, WH_CMD_FLASH_ERASE4K, start_addr);
			if (!retval)
				continue;

			retval = wh_w8755_dev_flash_write_data(pdev, (BYTE*) pdata, start_addr, page_size);
			if (!retval)
				continue;

			calc_checksum = misr_for_bytes(0, (BYTE*) pdata, 0, page_size);
			retval = wh_w8755_dev_flash_get_checksum(pdev, &read_checksum, start_addr, page_size);

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

		// keep the first page to write to the flash in the last loop
		if (size == 0 && is_first_page) {		
			size = WDT_PAGE_SIZE;
			start_addr = pChunk->chuckInfo.targetStartAddr;
			pdata = (char*) pChunk->pData;
			is_first_page = 0;		
		}
	}

	retval = wh_w8755_dev_send_commands(pdev, WH_CMD_FLASH_LOCK, 0);
	if (!retval)
		return retval;

	retval = wh_w8755_dev_send_commands(pdev, WH_CMD_ALGO_START, 0);
	if (!retval)
		return retval;
	
	if (retry_count == RETRY_COUNT) {
		printf("stop 4k chunk program : fail \n");
		return 0;
	}

	return 1;

}


int wh_w8755_dev_verify_chunk_by_read_checksum(WDT_DEV* pdev, CHUNK_INFO_EX* pChunk)
{
	int retval = 0, result = 1;
	UINT32	bin_checksum;
	UINT32	read_checksum;
	
	retval = wh_w8755_dev_send_commands(pdev, WH_CMD_ALGO_STOP, 0);
	if (!retval)
		return retval;
		
	printf("Calculating checksum...\n");
	
	bin_checksum = misr_for_bytes(0, pChunk->pData, 0, pChunk->chuckInfo.length);

	retval = wh_w8755_dev_flash_get_checksum(pdev, &read_checksum, pChunk->chuckInfo.targetStartAddr, pChunk->chuckInfo.length);
	if (!retval)
		return retval;

	if (bin_checksum != read_checksum) {
		printf("Checksum mismatch!!! Original=0x%x, Flash checksum=0x%x", bin_checksum, read_checksum);
		result = 0;
	}
	
	retval = wh_w8755_dev_send_commands(pdev, WH_CMD_ALGO_START, 0);
	if (!retval)
		return retval;
		
	return result;
}


int wh_w8755_dev_program_chunk_verify(WDT_DEV* pdev, CHUNK_INFO_EX* pInputChunk, int option)
{
	int retval = 0;
	int ret = 0;

	CHUNK_INFO_EX	*pChunk = pInputChunk;
	FUNC_PTR_STRUCT_DEV_OPERATION funcs;

	memset(&funcs, 0, sizeof(FUNC_PTR_STRUCT_DEV_OPERATION));	

	retval = wh_w8755_dev_send_commands(pdev, WH_CMD_ALGO_STOP, 0);
	if (!retval)
		return retval;
		
	retval = wh_w8755_dev_send_commands(pdev, WH_CMD_FLASH_UNLOCK, 0);
	if (!retval)
		return retval;

	retval = wh_w8755_dev_flash_erase(pdev, pChunk->chuckInfo.targetStartAddr, pChunk->chuckInfo.length);
	if (!retval)
		goto chunk_exit;
		
	printf("Chunk program begin ...\n");
	retval = wh_w8755_dev_flash_write_data(pdev, pChunk->pData, pChunk->chuckInfo.targetStartAddr, pChunk->chuckInfo.length);
	if (!retval)
		goto chunk_exit;
	printf("Chunk program end...\n");

	if (wh_w8755_dev_verify_chunk(pdev, pInputChunk) <= 0) {
		printf("Checksum failed\n");
		goto chunk_exit;
	}
		
chunk_exit:
	ret = wh_w8755_dev_send_commands(pdev, WH_CMD_FLASH_LOCK, 0);
	if (!ret)
		return ret;
	
	ret = wh_w8755_dev_send_commands(pdev, WH_CMD_ALGO_START, 0);
	if (!ret)
		return ret;
		
	return retval;

}

int wh_w8755_dev_verify_chunk(WDT_DEV* pdev, CHUNK_INFO_EX* pChunk)
{
	if (!pdev)
		return 0;

	return wh_w8755_dev_verify_chunk_by_read_checksum(pdev, pChunk);
}

int wh_w8755_dev_program_chunk(WDT_DEV* pdev, CHUNK_INFO_EX* pInputChunk, int option)
{
	if (!pdev)
		return 0;
	
	if (pdev->pparam->argus & OPTION_BLOCK)
		return wh_w8755_dev_program_chunk_verify(pdev, pInputChunk, option);
	else
		return wh_w8755_dev_program_4k_chunk_verify(pdev, pInputChunk, option);

	return 1;
}


int wh_w8755_dev_set_feature(WDT_DEV* pdev, BYTE* buf, UINT32 buf_size)
{
	int ret = 0;
	
	if (!pdev)
		return 0;

	if (pdev->intf_index == INTERFACE_I2C) {
		ret = wh_i2c_set_feature(pdev, buf, buf_size);	
		return ret;
	}

	return 0;
}

int wh_w8755_dev_get_feature(WDT_DEV* pdev, BYTE* buf, UINT32 buf_size)
{
	int ret = 0;

	if (!pdev)
		return 0;

	if (pdev->intf_index == INTERFACE_I2C) {
		ret = wh_i2c_get_feature(pdev, buf, buf_size);		
		return ret;
	}

	return 0;
}

 
int wh_w8755_dev_read_report(WDT_DEV* pdev, BYTE* buf, UINT32 buf_size)
{
	if (!pdev)
		return 0;

	if (pdev->intf_index == INTERFACE_I2C)
		return wh_i2c_read(pdev, buf, buf_size);

	return 0;
}

int wh_w8755_dev_set_basic_op(WDT_DEV *pdev)
{
	if (!pdev)
		return 0;

	g_func_dev_basic.p_wh_get_feature = wh_w8755_dev_get_feature;
	g_func_dev_basic.p_wh_set_feature = wh_w8755_dev_set_feature;
	g_func_dev_basic.p_wh_read_report = wh_w8755_dev_read_report;

	return 1;
}

int wh_w8755_dev_flash_read_data(WDT_DEV* pdev, BYTE* data, UINT32 address, int length)
{
	int		addr_start, data_len, packet_size;
	BYTE*	 psource_data = 0;
	int		count = 0;
	int		retval = 1;

	if (!pdev || !data)
		return 0;

	// address and length should be align to 4
	if ((address & 0x3) != 0 || (length & 0x3) != 0)
		return 0;

	data_len = length;
	addr_start = address;
	psource_data = data;

	packet_size = W8755_PACKET_SIZE;

	retval = wh_w8755_dev_exec_report_type_write(pdev, W8755_ISP_SET_FLASH_ADDRESS, (BYTE *) &addr_start, 4);
	if (!retval)
		return 0;

	while(data_len)	{
		if (data_len < W8755_PACKET_SIZE)
			packet_size = data_len;

		if (!wh_w8755_dev_exec_report_type_read(pdev, W8755_ISP_GET_FLASH, psource_data, packet_size, 0)) {
			printf("can't get flash: 0x%x\n", addr_start);
			break;
		}

		data_len = data_len - packet_size;
		psource_data = psource_data + packet_size;
		addr_start = addr_start + packet_size;

		wh_sleep(1);
		count++;
	}

	return retval;

}


int wh_w8755_dev_read_flash_map(WDT_DEV* pdev, BOARD_INFO* p_out_board_info)
{

	BYTE	buffer[64];
	int 	retval = 1;

	if (!p_out_board_info) 
		return 0;

	W8755_SEC_ADDR_TYPE *psec_addr_type = &p_out_board_info->sec_header.w8755_sec_header;

	memset(psec_addr_type->device_id, 0, 10);

	int count = 20;
	do {
		wh_w8755_dev_set_device_mode(pdev, W8755_DM_COMMAND);
		wh_sleep(5);
	} while (wh_w8755_dev_get_device_mode(pdev) != W8755_DM_COMMAND && count-- > 0);
	
	
	retval = wh_w8755_dev_flash_read_data(pdev, buffer, W8755_SEC_ADDR_TABLE_OFFSET, 48);
	if (!retval)
		goto failed_exit;


	psec_addr_type->fastboot_addr = (get_unaligned_le16(&buffer[0]) << 8);
	psec_addr_type->library_addr = (get_unaligned_le16(&buffer[2]) << 8);
	psec_addr_type->firmware_image_addr = (get_unaligned_le16(&buffer[4]) << 8);
	psec_addr_type->parameter_addr = (get_unaligned_le16(&buffer[6]) << 8);		
	psec_addr_type->ate_firmware_addr = (get_unaligned_le16(&buffer[8]) << 8);		
	psec_addr_type->recovery_addr = (get_unaligned_le16(&buffer[10]) << 8);		
	psec_addr_type->param_clone_addr = (get_unaligned_le16(&buffer[12]) << 8);	
	psec_addr_type->secondary_image_address = (get_unaligned_le16(&buffer[14]) << 8);


	if (p_out_board_info->dev_info.w8755_dev_info.boot_partition == W8755_BP_SECONDARY)
	{
		memset(buffer, 0, sizeof(buffer));
  
		retval = wh_w8755_dev_flash_read_data(pdev, buffer, W8755_SEC_ADDR_TABLE_EXTENDED_OFFSET, 32);
		if (!retval)
			goto failed_exit;

		psec_addr_type->secondary_param_addr = (get_unaligned_le16(&buffer[0]) << 8);
		psec_addr_type->secondary_param_clone_addr = (get_unaligned_le16(&buffer[2]) << 8);


	}


failed_exit:
	wh_w8755_dev_set_device_mode(pdev, W8755_DM_SENSING);

	return retval;
}





int wh_w8755_prepare_data(WDT_DEV* pdev, BOARD_INFO* pboard_info, int maybe_isp)
{
	 /* initialize the basic function for handling the following operations */
        if(!wh_w8755_dev_set_basic_op(pdev)) {
		wh_printf("pdev is null \n");
		return 0;
	}




        if (!wh_w8755_dev_parse_new_dev_info(pdev, &pboard_info->dev_info.w8755_dev_info)) {
                printf("Can't get new device info!\n");
		wh_w8755_dev_set_device_mode(pdev, W8755_DM_SENSING);
                return 0;
        }

	if (!wh_w8755_dev_read_flash_map(pdev, pboard_info)) {
                 printf("Can't get address table!\n");
                 return 0;
         }


        return 1;
}


int wh_w8755_i2c_delay(WDT_DEV* pdev, unsigned long delay)
{
        /* if the fw version is not supported,  just delay the max period and return */
        if (pdev->board_info.dev_info.w8755_dev_info.protocol_version < 0x01000006)
                wh_sleep(delay);
        else {
                BYTE rc = W8755_ISP_RSP_BUSY;
                unsigned long   start_tick = get_current_ms();
                int retval;
                BYTE readByte[8];
                int count = 0;
                unsigned long time_period = 0;
                int delay_slot = 10;

                if (delay < 100)
                        delay_slot = 5;

                if (!pdev || !pdev->dev_handle)
                                return 0;

                while (rc != W8755_ISP_RSP_OK && ((get_current_ms() - start_tick) < (delay + 100))) {

                        /* polling interval => 10ms */
                        wh_sleep(delay_slot);

                        retval = wh_i2c_rx(pdev, 0x2C, readByte, 3);
                        if (!retval)
                                continue;
                        else
                                /* 3 byte format: 0x0, 0x0, status */
                                rc = readByte[2];

                        count ++;
                }

                time_period = (get_current_ms() - start_tick);
                if (time_period > (delay + 50))
                        printf("%s: timeout %d occured!\n", __func__, (int) time_period);

                return time_period;
        }

        return delay;
}


