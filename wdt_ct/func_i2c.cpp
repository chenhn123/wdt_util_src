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
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include "i2c-dev.h"

#include "wdt_dev_api.h"
#include "wdt_ct.h"
#include "w8755_def.h"
#include "w8755_funcs.h"
#include "w8760_def.h"
#include "w8760_funcs.h"
#include "w8790_funcs.h"


#define		MAX_DEV			16
/* i2c-hid driver for weida's controller */
#define		ACPI_NAME_HID		"i2c-WDHT"

#define		HIDI2C_OPCODE_SET_REPORT	0x03
#define         HIDI2C_OPCODE_GET_REPORT	0x02

static char		g_dev_path[64];

int wh_i2c_scan_driver_path(WDT_DEV* pdev, int *adaptor_no)
{
	DIR	*d;
	struct dirent *dir;
	int found = 0;
	int dev_addr = 0;

	/* weida driver path in sysfs */
	char dev_sysfs_path[] = "/sys/bus/i2c/drivers/wdt87xx_i2c";

	d = opendir(dev_sysfs_path);	
	if (d) {
		if (pdev->pparam->argus & OPTION_INFO)
			printf("Scan I2C device in driver path...\n");
		while ((dir = readdir(d)) != NULL) {
			sscanf(dir->d_name, "%d-%x", adaptor_no, &dev_addr);
			if (dev_addr == 0x2C) {
				found = 1;
				pdev->is_legacy = 1;
				break;	
			}
		}
		closedir(d);
	}

	return found;
}

int wh_i2c_scan_adaptor_path(WDT_DEV* pdev, int *adaptor_no)
{
	DIR	*d;
	struct dirent *dir;
	int found = 0;
	int adp_no = 0;
	char dev_path[64];			

	/* i2c device path in sysfs */
	char dev_sysfs_adapter_path[] = "/sys/bus/i2c/devices";	

	if (pdev->pparam->argus & OPTION_INFO)
		printf("Scan I2C device in adapter path...\n");		
	
	adp_no = 0;
	while (adp_no < MAX_DEV) {
		sprintf(dev_path, "%s/i2c-%d", dev_sysfs_adapter_path, adp_no);
		d = opendir(dev_path);	
		if (d) {	
			char slave_dev[10];

			wh_printf("scan %s\n", dev_path);
			sprintf(slave_dev, "%d-002c", adp_no);		
			while ((dir = readdir(d)) != NULL) {
				if (memcmp(dir->d_name, ACPI_NAME_HID, strlen(ACPI_NAME_HID)) == 0) {
					found = 1;
					break;	
				}				
				if (memcmp(dir->d_name, slave_dev, strlen(slave_dev)) == 0) {
					found = 1;
					break;
				}	
			}
		}
		closedir(d);
	
		if (found)
			break;
		
		adp_no ++;
	}

	*adaptor_no = adp_no;

	return found;
}

int wh_i2c_scan_hid_path(WDT_DEV* pdev, int *adaptor_no)
{
	DIR	*d;
	struct dirent *dir;
	int found = 0;
	int dev_addr = 0;

	/* hid over i2c driver path in sysfs */
	char dev_sysfs_hid_path[] = "/sys/bus/i2c/drivers/i2c_hid";	

	d = opendir(dev_sysfs_hid_path);	
	if (d) {
		if (pdev->pparam->argus & OPTION_INFO)
			printf("Scan I2C device in hid path...\n");
		
		while ((dir = readdir(d)) != NULL) {
			sscanf(dir->d_name, "%d-%x", adaptor_no, &dev_addr);
			if (dev_addr == 0x2C) {
				found = 1;
				break;	
			}
		}
		closedir(d);
	}		

	return found;
}

int	 wh_i2c_scan_device(WDT_DEV* pdev)
{
	int 	found = 0;
	int		adaptor_no = -1;
	long 	file_no = 0;

	if (!pdev)
		return 0;

	strcpy(g_dev_path, "/dev/i2c-2");

	/* initialize the basic function for handling the following operations */
	wh_w8755_dev_set_basic_op(pdev);

	pdev->dev_state = DS_ENUM;

	found = wh_i2c_scan_driver_path(pdev, &adaptor_no);

	if (!found) 
		found = wh_i2c_scan_hid_path(pdev, &adaptor_no);

	if (!found) 
		found = wh_i2c_scan_adaptor_path(pdev, &adaptor_no);
	
	if (!found)
		printf("Use the default i2c-dev: %s\n", g_dev_path);
	else
		sprintf(g_dev_path, "/dev/i2c-%d", adaptor_no);

	file_no = open(g_dev_path, O_RDWR);

	if (file_no < 0) {
		printf("Open device failed!\n");
		return 0;
	}

	pdev->adaptor_no = adaptor_no;

	close(file_no);

	return 1;
}

int	wh_i2c_get_device(WDT_DEV* pdev, WDT_DEVICE_INFO *pDevInfo, int flag)
{
	if (pdev && pDevInfo) {
		strcpy(pDevInfo->path, g_dev_path);
		return 1;
	}

	return 0;
}

int	wh_i2c_open_device(WDT_DEV* pdev)
{
	long		fileno = 0;
	unsigned long	funcs = 0;

	if (!pdev)
		return 0;
	else 
		fileno = open(pdev->dev_path, O_RDWR);

	wh_w8755_dev_set_basic_op(pdev);

	if (fileno >= 0) {
		if (ioctl(fileno, I2C_FUNCS, &funcs) < 0) {
			wh_printf("Can't get the i2c funcs !\n");
			close(fileno);
			fileno = 0;
		}

		if (!(funcs & I2C_FUNC_I2C)) {
			wh_printf("Oops, no I2C function support !\n");
			close(fileno);
			fileno = 0;
		}

		pdev->dev_handle = (WH_HANDLE) fileno;
	} else
		printf("Can't open device %s\n", pdev->dev_path);

	return (fileno >= 0);
}

int	wh_i2c_close_device(WDT_DEV* pdev)
{
	if (pdev && pdev->dev_handle) {
		close((long) pdev->dev_handle);
		return 1;
	}

	return 0;
}

int wh_i2c_get_param_hid(WDT_DEV *pdev, BOARD_INFO *pinfo)
{
	BYTE buf[80];

	buf[0] = 0x20;
	buf[1] = 0x00;

	if (!wh_i2c_xfer(pdev, 0x2C, buf, 2, (BYTE*) &pinfo->dev_hid_desc, sizeof(I2C_HID_DESC))) {
		wh_printf("failed to get hid desc\n");
		return 0;
	}

	pinfo->vid = pinfo->dev_hid_desc.wVendorID;
	pinfo->pid = pinfo->dev_hid_desc.wProductID;
	pdev->board_info.vid = pinfo->vid;
	pdev->board_info.pid = pinfo->pid;
	pdev->board_info.dev_hid_desc = pinfo->dev_hid_desc;


	return 1;
}

int wh_w8755_i2c_delay(WDT_DEV* pdev, unsigned long delay)
{
	/* if the fw version is not supported,  just delay the max period and return */
	if (pdev->board_info.dev_info.w8755_dev_info.protocol_version < 0x01000006) 
		wh_sleep(delay);
	else {
		BYTE rc = W8755_ISP_RSP_BUSY;
		unsigned long 	start_tick = get_current_ms();
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


int	wh_w8755_i2c_prepare_data(WDT_DEV* pdev, BOARD_INFO* pboard_info, int maybe_isp)
{

	if (!wh_w8755_dev_parse_new_dev_info(pdev, &pboard_info->dev_info.w8755_dev_info)) {
		printf("Can't get new device info!\n");
		return 0;
	}

	wh_w8755_dev_set_device_mode(pdev, W8755_DM_SENSING);

	return 1;
}

int wh_w8762_isp_rerun_recovery(WDT_DEV *pdev)
{
	wh_printf("It is maybe WDT8762 ISP\n");
	wh_w8760_dev_set_men_address(pdev, 0xA022750A);            
	wh_w8760_dev_write_men_halfword(pdev, 0);
	wh_w8760_dev_run_program_from_background(pdev, 0x061000);
	wh_printf("Rerun Recovery fw \n");	
	return 1;
}

int wh_w8760_isp_rerun_recovery(WDT_DEV *pdev)
{
	wh_printf("It is maybe WDT8760 ISP\n");
	wh_w8760_dev_run_program_from_background(pdev, 0x061000);
	wh_printf("Rerun Recovery fw \n");	
	return 1;
}



int	wh_i2c_prepare_data(WDT_DEV *pdev, BOARD_INFO* pboard_info)
{
	BYTE				buf[80];
	BOARD_INFO			board_info;	
	int	ret_size;
	int 	ret = 0;
	int 	fw_id = 0;
	int     retryF2 = 3;

	if (!pdev || !pdev->dev_handle || !pboard_info) {
		printf("device ptr is null !\n");
		return 0;
	}

	memset(&board_info, 0, sizeof(BOARD_INFO));

	pdev->dev_state = DS_GET_INFO;
	int get_param_hid_ret = wh_i2c_get_param_hid(pdev, &board_info);
	if(get_param_hid_ret == 0) {
		printf("i2c_get_param_hid fail !");
	}
		
	

	buf[0] = VND_REQ_DEV_INFO;
	while ((retryF2 && ret <= 0) || fw_id == 0)
	{
		ret = wh_i2c_get_feature(pdev, buf, 64);	
		fw_id = get_unaligned_le32(buf + 1);
		retryF2 --;

		if (ret <= 0 || fw_id == 0) {
			pboard_info->dev_type = FW_MAYBE_ISP;	
			wh_printf("Can't get fw id, should be in ISP mode !\n");

			if ((buf[0x26] == 0x49 && buf[0x27] == 0x53 && buf[0x28] == 0x50)) {
				BYTE romSig[8];
				memset(romSig, 0, sizeof(romSig));
				wh_w8760_get_rom_signature(2, romSig);
				if(memcmp(&buf[0 + 0x18], romSig, sizeof(romSig)) == 0)
				{	
					board_info.dev_type = FW_WDT8760_2_ISP;
					wh_w8762_isp_rerun_recovery(pdev);		
				}
				memset(romSig, 0, sizeof(romSig));
				wh_w8760_get_rom_signature(1, romSig);
				if(memcmp(&buf[0 + 0x18], romSig, sizeof(romSig)) == 0)
				{
					board_info.dev_type = FW_WDT8760_2_ISP;
					wh_w8762_isp_rerun_recovery(pdev);			
				}
				memset(romSig, 0, sizeof(romSig));
				wh_w8760_get_rom_signature(0, romSig);
				if(memcmp(&buf[0 + 0x18], romSig, sizeof(romSig)) == 0)
				{
					board_info.dev_type = FW_WDT8760_2_ISP;
					wh_w8760_isp_rerun_recovery(pdev);
				}	
			
			} 
			if(retryF2 == 0){
				printf("Can't get fw id, should be in ISP mode !\n");
				return 0;
			}
		}
	}
	


	if (buf[0] != VND_REQ_DEV_INFO) {
		pboard_info->dev_type = FW_MAYBE_ISP;	
		printf("Firmware id packet error !\n");
		return 0;
	}

	board_info.firmware_id = fw_id;
	board_info.hardware_id = get_unaligned_le32(buf + 5);
	board_info.serial_no = get_unaligned_le32(buf + 9);

	board_info.dev_type = check_firmware_id(pdev, board_info.firmware_id);

	if (board_info.dev_type & FW_WDT8790) {
		wh_w8790_parse_device_info(&board_info.dev_info.w8790_feature_devinfo, buf);

		memcpy(&pdev->board_info.dev_info.w8790_feature_devinfo, &board_info.dev_info.w8790_feature_devinfo,
			sizeof(W8790_DEV_INFO));
		if (wh_w8790_prepare_data(pdev, &board_info)){
			memcpy(pboard_info, &board_info, sizeof(BOARD_INFO));
                        return 1;

		}
	}



	if (board_info.dev_type & (FW_WDT8760_2 | FW_WDT8760_2_ISP)) {
		wh_w8760_get_feature_devinfo(&board_info.dev_info.w8760_feature_devinfo, buf);	
		
		memcpy(&pdev->board_info.dev_info.w8760_feature_devinfo, &board_info.dev_info.w8760_feature_devinfo, 
			sizeof(W8760_REPORT_FEATURE_DEVINFO));

		if (wh_w8760_prepare_data(pdev, &board_info)) {			
			memcpy(pboard_info, &board_info, sizeof(BOARD_INFO));
			return 1;
		}
	}

	buf[0] = 0xf4;
	if (!wh_i2c_get_feature(pdev, buf, 56)) 
		printf("failed to get i2c cfg\n");
	else 
		if (buf[0] != 0xf4)
			wh_printf("wrong id[0xf4] of fw response: 0x%x\n", buf[0]);
		else
			board_info.i2c_dummy = buf[1];

	if (buf[0] == 0xf4 && (get_unaligned_le16(buf + 2) == 0x154f)) { 

		board_info.dev_type |= FW_WDT8755;
		board_info.platform_id[1] = buf[5];

		memcpy(&board_info.sys_param, &buf[10], get_unaligned_le16(buf + 12));
		if (wh_i2c_get_param_hid(pdev, &board_info)) 
			if (wh_w8755_i2c_prepare_data(pdev, &board_info, 0)) {
				memcpy(pboard_info, &board_info, sizeof(BOARD_INFO));
				return 1;
			}
	}

	if (!wh_i2c_get_desc(pdev, GD_DEVICE, 0, (BYTE*) buf, 18))	{
		board_info.dev_type = FW_MAYBE_ISP;
		printf("Get device desc error !\n");
		return 0;	
	}



	ret_size = wh_i2c_get_desc(pdev, GD_STRING, STRIDX_PARAMETERS, (BYTE*) buf, 38);
	if (!ret_size)	{
		printf("Get parameters error !\n");
		return 0;
	}

	memset((void*) &board_info.sys_param, 0, sizeof(SYS_PARAM));
	memcpy((void*) &board_info.sys_param, buf, ret_size);	
	memcpy(pboard_info, &board_info, sizeof(BOARD_INFO));
	
	return 1;
}


int wh_i2c_tx(WDT_DEV *pdev, BYTE slave_addr, BYTE* pbuf, UINT32 buf_size)
{
	int err;
	struct i2c_rdwr_ioctl_data	i2c_rdwr_data;
	struct i2c_msg msgs[1];	
	
	if (!pbuf || !pdev) {
		wh_printf("%s : pointer is null\n", __func__);
		return 0;
	}
	
	msgs[0].addr	= slave_addr;
	msgs[0].flags	= 0; //I2C_M_IGNORE_NAK;
	msgs[0].len = buf_size;
	msgs[0].buf = (char*) pbuf;
	
	i2c_rdwr_data.msgs = msgs;
	i2c_rdwr_data.nmsgs = 1;

	err = ioctl( (long) pdev->dev_handle, I2C_RDWR, &i2c_rdwr_data);
	
	if (err < 0) {
		wh_printf("%s: ioctl operation failed: (%d)\n", __func__, err);
		return 0;
	}

	
	//wh_udelay(I2C_OPERATION_DELAY_US);

	return buf_size;
}

int wh_i2c_rx(WDT_DEV *pdev, BYTE slave_addr, BYTE* pbuf, UINT32 buf_size)
{
	int err = 0;
	struct i2c_rdwr_ioctl_data	i2c_rdwr_data;
	struct i2c_msg msgs[1];

	if (!pbuf || !pdev) {
		wh_printf("%s : pointer is null\n", __func__);
		return 0;
	}

 	msgs[0].addr = slave_addr;
	msgs[0].flags = I2C_M_RD;
	msgs[0].len = buf_size;
	msgs[0].buf = (char*) pbuf;

	i2c_rdwr_data.msgs = msgs;
	i2c_rdwr_data.nmsgs = 1;
		
	err = ioctl( (long) pdev->dev_handle, I2C_RDWR, &i2c_rdwr_data);
	
	if (err < 0) {
		wh_printf("%s: ioctl operation failed: (%d)\n", __func__, err);
		return 0;
	}
	
//	wh_udelay(I2C_OPERATION_DELAY_US);
	return buf_size;
}

int wh_i2c_xfer(WDT_DEV *pdev, BYTE slave_addr, BYTE* txbuf, UINT32 tx_len,
		BYTE* rxbuf, UINT32 rx_len)	
{
	int err = 0;
	struct i2c_rdwr_ioctl_data	i2c_rdwr_data;
	struct i2c_msg msgs[2];		
	
	if (!txbuf || !rxbuf || !pdev) {
		wh_printf("%s : pointer is null\n", __func__);
		return 0;
	}
		
	msgs[0].addr	= slave_addr;
	msgs[0].flags	= 0;
	msgs[0].len = tx_len;
	msgs[0].buf = (char*) txbuf;
	
	msgs[1].addr	= slave_addr;
	msgs[1].flags	= I2C_M_RD;
	msgs[1].len = rx_len;
	msgs[1].buf = (char*) rxbuf;
	
	i2c_rdwr_data.msgs = msgs;
	i2c_rdwr_data.nmsgs = 2;

	err = ioctl( (long) pdev->dev_handle, I2C_RDWR, &i2c_rdwr_data);	
	
	if (err < 0) {
		wh_printf("%s: ioctl operation failed: (%d)\n", __func__, err);
		return 0;
	}
	
//	wh_udelay(I2C_OPERATION_DELAY_US);
	return 2;
}


int wh_i2c_set_feature(WDT_DEV *pdev, BYTE* buf, UINT32 buf_size)
{

	REQ_DATA*	p_req_data = (REQ_DATA*) buf;
	int		data_len = 0;
	BYTE 	cmd;
	BYTE	tx_buffer[80];
	bool    retryflag = true;	
	int 	retval = 0;

	if (buf_size > 64)
		buf_size = 64;
	
	if (!buf || !pdev) {
		wh_printf("%s : pointer is null\n", __func__);
		return 0;
	}

retry:
	data_len = 0;
	cmd = buf[0];
	tx_buffer[data_len++] = pdev->board_info.dev_hid_desc.wCommandRegister; 
	tx_buffer[data_len++] = pdev->board_info.dev_hid_desc.wCommandRegister >> 8;



	if (p_req_data->DD.report_id > 0xF) {
		if(retryflag == true)
			tx_buffer[data_len++] = 0x3F;
		else 
			tx_buffer[data_len++] = 0x30;
		tx_buffer[data_len++] = HIDI2C_OPCODE_SET_REPORT;
		tx_buffer[data_len++] = cmd;
		
	} else {
		tx_buffer[data_len++] = 0x30 | cmd;
		tx_buffer[data_len++] = HIDI2C_OPCODE_SET_REPORT;
	}
	

	
	tx_buffer[data_len++] = pdev->board_info.dev_hid_desc.wDataRegister; 
	tx_buffer[data_len++] = pdev->board_info.dev_hid_desc.wDataRegister >> 8;

	if ((pdev->board_info.dev_type & FW_WDT8755 &&
		 pdev->board_info.dev_info.w8755_dev_info.protocol_version >= 0x01000007) ||
		 (pdev->dev_state != DS_PROGRAM) )
	{
		int xfer_size = buf_size + 2;
		tx_buffer[data_len++] = (xfer_size & 0xFF);
		tx_buffer[data_len++] = ((xfer_size & 0xFF00) >> 8);
	} else {
		tx_buffer[data_len++] = (buf_size & 0xFF);
		tx_buffer[data_len++] = ((buf_size & 0xFF00) >> 8);
	}

	memcpy(&tx_buffer[data_len], buf, buf_size);

	retval = wh_i2c_tx(pdev, 0x2C, tx_buffer,
			 data_len + buf_size);	

	
	if( (buf[2] != cmd) && (retryflag == true) && (p_req_data->DD.report_id > 0xF) ) {
		retryflag = false;
		goto  retry;
	}

	return retval;
}

int wh_i2c_get_feature(WDT_DEV *pdev, BYTE* buf, UINT32 buf_size)
{
	int 		retval;
	REQ_DATA*	p_req_data = (REQ_DATA*) buf;
	int		data_len = 0;
	BYTE	cmd;
	BYTE	tx_buffer[10]; 
	BYTE	rx_buffer[80];
	bool    retryflag = true;

	if (buf_size > 64)
		buf_size = 64;

	if (!buf || !pdev) {
		wh_printf("%s : pointer is null\n", __func__);
		return 0;
	}

retry:
	data_len = 0;
	cmd = buf[0];
	tx_buffer[data_len++] = pdev->board_info.dev_hid_desc.wCommandRegister; 
	tx_buffer[data_len++] = pdev->board_info.dev_hid_desc.wCommandRegister>>8; 


	if (p_req_data->DD.report_id > 0xF)
	{
		if(retryflag == true)
			tx_buffer[data_len++] = 0x3F;
		else 
			tx_buffer[data_len++] = 0x30;
		tx_buffer[data_len++] = HIDI2C_OPCODE_GET_REPORT;
		tx_buffer[data_len++] = cmd;
	}
	else
	{
		tx_buffer[data_len++] = 0x30 | cmd;
		tx_buffer[data_len++] = HIDI2C_OPCODE_GET_REPORT;
	}

        tx_buffer[data_len++] = pdev->board_info.dev_hid_desc.wDataRegister;
        tx_buffer[data_len++] = pdev->board_info.dev_hid_desc.wDataRegister>>8;


	if (pdev->pparam->options & EXEC_I2C_REDUNDANT) {
		tx_buffer[data_len++] = 0x00;
		tx_buffer[data_len++] = 0x00;
	}

	retval = wh_i2c_xfer(pdev, 0x2C, tx_buffer, data_len, rx_buffer, buf_size + 2);
	if (!retval)
		return 0;

	UINT32 	xfer_length = rx_buffer[1];
	xfer_length = (xfer_length << 8) | rx_buffer[0];

	if (buf_size < xfer_length)
		xfer_length = buf_size;

	memcpy(buf, &rx_buffer[2], xfer_length);

	if( (rx_buffer[2] != cmd) && (retryflag == true) &&
		(p_req_data->DD.report_id > 0xF) ) {
		retryflag = false;
		goto  retry;
	}	

	return 1;
}

int wh_i2c_get_desc(WDT_DEV *pdev, BYTE desc_type, BYTE string_idx, BYTE* target_buf, UINT32 buf_size)
{
	int	retval;
	int	ret_size = 0;
	UINT16 cmd_reg = pdev->board_info.dev_hid_desc.wCommandRegister;
        UINT16 data_reg = pdev->board_info.dev_hid_desc.wDataRegister;
        char    str_txdata[10] = { (BYTE)cmd_reg, (BYTE)(cmd_reg>>8), 0x13, 0x0E, 0x00, (BYTE)data_reg, (BYTE)(data_reg>>8), 0x00, 0x00, 0x00 };
        char    desc_txdata[10] = { (BYTE)cmd_reg, (BYTE)(cmd_reg>>8), 0x10, 0x0E, (BYTE)data_reg, (BYTE)(data_reg>>8), 0x00, 0x00, 0x00, 0x00 };
	
	BYTE*	txbuf;
	int 	txlen, rxlen;
	BYTE	xfer_buffer[80]; 

	if (buf_size > 64)
		buf_size = 64;

	if (!target_buf || !pdev)	{
		wh_printf("%s : pointer is null\n", __FUNCTION__);
		return 0;
	}

	if (desc_type == GD_STRING)	{
		str_txdata[4] = string_idx;
		txlen = 7;

		txbuf = (BYTE*) str_txdata;
		rxlen = buf_size + 2;
	} else {
		desc_txdata[2] = 0x10 | (desc_type & 0xF);
		txlen = 6;
		txbuf = (BYTE*) desc_txdata;
		rxlen = buf_size;
	}

	if (pdev->pparam->options & EXEC_I2C_REDUNDANT) 
		txlen += 2;

	retval = wh_i2c_xfer(pdev, 0x2C, (BYTE*) txbuf, txlen, (BYTE*) xfer_buffer, rxlen);

	if (!retval)
		return 0;
	
	if (desc_type == GD_STRING)	{
		if (xfer_buffer[1] != 0x03) {
			printf("packet error on string id: %d\n", xfer_buffer[1]);
			return 0;
		}
	
		UINT32 	xfer_length = xfer_buffer[0] - 2;

		if (buf_size < xfer_length)
			xfer_length = buf_size;

		memcpy(target_buf, &xfer_buffer[2], xfer_length);
		ret_size = xfer_length;
	} else {
		if (xfer_buffer[0] == buf_size) {
			memcpy(target_buf, &xfer_buffer[0], buf_size);
			ret_size = buf_size;
		} else	{
			printf("packet error on desc: %x %x %x %x\n", xfer_buffer[0],
				xfer_buffer[1], xfer_buffer[2], xfer_buffer[3]);
		}
	}
	
	return ret_size;
}

int wh_i2c_get_indexed_string(WDT_DEV *pdev, UINT32 index, BYTE* buf, UINT32 buf_size)
{
	if (pdev)
		return wh_i2c_get_desc(pdev, GD_STRING, index, buf, buf_size);

	return 0;
}

int wh_i2c_read(WDT_DEV* pdev, BYTE* buf, UINT32 buf_size)
{
	return 0;
}

