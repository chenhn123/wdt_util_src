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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <time.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <dirent.h>

#include "wdt_dev_api.h"
#include "dev_def.h"
#include "w8755_funcs.h"
#include "w8760_funcs.h"
#include "w8790_funcs.h"
#include "wdt_ct.h"
#include "wif2.h"


int wh_get_device_access_func(int interfaceIndex, FUNC_PTR_STRUCT_DEV_ACCESS*  pFuncs)
{
	if (!pFuncs)
		return 0;

	if (interfaceIndex == INTERFACE_I2C) {
		pFuncs->p_wh_scan_device = (LPFUNC_wh_scan_device) wh_i2c_scan_device;
		pFuncs->p_wh_get_device = (LPFUNC_wh_get_device) wh_i2c_get_device;
		pFuncs->p_wh_open_device = (LPFUNC_wh_open_device) wh_i2c_open_device;
		pFuncs->p_wh_close_device = (LPFUNC_wh_close_device) wh_i2c_close_device;
		pFuncs->p_wh_prepare_data = (LPFUNC_wh_prepare_data) wh_i2c_prepare_data;			
		return 1;
	}

	return 0;
}

int wh_get_device_private_access_func(WDT_DEV* pdev,  FUNC_PTR_STRUCT_DEV_OPERATION*  pFuncs)
{
	if (!pFuncs || !pdev)
		return 0;

	if (pdev->board_info.dev_type & FW_WDT8755) {
		pFuncs->p_wh_program_chunk = (LPFUNC_wh_program_chunk) wh_w8755_dev_program_chunk;
		pFuncs->p_wh_verify_chunk	= (LPFUNC_wh_verify_chunk) wh_w8755_dev_verify_chunk;
		pFuncs->p_wh_flash_write_data = (LPFUNC_wh_flash_write_data) wh_w8755_dev_flash_write_data;
		pFuncs->p_wh_flash_get_checksum = (LPFUNC_wh_flash_get_checksum) wh_w8755_dev_flash_get_checksum;
 		pFuncs->p_wh_send_commands = (LPFUNC_wh_send_commands) wh_w8755_dev_send_commands;

		return wh_w8755_dev_set_basic_op(pdev);
	}

	if (pdev->board_info.dev_type & FW_WDT8760_2) {
		pFuncs->p_wh_program_chunk = (LPFUNC_wh_program_chunk) wh_w8760_dev_program_chunk;
		pFuncs->p_wh_verify_chunk	= (LPFUNC_wh_verify_chunk) wh_w8760_dev_verify_chunk;
		pFuncs->p_wh_flash_write_data = (LPFUNC_wh_flash_write_data) wh_w8760_dev_flash_write_data;
		pFuncs->p_wh_flash_get_checksum = (LPFUNC_wh_flash_get_checksum) wh_w8760_dev_flash_get_checksum;
 		pFuncs->p_wh_send_commands = (LPFUNC_wh_send_commands) wh_w8760_dev_send_commands;

		return wh_w8760_dev_set_basic_op(pdev);
	}
	if (pdev->board_info.dev_type & FW_WDT8790) {
		pFuncs->p_wh_flash_write_data = (LPFUNC_wh_flash_write_data)wh_w8790_dev_flash_write_data;
		pFuncs->p_wh_flash_get_checksum = (LPFUNC_wh_flash_get_checksum)wh_w8790_dev_flash_get_checksum;
		pFuncs->p_wh_send_commands = (LPFUNC_wh_send_commands)wh_w8790_dev_send_commands;
		pFuncs->p_wh_flash_erase = (LPFUNC_wh_flash_erase)wh_w8790_dev_flash_erase;


		return wh_w8790_dev_set_basic_op(pdev);
	}


	return 0;

}

int wh_get_device_basic_access_func(WDT_DEV* pdev,  FUNC_PTR_STRUCT_DEV_BASIC*  pFuncs)
{
	if (!pFuncs || !pdev)
		return 0;


	if (pdev->board_info.dev_type & FW_WDT8755) {
		pFuncs->p_wh_get_feature = (LPFUNC_wh_get_feature) wh_w8755_dev_get_feature;
		pFuncs->p_wh_set_feature = (LPFUNC_wh_set_feature) wh_w8755_dev_set_feature;
		pFuncs->p_wh_get_index_string = (LPFUNC_wh_get_index_string) wh_w8755_dev_get_indexed_string;
		pFuncs->p_wh_read_report = (LPFUNC_wh_read_report) wh_w8755_dev_read_report;

		return 1;
	}
	
	if (pdev->board_info.dev_type & FW_WDT8760_2) {
		pFuncs->p_wh_get_feature = (LPFUNC_wh_get_feature) wh_w8760_dev_get_feature;
		pFuncs->p_wh_set_feature = (LPFUNC_wh_set_feature) wh_w8760_dev_set_feature;
		pFuncs->p_wh_get_index_string = (LPFUNC_wh_get_index_string) wh_w8760_dev_get_indexed_string;
		pFuncs->p_wh_read_report = (LPFUNC_wh_read_report) wh_w8760_dev_read_report;

		return 1;
	}

	if (pdev->board_info.dev_type & FW_WDT8790) {
		pFuncs->p_wh_get_feature = (LPFUNC_wh_get_feature) wh_w8790_dev_get_feature;
                pFuncs->p_wh_set_feature = (LPFUNC_wh_set_feature) wh_w8790_dev_set_feature;
                pFuncs->p_wh_get_index_string = (LPFUNC_wh_get_index_string) wh_w8790_dev_get_indexed_string;
                pFuncs->p_wh_read_report = (LPFUNC_wh_read_report) wh_w8790_dev_read_report;

		return 1;

        }



	return 0;
}

int check_firmware_id(WDT_DEV *pdev, UINT32 fwid)
{
	if ((fwid & 0xF0000000) == 0x30000000) {
		if (pdev->pparam->argus & OPTION_INFO)		
			printf("It is WDT8755 or WDT8752 !\n");	
		return FW_WDT8755;
	}

	if ((fwid & 0xFFFF0000) == 0xFFFF0000) {
		if (pdev->pparam->argus & OPTION_INFO)		
			printf("It is WDT8752 recovery fw !\n");	
		return FW_WDT8755;
	}	

	if ((fwid & 0xF0000000) == 0x40000000) {
		if (pdev->pparam->argus & OPTION_INFO)	
			printf("It is WDT8760 alike !\n");	
		return FW_WDT8760;
	}
	if ((fwid & 0xF0000000) == 0x50000000) {
		if(pdev->pparam->argus & OPTION_INFO)
			printf("It is WDT8790 !\n");
		return FW_WDT8790;

	}
	
	return FW_WITH_CMD;
}

UINT16 get_unaligned_le16(const void *p)
{
	const BYTE *_p = (BYTE *) p;
	return _p[0] | _p[1] << 8;
}

UINT32 get_unaligned_le32(const void *p)
{
	const BYTE *_p = (BYTE *) p;
	return _p[0] | _p[1] << 8 | _p[2] << 16 | _p[3] << 24;
}

void put_unaligned_le16(UINT16 val, BYTE *p)
{
	*p++ = (BYTE) val;
	*p++ = (BYTE) (val >> 8);
}

void put_unaligned_le32(UINT32 val, BYTE *p)
{
	put_unaligned_le16(val >> 16, p + 2);
	put_unaligned_le16(val, p);
}


int check_is_all_ff(BYTE* data, int length)
{
	if (data == 0)
		return 0;

	int idx;

	for (idx = 0; idx < length; idx++)
		if (data[idx] != 0xFF)
			return 0;
	return 1;
}

int count_ff_bytes(BYTE* data, int start, int size)
{
	int count = 0;
	for (int i = 0; i < size; i++)
	{
		if (data[start + i] == 0xFF)
			count++;
	}
	return count;
}


int load_lib_func_address(WDT_DEV *pdev, EXEC_PARAM *pparam)
{
	if (!pdev)
		return 0;

	pdev->func_wh_open_whiff = (LPFUNC_wh_open_whiff) wh_open_whiff_file;
	if (!pdev->func_wh_open_whiff) {
		printf("Not found: wh_open_whiff \n");
		return 0;
	}

	pdev->func_wh_close_whiff = (LPFUNC_wh_close_whiff) wh_close_whiff_file;
	if (!pdev->func_wh_close_whiff)	{
		printf("Not found: wh_close_whiff \n");
		return 0;
	}

	pdev->func_wh_get_chunk_info = (LPFUNC_wh_get_chunk_info) wh_get_chunk_info;
	if (!pdev->func_wh_get_chunk_info) {
		printf("Not found: wh_get_chunk_info \n");
		return 0;
	}

	pdev->func_wh_get_device_access_func = (LPFUNC_wh_get_device_access_func) wh_get_device_access_func;
	if (!pdev->func_wh_get_device_access_func) {
		printf("Not found: wh_get_device_access_func \n");
		return 0;
	}

	pdev->func_wh_get_device_private_access_func = (LPFUNC_wh_get_device_private_access_func) wh_get_device_private_access_func;
	if (!pdev->func_wh_get_device_private_access_func) {
		printf("Not found: wh_get_device_private_access_func \n");
		return 0;
	}

	pdev->func_wh_get_device_basic_access_func = (LPFUNC_wh_get_device_basic_access_func) wh_get_device_basic_access_func;
	if (!pdev->func_wh_get_device_basic_access_func) {
		printf("Not found: wh_get_device_basic_access_func \n");
		return 0;
	}
	
	return 1;
}

int load_wif(WDT_DEV *pdev, char *path)
{
	if (!pdev || !path)
		return 0;

	strcpy(pdev->wif_access.wif_path, path);

	pdev->wif_access.wif_handle = pdev->func_wh_open_whiff(pdev->wif_access.wif_path);

	if (!pdev->wif_access.wif_handle) {
		wh_printf("Parse input file error");
		return 0;
	}

	memset(&pdev->wif_access.wif_chunk_info, 0, sizeof(CHUNK_INFO_EX));

	return 1;
}

int close_wif(WDT_DEV *pdev)
{
	if (!pdev->func_wh_close_whiff(pdev->wif_access.wif_handle)) {
		wh_printf("Close input file error");
		return 0;
	}
	return 1;
}

int init_n_scan_device(WDT_DEV *pdev, EXEC_PARAM *pparam, unsigned int flag)
{
	WDT_DEVICE_INFO	wdtDevInfo;

	if (!pdev || !pparam)
		return 0;

	pdev->intf_index = pparam->interface_num;

	if (!pdev->func_wh_get_device_access_func(pdev->intf_index, &pdev->funcs_device)) {
		wh_printf("Get device funcs error");
		return 0;		
	}

	if (!strlen(pparam->dev_path)) {
		memset(&wdtDevInfo, 0, sizeof(WDT_DEVICE_INFO));	
		
		/* num of devices */
		int num = pdev->funcs_device.p_wh_scan_device(pdev);
		
		if (num == 0) {
			wh_printf("Open device error");
			return 0;
		}

		/* just use index 0 to get the device info */
		if (!pdev->funcs_device.p_wh_get_device(pdev, &wdtDevInfo, 0))
			return 0;
			
		strcpy(pdev->dev_path, wdtDevInfo.path);
	}else
		strcpy(pdev->dev_path, pparam->dev_path);

	if (pdev->funcs_device.p_wh_open_device(pdev)) {
		if (pdev->funcs_device.p_wh_prepare_data(pdev, &pdev->board_info)) {		
			if (pdev->is_legacy)
				return 1;
			
			if (!pdev->func_wh_get_device_private_access_func(pdev, &pdev->funcs_device_private)) {
				wh_printf("Get device private funcs error");
				return 0;		
			}

			return 1;
		}else
			wh_printf("Get system info error");
	}

	return 0;
}

void close_device(WDT_DEV *pdev)
{
	if (pdev)
		pdev->funcs_device.p_wh_close_device(pdev);
}



int fw_version_check(EXEC_PARAM *pparam, BOARD_INFO *pinfo, CHUNK_INFO_EX *pchunk_info)
{
	if (!pparam || !pinfo || !pchunk_info)
		return 0;

	char	fw_id = ((pchunk_info->chuckInfo.versionNumber >> 12) & 0xF);
	char	chip_id = ((pinfo->firmware_id >> 12) & 0xF);
	
	if (fw_id != chip_id) {
		printf("This firmware is not matched with this chip, fwid(%x), chip_id(%x)\n", fw_id, chip_id);
		return 0;
	} 

	if (pinfo->dev_type & FW_WDT8760) {
		if ((pchunk_info->chuckInfo.temp & 0xFF000000) != 0x31000000) {			
			printf("The device type is not matched with this firmware (%x)\n", pchunk_info->chuckInfo.temp);
			return 0;
		}
	} else if (pinfo->dev_type & FW_WDT8762) {
		if ((pchunk_info->chuckInfo.temp & 0xFF000000) != 0x32000000) { 		
			printf("The device type is not matched with this firmware (%x)\n", pchunk_info->chuckInfo.temp);
			return 0;
		}
	}

	wh_printf("The firmware vession: dev %x, wif %x\n", pinfo->firmware_id,
			  pchunk_info->chuckInfo.versionNumber); 

	unsigned int fw_ver = pchunk_info->chuckInfo.versionNumber & 0xFFF;
	unsigned int chip_fw_ver = pinfo->firmware_id & 0xFFF;

	/* just ignore the recovery firmware */
	if (( fw_ver <= chip_fw_ver) && (chip_fw_ver != 0xFFF)) 
		return 2;

	return 1;
}

int config_id_check(EXEC_PARAM *pparam, BOARD_INFO *pinfo, CHUNK_INFO_EX *pchunk_info)
{
	if (!pparam || !pinfo || !pchunk_info)
		return 0;

	unsigned int 	xmlId = 0;

	if (pchunk_info->chuckInfo.attribute & 0x2)
		xmlId = pchunk_info->chuckInfo.versionNumber;

	wh_printf("The config data in dev: %04x, wif: %04x\n", xmlId, pinfo->sys_param.xmls_id1);
	if (xmlId == pinfo->sys_param.xmls_id1) 
		return 2;

	return 1;
}

int program_one_chunk(WDT_DEV *pdev, const char *chunk_name, UINT32 chunk_id, UINT32 option, CHUNK_INFO_EX *pinfo)
{
	CHUNK_INFO_EX	chunk_info;
	CHUNK_INFO_EX	*pchunk_info = NULL;

	if (!pdev)
		return 0;

	if (pinfo == NULL) {
		memset(&chunk_info, 0, sizeof(CHUNK_INFO_EX));
		if (pdev->func_wh_get_chunk_info(pdev->wif_access.wif_handle, chunk_id, &chunk_info))
			pchunk_info = &chunk_info;
		else
			return 1;
	} else
		pchunk_info = pinfo;

	if (!pchunk_info)
		return 0;
		
	printf("\n[%s] programming ....\n", chunk_name);
				
	if (!pdev->funcs_device_private.p_wh_program_chunk(pdev, pchunk_info, option ))	{
		char	msg[64];

		sprintf(msg, "[%s] Write chunk error", chunk_name);
		wh_printf(msg);
		return 0;	
	}

	printf("[%s] chunk program : pass...\n", chunk_name);
	return 1;
}



int image_file_burn_data_verify(WDT_DEV *pdev, EXEC_PARAM *pparam)
{
	BOARD_INFO	*pinfo = &pdev->board_info;
	CHUNK_INFO_EX	chunk_info_fw;
	CHUNK_INFO_EX	chunk_info_cfg;
	int		is_fw_update = 1;
	int		is_cfg_update = 1;
	int 	err = 0;


	if (!pdev || !pparam)
		return 0;

	if (pinfo->dev_type & (FW_MAYBE_ISP | FW_WDT8755_ISP | FW_WDT8760_2_ISP))
		return 0;	

        if (!init_n_scan_device(pdev, pparam, 0)) {
		printf("Wdt controller not found !\n");
                goto exit_burn;
        }

	if (pdev->board_info.dev_type & FW_WDT8790) {
		return update_fw_by_wif2(pdev, (char*)pparam->image_file);
	}

        if (pdev->is_legacy) {
                printf("Not support legacy FW update !\n");
                goto exit_burn;
        }


	if (!load_wif(pdev, (char*)pparam->image_file)){
		printf("Load WIF failed !\n");
		goto exit_burn;
	}
	
	memset(&chunk_info_fw, 0, sizeof(CHUNK_INFO_EX));
	memset(&chunk_info_cfg, 0, sizeof(CHUNK_INFO_EX));

	if (!pdev->func_wh_get_chunk_info(pdev->wif_access.wif_handle, CHUNK_ID_FRWR, &chunk_info_fw)) {
		printf("Not found fw chunk !\n");
		goto exit_burn;
	}

	if (!pdev->func_wh_get_chunk_info(pdev->wif_access.wif_handle, CHUNK_ID_CNFG, &chunk_info_cfg)) {
		printf("Not found cfg chunk !\n");
		goto exit_burn;
	}

	if (!chunk_info_fw.chuckInfo.versionNumber) {
		printf("Wif fw version is null!\n");
		goto exit_burn;
	}
		
	err = fw_version_check(pparam, pinfo, &chunk_info_fw);
	/* fw is not matching */
	if (err == 0)	
		goto exit_burn;

	if (pdev->pparam->argus & OPTION_NO_FORCE) {
		printf("Version checking ....\n");
		
		/* fw is most updated */
		if (err == 2)	{
			printf("The firmware in controller is most updated!\n");
			is_fw_update = 0; 
		}

		err = config_id_check(pparam, pinfo, &chunk_info_cfg);

		if (err == 2)	{
			printf("The cfg in controller is most updated!\n");
			is_cfg_update = 0; 
		}
	} 
	
	if (is_cfg_update && chunk_info_cfg.chuckInfo.targetStartAddr) {
		UINT32 tempStartAddr = chunk_info_cfg.chuckInfo.targetStartAddr;

		/*
		 * it will program a backup parameters to 0x58000 in general
		 * just specify OPTION_NO_RPARAM if don't want this backup
		 */
		if (!(pdev->pparam->argus & OPTION_NO_RPARAM)) {
			if (pdev->board_info.dev_type & FW_WDT8755) {
				chunk_info_cfg.chuckInfo.targetStartAddr = 0x58000;
				err = program_one_chunk(pdev, "r_config", CHUNK_ID_CNFG, OPTION_4K_VERIFY, &chunk_info_cfg);

				if (!err)
					goto exit_burn;
			}
		}

		chunk_info_cfg.chuckInfo.targetStartAddr = tempStartAddr;

		/* fw should be reprogramed when parameters have been programmed */
		chunk_info_cfg.chuckInfo.temp = chunk_info_fw.chuckInfo.targetStartAddr;
		err = program_one_chunk(pdev, "config", CHUNK_ID_CNFG, OPTION_4K_VERIFY | OPTION_ERASE_TEMP,
								&chunk_info_cfg);

		if (!err)
			goto exit_burn;
	
		if (!program_one_chunk(pdev, "ext bin", CHUNK_ID_EXTB, OPTION_4K_VERIFY, NULL))
			goto exit_burn;

		if (!err)
			goto exit_burn;

		is_fw_update = 1;
	}

	if (pdev->board_info.dev_type & FW_WDT8755) {
		if (chunk_info_fw.chuckInfo.targetStartAddr == 0) {
			printf("Address can not be %d \n", chunk_info_fw.chuckInfo.targetStartAddr);
			goto exit_burn;
		}			
	} else if (pdev->board_info.dev_type & FW_WDT8760_2) {
		if (chunk_info_fw.chuckInfo.targetStartAddr >= 0x60000) {
			printf("Address can not be %d \n", chunk_info_fw.chuckInfo.targetStartAddr);
			goto exit_burn;
		}			
	}

	if (is_fw_update && (chunk_info_fw.chuckInfo.versionNumber)) {
		err = program_one_chunk(pdev, "firmware", CHUNK_ID_FRWR, OPTION_4K_VERIFY, &chunk_info_fw);

		if (!err)
			goto exit_burn;
	}
	
	if (is_fw_update || is_cfg_update) {
		pdev->funcs_device_private.p_wh_send_commands(pdev, WH_CMD_RESET, 0);
		printf("Reset device ... \n");

		wh_sleep(2000);
	}

exit_burn:	
	close_device(pdev);	

	if (!close_wif(pdev))
		return 0;
	
	return err;
}

unsigned int cal_checksum(unsigned char *buffer, int length)
{
	unsigned int	value, value2, value3;
	unsigned int	tmpbuffer, output, source;
	int		i, j;


	output = 0xFFFFFFFF;

	for (i=0; i<(length/4); i++)
	{
		j = i * 4;
		source = output;
		value = output <<1;
		value2 = ((source & 0x80000000) >>31) ^ ((source & 0x200000) >>21) ^ ((source & 0x2) >>1);
		value3 = value | value2;

		tmpbuffer = buffer[j+3]<<24 | buffer[j+2]<<16 | buffer[j+1]<<8 | buffer[j];
		output = value3 ^ tmpbuffer;
	}

	return output;
}

int show_info(WDT_DEV *pdev, EXEC_PARAM *pparam)
{
	BOARD_INFO	*pinfo = &pdev->board_info;	
	int ret = 0;

	if (!pdev || !pparam)
		return 0;

	if (!init_n_scan_device(pdev, pparam, 0))
		return 0;

	ret = !(pinfo->dev_type & (FW_MAYBE_ISP | FW_WDT8755_ISP | FW_WDT8760_2_ISP));

	if (!ret)
		goto info_exit;

	if (pparam->argus & OPTION_HW_ID) {
		if (pdev->is_legacy)
			printf("%04x%04x", pinfo->vid, pinfo->pid);
		else {
			// to fix the temporary HWID issue, only happened in early build of Fleex.
			if (pinfo->hardware_id == 0x01027401)
				pinfo->hardware_id = 0x01017402;
			printf("%08x", pinfo->hardware_id);
		}
	}

	if (pparam->argus & OPTION_FW_VER) {
		if (pparam->argus & OPTION_HW_ID)
			printf("_");

		if (pdev->board_info.dev_type & FW_WDT8755) {
			printf("%04x", pinfo->firmware_id & 0xFFFF);
        	} else if (pdev->board_info.dev_type & FW_WDT8760_2) {
        		int fwrev = pinfo->dev_info.w8760_feature_devinfo.firmware_id & 0x0FFF;
        		int fwrexext = pinfo->dev_info.w8760_feature_devinfo.firmware_rev_ext & 0x000F;
        		int versionOuput = (fwrev << 4 | fwrexext);
			printf("%04x", versionOuput);
		}
		else if (pdev->board_info.dev_type & FW_WDT8790) {
			int fwrev = pinfo->dev_info.w8790_feature_devinfo.firmware_version & 0x0FFF;
                        int fwrexext = pinfo->dev_info.w8790_feature_devinfo.firmware_revision_ext & 0x000F;
                        int versionOuput = (fwrev << 4 | fwrexext);
                        printf("%04x", versionOuput);

		}
	}	
		
	if (pparam->argus & OPTION_CFG_CHKSUM) {
		if (pparam->argus & (OPTION_FW_VER | OPTION_HW_ID))
			printf("_");
		
		if (pdev->is_legacy)
			printf("%04x%04x", pinfo->sys_param.xmls_id1, pinfo->sys_param.xmls_id2);
		else 
			printf("%08x", pinfo->serial_no);
	}

	if (pparam->argus & (OPTION_HW_ID | OPTION_FW_VER | OPTION_CFG_CHKSUM)) {
		printf("\n");
		goto info_exit;
	}
	
	if (ret) {
		printf("Vendor_ID: 0x%04x\n", pinfo->vid);
		printf("Product_ID: 0x%04x\n", pinfo->pid);
		printf("Firmware_ID: 0x%x\n", pinfo->firmware_id);
		printf("Hardware_ID: 0x%x\n", pinfo->hardware_id);		
		printf("Serial_No: 0x%x\n", pinfo->serial_no);
		if ((pinfo->platform_id[1] & 0xF0) == 0x40)
			printf("Platform_ID: 0x%x(TC)\n", pinfo->platform_id[1]);			
		else
			printf("Platform_ID: 0x%x\n", pinfo->platform_id[1]);
		printf("XmlId1: %x   XmlId2: %x\n", pinfo->sys_param.xmls_id1, pinfo->sys_param.xmls_id2);
		printf("Param: phy_x %d, phy_y %d\n", pinfo->sys_param.Phy_Frmbuf_W, pinfo->sys_param.Phy_Frmbuf_H);
	} 

	if (pparam->argus & OPTION_EXTRA_INFO) {
		if (pinfo->dev_type & FW_WDT8755) {
			printf("\nprotocol_version 0x%x\n", pinfo->dev_info.w8755_dev_info.protocol_version);
			printf("firmware_id 0x%x\n", pinfo->dev_info.w8755_dev_info.firmware_id);
			printf("config_size 0x%x\n", pinfo->dev_info.w8755_dev_info.config_size);
			printf("parameter_map_sum 0x%x\n", pinfo->dev_info.w8755_dev_info.parameter_map_sum);
			printf("firmware_revision 0x%x\n", pinfo->dev_info.w8755_dev_info.firmware_revision);
			printf("max_points 0x%x\n", pinfo->dev_info.w8755_dev_info.max_points); 
			printf("bytes_per_point 0x%x\n", pinfo->dev_info.w8755_dev_info.bytes_per_point);	
			printf("customer_config_id 0x%x\n", pinfo->dev_info.w8755_dev_info.customer_config_id); 	
			printf("boot_partition: ");

			if (pinfo->dev_info.w8755_dev_info.boot_partition == BP_SECONDARY) 
			{
				printf("Secondary");
				printf("\n\nfastboot_addr: 0x%X\n", pinfo->sec_header.w8755_sec_header.fastboot_addr);
				printf("library_addr: 0x%X\n", pinfo->sec_header.w8755_sec_header.library_addr);
				printf("firmware_image_addr: 0x%X\n", pinfo->sec_header.w8755_sec_header.secondary_image_address);
				printf("parameter_addr: 0x%X\n", pinfo->sec_header.w8755_sec_header.secondary_param_addr);
				printf("ate_firmware_addr: 0x%X\n", pinfo->sec_header.w8755_sec_header.ate_firmware_addr);
				printf("recovery_addr: 0x%X\n", pinfo->sec_header.w8755_sec_header.recovery_addr);
				printf("param_clone_addr: 0x%X\n", pinfo->sec_header.w8755_sec_header.secondary_param_clone_addr);

			}
			else 
			{
				printf("Primary");
				printf("\n\nfastboot_addr: 0x%X\n", pinfo->sec_header.w8755_sec_header.fastboot_addr);
				printf("library_addr: 0x%X\n", pinfo->sec_header.w8755_sec_header.library_addr);
				printf("firmware_image_addr: 0x%X\n", pinfo->sec_header.w8755_sec_header.firmware_image_addr);
				printf("parameter_addr: 0x%X\n", pinfo->sec_header.w8755_sec_header.parameter_addr);
				printf("ate_firmware_addr: 0x%X\n", pinfo->sec_header.w8755_sec_header.ate_firmware_addr);
				printf("recovery_addr: 0x%X\n", pinfo->sec_header.w8755_sec_header.recovery_addr);
				printf("param_clone_addr: 0x%X\n", pinfo->sec_header.w8755_sec_header.param_clone_addr);
			}



		} else if (pinfo->dev_type & FW_WDT8760_2) {
			char str[16];	
			printf("\nMax_points 0x%X\n", pinfo->dev_info.w8760_feature_devinfo.n_touches_usb);
			printf("Bytes_per_point 0x%X\n", pinfo->dev_info.w8760_feature_devinfo.n_bytes_touch);		
			memset(str, 0, 16);
			memcpy(str, pinfo->dev_info.w8760_feature_devinfo.platform_id, 8);
			printf("Platform id %s\n", str);
			memset(str, 0, 16);
			memcpy(str, pinfo->dev_info.w8760_feature_devinfo.program_name_fourcc, 4);
			printf("ProgramFourcc %s\n", str);
			printf("ProtocolRevision 0x%X\n", pinfo->dev_info.w8760_feature_devinfo.protocol_version);
			printf("FirmwareRevisionExt 0x%X\n", pinfo->dev_info.w8760_feature_devinfo.firmware_rev_ext);
			memset(str, 0, 16);
			memcpy(str, pinfo->dev_info.w8760_feature_devinfo.part_number_ext, 8);		
			printf("PartNumberExt %s\n", str);
		 }else if (pinfo->dev_type & FW_WDT8790) {
			char str[16] ;
			memset(str, 0xff, sizeof(str));
			printf("\nMaxTouches 0x%X\n", pinfo->dev_info.w8790_feature_devinfo.max_touches);
			printf("FirmwareRevisionExt 0x%X\n", pinfo->dev_info.w8790_feature_devinfo.firmware_revision_ext);
			printf("Partition 0x%X\n", pinfo->dev_info.w8790_feature_devinfo.partition);
			printf("PartitionFormatRevision 0x%X\n", pinfo->dev_info.w8790_feature_devinfo.partition_format_revision);

			if(memcmp(str, pinfo->dev_info.w8790_feature_devinfo.part_number, sizeof(str)) == 0)
				printf("PartNumber all 0xFF \n");
			else
			{
				memset(str, '\0', sizeof(str));
				memcpy(str, pinfo->dev_info.w8790_feature_devinfo.part_number, sizeof(pinfo->dev_info.w8790_feature_devinfo.part_number));
				printf("PartNumber %s\n", str);
			}
			printf("RomSignature ");
			for (int idx = 0; idx < 8; idx++)
				printf("%02X", pinfo->dev_info.w8790_feature_devinfo.rom_signature[idx]);
			printf("\n");
			memset(str, '\0', sizeof(str));
			memcpy(str, pinfo->dev_info.w8790_feature_devinfo.program_name_fourcc, 4);
			printf("ProgramFourcc %s\n", str);

		 }

	}

info_exit:	
	close_device(pdev);
	
	return ret;
}

int show_wif_info(WDT_DEV *pdev, EXEC_PARAM *pparam)
{
	if (!pdev || !pparam)
		return 0;
	if(show_wif2_info((char*)pparam->image_file))
		return 1;

	if (!load_wif(pdev, (char*)pparam->image_file))
		return 0;

	CHUNK_INFO_EX           chunk_info_ex;
	if (pdev->func_wh_get_chunk_info(pdev->wif_access.wif_handle, CHUNK_ID_FRWR, &chunk_info_ex)) 
		printf("FW id: 0x%08x\n", chunk_info_ex.chuckInfo.versionNumber);

	if (pdev->func_wh_get_chunk_info(pdev->wif_access.wif_handle, CHUNK_ID_CNFG, &chunk_info_ex)) {
		UINT32	config_id = 0;
		
		if (chunk_info_ex.chuckInfo.attribute & 0x2)
			config_id = chunk_info_ex.chuckInfo.versionNumber;
		printf("Config id: 0x%x\n", config_id);		
	}
	
	if (!close_wif(pdev))
		return 0; 
	
	return 1;
}

int find_hid_dev_name(int bus, int vid, int pid, char *device_name)
{
	int ret = 0;
	struct dirent * dev_dir_entry;
	DIR * dev_dir;
	char device_ids[32];

	snprintf(device_ids, 15, "%04X:%04X:%04X", bus, vid, pid);

	dev_dir = opendir("/sys/bus/hid/devices");
	if (!dev_dir) {
		printf("open dev dir failed !\n");
		return 0;
	}

	while ((dev_dir_entry = readdir(dev_dir)) != NULL) {
		if (!strncmp(dev_dir_entry->d_name, device_ids, 14)) {
			strcpy(device_name, dev_dir_entry->d_name);
			ret = 1;
			break;
		}
	}
	closedir(dev_dir);

	return ret;
}

int find_device_name(char *hid_dev_name, char *driver_name, char *driver_path)
{
	char dev_path[] = "/sys/bus/i2c/devices/";

	struct dirent * devs_dir_entry;
	DIR * devs_dir;
	struct dirent * dev_dir_entry;
	DIR * dev_dir;
	int 	device_found = 0;
	ssize_t sz;
	char	tmp_buf[256];
	char	tmp_path[277];

	devs_dir = opendir(dev_path);
	if (!devs_dir) {
		printf("can not open device path: %s\n", dev_path);
		return 0;
	}


	while((devs_dir_entry = readdir(devs_dir)) != NULL) {
		if (devs_dir_entry->d_type != DT_LNK)
			continue;

		sz = readlinkat(dirfd(devs_dir), devs_dir_entry->d_name, tmp_buf, 256);
		if (sz < 0)
			continue;

		tmp_buf[sz] = 0;

		sprintf(tmp_path, "%s%s", dev_path, tmp_buf);

		dev_dir = opendir(tmp_path);
		if (!dev_dir) 
			continue;

		while ((dev_dir_entry = readdir(dev_dir)) != NULL) {
			if (!strcmp(dev_dir_entry->d_name, hid_dev_name)) {
				strcpy(driver_name, devs_dir_entry->d_name);
				device_found = 1;
				break;
			}
		}
		closedir(dev_dir);

		if (device_found){
			strcat(tmp_path, "/uevent");
			FILE *stream;
                        char line[64];

                	stream = fopen(tmp_path, "r");
                	if (stream == NULL) {
            	        	printf("can not open driver path: %s\n", tmp_path);
		        	return 0;
               		}

                	if(fgets (line, 64, stream)!=NULL) {
            			line[strcspn(line, "\n")] = 0;
                        	char *modulename;
                		modulename = strchr(line, '=') +1;
                        	strcat(driver_path, modulename);
                        	strcat(driver_path, "/");
                	}
                	fclose(stream);
                	break;
		}
	}
	closedir(devs_dir);
	return device_found;
}

int write_devname_to_sys_attr(const char *attr, const char *action)
{
	int fd;
	ssize_t size;

	fd = open(attr, O_WRONLY);
	if (fd < 0) {
		printf("%s: open file error !", __func__);
		return 0;
	}

	for (;;) {
		size = write(fd, action, strlen(action));
		if (size < 0) {
			if (errno == EINTR)
				continue;

			return 0;
		}
		break;
	}

	close(fd);

	return (size == (ssize_t) strlen(action));
}



int rebind_driver(WDT_DEV *pdev)
{
	int 	bus = 0x18;
	int 	vendor = pdev->board_info.vid;
	int 	product = pdev->board_info.pid;
	char	hid_dev_name[64];
	char	driver_path[64];
	char	i2c_dev_name[64];
	char	attr_str[70];

	printf("Start to rebind driver !\n");

	if (!find_hid_dev_name(bus, vendor, product, hid_dev_name)) {
		printf("Not found hid device: 0x%x:0x%x:0x%x\n", bus, vendor, product);
		return 0;
	}



	strcpy(driver_path, "/sys/bus/i2c/drivers/");

	if (!find_device_name(hid_dev_name, i2c_dev_name, driver_path)) {
		printf("find device name failed %s\n", hid_dev_name);
		return 0;
	}


	sprintf(attr_str, "%s%s", driver_path, "unbind");


	if (!write_devname_to_sys_attr(attr_str, i2c_dev_name)) {
		printf("failed to unbind HID device %s %s\n", attr_str, i2c_dev_name);
		return 0;
	}
	
	wh_sleep(300);

	sprintf(attr_str, "%s%s", driver_path, "bind");

	if (!write_devname_to_sys_attr(attr_str, i2c_dev_name)) {
		printf("failed to bind HID device %s %s\n", attr_str, i2c_dev_name);
		return 0;
	}

	wh_sleep(300);

	printf("Rebind driver is done !\n");

	return 1;
}


UINT32 get_chunk_fourcc(UINT32 chunk_index)
{
	switch (chunk_index) {
		case	CHUNK_ID_FRMT:
			return FOURCC_ID_FRMT;
		case	CHUNK_ID_FRWR:
			return FOURCC_ID_FRWR;
		case	CHUNK_ID_CNFG:
			return FOURCC_ID_CNFG;
		case	CHUNK_ID_HDRS:
			return FOURCC_ID_HDRS;
		case	CHUNK_ID_FSBT:
			return FOURCC_ID_FSBT;
		case	CHUNK_ID_BINF:
			return FOURCC_ID_BINF;
		case	CHUNK_ID_RCVY:
			return FOURCC_ID_RCVY;
		case	CHUNK_ID_TSTB:
			return FOURCC_ID_TSTB;
		case	CHUNK_ID_EXTB:
			return FOURCC_ID_EXTB;			
		default:
			return 0;
	}
	return 0;
}

int process_whiff_file(WIF_FILE *pcur_wif)
{
	UINT32*	pstruct = NULL;

	if (!pcur_wif)
		return 0;

	pstruct = (UINT32*) pcur_wif->pdata;

	if (pstruct[0] == FOURCC_ID_RIFF && pstruct[2] == FOURCC_ID_WHIF) {
		
		/* lengths should be the same */
		if (pcur_wif->data_len == pstruct[1]) {
			pcur_wif->pformat_chunk = (FORMAT_CHUNK*) &pstruct[3];
			return 1;
		}
	}

	return 0;
}

int wh_close_whiff_file(WH_HANDLE handle)
{
	WIF_FILE	*pcur_wif = (WIF_FILE*) handle;

	if (pcur_wif) {
		if (pcur_wif->pdata)
			free(pcur_wif->pdata);

		free(pcur_wif);
		return 1;
	}

	return 0;
}

WH_HANDLE wh_open_whiff_file(char* path)
{
	FILE*			pfile = NULL;
	WIF_FILE 		*pcur_wif = NULL;

	pfile = fopen(path, "rb");
	if (!pfile)
		return NULL;

	pcur_wif = (WIF_FILE*) malloc(sizeof(WIF_FILE));
	if (!pcur_wif) {
		fclose(pfile);
		return NULL;
	}

	/* set file ptr to the end */
	fseek(pfile, 0, SEEK_END);
	pcur_wif->data_len = ftell(pfile);

	/* set the file ptr the beginning */
	rewind(pfile);		

	pcur_wif->pdata = (BYTE*) malloc(pcur_wif->data_len + 32);

	if (!pcur_wif->pdata)
		goto failed;

	if (fread(pcur_wif->pdata, 1, pcur_wif->data_len, pfile) == pcur_wif->data_len)	{	
		process_whiff_file(pcur_wif);
		fclose(pfile);

		return (WH_HANDLE) pcur_wif;
	}

failed:
	wh_close_whiff_file((WH_HANDLE) pcur_wif);
		
	return NULL;
}


int wh_get_chunk_info(WH_HANDLE handle, UINT32 chunk_index, CHUNK_INFO_EX* pchunk_info_ex)
{
	WIF_FILE	*pcur_wif = (WIF_FILE*) handle;

	if (!pcur_wif)
		return 0;

	UINT32	chunk_four_cc = get_chunk_fourcc (chunk_index);

	if (!chunk_four_cc)
		return 0;

	if (!pcur_wif->pformat_chunk)
		return 0;

	/* check if the chunk is existed */
	if (pcur_wif->pformat_chunk->enableFlag | chunk_index) {
		
		/* 12 is the header size */
		UINT32	chunk_start_pos = 12 + sizeof (FORMAT_CHUNK);
		CHUNK_DATA*	pchunk_data = NULL;

		while (chunk_start_pos < pcur_wif->data_len) {
			pchunk_data = (CHUNK_DATA*) & pcur_wif->pdata[chunk_start_pos];

			/* we got it */
			if (pchunk_data->ckID == chunk_four_cc)	{
				memcpy((void*) &pchunk_info_ex->chuckInfo, (void*) &pchunk_data->chunkInfo, sizeof(CHUNK_INFO));
				pchunk_info_ex->length = pchunk_data->chunkInfo.length;
				pchunk_info_ex->pData = (BYTE*) &pcur_wif->pdata[chunk_start_pos + 8 + sizeof(CHUNK_INFO)];
				
				return 1;
			} else
				/* 8 is the header size */
				chunk_start_pos = chunk_start_pos + pchunk_data->ckSize + 8;
		}
	}

	return 0;
}

/* 
 * 	the checksum functions
 */
UINT16 misr_16b( UINT16 currentValue, UINT16 newValue )
{
	unsigned int a, b;
	unsigned int bit0;
	unsigned int y;

	a = currentValue;
	b = newValue;
	bit0 = a^(b&1);
	bit0 ^= a>>1;
	bit0 ^= a>>2;
	bit0 ^= a>>4;
	bit0 ^= a>>5;
	bit0 ^= a>>7;
	bit0 ^= a>>11;
	bit0 ^= a>>15;
	y = (a<<1)^b;
	y = (y&~1) | (bit0&1);

	return (UINT16) y;
}

UINT16 misr_32b(UINT16 current_value, UINT32 new_word)
{
	UINT16 checksum = misr_16b(current_value, (UINT16)new_word);
	checksum = misr_16b(checksum, (UINT16)(new_word >> 16));
	return checksum;
}




UINT16 misr_for_halfwords(UINT16 current_value, BYTE *buf, int start, int hword_count)
{
	int i;
	UINT32 checksum = current_value;
	UINT16 *p_hword = (UINT16 *)buf;
	
	for (i = 0; i < hword_count; i++)
		checksum = misr_16b(checksum, *p_hword++);

	return checksum;
}

UINT16 misr_for_bytes(UINT16 current_value, BYTE *bytes, int start, int size)
{
	UINT32 checksum = current_value;

	if (size / 2 > 0)
		checksum = misr_for_halfwords(checksum, bytes, start, size / 2);

	if ((size % 2) != 0)
		checksum = misr_16b(checksum, bytes[start + size - 1]);
	
	return checksum;
}

