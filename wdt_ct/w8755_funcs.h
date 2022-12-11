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

#ifndef	__W8755_FUNCS_H__
#define	__W8755_FUNCS_H__

#define		FLASH_PAGE_WRITE_DELAY_US		100
#define 	I2C_OPERATION_DELAY_US			100


int wh_w8755_dev_program_4k_chunk_verify(WDT_DEV*, CHUNK_INFO_EX*, int);
int wh_w8755_dev_verify_chunk(WDT_DEV*, CHUNK_INFO_EX*);
int wh_w8755_dev_program_chunk(WDT_DEV*, CHUNK_INFO_EX*, int);

/* Private Device Access Function Pointer typedef */
int wh_w8755_dev_flash_read_data(WDT_DEV*, BYTE*, UINT32, int); 
int wh_w8755_dev_flash_write_data(WDT_DEV*, BYTE*, UINT32, int);
int wh_w8755_dev_flash_get_checksum(WDT_DEV*, UINT32*, UINT32, int);
int wh_w8755_dev_mem_read_data(WDT_DEV*, BYTE*, UINT32, int);
int wh_w8755_dev_mem_write_data(WDT_DEV*, BYTE*, UINT32, int);
int wh_w8755_dev_send_commands(WDT_DEV*, int, UINT32);

/* Basic Device Access Function Pointer typedef */
int wh_w8755_dev_set_feature(WDT_DEV*, BYTE*, UINT32);
int wh_w8755_dev_get_feature(WDT_DEV*, BYTE*, UINT32);
int wh_w8755_dev_get_indexed_string(WDT_DEV*, UINT32, BYTE*, UINT32);
int wh_w8755_dev_read_report(WDT_DEV*, BYTE*, UINT32);


int wh_w8755_dev_set_basic_op(WDT_DEV *pdev);
int wh_w8755_dev_identify_platform(WDT_DEV* pdev);
int wh_w8755_dev_parse_new_dev_info(WDT_DEV* pdev, W8755_DEV_INFO_NEW *pdev_info_new);
int wh_w8755_dev_set_device_mode(WDT_DEV* pdev, BYTE mode);

/* __W8755_FUNCS_H__ */
#endif
