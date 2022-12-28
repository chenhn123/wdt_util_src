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

#ifndef	__WDT8790_FUNCS_H__
#define	__WDT8790_FUNCS_H__

int wh_w8790_parse_device_info(W8790_DEV_INFO* report_feature_devinfo, BYTE* buf);
int wh_w8790_prepare_data(WDT_DEV* pdev, BOARD_INFO* p_out_board_info);
int wh_w8790_dev_get_feature(WDT_DEV* pdev, BYTE* buf, UINT32 buf_size);
int wh_w8790_dev_set_feature(WDT_DEV* pdev, BYTE* buf, UINT32 buf_size);
int wh_w8790_dev_get_indexed_string(WDT_DEV* pdev, UINT32 index, BYTE* buf, UINT32 buf_size);
int wh_w8790_dev_read_report(WDT_DEV* pdev, BYTE* buf, UINT32 buf_size);
int wh_w8790_dev_set_basic_op(WDT_DEV* pdev);
int wh_w8790_dev_identify_platform(WDT_DEV* pdev);
int wh_w8790_dev_set_device_mode(WDT_DEV* pdev, BYTE mode);
int wh_w8790_dev_read_buf_response(WDT_DEV* pdev, BYTE* data, int size);
int wh_w8790_dev_get_device_info(WDT_DEV* pdev, BYTE* buf, int offset, int size);
int wh_w8790_dev_get_device_status(WDT_DEV* pdev, BYTE* buf, int offset, int size);
int wh_w8790_dev_read_parameter_page(WDT_DEV* pdev, BYTE* buf, int page_index);
int wh_w8790_dev_flash_read_data(WDT_DEV* pdev, BYTE* data, UINT32 address, int length);
int wh_w8790_dev_flash_write_data(WDT_DEV* pdev, BYTE* data, UINT32 address, int length);
int wh_w8790_dev_flash_get_checksum(WDT_DEV* pdev, UINT32* pchecksum, UINT32 address, int size, UINT32 initial);
int wh_w8790_dev_flash_erase(WDT_DEV*, UINT32 address, int size);
int wh_w8790_dev_flash_block_write(WDT_DEV* pdev, BYTE* data, UINT32 address, int size);
int wh_w8790_dev_send_commands(WDT_DEV* pdev, int cmd, UINT32 value);

#endif		// __w8790_FUNCS_H__
