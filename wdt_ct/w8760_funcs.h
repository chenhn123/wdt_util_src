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

#ifndef	__WDT8760_FUNCS_H__
#define	__WDT8760_FUNCS_H__

int	wh_w8760_prepare_data(WDT_DEV* pdev, BOARD_INFO* p_out_board_info);
int	wh_w8760_dev_get_feature(WDT_DEV* pdev, BYTE* buf, UINT32 buf_size);
int	wh_w8760_dev_set_feature(WDT_DEV* pdev, BYTE* buf, UINT32 buf_size);
int	wh_w8760_dev_read_report(WDT_DEV* pdev, BYTE* buf, UINT32 buf_size);
int	wh_w8760_dev_set_basic_op(WDT_DEV *pdev);
int	wh_w8760_get_feature_devinfo(W8760_REPORT_FEATURE_DEVINFO* report_feature_devinfo, BYTE* buf);
int	wh_w8760_dev_identify_platform(WDT_DEV* pdev, BOARD_INFO* pboardInfo);
int	wh_w8760_dev_set_device_mode(WDT_DEV* pdev, BYTE mode);
int	wh_w8760_dev_read_buf_response(WDT_DEV* pdev, BYTE* data, int size);
int	wh_w8760_dev_get_device_info(WDT_DEV* pdev, BYTE* buf, int offset, int size);
int	wh_w8760_dev_get_device_status(WDT_DEV* pdev, BYTE* buf, int offset, int size);
int	wh_w8760_dev_read_parameter_page(WDT_DEV* pdev, BYTE* buf, int page_index);
int	wh_w8760_dev_get_context(WDT_DEV* pdev, W8760_PCT_DATA* pPct);
int	wh_w8760_dev_flash_write_data(WDT_DEV* pdev, BYTE* data, UINT32 address, int length);
int	wh_w8760_dev_flash_get_checksum(WDT_DEV* pdev, UINT32* pchecksum, UINT32 address, int size);
int	wh_w8760_dev_flash_erase(WDT_DEV*, UINT32 address, int size);
int	wh_w8760_dev_send_commands(WDT_DEV* pdev, int cmd, UINT32 value);
int	wh_w8760_dev_set_men_address(WDT_DEV* pdev, UINT32 address);
int	wh_w8760_dev_write_men_halfword(WDT_DEV* pdev, UINT16 hwords);
int	wh_w8760_dev_run_program_from_background(WDT_DEV* pdev, UINT32 program_address);
int	wh_w8760_dev_verify_chunk(WDT_DEV* pdev, CHUNK_INFO_EX* pChunk);
int	wh_w8760_dev_program_chunk(WDT_DEV* pdev, CHUNK_INFO_EX* pInputChunk, int option);
int	wh_w8760_dev_program_4k_chunk_verify(WDT_DEV* pdev, CHUNK_INFO_EX* pInputChunk, int option);
int	wh_w8760_dev_program_chunk_verify(WDT_DEV* pdev, CHUNK_INFO_EX* pInputChunk, int option);
int	wh_w8760_get_rom_signature(int type, BYTE* buf);
int	wh_w8762_isp_rerun_recovery(WDT_DEV *pdev);
int	wh_w8760_isp_rerun_recovery(WDT_DEV *pdev);

/* __w8760_FUNCS_H__ */
#endif		

