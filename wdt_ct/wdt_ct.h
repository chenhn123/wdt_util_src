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

#ifndef	__WDT_CT_H__
#define	__WDT_CT_H__

/* define for device control */
#define		OPTION_UPDATE			0x1
#define		OPTION_ISP_UPDATE		0x2
#define		OPTION_NO_FORCE			0x4
#define		OPTION_INFO			0x8
#define		OPTION_EXTRA_INFO		0x10
#define 	OPTION_NO_RPARAM		0x20
#define		OPTION_NO_REBIND		0x40
#define 	OPTION_BLOCK			0x80

/* define for wif file */
#define		OPTION_WIF_INFO			0x100

/* define for info from the device */
#define		OPTION_FW_VER			0x1000
#define		OPTION_CFG_CHKSUM		0x2000
#define		OPTION_HW_ID			0x4000

#define		TOOL_TITLE_STR			"Weida Update Utility"
#define		TOOL_VERSION_STR		"V0.9.12"

int		load_lib_func_address(WDT_DEV*, EXEC_PARAM*);
int		image_file_burn_data_verify(WDT_DEV *pdev, EXEC_PARAM *pParam);
int 		show_wif_info(WDT_DEV *pdev, EXEC_PARAM *pparam);
int		show_info(WDT_DEV *pdev, EXEC_PARAM *pParam);
int		rebind_driver(WDT_DEV *pdev);

void 		wh_printf(const char *fmt, ...);
void 		wh_sleep(int ms);
void 		wh_udelay(int us);
unsigned long 	get_current_ms();

/* __WDT_CT_H__ */
#endif
