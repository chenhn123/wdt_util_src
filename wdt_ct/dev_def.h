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

#ifndef	__DEV_DEF_H__
#define	__DEV_DEF_H__

#include "w8755_def.h"
#include "w8760_def.h"
#include "w8790_def.h"

/* what version FW is running in the device */
#define		FW_MAYBE_ISP		0x01
#define		FW_WITH_CMD		0x02
#define		FW_LEGACY		0x04
#define		FW_WDT8755		0x20
#define		FW_WDT8755_ISP		0x40
#define		FW_WDT8790		0x200
#define		FW_WDT8790_ISP		(FW_WDT8790 |FW_MAYBE_ISP)
#define		FW_WDT8760		0x800
#define		FW_WDT8760_ISP		0x1000
#define		FW_WDT8762		0x2000
#define		FW_WDT8762_ISP		0x4000
#define		FW_WDT8760_2		(FW_WDT8760 | FW_WDT8762)
#define		FW_WDT8760_2_ISP	(FW_WDT8760_ISP | FW_WDT8762_ISP)


/* compatibility to the usb descriptor */
#define 	GD_DEVICE          	0x01
#define 	GD_STRING          	0x03

#define		STRIDX_PARAMETERS	0x81

#define 	VND_REQ_DEV_INFO	0xF2

#define		WDT_PAGE_SIZE		0x1000


typedef	union
{
	struct {
		BYTE	report_id;
		BYTE	type;
		UINT16	index;
		UINT32	length;
		BYTE	data[56];
	} DD;
	BYTE	buffer[64];
} REQ_DATA;

typedef	struct SysParam
{
	UINT16	temp0;
	UINT16	temp1;
	UINT16	xmls_id1;
	UINT16	xmls_id2;
	UINT16	Phy_Frmbuf_W;
	UINT16	Phy_Frmbuf_H;
	UINT16	Phy_X0;
	UINT16	Phy_X1;
	UINT16	Phy_Y0;
	UINT16	Phy_Y1;
	UINT16	cts_cfg;
	UINT16	lcd_w;
	UINT16	lcd_h;
	UINT16	autocal_gen_conf;
	UINT16	cal_nframes;
	UINT16	threshold;
	UINT16 	scale_factor;
	UINT16	usb_dbg_cfg;
	UINT16	i2c_dbg_cfg;
} SYS_PARAM;

typedef struct i2c_hid_desc 
{
	UINT16 wHIDDescLength;
	UINT16 bcdVersion;
	UINT16 wReportDescLength;
	UINT16 wReportDescRegister;
	UINT16 wInputRegister;
	UINT16 wMaxInputLength;
	UINT16 wOutputRegister;
	UINT16 wMaxOutputLength;
	UINT16 wCommandRegister;
	UINT16 wDataRegister;
	UINT16 wVendorID;
	UINT16 wProductID;
	UINT16 wVersionID;
	UINT32 reserved;
} I2C_HID_DESC;

typedef union u_dev_info {
	W8755_DEV_INFO_NEW	w8755_dev_info;
	W8760_REPORT_FEATURE_DEVINFO	w8760_feature_devinfo;
	W8790_DEV_INFO	w8790_feature_devinfo;
} U_DEV_INFO;

typedef union sec_header {

	W8755_SEC_ADDR_TYPE	w8755_sec_header;
	W8760_SECTION_MAP_ADDR	w8760_sec_addr;
	W8790_FLASH_MAP		w8790_sec_addr;

} U_SEC_HEADER;


typedef	struct BoardInfo
{
	UINT32			dev_type;
	UINT32			vid;
	UINT32			pid;
	UINT32			i2c_dummy;
	UINT32			firmware_id;
	UINT32			hardware_id;
	UINT32			serial_no;
	
	SYS_PARAM		sys_param;
	BYTE			platform_id[12];

	I2C_HID_DESC		dev_hid_desc;
	U_DEV_INFO		dev_info;
	U_SEC_HEADER		sec_header;
} BOARD_INFO;


typedef struct	WdtDeviceInfo
{
	UINT32	vid;
	UINT32	pid;
	char	path[256];
} WDT_DEVICE_INFO;

/* forward declaration */
struct WdtDevice;
typedef	struct WdtDevice	WDT_DEV;	

int wh_i2c_tx(WDT_DEV *pdev, BYTE slave_addr, BYTE* pbuf, UINT32 buf_size);
int wh_i2c_rx(WDT_DEV *pdev, BYTE slave_addr, BYTE* pbuf, UINT32 buf_size);
int wh_i2c_xfer(WDT_DEV *pdev, BYTE slave_addr, BYTE* txbuf, UINT32 tx_len, BYTE* rxbuf, UINT32 rx_len);

int wh_i2c_set_feature(WDT_DEV *pdev, BYTE* buf, UINT32 buf_size);
int wh_i2c_get_feature(WDT_DEV *pdev, BYTE* buf, UINT32 buf_size);
int wh_i2c_get_indexed_string(WDT_DEV *pdev, UINT32 index, BYTE* buf, UINT32 buf_size);
int wh_i2c_read(WDT_DEV *pdev, BYTE* buf, UINT32 buf_size);
int wh_i2c_get_desc(WDT_DEV *pdev, BYTE desc_type, BYTE string_idx, BYTE* target_buf, UINT32 buf_size);

/* __DEV_DEF_H__ */
#endif
