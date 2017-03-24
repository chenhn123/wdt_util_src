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

/* what version FW is running in the device */
#define		FW_MAYBE_ISP			0x01
#define		FW_WITH_CMD				0x02
#define		FW_LEGACY				0x04
#define		FW_WDT8755				0x20
#define		FW_WDT8755_ISP			0x40

/* compatibility to the usb descriptor */
#define 	GD_DEVICE          		0x01
#define 	GD_STRING          		0x03

#define		STRIDX_IDENTIFICATION	0x3C
#define		STRIDX_PLATFORM_ID		0x80
#define		STRIDX_PARAMETERS	    0x81

#define		WDT_PAGE_SIZE			0x1000

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
	UINT16 reserved;
} I2C_HID_DESC;

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
	I2C_HID_DESC			dev_hid_desc;
	W8755_DEV_INFO_NEW		dev_info_new;
} BOARD_INFO;

typedef	struct UsbDeviceDesc
{
	BYTE 	bLength;
	BYTE	bDescriptorType;
	UINT16  bcdUSB;
	BYTE 	bDeviceClass;
	BYTE	bDeviceSubClass;
	BYTE	bDeviceProtocol;
	BYTE 	bMaxPacketSize0;
	UINT16	idVendor;
	UINT16	idProduct;
	UINT16  bcdDevice;
	BYTE	iManufacturer;
	BYTE 	iProduct;
	BYTE 	iSerialNumber;
	BYTE	bNumConfigurations;
} USB_DEVICE_DESC;

#define		GET_DEVICE_BY_PATH			0x100
#define		GET_DEVICE_BY_LPATH			0x200

typedef struct	WdtDeviceInfo
{
	UINT32	vid;
	UINT32	pid;
	char	path[256];
	char 	l_path[256];
} WDT_DEVICE_INFO;

/* __DEV_DEF_H__ */
#endif
