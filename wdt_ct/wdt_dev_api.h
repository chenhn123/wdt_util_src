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

#ifndef	__WDT_DEV_API_H__
#define	__WDT_DEV_API_H__

#include	"whiff.h"
#include	"dev_def.h"


#define		INTERFACE_USB			0x1
#define		INTERFACE_I2C			0x2
#define		INTERFACE_HIDRAW		0x3

#define		RETRY_COUNT			3

#define		OPTION_DES			0x1
#define		OPTION_4K_VERIFY		0x2
#define		OPTION_ERR_RTN			0x4
#define		OPTION_ISP_MODE			0x8
#define		OPTION_FASTBOOT			0x100
#define		OPTION_FORCE_ACT		0x200
#define		OPTION_ERASE_TEMP		0x400

/* standard commands */
#define		WH_CMD_RESET			0x01
#define		WH_CMD_ALGO_STOP		0x02
#define		WH_CMD_ALGO_START		0x03
#define		WH_CMD_ALGO_RESTART		0x04
#define		WH_CMD_SET_DEV_MODE		0x05

#define		WH_CMD_FLASH_LOCK		0x10
#define		WH_CMD_FLASH_UNLOCK		0x11
#define		WH_CMD_FLASH_ERASEALL		0x12
#define		WH_CMD_FLASH_ERASE4K		0x13
#define		WH_CMD_FLASH_ERASE64K		0x14
#define		WH_CMD_FLASH_ERASE32K		0x15
#define		WH_CMD_FLASH_PROTECTION_ON	0x16
#define		WH_CMD_FLASH_PROTECTION_OFF	0x17





/* forward declaration */
struct WdtDevice;
typedef	struct WdtDevice			WDT_DEV;	
typedef struct FuncPtrStructDevAccess 		FUNC_PTR_STRUCT_DEV_ACCESS; 
typedef struct FuncPtrStructDevOperation 	FUNC_PTR_STRUCT_DEV_OPERATION; 
typedef struct FuncPtrStructDevBasic 		FUNC_PTR_STRUCT_DEV_BASIC; 

/* Device Access Function Pointer typedef */
typedef	int		(* LPFUNC_wh_scan_device)(WDT_DEV*);   
typedef	int		(* LPFUNC_wh_get_device) (WDT_DEV*, void*, int);  
typedef	int		(* LPFUNC_wh_open_device) (WDT_DEV*);
typedef	int		(* LPFUNC_wh_close_device) (WDT_DEV*);	
typedef	int	 	(* LPFUNC_wh_program_chunk) (WDT_DEV*, CHUNK_INFO_EX*, int);
typedef	int	 	(* LPFUNC_wh_verify_chunk) (WDT_DEV*, CHUNK_INFO_EX*);

/* Private Device Access Function Pointer typedef */
typedef	int		(* LPFUNC_wh_flash_read_data) (WDT_DEV*, BYTE*, UINT32, int); 
typedef	int		(* LPFUNC_wh_flash_write_data) (WDT_DEV*, BYTE*, UINT32, int);
typedef	int		(* LPFUNC_wh_flash_get_checksum) (WDT_DEV*, UINT32*, UINT32, int, UINT32);
typedef	int		(* LPFUNC_wh_send_commands) (WDT_DEV*, int, UINT32);
typedef	int		(* LPFUNC_wh_prepare_data) (WDT_DEV*, BOARD_INFO*);
typedef int		(* LPFUNC_wh_flash_erase)(WDT_DEV*, UINT32, int);


/* Basic Device Access Function Pointer typedef */
typedef	int	 	(* LPFUNC_wh_set_feature) (WDT_DEV*, BYTE*, UINT32);
typedef	int	 	(* LPFUNC_wh_get_feature) (WDT_DEV*, BYTE*, UINT32);
typedef	int	 	(* LPFUNC_wh_get_index_string) (WDT_DEV*, UINT32, BYTE*, UINT32);
typedef	int	 	(* LPFUNC_wh_read_report) (WDT_DEV*, BYTE*, UINT32);


typedef	WH_HANDLE	(* LPFUNC_wh_open_whiff)(char*);  
typedef	int		(* LPFUNC_wh_close_whiff)(WH_HANDLE);
typedef	int		(* LPFUNC_wh_get_chunk_info)(WH_HANDLE, UINT32, CHUNK_INFO_EX*);	
typedef	int		(* LPFUNC_wh_get_device_access_func)(int, FUNC_PTR_STRUCT_DEV_ACCESS* );   
typedef	int		(* LPFUNC_wh_get_device_private_access_func)(WDT_DEV*,  FUNC_PTR_STRUCT_DEV_OPERATION*);   
typedef	int		(* LPFUNC_wh_get_device_basic_access_func)(WDT_DEV*, FUNC_PTR_STRUCT_DEV_BASIC*);   

typedef struct FuncPtrStructDevAccess { 
	LPFUNC_wh_scan_device		p_wh_scan_device;	 
	LPFUNC_wh_get_device		p_wh_get_device;
	LPFUNC_wh_open_device		p_wh_open_device;	
	LPFUNC_wh_close_device		p_wh_close_device;	
	LPFUNC_wh_prepare_data		p_wh_prepare_data;	
} FUNC_PTR_STRUCT_DEV_ACCESS; 


typedef struct	FuncPtrStructDevOperation { 
	LPFUNC_wh_program_chunk		p_wh_program_chunk;
	LPFUNC_wh_verify_chunk		p_wh_verify_chunk;
	LPFUNC_wh_flash_read_data	p_wh_flash_read_data;
	LPFUNC_wh_flash_write_data	p_wh_flash_write_data;
	LPFUNC_wh_flash_get_checksum	p_wh_flash_get_checksum;
	LPFUNC_wh_send_commands		p_wh_send_commands;
	LPFUNC_wh_flash_erase		p_wh_flash_erase;
} FUNC_PTR_STRUCT_DEV_OPERATION; 

typedef struct 	FuncPtrStructDevBasic {
	LPFUNC_wh_set_feature		p_wh_set_feature;
	LPFUNC_wh_set_feature		p_wh_get_feature;
	LPFUNC_wh_get_index_string	p_wh_get_index_string;
	LPFUNC_wh_read_report		p_wh_read_report;
} FUNC_PTR_STRUCT_DEV_BASIC; 

typedef	struct ExecParam
{
	UINT32		argus;
	UINT32		interface_num;
	UINT32		options;
	char		*image_file;
	char		dev_path[64];
} EXEC_PARAM ;

typedef enum tagDevState
{
	DS_NONE = 0,
	DS_ENUM = 1,
	DS_GET_INFO = 2,
	DS_PROGRAM = 3,
} DEV_STATE;

typedef struct WifAccess {
	char				wif_path[256];
	WH_HANDLE			wif_handle;
	CHUNK_INFO_EX			wif_chunk_info;
} WIF_ACCESS;

typedef struct WdtDevice {
	UINT32				intf_index;
	UINT32				is_legacy;
	UINT32				adaptor_no;
	char				dev_path[64];
	WH_HANDLE			dev_handle;
	WIF_ACCESS			wif_access;
	BOARD_INFO			board_info;
	DEV_STATE			dev_state;
	EXEC_PARAM			*pparam;	

	FUNC_PTR_STRUCT_DEV_ACCESS		funcs_device;
	FUNC_PTR_STRUCT_DEV_OPERATION		funcs_device_private;
	FUNC_PTR_STRUCT_DEV_BASIC		funcs_device_basic;

	LPFUNC_wh_open_whiff			func_wh_open_whiff;
	LPFUNC_wh_close_whiff			func_wh_close_whiff;

	LPFUNC_wh_get_chunk_info		func_wh_get_chunk_info;
	LPFUNC_wh_get_device_access_func	func_wh_get_device_access_func;
	LPFUNC_wh_get_device_private_access_func	func_wh_get_device_private_access_func;
	LPFUNC_wh_get_device_basic_access_func		func_wh_get_device_basic_access_func;

} WDT_DEV;

WH_HANDLE	wh_open_whiff_file(char *path);
int		wh_close_whiff_file(WH_HANDLE handle);
int		wh_get_chunk_info(WH_HANDLE handle, UINT32 chunk_index, CHUNK_INFO_EX *pChunkInfoEx);

int		wh_get_device_access_func(int interfaceIndex, FUNC_PTR_STRUCT_DEV_ACCESS *pFuncs );   
int		wh_get_device_private_access_func(WDT_DEV *pdev, FUNC_PTR_STRUCT_DEV_OPERATION *pFuncs );   
int		wh_get_device_basic_access_func(WDT_DEV *pdev, FUNC_PTR_STRUCT_DEV_BASIC *pFuncs );

int		wh_i2c_scan_device(WDT_DEV *pdev);
int		wh_i2c_get_device(WDT_DEV *pdev, WDT_DEVICE_INFO *pDevInfo, int flag);
int 		wh_i2c_open_device(WDT_DEV *pdev);
int		wh_i2c_close_device(WDT_DEV *pdev);
int		wh_i2c_prepare_data(WDT_DEV *pDev, BOARD_INFO *pboard_info);

UINT16 		get_unaligned_le16(const void *p);
UINT32 		get_unaligned_le32(const void *p);
void 		put_unaligned_le16(UINT16 val, BYTE *p);
void 		put_unaligned_le32(UINT32 val, BYTE *p);
int		check_is_all_ff(BYTE* data, int length);
int		count_ff_bytes(BYTE* data, int start, int size);


int 		check_firmware_id(WDT_DEV *pdev, UINT32 fwid);
UINT16 		misr_for_bytes(UINT16 current_value, BYTE *bytes, int start, int size);
UINT16		misr_32b(UINT16 current_value, UINT32 new_word);


/* __WDT_DEV_API_H__ */
#endif
