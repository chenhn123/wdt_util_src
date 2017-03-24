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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <getopt.h>
#include <stdarg.h>

#include "wdt_dev_api.h"
#include "wdt_ct.h"

#define WDT_UTIL_GETOPTS	"hd:u:fbrsw:vcix"

static struct option long_options[] = {
	{"help", 0, NULL, 'h'},
	{"device", 1, NULL, 'd'},		
	{"update", 1, NULL, 'u'},
	{"no_force", 0, NULL, 'f'},
	{"no_bind", 0, NULL, 'b'},
	{"no_rcry", 0, NULL, 'r'},
	{"info", 0, NULL, 's'},	
	{"wif-info", 1, NULL, 'w'},
	{"fw-ver", 0, NULL, 'v'},
	{"cfg-cksum", 0, NULL, 'c'},
	{"hw-id", 0, NULL, 'i'},	
	{"ext-info", 0, NULL, 'x'},
	{0, 0, 0, 0},
};

static int g_show_extra_info = 0;

void print_version()
{
	printf("%s %s\n", TOOL_TITLE_STR, TOOL_VERSION_STR);
}

void print_help(const char *prog_name)
{
	print_version();
	
	printf("\nUsage: %s [OPTIONS] [FW_FILE|PD_FILE|SUB-ARGU]\n", prog_name);
	printf("\t-h, --help\tPrint this message\n");
	printf("\t-d, --device\ti2c device file associated with the device.\n");	
	printf("\t-u, --update\tUpdate firmware with verification\n");
	printf("\t-f, --no_force\tNot to force updating firmware\n");
	printf("\t-b, --no_bind\tNot to rebind driver after firmware updated\n");	
	printf("\t-r, --no_rpara\tNo need to update the recovery parameter\n");
	printf("\t-s, --info\tPrint the info associated with the devcie.\n");
	printf("\t-w, --wif-info\tPrint the info associated with wif image file.\n");
	printf("\t-v, --fw-ver\tRead the fw version from the device.\n");	
	printf("\t-c, --cfg-cksum\tRead the cfg chksum from the device\n");		
	printf("\t-i, --hw-id\tRead the hardware id from the device\n");			
	printf("\t-x, --ext-info\tShow more information.\n");
}

void wh_printf(const char *fmt, ...)
{
	if (!g_show_extra_info)
		return;
	
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

void wh_sleep(int ms)
{
	usleep(ms * 1000);
}

void wh_udelay(int us)
{
	usleep(us);
}

unsigned long get_current_ms()
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

int check_privilege()
{
	uid_t uid = getuid();
	uid_t euid = geteuid();

	if (uid == 0 || euid == 0)
		return 1;

	return 0;
}

int check_file(char* filename)
{
	FILE*	p_file = 0;

	p_file = fopen(filename, "r");

	if (p_file) {
		
		/* file existed */
		fclose(p_file);
		return 1;		
	}

	return 0;
}

int parse_args(int argc, char* argv[], EXEC_PARAM* pparam)
{
	int 	opt;
	int 	index;
	char	*parg = 0;	

	/* only support I2C here */
	pparam->interface_num = INTERFACE_I2C;

	while ((opt = getopt_long(argc, argv, WDT_UTIL_GETOPTS, long_options, &index)) != -1) {
		switch (opt) {
			case 'h':
				print_help(argv[0]);
				return 0;
			case 'd':
				/* there would be the 0x20 in the leading sometimes */
				parg = optarg;
				while (*parg == 0x20)
					parg++;
				
				if (memcmp("/dev", parg, 4))
					sprintf(pparam->dev_path, "/dev/%s", parg);
				else
					strcpy(pparam->dev_path, parg);
				break;
			case 'u':
				pparam->argus |= OPTION_UPDATE;
				pparam->image_file = optarg;
				break;
			case 'f':
				pparam->argus |= OPTION_NO_FORCE;	
				break;
			case 'b':
				pparam->argus |= OPTION_NO_REBIND;
				break;
			case 'r':
				pparam->argus |= OPTION_NO_RPARAM;	
				break;				
			case 's':
				pparam->argus |= OPTION_INFO;
				break;				
			case 'w':
				pparam->argus |= OPTION_WIF_INFO;
				pparam->image_file = optarg;				
				break;
			case 'v':
				pparam->argus |= OPTION_FW_VER;
				break;
			case 'c':
				pparam->argus |= OPTION_CFG_CHKSUM;
				break;
			case 'i':
				pparam->argus |= OPTION_HW_ID;
				break;
			case 'x':
				pparam->argus |= OPTION_EXTRA_INFO;		
				g_show_extra_info = 1;
			default:
				break;

		}
	}

	if (optind != argc) {
		int i=0; 
		while (i<argc) {
			printf("%s ", argv[i]);
			i++;
		}
		printf("\n");
		
		print_help(argv[0]);
		return 0;
	}

	return pparam->argus;
}


int main(int argc, char * argv[]) 
{
	int				ret = 0;
	int				info_mask = OPTION_FW_VER | OPTION_CFG_CHKSUM | OPTION_HW_ID;
	EXEC_PARAM		exec_param;
	WDT_DEV			wdt_dev;
	unsigned long	start_tick;
	int (*LPFUNC_execution)(WDT_DEV*, EXEC_PARAM*);

	memset((void*) &exec_param, 0, sizeof(EXEC_PARAM));
	if(!parse_args(argc, argv, &exec_param)) {
		return 0;
	}

	if (!(exec_param.argus & info_mask))
		print_version();

	if (!check_privilege()) {
		printf("Must be a root to run this program!\n");
		return 0;
	}

	memset(&wdt_dev, 0, sizeof(WDT_DEV));
	
	if (!load_lib_func_address(&wdt_dev, &exec_param)) {
		printf("Load function table failed !\n");
		return 0;
	}

	wdt_dev.pparam = &exec_param;
	start_tick = get_current_ms();

	LPFUNC_execution = NULL;
	if (exec_param.argus & OPTION_UPDATE)
		LPFUNC_execution = image_file_burn_data_verify; 
	else if (exec_param.argus & (info_mask | OPTION_INFO))
		LPFUNC_execution = show_info; 
	else if (exec_param.argus & OPTION_WIF_INFO)
		LPFUNC_execution = show_wif_info; 
	
	if (LPFUNC_execution)
		ret = LPFUNC_execution(&wdt_dev, &exec_param);

	if (exec_param.argus & OPTION_UPDATE) {
		if (!(exec_param.argus & OPTION_NO_REBIND)) {
			if (!rebind_driver(&wdt_dev)) {
				printf("Faild to rebind driver !\n");
				return 0;
			}
		}
		
		printf("It takes %ums\n", (unsigned int) (get_current_ms() - start_tick));
	}
	
	return ret;
}
