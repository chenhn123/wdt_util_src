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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wdt_dev_api.h"
#include "wif2.h"
#include "wdt_ct.h"

int process_wif2(WIF_FILE2 *pcur_wif)
{
	UINT32 *pstruct = NULL;

	if (!pcur_wif)
		return 0;

	pstruct = (UINT32 *)pcur_wif->pdata;

	if (pstruct[0] == FOURCC_ID_RIFF && pstruct[2] == FOURCC_ID_WIF2) {
		/* lengths should be the same */
		if (pcur_wif->data_len == pstruct[1]) {
			return 1;
		}
	}

	return 0;
}

int free_wif2(WIF_FILE2 *pcur_wif)
{
	if (pcur_wif->pdata) {
		free(pcur_wif->pdata);
		return 1;
	}

	return 0;
}



int get_wif2(char *path, WIF_FILE2 *out_pcur_wif)
{
	FILE *pfile = NULL;
	int ret = 1;

	pfile = fopen(path, "rb");
	if (!pfile)
		return 0;

	/* set file ptr to the end */
	fseek(pfile, 0, SEEK_END);
	out_pcur_wif->data_len = ftell(pfile);

	/* set the file ptr the beginning */
	rewind(pfile);
	UINT32 pdataSize = out_pcur_wif->data_len;

	out_pcur_wif->pdata = (BYTE *)malloc(pdataSize);

	if (!out_pcur_wif->pdata) {
		ret = 0;
		goto finish;
	}

	if (fread(out_pcur_wif->pdata, 1, out_pcur_wif->data_len, pfile) ==
	    out_pcur_wif->data_len) {
		ret = process_wif2(out_pcur_wif);
		if (ret == 1) {
			ret = 1;
			goto finish;
		} else {
			ret = 0;
			goto finish;
		}
	} else {
		ret = 0;
		goto finish;
	}

finish:

	fclose(pfile);

	return ret;
}

int do_wif2_chunk_info(WIF_FILE2 *pcur_wif, UINT32 chunk_four_cc)
{
	if (!pcur_wif)
		return 0;

	if (!chunk_four_cc)
		return 0;
	WIF2_Info_Chunk *pchunk_info_ex;
	pchunk_info_ex = (WIF2_Info_Chunk *)malloc(sizeof(WIF2_Info_Chunk));
	if (!pchunk_info_ex)
		return 0;
	int ret = 1;
	UINT32 chunk_start_pos = 0 + sizeof(ChunkHeader);
	WIF2_Chunk_Header *pchunk_data = NULL;
	 
	while (chunk_start_pos < pcur_wif->data_len) {
		pchunk_data = (WIF2_Chunk_Header *)&pcur_wif->pdata[chunk_start_pos];

		/* we got it */
		if (pchunk_data->FourCC == chunk_four_cc) {
			pchunk_info_ex->Header.FourCC = pchunk_data->FourCC;
			pchunk_info_ex->Header.Size = pchunk_data->Size;

			pchunk_info_ex->BinaryData = (BYTE *)malloc(pchunk_data->Size);
			if (!pchunk_info_ex->BinaryData){
				ret = 0;
				goto finish;
			}

			chunk_start_pos = chunk_start_pos + pchunk_data->Size + 8;
			if (pchunk_info_ex->BinaryData)
                        	free(pchunk_info_ex->BinaryData);


		} else{
			/* 8 is the header size */
			chunk_start_pos = chunk_start_pos + pchunk_data->Size + 8;
		}

	}
finish:
	if(pchunk_info_ex)
		free(pchunk_info_ex);

	return ret;
}

int do_update_fw_by_wif2_chunk_fbin(WDT_DEV *pdev, WIF_FILE2 *pcur_wif, UINT32 chunk_four_cc)
{
	int ret = 1;
	if (!pcur_wif)
		return 0;

	if (!chunk_four_cc)
		return 0;

	WIF2_FlashBinary_Chunk *pchunk_info_ex;
	pchunk_info_ex = (WIF2_FlashBinary_Chunk *)malloc(sizeof(WIF2_FlashBinary_Chunk));
	if (!pchunk_info_ex)
		return 0;

	UINT32 chunk_start_pos = 0 + sizeof(ChunkHeader);
	WIF2_Chunk_Header *pchunk_data = NULL;

	while (chunk_start_pos < pcur_wif->data_len) {
		pchunk_data = (WIF2_Chunk_Header *)&pcur_wif->pdata[chunk_start_pos];

		/* we got it */
		if (pchunk_data->FourCC == chunk_four_cc) {
			pchunk_info_ex->Header.FourCC = pchunk_data->FourCC;
			pchunk_info_ex->Header.Size = pchunk_data->Size;

			UINT32 pdata_pos = chunk_start_pos + sizeof(WIF2_Chunk_Header);

			// Flash space to erase
			pchunk_info_ex->SpaceToErase.Address =
				get_unaligned_le32(&pcur_wif->pdata[pdata_pos]);
			pdata_pos = pdata_pos + sizeof(UINT32);
			pchunk_info_ex->SpaceToErase.Size =
				get_unaligned_le32(&pcur_wif->pdata[pdata_pos]);
			pdata_pos = pdata_pos + sizeof(UINT32);

			//printf("SpaceToEraseAddress:0x%x\n",pchunk_info_ex->SpaceToErase.Address);
			//printf("SpaceToEraseSize:0x%x\n", pchunk_info_ex->SpaceToErase.Size);

			// Flash image
			pchunk_info_ex->Binary.Address =
				get_unaligned_le32(&pcur_wif->pdata[pdata_pos]);
			pdata_pos = pdata_pos + sizeof(UINT32);
			pchunk_info_ex->Binary.Size =
				get_unaligned_le32(&pcur_wif->pdata[pdata_pos]);
			pdata_pos = pdata_pos + sizeof(UINT32);

			//printf("BinaryAddress:0x%x\n", pchunk_info_ex->Binary.Address);
			//printf("BinarySize:0x%x\n", pchunk_info_ex->Binary.Size);

			pchunk_info_ex->BinaryData = (BYTE *)malloc(pchunk_info_ex->Binary.Size);
			if (!pchunk_info_ex->BinaryData) {
				ret = 0;
				if (pchunk_info_ex->BinaryData)
                			free(pchunk_info_ex->BinaryData);
				goto finish;
			}

			memcpy((BYTE *)pchunk_info_ex->BinaryData,
			       (BYTE *)&pcur_wif->pdata[pdata_pos], pchunk_info_ex->Binary.Size);
			
			ret = pdev->funcs_device_private.p_wh_send_commands(pdev, WH_CMD_FLASH_UNLOCK, 0);
			if (!ret) {
				if (pchunk_info_ex->BinaryData)
                			free(pchunk_info_ex->BinaryData);

				goto finish;
			}
			// address and size align to 0x100
			UINT32 protect_off_arg =
				(pchunk_info_ex->Binary.Address >> 8 << 16 & 0xffff0000) |
				(pchunk_info_ex->Binary.Size >> 8 & 0x0000ffff);

			ret = pdev->funcs_device_private.p_wh_send_commands(
				pdev, WH_CMD_FLASH_PROTECTION_OFF, protect_off_arg);
			if (!ret) {
            			if (pchunk_info_ex->BinaryData)
                			free(pchunk_info_ex->BinaryData);

				goto finish;
			}
			ret = pdev->funcs_device_private.p_wh_flash_erase(
				pdev, pchunk_info_ex->SpaceToErase.Address,
				pchunk_info_ex->SpaceToErase.Size);
			if (!ret) {
				if (pchunk_info_ex->BinaryData)
                			free(pchunk_info_ex->BinaryData);

				goto finish;
			}

			
			printf("Use 4k program\n");
			ret = pdev->funcs_device_private.p_wh_flash_erase(
					pdev, pchunk_info_ex->SpaceToErase.Address,
					pchunk_info_ex->SpaceToErase.Size);
			if (!ret) {
				if (pchunk_info_ex->BinaryData)
                			free(pchunk_info_ex->BinaryData);

				goto finish;
			}

			ret = pdev->funcs_device_private.p_wh_flash_write_data(
					pdev, pchunk_info_ex->BinaryData,
					pchunk_info_ex->Binary.Address,
					pchunk_info_ex->Binary.Size);
			if (!ret) {
            			if (pchunk_info_ex->BinaryData)
               				free(pchunk_info_ex->BinaryData);

				goto finish;
			}	

			chunk_start_pos = chunk_start_pos + pchunk_data->Size + 8;

			if (pchunk_info_ex->BinaryData)
                        	free(pchunk_info_ex->BinaryData);


		} else{
			/* 8 is the header size */
			chunk_start_pos = chunk_start_pos + pchunk_data->Size + 8;
		}

	}
finish:
	pdev->funcs_device_private.p_wh_send_commands(pdev, WH_CMD_FLASH_PROTECTION_ON, 0);

	if (pchunk_info_ex)
		free(pchunk_info_ex);

	return ret;
}

/* Given a reference (pointer to pointer) to the head
   of a list and an int, appends a new node at the end  */
int append_WIF2_flash_node(struct WIF2FlashNode **head_ref, WIF2_Flash_Space new_data)
{
	/* 1. allocate node */
	struct WIF2FlashNode *new_node =
		(struct WIF2FlashNode *)malloc(sizeof(struct WIF2FlashNode));
	if (!new_node)
		return 0;

	struct WIF2FlashNode *last = *head_ref; /* used in step 5*/

	/* 2. put in the data  */
	new_node->Space = new_data;

	/* 3. This new node is going to be the last node, so make next of
	it as NULL*/
	new_node->Next = NULL;

	/* 4. If the Linked List is empty, then make the new node as head */
	if (*head_ref == NULL) {
		*head_ref = new_node;
		return 0;
	}

	/* 5. Else traverse till the last node */
	while (last->Next != NULL)
		last = last->Next;

	/* 6. Change the next of last node */
	last->Next = new_node;
	return 1;
}

void free_WIF2_flash_node(WIF2FlashNode *pHead)
{
	WIF2FlashNode *pNode = pHead, *pNext;

	while (NULL != pNode) {
		pNext = pNode->Next;
		free(pNode);
		pNode = pNext;
	}
}

int do_update_fw_by_wif2_chunk_fsum(WDT_DEV *pdev, WIF_FILE2 *pcur_wif, UINT32 chunk_four_cc)
{
	if (!pcur_wif)
		return 0;

	if (!chunk_four_cc)
		return 0;
	int ret = 1;
	WIF2_Flash_Checksum_Chunk *pchunk_info_ex;
	pchunk_info_ex = (WIF2_Flash_Checksum_Chunk *)malloc(sizeof(WIF2_Flash_Checksum_Chunk));
	if (!pchunk_info_ex)
		return 0;

	UINT32 chunk_start_pos = 0 + sizeof(ChunkHeader);
	WIF2_Chunk_Header *pchunk_data = NULL;
	WIF2FlashNode *head = pchunk_info_ex->Spaces = NULL;

	while (chunk_start_pos < pcur_wif->data_len) {
		pchunk_data = (WIF2_Chunk_Header *)&pcur_wif->pdata[chunk_start_pos];

		/* we got it */
		if (pchunk_data->FourCC == chunk_four_cc) {
			pchunk_info_ex->Header.FourCC = pchunk_data->FourCC;
			pchunk_info_ex->Header.Size = pchunk_data->Size;

			UINT32 pdata_pos = chunk_start_pos + sizeof(WIF2_Chunk_Header);
			pchunk_info_ex->InitSum = get_unaligned_le32(&pcur_wif->pdata[pdata_pos]);
			pdata_pos = pdata_pos + sizeof(UINT32);
			pchunk_info_ex->ExpectedSum =
				get_unaligned_le32(&pcur_wif->pdata[pdata_pos]);
			pdata_pos = pdata_pos + sizeof(UINT32);
			int erase_count =
				(pchunk_data->Size - sizeof(UINT32) * 2) / (sizeof(UINT32) * 2);
			pchunk_info_ex->Spaces = NULL;

			for (int i = 0; i < erase_count; i++) {
				WIF2_Flash_Space data;
				data.Address = get_unaligned_le32(&pcur_wif->pdata[pdata_pos]);
				pdata_pos = pdata_pos + sizeof(UINT32);
				data.Size = get_unaligned_le32(&pcur_wif->pdata[pdata_pos]);
				pdata_pos = pdata_pos + sizeof(UINT32);

				append_WIF2_flash_node(&pchunk_info_ex->Spaces, data);
			}
			UINT32 sum = pchunk_info_ex->InitSum;
			head = pchunk_info_ex->Spaces;
			if (pchunk_info_ex->Spaces) {
				ret = pdev->funcs_device_private.p_wh_send_commands(
					pdev, WH_CMD_FLASH_UNLOCK, 0);
				if (!ret) {
					goto finish;
				}
				while (pchunk_info_ex->Spaces) {
					// printf("address:0x%x\n",
					// pchunk_info_ex->Spaces->Space.Address);
					// printf("size:0x%x\n",
					// pchunk_info_ex->Spaces->Space.Size);
					ret = pdev->funcs_device_private.p_wh_flash_get_checksum(
						pdev, &sum, pchunk_info_ex->Spaces->Space.Address,
						pchunk_info_ex->Spaces->Space.Size, sum);
					if (!ret) {
						goto finish;
					}
					pchunk_info_ex->Spaces = pchunk_info_ex->Spaces->Next;
				}
			}
			if (sum != pchunk_info_ex->ExpectedSum) {
				printf("Checksum fails. checksum is 0x%x but Expected 0x%x \n", sum,
				       pchunk_info_ex->ExpectedSum);

			} else {
				printf("Checksum psss! (0x%x)\n", sum);
			}

			chunk_start_pos = chunk_start_pos + pchunk_data->Size + 8;

		} else {
			/* 8 is the header size */
			chunk_start_pos = chunk_start_pos + pchunk_data->Size + 8;
		}
	}
finish:
	pchunk_info_ex->Spaces = head;


	if (pchunk_info_ex->Spaces) {
		free_WIF2_flash_node(pchunk_info_ex->Spaces);
	}

	if (pchunk_info_ex)
        	free(pchunk_info_ex);


	return 1;
}

int do_update_fw_by_wif2_chunk_fera(WDT_DEV* pdev, WIF_FILE2* pcur_wif, UINT32 chunk_four_cc)
{
    int ret = 1;
    if (!pcur_wif)
        return 0;

    if (!chunk_four_cc)
        return 0;

    WIF2_FlashErase_Chunk pchunk_info_ex;

    UINT32	chunk_start_pos = 0 + sizeof(ChunkHeader);
    WIF2_Chunk_Header* pchunk_data = NULL;

    while (chunk_start_pos < pcur_wif->data_len) {
        pchunk_data = (WIF2_Chunk_Header*)&pcur_wif->pdata[chunk_start_pos];

        /* we got it */
        if (pchunk_data->FourCC == chunk_four_cc)
        {
            pchunk_info_ex.Header.FourCC = pchunk_data->FourCC;
            pchunk_info_ex.Header.Size = pchunk_data->Size;

            UINT32	pdata_pos = chunk_start_pos + sizeof(WIF2_Chunk_Header);

            // Flash space to erase
            pchunk_info_ex.SpaceToErase.Address = get_unaligned_le32(&pcur_wif->pdata[pdata_pos]);
            pdata_pos = pdata_pos + sizeof(UINT32);
            pchunk_info_ex.SpaceToErase.Size = get_unaligned_le32(&pcur_wif->pdata[pdata_pos]);
            pdata_pos = pdata_pos + sizeof(UINT32);




            ret = pdev->funcs_device_private.p_wh_send_commands(pdev, WH_CMD_FLASH_UNLOCK, 0);
            if (!ret) {
                goto finish;
            }
            //address and size align to 0x100
            UINT32 protect_off_arg = (pchunk_info_ex.SpaceToErase.Address >> 8 << 16 & 0xffff0000) | (pchunk_info_ex.SpaceToErase.Size >> 8 & 0x0000ffff);

            ret = pdev->funcs_device_private.p_wh_send_commands(pdev, WH_CMD_FLASH_PROTECTION_OFF, protect_off_arg);
            if (!ret) {
                goto finish;
            }
            ret = pdev->funcs_device_private.p_wh_flash_erase(pdev, pchunk_info_ex.SpaceToErase.Address, pchunk_info_ex.SpaceToErase.Size);


            if (!ret) {
                goto finish;
            }

            chunk_start_pos = chunk_start_pos + pchunk_data->Size + 8;


        }
        else
            /* 8 is the header size */
            chunk_start_pos = chunk_start_pos + pchunk_data->Size + 8;




    }
finish:
    pdev->funcs_device_private.p_wh_send_commands(pdev, WH_CMD_FLASH_PROTECTION_ON, 0);




    return ret;
}



int do_update_fw_by_wif2_flow(WDT_DEV *pdev, WIF_FILE2 *pcur_wif)
{
	//do_update_fw_by_wif2_chunk_fera(pdev, pcur_wif,  FOURCC_ID_FERA);

	if (!do_update_fw_by_wif2_chunk_fbin(pdev, pcur_wif, FOURCC_ID_FBIN))
		return 0;

	if (!do_update_fw_by_wif2_chunk_fsum(pdev, pcur_wif, FOURCC_ID_FSUM))
		return 0;

	pdev->funcs_device_private.p_wh_send_commands(pdev, WH_CMD_RESET, 0);
	printf("Reset device ... \n");
	wh_sleep(2000);

	return 1;
}

int do_check_fw_by_wif2_flow(WDT_DEV *pdev, WIF_FILE2 *pcur_wif)
{
	if (!do_update_fw_by_wif2_chunk_fsum(pdev, pcur_wif, FOURCC_ID_FSUM))
		return 0;
	else
		return 1;

}



int do_show_wif2_info_chunk(WIF_FILE2* pcur_wif)
{
	if (!pcur_wif)
		return 0;
	WIF2_Info_Chunk* pchunk_info_ex;
	pchunk_info_ex = (WIF2_Info_Chunk*)malloc(sizeof(WIF2_Info_Chunk));
	if (!pchunk_info_ex)
		return 0;
	int ret =1;
	UINT32	chunk_start_pos = 0 + sizeof(ChunkHeader);
	WIF2_Chunk_Header* pchunk_data = NULL;

	while (chunk_start_pos < pcur_wif->data_len)
       	{
		pchunk_data = (WIF2_Chunk_Header*)&pcur_wif->pdata[chunk_start_pos];
		/* we got it */
		if (pchunk_data->FourCC == FOURCC_ID_INFO)
		{
			pchunk_info_ex->Header.FourCC = pchunk_data->FourCC;
			pchunk_info_ex->Header.Size = pchunk_data->Size;
			pchunk_info_ex->BinaryData = (BYTE*)malloc(pchunk_data->Size);
			if (!pchunk_info_ex->BinaryData){
				ret = 0;
				goto finish;
			}

			memcpy((BYTE*)pchunk_info_ex->BinaryData, (BYTE*)&pcur_wif->pdata[chunk_start_pos], pchunk_data->Size);
			for (size_t i = 0; i < pchunk_data->Size; i++)
				printf("%c", (unsigned char)(pchunk_info_ex->BinaryData[i]));
			printf("\n");
			
			chunk_start_pos = chunk_start_pos + pchunk_data->Size + 8;
                	if (pchunk_info_ex->BinaryData)
                        	free(pchunk_info_ex->BinaryData);


		}
		else
		{
			/* 8 is the header size */
			chunk_start_pos = chunk_start_pos + pchunk_data->Size + 8;
		}

	}
finish:
	if(pchunk_info_ex)
		free(pchunk_info_ex);

	return ret;
}

int show_wif2_info(char *path)
{
	WIF_FILE2 wif2;
        int ret;
        ret = get_wif2(path, &wif2);
        if (ret == 0) 
                goto finish;
	ret = do_show_wif2_info_chunk(&wif2);


finish:
        free_wif2(&wif2);
        return ret;

}



int update_fw_by_wif2(WDT_DEV *pdev, char *path)
{
	WIF_FILE2 wif2;
	int ret;
	ret = get_wif2(path, &wif2);
	if (ret == 0) {
		goto finish;
	}
	ret = do_update_fw_by_wif2_flow(pdev, &wif2);

finish:
	free_wif2(&wif2);
	printf("Operation done!\n");

	return ret;
}

int check_fw_by_wif2(WDT_DEV *pdev, char *path)
{
	WIF_FILE2 wif2;
	int ret;
	ret = get_wif2(path, &wif2);
	if (ret == 0) {
		goto finish;
	}
	ret = do_check_fw_by_wif2_flow(pdev, &wif2);

finish:
	free_wif2(&wif2);
	
	pdev->funcs_device.p_wh_close_device(pdev);
	printf("Operation done!\n");

	return ret;
}
