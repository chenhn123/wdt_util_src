# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

## [Unreleased]

## [0.9.17] - 2025-05-19
### Added
- Add initialize to *dir.
- Add support for the secondary firmware update on W8752 dual-partition devices.

### Changed
- Modify FW_WDT8755_ISP Macro.

### Removed
- Remove Macros OPTION_DES, OPTION_ERR_RTN, OPTION_FASTBOOT and OPTION_FORCE_ACT.

## [0.9.16] - 2024-12-30

### Added
- Add a message for open device failed.

### Changed
- Fix misr_for_halfwords checksum if start not zero.
- Fix indent.
- Modify misr_16b declare type.
- Use 2 byte to check device type if fwid > 0x50000000.
- Replace FW_LEGACY with FW_NOT_SUPPORT.


### Removed
- Remove cal_checksum function.
- Remove cmd unprotect 512k from w8760/w8790 device.
- Remove get_indexed_string api.
- Remove remove erase all command in w8760 device.
- Remove the read hid prameter twice in w87555 device.

### Fixed
- I2C_HID_DESC not packed issue.
- Remove the timeout message in the -v command that caused the script parsing issue.


## [0.9.15] - 2024-01-19
### Added
- Add definition hid_desc_reg_offset.
- Add message hint when open wif2 file fail.
### Changed
- Use 4k checksum to replace the checksum in wif2 when burning firmware.
### Removed
- Remove the definition of bootloader mode.


## [0.9.14] - 2023-09-15
### Added
- Support multiple from ACPI table.
- Support scan WEIDA device form i2c_hid_of path.
- Support WIF2 FOURCC_ID_FERA feature.
- Add CHANGELOG.md
### Changed 
- Changed print message Platform id name to  Platform_id. 

### Removed 
- Remove wdt_util.query.policy.
- Remove wdt_util.update.policy.
- Remove  unused struct W8760_WRITE_DATA,  W8760_REQ_READ, W8760_READ_DATA
- Remove  unused function wh_w8790_dev_flash_block_write
- Remove  sub_argu in EXEC_PARAM
- Remove  FOURCC_ID_FCRC
### Security
- Add workaround for hardware reset.


