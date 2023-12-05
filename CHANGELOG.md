# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)


## [Unreleased]
### Added
- Add definition hid_desc_reg_offset.
- Add message hint when open wif2 file fail. 
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


