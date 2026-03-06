# wdt_util_src

A Linux utility used to operate Weida controllers for retrieving device information and upgrading firmware.

---

# Build Instructions

Clone or download the entire project and enter the project directory:

```
cd wdt_util_src
```

## Build (Native)

Compile the project on the host machine:

```
make
```

This will generate the executable:

```
wdt_util
```

## Clean Build Files

Remove all generated objects and binaries:

```
make clean
```

---

# Cross Compilation

This project supports cross compilation using the `CROSS_COMPILE` variable.

The variable should contain the **toolchain prefix**.

Example format:

```
<toolchain-prefix>gcc
<toolchain-prefix>g++
```

---

## Example: Cross Compile for ARM (32-bit)

Install the ARM toolchain:

```
sudo apt install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
```

Build the project:

```
make CROSS_COMPILE=arm-linux-gnueabihf-
```

---

## Example: Cross Compile for ARM64

Install the toolchain:

```
sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
```

Build:

```
make CROSS_COMPILE=aarch64-linux-gnu-
```

---

## Debug Build

To build with debugging symbols:

```
make CONFIG=debug
```

Cross compile with debug symbols:

```
make CONFIG=debug CROSS_COMPILE=arm-linux-gnueabihf-
```

---

# Output Verification

You can verify the architecture of the generated binary using:

```
file wdt_util
```

Example output:

```
wdt_util: ELF 32-bit LSB executable, ARM
```


---

# License

Weida Update Utility
Copyright 2026 Weida Hi-Tech Co., Ltd
http://www.weidahitech.com/

