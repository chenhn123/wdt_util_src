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


---

## Example: Cross Compile for ARM64

Install the toolchain:

```
sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
```

Build:

```
make CROSS_COMPILE=aarch64-linux-gnu- CXX=aarch64-linux-gnu-g++
```

---

## Debug Build

To build with debugging symbols:

```
make CONFIG=debug
```


---

# Output Verification

You can verify the architecture of the generated binary using:

```
file wdt_util
```

Example output:

```
wdt_util: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV)
```


```
wdt_util:  ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)
```


---

# License

Weida Update Utility
Copyright 2026 Weida Hi-Tech Co., Ltd
http://www.weidahitech.com/

