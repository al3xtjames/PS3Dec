# PS3Dec
An alternative ISO encryptor/decryptor for PS3 disc images by red_meryl,
originally posted on the [k3y forums](https://web.archive.org/web/20140326142553/http://k3yforums.com/viewtopic.php?f=31&t=10460).

This is a slightly modified version of PS3Dec r5, using statically-linked
mbedTLS for AES encryption/decryption and CMake as the build system.

### Original README
```
PS3Dec r5
---
Encrypt/Decrypt a PS3 disc image. Supports original images (if user supplies
the key) and 3k3y images.

Usage: PS3Dec <mode> <type> [type_op] in [out]

If out is not defined, name is in.something, as appropriate

<mode>: 'd' for decrypt
        'e' for encrypt
<type>: "3k3y" for a 3k3y image (requires no type_op)
        "d1"   says type_op is d1 in hex form (32 char ascii) BEFORE
               it's been processed into the actual decryption key
        "key"  says type_op is the actual key in hex form (32 char
               ascii), aka d1 AFTER it has been processed, aka disc_key
---
Changes since r4:
*type renamed: "hex" to "d1"
*type added  : "key", the actual disc_key used to crypt
*type removed: "file", there's no standardised file format as yet. Until there
               is (if there is), this stays removed
*Can now compile elf 32bit
```

### Dependencies
#### Windows
 - Visual Studio 2017 (with Visual Studio C++ tools for CMake installed)

#### *nix
 - A compiler with OpenMP support
 - CMake
 - [Ninja](https://ninja-build.org/) (optional)

On macOS, libomp must be installed (available in Homebrew).

### Compilation
#### Windows
1. `git clone --recurse-submodules https://github.com/al3xtjames/PS3Dec`
2. In Visual Studio: Select `File > Open > CMake...` and open
   PS3Dec/CMakeLists.txt
3. Change the current configuration to `x64-Release`
4. Select `Build > Build Current Document (CMakeLists.txt)`
5. Select `CMake > Cache > Open Cache Folder (x64-Release Only) > PS3Dec`
6. Run the PS3Dec binary (`RelWithDebInfo\PS3Dec.exe`)

#### *nix
1. `git clone --recurse-submodules https://github.com/al3xtjames/PS3Dec && cd PS3Dec`
2. `mkdir build && cd build`
3. `cmake -G Ninja .. && ninja` if Ninja is installed; otherwise,
   `cmake .. && make`
4. Run the PS3Dec binary (`Release/PS3Dec`)

### Credits
 - [ARMmbed](https://github.com/ARMmbed) for [mbedTLS](https://github.com/ARMmbed/mbedtls)
 - red_meryl for writing the software
