# NERVA

Copyright (c) 2021 The NERVA Project.   
Copyright (c) 2014-2021 The Monero Project.   
Copyright (c) 2017-2018 The Masari Project.   
Portions Copyright (c) 2012-2013 The Cryptonote developers.



## License

See [LICENSE](LICENSE).



## Compiling Nerva from source
Nerva can be compiled by running build script inside `nerva/builder/`

By default, it checks if your processor has AES support and builds based on that.  It calls default() function.  There is also release() function that creates both AES and non-AES files.  If you'd like to use that, call it at the end of build script instead of default function.

In the same build directory, there is also environment script file that controls some aspects of the build.  By default, it will build in Release mode and will not build extras.  You can change that behavior by editing those flags so to build extras, change the flag from OFF to ON: `BUILD_EXTRAS=ON`.

If you run default build, files are created under: `nerva/build/output/windows/release/bin/`

If you run production build, files are created under: `nerva/build/output/`. Those files are automatically zipped so you need zip:   
Linux: `sudo apt install zip`
Windows: `pacman -S zip`



## Compiling on Linux

### Install dependencies on Debian/Ubuntu:
```bash
sudo apt update && sudo apt install build-essential cmake pkg-config libboost-all-dev libssl-dev libzmq3-dev libpgm-dev libunbound-dev libsodium-dev
```

### Build on Linux
```bash
git clone --recursive https://github.com/nerva-project/nerva.git
```
This will create `nerva` directory.

If you'd like to clone specific branch, add `--branch github-branch-name` at the end of above git command

```bash
cd nerva/builder
```
```bash
./build
```



## Compiling on Windows

### Install MSYS2
Install MSYS2 (Software Distribution and Building Platform for Windows):   
[MSYS2 Website][msys2-link]

Open MSYS2 Shell and run below to update:
```bash
pacman -Syu
```

### Install dependancies
You'll need below dependencies to build nerva.  Run command for your target Windows version.   
Windows 64-bit:
```bash
pacman -S mingw-w64-x86_64-toolchain make mingw-w64-x86_64-cmake mingw-w64-x86_64-boost mingw-w64-x86_64-openssl mingw-w64-x86_64-zeromq mingw-w64-x86_64-libsodium mingw-w64-x86_64-hidapi mingw-w64-x86_64-unbound git
```

Windows 32-bit:
```bash
pacman -S mingw-w64-i686-toolchain make mingw-w64-i686-cmake mingw-w64-i686-boost mingw-w64-i686-openssl mingw-w64-i686-zeromq mingw-w64-i686-libsodium mingw-w64-i686-hidapi mingw-w64-i686-unbound git
```

### Build on Windows
In MSYS2 shell, go to directory where you want to clone nerva (ex: `/c/msys64/usr/local`) and clone repository:
```bash
git clone --recursive https://github.com/nerva-project/nerva.git
```
This will create `nerva` directory.

If you'd like to clone specific branch, add `--branch github-branch-name` at the end of above git command

Run build process:
```bash
cd nerva/builder
```
```bash
./build
```



## MacOS
Instructions coming soon.



## Help Me!

[GitHub docs][nerva-docs-link] is your friend, or head to [Discord][nerva-discord-link] to talk to a person.



<!-- Reference links -->
[nerva-discord-link]: https://discord.gg/jsdbEns
[nerva-docs-link]: https://docs.nerva.one
[msys2-link]: https://www.msys2.org