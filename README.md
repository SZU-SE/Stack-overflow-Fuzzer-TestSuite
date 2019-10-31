# Stack-overflow-Fuzzer-TestSuite

Stack-overflow testsuite used for fuzzing experiment

Seeds and POCs are in the folder

If you Cannot reproduce the bug, try to reduce the memory limit.
For example:
- `ulimit -a` to see the information of memory limit.
- `sudo ulimit -s 8192` or `sudo ulimit -s 4096` to reduce the stack size.
- `sudo ulimit -m 36700160` to reduce the memory size.

The detail information of the benchmark can be seen as follow.

### 1. [cxxfilt 2.31](./cxxfilt/README.md)
- Bug type: stack-overflow
- CVE ID: 
  - [CVE-2018-9138](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9138)
  - [CVE-2018-9996](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9996)
  - [CVE-2018-17985](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17985)
  - [CVE-2018-18484](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-18484)
  - [CVE-2018-18700](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-18700)
- Download:
    - [https://ftp.gnu.org/gnu/binutils/](https://ftp.gnu.org/gnu/binutils/)
- Reproduce: `c++filt -t < @@`

### 2. [nm 2.31](./nm/README.md)
- Bug type: stack-overflow
- CVE ID: 
  - [CVE-2018-12641](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12641)
  - [CVE-2018-17985](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17985)
  - [CVE-2018-18484](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-18484)
  - [CVE-2018-18700](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-18700)
  - [CVE-2018-18701](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-18701)
  - [CVE-2019-9070](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9070)
  - [CVE-2019-9071](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9071)


- Download:
    - [https://ftp.gnu.org/gnu/binutils/](https://ftp.gnu.org/gnu/binutils/)
- Reproduce: `nm -C @@`

### 3. [NASM 2.14.03rc1](./nasm/README.md)
- Bug type: stack-overflow
- CVE ID: 
  - [CVE-2019-6291](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6291)
  - [CVE-2019-6290](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6290)
  - [CVE-2018-1000886](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000886)
- Download:
  ```
  git clone git://repo.or.cz/nasm.git
  git checkout 81f98fe79be23174e2d6ddd9f17a5cfb9ca71ec7
  ```
- Reproduce: `nasm -f bin @@ -o ./tmp`

### 4. [mjs 1.20.1](./mjs/README.md)
- Bug type: stack-overflow
- CVE ID: 
  - [issue#58](https://github.com/cesanta/mjs/issues/58)
  - [issue#106](https://github.com/cesanta/mjs/issues/106)
- Download:
  ```
  git clone https://github.com/cesanta/mjs.git
  git checkout 2827bd00b59bdc176a010b22fc4acde9b580d6c2
  ```
- install:`clang mjs.c -DMJS_MAIN -fsanitize=address -g -o mjs.out -ldl`
- Reproduce: `mjs.out @@`
- ASAN dumps the backtrace:


### 5. [Flex 2.6.4](./flex/README.md)
- Bug type: stack-overflow
- CVE ID: 
  - [CVE-2019-6293](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6293)
- Download:
  ```
  git clone https://github.com/westes/flex
  git checkout 98018e3f58d79e082216d406866942841d4bdf8a
  ```
- Reproduce: `flex @@`


### 6. [Yaml-cpp 0.6.2](./yaml-cpp/README.md)
- Bug type: stack-overflow
- CVE ID: 
  - [CVE-2019-6292](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6292)
  - [CVE-2019-6285](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6285)
  - [CVE-2018-20573](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20573)
  - [CVE-2018-20574](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20574)
- Download:
  ```
  git clone https://github.com/jbeder/yaml-cpp
  git checkout cdbacf53a4ddac2bf1bc2f4bbe93fbe0a06bfff7
  ```
- Reproduce: `parse @@`


### 7. [Yara 3.5.0](./yara/README.md)
- Bug type: stack-overflow
- CVE ID: 
  - [CVE-2017-9438](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9438)
  - [CVE-2017-9304](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9304)
- Download:
  ```
  git clone https://github.com/VirusTotal/yara
  git checkout 012269756149ae99745b6dafefd415843d7420bb
  ```
- Reproduce: `yara @@ strings`

### 8. [Libsass 3.5.4](./libsass/README.md)
- Bug type: stack-overflow
- CVE ID: 
  - [CVE-2018-19837](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19837)
  - [CVE-2018-20821](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20821)
  - [CVE-2018-20822](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20822)
- Download:
  ```
  git clone https://github.com/sass/libsass
  git checkout 45f50873962b7d1c66bd115ba6e644bdaaf6cac1
  ```
- Reproduce: `tester @@`

### 9. [Libming 0.4.8](./libming/README.md)
- Bug type: stack-overflow
- CVE ID: 
  - [issue#81](https://github.com/libming/libming/issues/181)
- Download:
  ```
  git clone https://github.com/libming/libming
  git checkout b72cc2fda0e8b3792b7b3f7361fc3f917f269433
  ```
- Reproduce: `listswf @@ `
