# strongSwan Configuration #

本项目从 [strongSwan with GM](https://github.com/highland0971/strongswan-gmalg-merge) 项目的克隆而来，旨在使用 GmSSL 增加 SM 国密算法的支持。

原项目的 [README](README_GM.md) 在此。

```
git clone --depth 20 git@github.com:leonardodalinky/strongswan.git
```

SM 国密算法直接使用 GmSSL 库的 v3.0.0 版本，详情请见 [GmSSL](https://github.com/guanzhi/GmSSL/tree/v3.0.0) 的库说明。

## 开发构建方式

先确保库依赖已安装：
```
sudo apt update

sudo apt install build-essential cmake libtool autoconf gettext libcurl4-openssl-dev libtss2-dev gperf libgmp-dev libssl-dev bison flex pkg-config
```

构建前，先安装子模块 `GmSSL`:
```bash
mkdir GmSSL/build
cd GmSSL/build
cmake ..
make
sudo make install
```
如果使用 arch 系的 linux 发行版，可以在 AUR 源中直接安装 gmssl.

本次国密算法的开发构建方式，分为以下几步：
1. 运行 `autogen.sh` 文件，配置国密算法的开发环境
2. 运行 `dev_configure.sh`，配置国密算法的编译环境
   * 此脚本为 `configure` 的包装，指定各种输出目录，**建议各位亲自查看一下**
   * GmSSL 库直接链接到 strongswan 中，不打算使用 plugin 的形式添加
   * 由于 strongswan 采用 automake 进行自动构建，因此 GmSSL 库需要分别在所需要的模块中添加链接选项。
   例如在 `src/libipsec` 中需要 gmssl 库的话，在 `src/libipsec/Makefile.am` 的最末尾添加语句:
   ```
   AM_LDFLAGS += -lgmssl
   # 如果 `AM_LDFLAGS` 尚未定义过，则改为:
   # AM_LDFLAGS = -lgmssl
   ```
   * 目前在 `libipsec`、`libstrongswan`、`libcharon` 和 `libcharon/kernel_libipsec` 中的 `Makefile.am` 添加了 GmSSL 库的链接选项。
   * 每次在新的库的 `Makefile.am` 中增加 GmSSL 的编译选项后，需要从第 1 步重新开始。
   * 链接后，即可在 c 代码中使用 `#include <gmssl/...>` 的形式引用 GmSSL 库中的头文件。
3. 使用 `make -j4` 和 `make install`，将编译后的程序安装到 `dev` 文件夹中

## 使用方式

首先切换至 `dev` 文件夹中。

**Step 1**: 首先，运行 ipsec 服务
```bash
sudo sbin/ipsec start
```
使用 `--help` 选项可以查看帮助，例如 `stop` 选项可以关闭此服务。

**Step 2**: TODO，使用 `sbin/swanctl` 吧，但我还在研究这玩意

## GmSSL 使用指南

参考 [GmSSL 官方网站](http://gmssl.org/docs/docindex.html).