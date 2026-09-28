# DFRoot —— SM-S938B（Galaxy S25 Ultra）适配版 · 快通道 + 手动

> [diabl0w/DFRoot](https://github.com/diabl0w/DFRoot) 的 fork，专门适配
> **三星 Galaxy S25 Ultra（SM-S938B / pa3q）**，界面与运行输出全部中文。
>
> 两条链路，一个界面：
>
> | 方案 | 漏洞 | 特点 |
> |---|---|---|
> | **快通道** | DirtyFrag（CVE-2026-43284） | 上游 DFRoot 那条，**几秒到几十秒** |
> | **手动** | CVE-2026-43499 | 概率型，三轮阶梯，最长十几分钟 |
>
> 默认「自动」：**先跑快通道**，它不成再自动接手动方案。

一句话：**开机自动获取 root**。每次开机先试几秒的快通道；不成的话，
自动接手动那条链路，按「快 → 稳 → 耐心」重试三轮。

拿到 root 之后还会自动跑两条 `cmd connectivity`（去掉三星「软件包安装程序」的广告），
命令、输出、退出码一样打在界面日志里 —— 见第五节「安装器广告设置」。
v1.8 起这两条命令会被写成 **KernelSU 的开机脚本**，以后每次开机由 KernelSU 自己以 root
执行，不用打开应用、也不用授权弹窗。

## v1.8 改了什么

* **开机后不再额外重启一次**：不再给 ksud 传 `--soft-reboot`。以前这个参数会让 ksud 装完
  之后重启一次系统框架 —— 用户看到的就是「开机之后又自己重启了一次」；更糟的是这次重启
  会把应用进程连同它正在跑的「安装器广告设置」一起打断；
* **安装器广告设置改成 KernelSU 开机脚本**：不再依赖应用在开机那一刻用 `su` 去跑
  （那时候 KernelSU 还没就绪，实机上每次开机都失败，必须手动打开 KernelSU 再打开应用
  才行）。现在把同样的两条命令写进 `/data/adb/service.d/dfroot-ads.sh`，KernelSU 每次开机
  都会以 root 执行它 —— **不经过应用、不经过 su、不需要任何授权弹窗**；
* **开机那一刻一次没成会自动重试**：交给前台服务在接下来 5 分钟里每 30 秒试一次，
  成功一次就收工（成功那次顺带把开机脚本装上）；
* 界面上多一行「开机脚本：…」，直接显示上一次脚本执行的结果。

## v1.7 改了什么

* 方案里的「**慢速**」改名「**手动**」，描述也跟着改：**自动不成功再手动尝试**；
* 新增「**安装器广告设置**」：拿到 root 后自动跑那两条 `cmd connectivity`，
  命令、输出、退出码全部打在界面日志里（**执行成功一定有输出**）；
* 每次开机、以及每次打开 App 都会检查一遍，没成功就补一次；
* 其它行为不变（快通道 + 手动方案 + 开机自动）。

---

## 一、两条链路各是什么

### 快通道：DirtyFrag（CVE-2026-43284）

上游 DFRoot 自带的那条，全部代码在 `app/src/main/jni/`（`exp.c` + 两段 shellcode +
`dirtyfrag-lkm/` 里的内核模块），编译成 `libexp.so` 由 App 直接调用：

1. 用 AES-CBC ESP 原地解密 + `splice()` 改掉只读文件的 page cache；
2. 把内核模块写进 `/vendor/lib64/libstagefrighthw.so` 再 `finit_module` 加载，
   把 SELinux 设成 permissive；
3. 挂钩 `libc.so` / `libc++.so`，借 `modprobe` 的域启动自带的 ksud，
   late-load KernelSU。

**快**（几秒），代价是它会在 `/dev/df` 留下"本轮已布防"的痕迹，
而且它的 ksud 安装路径和手动那条不一样（见第七节）。

### 手动：CVE-2026-43499

三个二进制都是预编译好的（逐字节未改）：

| 文件 | 位置 | 作用 |
|---|---|---|
| `libcve43499root.so` | `jniLibs/arm64-v8a/` | helper，可执行 ELF，App 直接 execve，**不需要 Shizuku** |
| `cve-2026-43499-app.so` | `assets/payloads/` | payload，由 helper dlopen 后执行漏洞 |
| `ksud-s25u-kdp` | `assets/payloads/` | KernelSU 本体（ksud + 内嵌 `kernelsu.ko`） |

```
1. helper --run-payload <payload> <helper> <log>   拿 root（概率型）
2. helper -c "cp ksud …"                           把 ksud 落到 /data/local/tmp
3. helper --late-load                              bind mount /system/bin/logcat，
                                                   再 exec "logcat late-load …" 装 KernelSU
```

成功判定：日志里同时出现 `exploit completed` 与 `done=1 root=1`。

界面上的「**手动**」方案跑的就是这条（「自动」方案在快通道不成时，也会接着跑它）。

---

## 二、自动模式怎么串（v1.5 加链路，v1.6 修开机自动，v1.7 加安装器广告设置，v1.8 修开机重启与广告设置）

```
手动点按钮（界面上）
   └─ 就在当前进程里跑：方案「自动」= 快通道 → 手动；方案「手动」= 直接手动

开机自动（BootReceiver，两次广播各来一遍）
   │
   ├─ 本轮已经拿到 root（已装凭据，或别的 root 还在）？
   │      ├─ 安装器广告设置还没做 → 补做一次，结束
   │      └─ 已经做过 → 跳过
   ├─ 前台服务正在跑 / 上一轮还没结束？ → 跳过
   │
   ├─ 第 1 步 · 快通道 DirtyFrag（几秒到几十秒，直接在广播里跑）
   │      ├─ 成功 → 第 3 步
   │      ├─ 失败但没留下痕迹（/dev/df 不存在）→ 继续第 2 步
   │      └─ 失败但已经布防（/dev/df 存在）→ 停止，提示重启手机
   │
   ├─ 第 2 步 · 手动方案 CVE-2026-43499（三轮阶梯，交给前台服务）
   │      ├─ 成功 → 第 3 步
   │      └─ 三轮都没成 → 本次不再折腾，等下次开机
   │
   └─ 第 3 步 · 安装器广告设置（两条 cmd connectivity，见第五节）
          ├─ 成功 → 顺手写成 KernelSU 的开机脚本（/data/adb/service.d/），以后每次开机自动执行
          └─ 没成功（还没解锁 / KernelSU 还没就绪）→ 前台服务每 30 秒重试一次，最多 5 分钟
```

> 「开机（未解锁）」那次广播**只跑快通道**：手动链路要把 ksud 落到
> `/data/local/tmp`，那是凭据加密存储，解锁前写不进去，跑了也是白跑。
> 所以手动链路等「开机完成」（用户解锁后）那次广播再跑。

### 开机自动为什么改成在广播里跑（v1.6 的修复）

v1.5 的开机自动是「收到广播 → 起前台服务，由服务去跑链路」，实机上**不生效**：
Android 12+ 限制后台应用启动前台服务，`LOCKED_BOOT_COMPLETED` 那一刻
`startForegroundService()` 会被系统直接拒掉，广播就静悄悄结束了 —— 开关是开的，
但什么都没发生。

v1.6 改回上游 DFRoot 的路子（它在实机上是验证过的）：**直接在广播里把快通道跑掉**，
并且做得更稳一点：

* `goAsync()` 保住进程：广播没结束，系统不会把这个进程当缓存进程回收；
* 最多等 45 秒，超时就放手（不把广播拖到超时），也不再叠加手动链路；
* 快通道没成再起前台服务跑手动链路；系统连前台服务也不让起，就发通知提醒手动运行；
* 每一步都写一笔 **`BootLog`**（设备加密存储），界面上那行「上次开机自动：…」
  直接显示最后一次结果 —— 显示「还没有记录」就说明开机广播压根没到。

**为什么布防后不接着跑手动方案**：两条链路都在内核里动手 —— 快通道会改 page cache、
加载内核模块把 SELinux 变成 permissive；这时候再叠一条概率型的漏洞，
是在一个已经"脏"的内核上再加一层不确定性。所以只要 `/dev/df` 出现，
就停下来让用户重启，而不是硬接。

### 手动方案的三轮阶梯

| 轮次 | 尝试次数 | 首次探测上限 | 单次上限 | 卡死判定 | 本轮上限 |
|---|---|---|---|---|---|
| 第 1 轮 · 快 | 6 | 20 s | 60 s | 40 s 没新日志 | 3 分钟 |
| 第 2 轮 · 稳 | 12 | 35 s | 100 s | 70 s 没新日志 | 8 分钟 |
| 第 3 轮 · 耐心 | 24 | 60 s | 180 s | 110 s 没新日志 | 15 分钟 |

* 每一轮都是**全新的 helper 进程**（随机性重新来过）；
* 但会**复用同一次开机里已经探测到的 KASLR 偏移**（日志里的
  `slide-kaslr-ok … slide=…`），省掉重复探测 —— 这个思路来自
  [polygraphene/DFReroot](https://github.com/polygraphene/DFReroot)；
* 参数在 `app/src/main/java/df/root/RmgChain.java` 的 `LADDER` 表里，想调直接改。

---

## 三、支持机型

| 机型 | 固件 | 内核 | 状态 |
|---|---|---|---|
| SM-S938B（Galaxy S25 Ultra，pa3q） | `BP4A.251205.006.S938BXXS9CZE1` | `6.6.98-android15-8-pe17667d-abogkiS938BXXS9CZE1-4k` | 两条链路都已适配 |

两条链路都**按内核版本匹配**（快通道靠 `android15-6.6` 的内核模块，
手动靠 6.6.98 的载荷）。换固件 / 换内核要换对应的内核模块与载荷。

App 启动时会把机型、固件、内核、KMI 和快通道需要的 6 条路径全部打出来。

---

## 四、编译

需要：**JDK 17+**、**Android SDK（platform 36 / build-tools 36.0.0）**。

**不需要 NDK**：`libexp.so` 是编译好的（随仓库提供），手动方案的三个二进制也是预编译的，
`app/build.gradle.kts` 里没有 `externalNativeBuild`。

```sh
export JAVA_HOME=/path/to/jdk-21
export PATH="$JAVA_HOME/bin:$PATH"
export ANDROID_HOME=/path/to/android-sdk

./create-keystore.sh                     # 生成 app/keystore.jks（已被 .gitignore 排除）
echo "sdk.dir=$ANDROID_HOME" > local.properties

./gradlew :app:assembleRelease
# → app/build/outputs/apk/release/dfroot.apk
```

或者直接 `./build.sh`，它会构建并复制成根目录下的 `dfroot.apk`。

> 想自己重编快通道的原生部分（`app/src/main/jni/`）：装 NDK 27.0.12077973，
> 在 `app/build.gradle.kts` 里加上 `ndkVersion` 与 `externalNativeBuild` 即可。
> 内核模块（`dirtyfrag-lkm/`）的重编需要 GKI DDK，见该目录下的 `build.sh`。

---

## 五、安装与使用

### 前置条件

装好 **KernelSU Manager**（`me.weishu.kernelsu`，v3.3.0）：
<https://github.com/tiann/KernelSU/releases/tag/v3.3.0>

### 步骤

1. 安装 APK（`adb install -r dfroot.apk`，或直接点安装）；
2. **先打开一次 App** —— 安卓要求应用至少启动过一次，才会在开机时收到广播；
3. 确认 KernelSU 管理器显示「未安装」（也就是当前没有 root）；
4. 方案保持「**自动**」，点下面的按钮，等输出「成功」；
5. 自动没成功时，切到「**手动**」再点一次 —— 手动那条是概率型的，多试几次命中率明显更高；
6. 拿到 root 后会自动跑「安装器广告设置」（两条 `cmd connectivity`，见下），
   并把它们写成 KernelSU 的开机脚本 —— 以后每次开机由 KernelSU 自己以 root 执行，
   不用打开应用，也不会再弹授权；
7. 「开机自动获取 Root」**默认已打开**，以后每次重启都会自动完成（不会再额外重启一次）；
8. 想让系统别拦着，去 **手机管家 / 电池 → 应用 → DFRoot**，设成「不受限制」并允许「自启动」。

方案只有两个：**自动**（先快通道，不成再手动）和**手动**（只跑 CVE-2026-43499）。
界面上的「上次开机自动：…」会显示上一次开机自动跑到哪一步。

> 第一次使用建议在**能充电、别乱动手机**的时候做：快通道几秒就有结果，
> 但手动那条最长可能跑十几分钟，中途别熄屏、别退出应用。
> 开机自动那一轮先跑快通道（几秒），要跑手动链路时才有前台服务通知。

### 安装器广告设置（拿到 root 后自动跑）

三星「软件包安装程序」的安装界面会拉广告。这两条命令本来是 adb 里手动敲的，
现在由 App 在**每次拿到 root 之后自动执行**：

```
cmd connectivity set-chain3-enabled true
cmd connectivity set-package-networking-enabled false com.samsung.android.packageinstaller
```

* 输出直接打在界面日志里：每条先打一行 `$ 命令`，接着是命令自己的输出，
  最后一行是 `→ 成功（exit 0，通道 …）` 这样的判定 —— **成功一定有输出**，
  没输出就是没跑成（日志里会写明原因）；
* 走哪条 root 通道是自动挑的：手动方案刚跑完时用 helper（自带 root，不用授权），
  其它情况用 KernelSU 的 `su`；
* **第一次成功之后，同样的两条命令会被写成 KernelSU 的开机脚本**
  `/data/adb/service.d/dfroot-ads.sh`：以后每次开机由 KernelSU 以 root 直接执行它，
  不用打开应用、不用 `su`、也不会弹授权；
* 开机那一刻应用自己那次可能失败（KernelSU 还没就绪）—— 这时前台服务会在接下来 5 分钟里
  每 30 秒重试一次，成功一次就收工；
* 同一次开机成功执行过就不再重复（应用侧的记录和开机脚本的记录都算）；没成功就留着，
  等下次开机广播、或下次打开 App 时再补一次；
* 这两条改的是系统运行期设置，**卸载 App 不会自动撤销** —— 想改回去就反向执行
  `cmd connectivity set-chain3-enabled false` 和
  `cmd connectivity set-package-networking-enabled true com.samsung.android.packageinstaller`。

### 应用内置的保护

| 状态 | 含义 |
|---|---|
| 状态：可以运行 | 当前没有 root，可以点按钮 |
| 状态：本轮已获取 Root | 同一次开机内已经装好了（用 `/proc/sys/kernel/random/boot_id` 记的凭据） |
| 本轮已布防（/dev/df 存在）… | 快通道已经动过手，需要硬重启才能再跑 |
| 检测到已有 root（… 存在）… | 别的 root 方案还在生效 |

为什么要拦住"已经有 root 时再跑"：这时 ksud 会跳过加载内核模块、停在
`vendor_modprobe` 域，"完成安装"那一步会失败，还可能把 `/system/bin/su`
截成 0 字节 —— 结果是模块还在、`su` 却用不了。重启一次即可恢复。

---

## 六、卸载 / 回退

1. 关掉「开机自动获取 Root」开关；
2. `adb uninstall df.root`（或系统设置里卸载）；
3. 重启手机，回到"无 root"状态。

两条链路都**不写任何分区、不改 boot、不动 `/data/system/packages.xml`**，
所以回退就是卸载 + 重启。

---

## 七、常见问题

**Q：为什么 root 经常失败，但多试几次又能成功？**
手动那条（CVE-2026-43499）要抢一个内核里的**竞态**（把页表项从"指向自己的页"
换成"指向目标页"），而且要先猜中本次开机的 **KASLR 偏移**，两者都是概率事件：
偏移猜错就白跑一轮，竞态窗口很窄、调度一抖就错过。所以单次成功率天然不是 100%，
但**每次尝试是独立的**，多试几次成功率明显上升。
这一版把它自动化了：先试快通道（几乎不靠运气），不行再自动跑手动方案的三轮阶梯，
并且记得住本次开机已经猜中的偏移。自动那一轮没成，就切到「**手动**」再点一次 ——
那只是同一条链路再来一轮，多试几次命中率明显更高。

**Q：快通道成功了，但 `adb shell` 里 `su` 还是 2000？**
两条链路都不给 ksud 传 `--allow-shell`（上游默认，也是手动那条的行为）。
普通 App 申请 root 走 KernelSU 管理器的授权弹窗，正常可用。

**Q：快通道失败之后为什么要重启，不能直接接着跑手动方案吗？**
如果快通道**已经布防**（`/dev/df` 出现，说明内核模块已加载、SELinux 可能已经
permissive），这时内核状态是"半成品"，再叠一条概率型漏洞会放大风险。
如果它**没留下痕迹**，本 fork 就会自动接着跑手动方案 —— 只有布防了才停下来。

**Q：root 拿到了，重启后没了？**
KernelSU 是 late-load 进内存的，bootloader 锁定的机器没法把它写进 boot 分区，
所以每次开机都要重新装一遍 —— 这正是「开机自动获取 Root」存在的原因。

**Q：为什么以前开机之后还会自己再重启一次？**
那是 ksud 的 `--soft-reboot`：装完之后它会把系统框架重启一次，好让新装上的 KernelSU
立刻生效。v1.8 起不再传这个参数，开机就只是一次正常开机。代价是 KernelSU 管理器可能
要你自己再打开一次才会刷新状态，重启一次手机也能达到同样效果。

**Q：安装器广告设置为什么以前必须「先打开 KernelSU 再打开 App」？**
开机那一刻 KernelSU 的 `su` 还没就绪（管理器没起来，授权弹窗也弹不出来），应用自己去跑
必定失败。v1.8 把那两条命令改成 KernelSU 的开机脚本（`/data/adb/service.d/`），
由 KernelSU 自己以 root 执行，跟应用和授权都无关 —— 开机必定执行。

**Q：开了「开机自动获取 Root」，重启后却什么都没发生？**
先看界面上那行「上次开机自动：…」：

| 显示 | 说明 |
|---|---|
| 还没有记录 | 开机广播没到。多半是系统把应用冻住了 —— 去 手机管家 / 电池 → 应用 → DFRoot，设成「不受限制」并允许「自启动」；另外应用必须**至少启动过一次**，没启动过的应用收不到开机广播 |
| 收到广播，开始跑快通道 → … | 广播到了，后半句就是结果（走通 / 没成 / 已布防 / 交给前台服务） |
| 本轮已有 root，补安装器广告设置 → … | 本轮已经有 root，只去补那两条 `cmd connectivity` |
| 跳过：本轮已经获取过 Root | 本轮已经搞定，什么也不用做 |

也可以 `adb logcat -s dfroot` 看运行日志。

**Q：会不会变砖？**
不会。两条链路都只在内存 / page cache 里动手，重启即还原；不写分区、不改 boot。

**Q：为什么没做 DFReroot 那种"持久化"（写 `packages.xml`、让 App 以 system UID 运行）？**
那种做法要**永久修改系统数据库** `/data/system/packages.xml`，写坏会导致无限重启，
而且它是服务于 DirtyFrag 那条链路的。这里用更保守的办法达到同样效果：
每次开机自动跑 + 自动重试。

---

## 八、本 fork 相对上游改了什么

上游：[diabl0w/DFRoot](https://github.com/diabl0w/DFRoot)。

| 改动 | 内容 |
|---|---|
| 中文化 | 界面、状态、运行日志（`strings.xml` + 各 Java 类） |
| 启动自检 | `DeviceCheck`：机型 / 固件 / 内核 / KMI + 快通道的 6 条必需路径 |
| 快通道封装 | `FastChain`：把上游的 DirtyFrag 链路抽成一个可复用的调用，并区分"没成"与"已布防" |
| **手动方案** | `RmgChain`：CVE-2026-43499（helper + payload + ksud，预编译二进制），三轮阶梯 + KASLR 偏移缓存 |
| **自动串联** | `MainActivity` / `RmgService` / `BootReceiver`：快通道优先，不成再自动接手动方案；布防后不叠加 |
| **开机自动在广播里跑** | v1.6 修复：快通道由 `BootReceiver` 用 `goAsync()` 直接跑（不再依赖前台服务能不能起），手动链路才交给 `RmgService` |
| **安装器广告设置** | v1.7 新增：`PostRoot` —— 拿到 root 后自动跑两条 `cmd connectivity`（去三星安装器广告），命令 / 输出 / 退出码全部进日志 |
| **开机脚本通道** | v1.8 新增：`BootScript` —— 成功之后把那两条命令写成 `/data/adb/service.d/dfroot-ads.sh`，KernelSU 每次开机以 root 执行，不依赖应用和授权弹窗 |
| **不再软重启** | v1.8 修复：`FastChain` 固定不给 ksud 传 `--soft-reboot`（开机后不会再额外重启一次） |
| **补设置重试** | v1.8 新增：`RmgService` 的补设置模式，开机后每 30 秒重试一次，最多 5 分钟 |
| 开机自动默认打开 | `BootReceiver` 监听 `LOCKED_BOOT_COMPLETED` + `BOOT_COMPLETED`，`directBootAware` |
| 开机诊断 | `BootLog`：每一步写一笔（DE 存储），界面上显示「上次开机自动：…」 |
| 凭据 / 缓存 | 用 `boot_id` 记"本轮已装好"；缓存本次开机的 KASLR 偏移 |
| 构建 | `versionCode 10` / `versionName 1.8-s938b-rmg` |

历史版本（v1.1 / v1.1.1 的 DirtyFrag 适配过程与实机日志）见 [PORTING.md](PORTING.md)。

---

## 九、致谢与许可

- 上游项目与快通道（DirtyFrag）：[diabl0w/DFRoot](https://github.com/diabl0w/DFRoot)、[lsposed/lspromise](https://github.com/lsposed/lspromise)
- SELinux permissive 内核模块与重试思路：[polygraphene/DFReroot](https://github.com/polygraphene/DFReroot)
- 非特权 XFRM socket 方法：[combeng6th/DirtyInit](https://github.com/combeng6th/DirtyInit)
- KernelSU：[tiann/KernelSU](https://github.com/tiann/KernelSU)

> [!WARNING]
> 仅用于你本人拥有或已获明确授权的设备。作者不对任何设备损坏负责。
