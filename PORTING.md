# DFRoot → SM-S938B (Galaxy S25 Ultra) 适配记录

适配日期：2026-09-26　设备：SM-S938B / BP4A.251205.006.S938BXXS9CZE1 / 内核 6.6.98-android15-8-pe17667d-abogkiS938BXXS9CZE1-4k

---

> **2026-09-27 更新（v1.8）**：v1.8 修掉两个开机自动的老毛病 ——
> ① 开机后不再额外重启一次：`FastChain` 固定不给 ksud 传 `--soft-reboot`
> （本文第 7 节记录的「设备短暂掉线、ksud 重启框架」就是它，现在没有了）；
> ② 安装器广告设置不再依赖「先打开 KernelSU 再打开 App」：成功后把两条
> `cmd connectivity` 写成 KernelSU 的开机脚本 `/data/adb/service.d/dfroot-ads.sh`，
> 每次开机由 KernelSU 以 root 执行（`BootScript`）；开机那一刻一次没成就交给
> 前台服务每 30 秒重试，最多 5 分钟（`RmgService` 的补设置模式）。
>
> **2026-09-27 更新（v1.7）**：v1.7 把方案里的「慢速」改名为「**手动**」（描述改成
> 「自动不成功再手动尝试」），并新增**安装器广告设置** —— 拿到 root 后自动跑两条
> `cmd connectivity`（去掉三星安装器的广告），命令 / 输出 / 退出码全部写进日志，
> 每次开机和每次打开 App 都会补一次。
>
> **2026-09-27 更新（v1.6）**：v1.6 修好了开机自动 —— 快通道不再经过前台服务，
> 而是由 `BootReceiver` 用 `goAsync()` 直接在开机广播里跑（前台服务只用来跑手动链路），
> 并把每一步写进 `BootLog`（界面显示「上次开机自动：…」）。
> 另外界面方案简化为「自动 / 手动」两项。
>
> 下面这段是 **v1.5** 的说明。本文件记录的是 **v1.1 / v1.1.1 的 DirtyFrag
> （CVE-2026-43284）适配过程与实机日志**，保留下来作为历史参考。
> 从 v1.5 起，DirtyFrag 作为**快通道**和手动方案 CVE-2026-43499 并存：
> 自动模式下先跑快通道，不成再自动接手动方案（布防过则不叠加）。
> 代码结构见 [README.md](README.md)：快通道在 `FastChain` + `app/src/main/jni/`，
> 手动方案在 `RmgChain`。
> 下面关于 `/dev/df`、ksud 参数（`--stage-from` / `--ro-partitions` /
> `--soft-reboot`）、`--allow-shell` 的内容说的是 v1.1.x 那版快通道的细节，
> 现在依然适用（快通道用的就是同一套 `libc.S` / ksud）。

## 1. 改了什么

基于上游 `diabl0w/DFRoot`（无 release，需自行构建）。

| 文件 | 改动 |
|---|---|
| `app/src/main/java/df/root/DeviceCheck.java` | **新增**。启动前自检：机型/固件/内核 release/KMI + 6 个必需路径是否齐全；不齐就拒绝动手，避免"patch 到一半失败" |
| `app/src/main/java/df/root/MainActivity.java` | 手动运行时先打印自检报告，critical 不通过就中止 |
| `app/src/main/java/df/root/BootReceiver.java` | 开机自动运行时同样先自检 |
| `app/build.gradle.kts` | 显式 `ndkVersion = 27.0.12077973`；`versionCode=2`，`versionName="1.1-s938b"` |
| `app/keystore.jks` | 新生成的签名（DFRoot 不用 sharedUserId，签名可随意） |

**ksud 保持上游原样**（未替换）。原因见第 3 节。

产物：`dirtyfrag-s938b.apk`（14 806 865 B，包名 `df.root`，versionName `1.1-s938b`）

---

## 2. 实机测试结果（2026-09-26 09:41，手动运行）

### ✅ 成功：整条 DirtyFrag 链在你的机器上跑通了

自检输出：

```
* device: samsung SM-S938B (pa3q)
* build : BP4A.251205.006.S938BXXS9CZE1
* kernel: 6.6.98-android15-8-pe17667d-abogkiS938BXXS9CZE1-4k
* kmi   : android15-6.6
* paths: all 6 required paths present
* profile: exact match (BP4A.251205.006.S938BXXS9CZE1)
```

落位标记全部出现（`/dev/df` `dfm0` `dfm2` `dfm3` `dfm6`），即：

1. `crash_dump64` page-cache 改写成功（DirtyFrag 原语可用 → **CVE-2026-43284 在这台机器的内核里仍然存在**）
2. `dirtyfrag-android15-6.6.ko` 写进 `libstagefrighthw.so` 并 `finit_module` **加载成功** → 印证了报告第 0 节的结论（vermagic 版本号确实被忽略）
3. libc `__libc_init` / libc++ ostream sentry 挂钩成功，孤儿进程触发 modprobe 成功
4. **`getenforce` 变成 `Permissive`** —— LKM 生效
5. ksud 以 `uid=0`、`context=u:r:vendor_modprobe:s0` 启动成功

ksud 侧日志证明参数全部被正确解析（DFRoot 自带 ksud 的 CLI 与 shellcode 完全匹配）：

```
ksud::cli: command: LateLoad { magica: None, allow_shell: false, post_magica: false,
  kmi: None, package_name: "me.weishu.kernelsu",
  stage_from: "/data/system/ksud", soft_reboot: false, ro_partitions: true }
ksuinit: KernelSU version: 32601
ksud::late_load: KernelSU already loaded, skip loading ko
ksud::cli: set 15 partition(s) read-only
```

### ⚠️ 两个副作用（都因为"在已经 root 的状态下跑"）

1. **KernelSU 安装步骤失败**：`Failed to extract assets: Operation not permitted`。
   因为模块已加载，ksud 跳过了 `load ko`，于是没有切到 `u:r:ksu:s0` 域，仍在
   `vendor_modprobe` 域里往 `/data/adb` 写资源 → 被 DEFEX/SELinux 拒。
   **干净开机时不会有这个问题**（会先加载模块、切域，再安装）。
2. **`/system/bin/su` 被截成 0 字节**，当前 root 失效。
   正是 `Root-My-Galaxy-Payloads/kernelsu/README.md` 里记录的
   "Late-load could not write a new /data/adb/ksud ... The failed destination remained a zero-byte file"。
   KernelSU 内核模块**仍在加载状态**（`/proc/modules` 里 `kernelsu ... Live`），但 `su` 无法执行。
   **重启即可清除该状态，再用 Root-My-Galaxy 重新拿一次 root 就会恢复。**

> 另外 SELinux 目前是 Permissive、`/dev/df` 挂钩已布防，两者都会在重启后自动清除。

---

## 3. 为什么没有换成 Root-My-Galaxy 的 ksud

一开始打算把 `assets/ksud` 换成 `Root-My-Galaxy-Payloads/kernelsu/ksud-s938b-cze1-kdp`，
但在设备上实测 `ksud late-load --help` 后发现 **CLI 不兼容**：

| 参数 | DFRoot 自带 ksud | RMG 的 `ksud-s938b-cze1-kdp` |
|---|---|---|
| `--package-name` | ✅ | ✅ |
| `--kmi` | ✅ | ✅ |
| `--stage-from` | ✅ | ❌ |
| `--soft-reboot` | ✅ | ❌ |
| `--ro-partitions` | ✅ | ❌ |

DFRoot 的 `libc.S` 固定传 `--stage-from` `--ro-partitions`（开机流程还要 `--soft-reboot`），
换成 RMG 的 ksud 会直接参数解析失败。而 `--soft-reboot` 是**开机自动恢复 root 的关键**：
开机时加载模块后必须软重启框架，KernelSU 的 post-fs-data / service 模块才会生效。

另一个考虑：DFRoot 自带 ksud 报 `ksud 932014a`，与 RMG 为 S938B 构建所依据的
KernelSU v3.3.0 commit `932014ab...` **是同一个**；且 DFRoot 只面向三星锁 BL 设备，
其 README 把 android16-6.12 标为已实机验证 —— 通用 GKI 模块在三星上必崩，所以它的内嵌模块
必然是做过三星 KDP 适配的。

**结论：先用自带 ksud。** 若干净开机测试仍在内核模块加载阶段失败，再回来改 `libc.S` 适配 RMG 的 CLI。

---

## 4. 下一步（待执行）

1. 重启手机（清除 Permissive / `/dev/df` / 0 字节 su）
2. 打开 DFRoot → 先**手动**点一次 "Launch Root"，观察是否走完到 KernelSU 加载完成
3. 成功后再打开 "Start at Boot" 开关，重启验证开机自动恢复

---

## 5. 构建方法（可复现）

本机没有 Java/SDK，已装到 `/Users/yuqi/Documents/dsh/toolchain/`：

```sh
export JAVA_HOME=/Users/yuqi/Documents/dsh/toolchain/jdk21/Contents/Home
export PATH="$JAVA_HOME/bin:$PATH"
export ANDROID_HOME=/Users/yuqi/Documents/dsh/toolchain/sdk
cd /Users/yuqi/Documents/dsh/DFRoot-S938B
./gradlew :app:assembleRelease
# → app/build/outputs/apk/release/dirtyfrag.apk
```

（JDK 21 Temurin + cmdline-tools + platform 36 + build-tools 36.0.0 + NDK 27.0.12077973）


---

## 6. 干净开机后的完整测试（2026-09-26 09:45）

重启后状态干净：`Enforcing`、无 `/dev/df`、KernelSU 未加载、无 su（确认 root 是 per-boot）。

手动点 "Launch Root" 后，**整条链完整走通**：

```
ksud::late_load: [late-load start] pid=16221, uid=0, selinux=u:r:vendor_modprobe:s0
ksud::late_load: Detected KMI: android15-6.6
ksud::late_load: Loading kernelsu.ko for KMI android15-6.6...
ksud::late_load: kernelsu.ko loaded successfully!            ← 关键
ksud::late_load: [after load_module] pid=16221, uid=0, selinux=u:r:ksu:s0   ← 域切换成功
ksud::module: load policy: /data/adb/modules/zygisksu/sepolicy.rule
ksud::module: exec /data/adb/modules/zygisk_lsposed/post-mount.sh
ksud::module: exec /data/adb/service.d/asteriskng_start.sh
ksud::module: exec /data/adb/modules/zygisksu/service.sh
ksud::module: exec /data/adb/modules/zygisk-sui/service.sh
ksud::module: exec /data/adb/modules/m_rcq/service.sh
ksud::module: exec /data/adb/modules/wifi-force-country/service.sh
ksud::module: exec /data/adb/modules/galaxy_root_secure/service.sh
ksud::cli: set 15 partition(s) read-only
```

KernelSU Manager 显示：

```
LKM  工作中 [越狱模式]
版本：32601-2        管理器 v3.3.0 (32601-2)
内核版本 6.6.98-android15-8-pe17667d-abogkiS938BXXS9CZE1-4k
SELinux 状态 强制执行
8 超级用户 / 7 模块
```

**结论：DFRoot 自带的内嵌 android15-6.6 KernelSU 模块在 S938B 上完全可用，没有 panic。
之前担心的"通用 GKI 模块会崩"在这里不成立。**

### 仍未解决：`su` 入口点

* `/system/bin/su` 不存在，`adb shell su` 报 not found；
* 用 `/data/local/tmp/su`（任意以 su 命名的文件会被 KernelSU 重定向到 ksud）能执行，
  但返回 `uid=2000`，未提权；
* 对比：Root-My-Galaxy 的流程会留下一个真实的 `/system/bin/su`（4 892 712 B）。

**推测**：DFRoot 的 `libc.S` 在 exec ksud 之前做了
`unshare(CLONE_NEWNS)` + `mount --make-rprivate /`（为绕过 DEFEX 而把
`/dev/.ksud` bind mount 到 `/system/bin/logcat`），ksud 因此在一个**私有 mount namespace**
里运行，它往 `/system` 写的东西不会出现在全局命名空间；而 `/system` 本身是 EROFS。
Root-My-Galaxy 的流程不做这层 unshare，所以它的 `su` 能落地。

**待验证**：开机流程会多传一个 `--soft-reboot`（手动运行时不传），
有可能在那一步才完成 su 的安装。所以下一步值得直接测开机自动恢复。



---

## 7. 开机自动恢复测试（2026-09-26 09:52，成功）

打开 DFRoot 的 **Start at Boot** 开关（注册 `LOCKED_BOOT_COMPLETED` + `BOOT_COMPLETED`），重启后：

```
09:52:52.986 I/dfroot: boot: android.intent.action.LOCKED_BOOT_COMPLETED
09:52:52.987 I/dfroot: preflight (boot)   → 6 条路径齐全、profile exact match
09:52:53.064 I/dfroot: * ko android15-6.6 (5656 bytes)
09:52:53.073 I/dfroot: patched 1312 bytes to /apex/.../crash_dump64+0x0
09:52:53.620 I/dfroot: patched 5664 bytes to /vendor/lib64/libstagefrighthw.so+0x0
09:52:53.627 I/dfroot: patched 1728 bytes to /system/lib64/libc.so+0xe87c0
09:52:53.635 I/dfroot: patched 352 bytes to /system/lib64/libc++.so+0x105138
09:52:55.815 I/dfroot: libc++: mutex acquired, forking
09:52:55.886 I/dfroot: success: ksud launched
...
09:52:57.220 I/KernelSU: ksud::module: exec /data/adb/modules/zygisksu/post-fs-data.sh
09:52:57.375 I/KernelSU: ksud::module: exec /data/adb/modules/zygisk_lsposed/post-fs-data.sh
09:52:57.431 I/KernelSU: ksud::module: exec /data/adb/service.d/asteriskng_start.sh
09:52:57.455 I/KernelSU: ksud::module: exec /data/adb/modules/zygisksu/service.sh
09:52:57.485 I/KernelSU: ksud::module: exec /data/adb/modules/zygisk-sui/service.sh
09:52:57.497 I/KernelSU: ksud::module: exec /data/adb/modules/m_rcq/service.sh
09:52:57.512 I/KernelSU: ksud::module: exec /data/adb/modules/wifi-force-country/service.sh
09:52:57.518 I/KernelSU: ksud::module: exec /data/adb/modules/galaxy_root_secure/service.sh
09:52:57.527 I/KernelSU: ksud::init_event: waiting for boot complete
09:53:49.660 I/KernelSU: ksud::init_event: on_boot_completed triggered!
09:53:51.024 I/dfroot: boot: already hooked, skipping
```

**结论：开机自动恢复 root 完全走通** —— 漏洞 → dirtyfrag.ko → SELinux permissive →
ksud late-load → KernelSU 模块加载 → 你原有的 7 个模块的 post-fs-data / service 全部执行。
中间设备会短暂掉线（ksud 的 `--soft-reboot` 重启框架），随后自行恢复。

### 关于 `su`：不是坏了，是 DFRoot 默认不给 adb shell 提权

* DFRoot 调 ksud 时 **没有传 `--allow-shell`**（日志里 `allow_shell: false`），
  所以 adb shell（uid 2000）不会被授权 root，`su` 即使能执行也只返回 uid=2000；
* `/system/bin/su` 这个文件本身也不存在（KernelSU 靠内核 hook 把名为 `su` 的
  execve 重定向到 ksud，并不需要真实文件；libsu 类的 root 应用通过这个重定向
  + 管理器授权拿 root）；
* KernelSU 正在工作：`cat /proc/modules` 返回 **Permission denied** —— 这正是
  `selinux_hide=1` 在隐藏自己；`/dev/df*` 标记同样被隐藏。

**如果你希望 adb shell 也能直接 `su`**（就像 Root-My-Galaxy 那套一样），
只要在 DFRoot 的 `libc.S` 里给 ksud 的 argv 加上 `--allow-shell` 即可（改一行、重编）。
代价是任何 adb shell 都能直接拿 root，安全性下降，所以上游默认不开。

---

## 8. 最终结论

| 项目 | 状态 |
|---|---|
| DirtyFrag 漏洞在 S938B 上可用 | ✅ 实测通过 |
| dirtyfrag.ko 加载 / SELinux permissive | ✅ 实测通过 |
| DFRoot 内嵌 android15-6.6 KernelSU 模块 | ✅ 实测通过（无 panic） |
| 开机自动恢复 root | ✅ 实测通过 |
| 原有 7 个模块 post-fs-data / service | ✅ 全部执行 |
| adb shell 直接 `su` | ⚠️ 默认不开（`allow_shell=false`），需要就加 `--allow-shell` |

