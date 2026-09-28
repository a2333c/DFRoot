**快通道（DirtyFrag，几秒）+ 手动（CVE-2026-43499，三轮重试）+ 开机自动 + 安装器去广告。**

> v1.9：**修掉「`Cannot run program "su": error=2, No such file or directory`」** ——
> v1.8 去掉 `--soft-reboot` 之后，本轮开机 `/system/bin/su` 永远不会出现（KernelSU 的 `su`
> 是内核模块在 post-fs-data 阶段才挂出来的，而 ksud late-load 不跑那个阶段），应用里
> `su -c …` 必然失败。v1.9 改用 **APK 自带的 ksud** 当 root 通道（`libksud.so debug su`，
> 提权走内核 `ioctl(KSU_IOCTL_GRANT_ROOT)`）—— 不依赖 `/system/bin/su`、不用授权弹窗、
> 也不用重启系统框架；通道顺序 helper → ksud → su，一次没成自动重试 4 次 × 15 秒，
> 日志里还会先打一行通道自检。
>
> v1.8：**修掉两个开机自动的老毛病** ——
> ① 开机后不会再额外重启一次（不再给 ksud 传 `--soft-reboot`，以前这个参数会让 ksud
> 装完重启一次系统框架，还会把正在跑的广告设置一起打断）；
> ② 安装器广告设置不再依赖「先打开 KernelSU 再打开 App」：拿到 root 后会把那两条命令写成
> KernelSU 的开机脚本（`/data/adb/service.d/dfroot-ads.sh`），以后每次开机由 KernelSU
> 自己以 root 执行，不用打开应用、也不用授权弹窗；开机那一刻一次没成时，前台服务会在
> 接下来 5 分钟里每 30 秒重试一次。
>
> v1.7：方案里的「慢速」改名「**手动**」，描述改成「**自动不成功再手动尝试**」；
> 新增「**安装器广告设置**」—— 拿到 root 后自动跑两条 `cmd connectivity` 去掉三星安装器的广告，
> 命令 / 输出 / 退出码全部打在界面日志里（成功一定有输出），每次开机和每次打开 App 都会补一次。
>
> v1.6：**修好了开机自动**（快通道改成直接在开机广播里跑），界面上的方案简化为两项。

基于 [diabl0w/DFRoot](https://github.com/diabl0w/DFRoot) 的 fork，适配
**三星 Galaxy S25 Ultra（SM-S938B / pa3q）**，界面与运行输出全部中文。

## 这一版做了什么

- **快通道加回来了**：上游的 DirtyFrag（CVE-2026-43284）链路重新装进 App，
  抽成 `FastChain`，几秒到几十秒就能出结果；
- **自动串联**：方案默认「自动」→ 先跑快通道；它没成、而且没留下布防痕迹
  （`/dev/df` 不存在）时，才自动接手动方案。布防过就停下提示重启，不在脏内核上
  叠加第二条漏洞；
- **手动方案**：helper（`libcve43499root.so`）、payload（`cve-2026-43499-app.so`）、
  ksud（`ksud-s25u-kdp`）是预编译好的（逐字节未改），
  运行时不需要 Shizuku；
- **三轮阶梯**：「快（3 分钟）→ 稳（8 分钟）→ 耐心（15 分钟）」，成功即停；
  每轮都是全新进程（随机性重来），但复用本次开机已探测到的 KASLR 偏移；
- **开机自动默认打开**：`LOCKED_BOOT_COMPLETED` / `BOOT_COMPLETED` 触发，
  快通道直接在广播里跑（`goAsync()`），手动链路才交给前台服务，失败会在下次开机自动再试；
- **方案只有两个**（自动 / 手动）；界面上「上次开机自动：…」直接显示上一次开机跑到哪一步；
- **安装器广告设置（v1.7 新增）**：拿到 root 后自动执行
  `cmd connectivity set-chain3-enabled true` 和
  `cmd connectivity set-package-networking-enabled false com.samsung.android.packageinstaller`，
  日志里会打出 `→ 成功（exit 0，通道 …）`；
- **开机脚本通道（v1.8 新增）**：广告设置成功一次之后，同样的两条命令会被写成
  `/data/adb/service.d/dfroot-ads.sh`，KernelSU 每次开机以 root 直接执行它 ——
  不用打开应用、不用 `su`、也不会弹授权；界面上「开机脚本：…」显示上一次执行结果；
- **不再额外重启一次（v1.8 修复）**：`FastChain` 固定不给 ksud 传 `--soft-reboot`；
- **补设置重试（v1.8 新增）**：开机那一刻一次没成就交给前台服务，每 30 秒重试，最多 5 分钟；
- **ksud 通道（v1.9 新增）**：广告设置优先用 APK 自带的 ksud（`libksud.so debug su`）提权，
  不依赖 `/system/bin/su`、不用授权弹窗；失败日志里的
  `Cannot run program "su": error=2, No such file or directory` 不会再出现；
- **通道自检 + 自动重试（v1.9 新增）**：先打一行 `* root 通道：helper=…，ksud=…，su=…`，
  一次没成自动重试 4 次 × 15 秒（约 45 秒）。

## 使用

1. 先装 KernelSU Manager v3.3.0；
2. 安装 APK，**先打开一次**（安卓要求应用启动过才会收到开机广播），确认管理器显示「未安装」；
3. 方案保持「自动」，点按钮，等输出「成功」；
4. 自动没成功时，切到「**手动**」再点一次（概率型，多试几次命中率明显更高）；
5. 拿到 root 后会自动跑安装器广告设置，并写成 KernelSU 的开机脚本 ——
   以后每次开机由 KernelSU 自己以 root 执行，不用打开应用、也不会再弹授权；
6. 以后每次开机自动完成。

## 注意

- 两条链路都按内核匹配（快通道要 `android15-6.6` 的内核模块，手动要 6.6.98 的载荷），
  换固件 / 换内核要换对应的文件；
- 都是概率型链路：快通道一般一次就成，手动方案会自动重试三轮，三轮不成下次开机会再来；
- 所有改动只在内存 / page cache 里，不写分区、不改 boot、不动 `packages.xml`，重启即还原
  （安装器广告那两条是系统运行期设置，卸载 App 不会自动撤销）；
- `versionCode 11` / `versionName 1.9-s938b-rmg`，签名与前几版相同，可直接覆盖安装。

详细说明见 [README.md](README.md)，
早期版本的实机适配记录见
[PORTING.md](PORTING.md)。

---

漏洞利用与载荷来自上游作者
（[diabl0w/DFRoot](https://github.com/diabl0w/DFRoot)、
[polygraphene/DFReroot](https://github.com/polygraphene/DFReroot)）。

> [!WARNING]
> 仅用于你本人拥有或已获明确授权的设备。作者不对任何设备损坏负责。
