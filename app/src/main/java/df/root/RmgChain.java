package df.root;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;
import android.system.Os;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CVE-2026-43499 链路（取自 Root My Galaxy / dev.busung.s25uroot）的移植。
 *
 * 这条链路把“提权”和“装 KernelSU”拆成两步，全部由 APK 自带的三个二进制完成：
 *
 *   lib/arm64-v8a/libcve43499root.so      helper。本身是可执行 ELF，放在 jniLibs 里，
 *                                         因此可以直接从 app 的 nativeLibraryDir execve。
 *   assets/payloads/cve-2026-43499-app.so  payload。由 helper dlopen 后执行漏洞。
 *   assets/payloads/ksud-s25u-kdp          KernelSU 本体（ksud + 内嵌 kernelsu.ko）。
 *
 * 执行顺序与 Root My Galaxy 的 InstallViewModel 完全一致：
 *
 *   1. helper --run-payload &lt;payload&gt; &lt;helper&gt; &lt;log&gt;   拿 root（留下 root holder）
 *   2. helper -c "cp ksud …"                            把 ksud 落到 /data/local/tmp
 *   3. helper --late-load                                bind mount /system/bin/logcat，
 *                                                        再 exec "logcat late-load …" 装 KernelSU
 *
 * 与 Shizuku 无关：helper 从 app 的 nativeLibraryDir 直接跑，不需要额外授权。
 *
 * 这一版加了“先快后慢”的重试阶梯（见 LADDER）：一次不成不代表链路不行，
 * 同一次开机里自动多试几轮，命中率明显更高，而且第一轮很快就能出结果。
 */
final class RmgChain {

    static final String TAG = "dfroot";

    /** 三个载荷的文件名（helper 必须与 jniLibs 里的文件名一致）。 */
    static final String HELPER_NAME  = "libcve43499root.so";
    static final String PAYLOAD_NAME = "cve-2026-43499-app.so";
    static final String KSUD_NAME    = "ksud-s25u-kdp";

    private static final String PAYLOAD_ASSET = "payloads/" + PAYLOAD_NAME;
    private static final String KSUD_ASSET    = "payloads/" + KSUD_NAME;

    /** helper 自己写死的落点，见 libcve43499root.so 里的字符串常量。 */
    private static final String REMOTE_KSUD       = "/data/local/tmp/" + KSUD_NAME;
    private static final String REMOTE_KSUD_STAGE = "/data/local/tmp/.ksud-stage";

    /** 一轮尝试的参数。 */
    static final class Round {
        final String label;
        final int attempts;
        final int p0TimeoutSec;
        final int attemptTimeoutSec;
        final long stallMillis;
        final long budgetMillis;

        Round(String label, int attempts, int p0TimeoutSec, int attemptTimeoutSec,
              long stallMillis, long budgetMillis) {
            this.label = label;
            this.attempts = attempts;
            this.p0TimeoutSec = p0TimeoutSec;
            this.attemptTimeoutSec = attemptTimeoutSec;
            this.stallMillis = stallMillis;
            this.budgetMillis = budgetMillis;
        }

        long budgetSeconds() {
            return budgetMillis / 1000L;
        }
    }

    /**
     * “先快后慢”的重试阶梯。
     *
     * 思路来自 DFReroot：一次不成功不代表这条链路不行，多试几次命中率会明显变高。
     * 所以第一轮用很短的超时快速试几次（命中就几秒到一两分钟出结果），
     * 不行再逐轮放宽单次尝试的时间上限，最后一轮最耐心。
     * 每轮都是全新的 helper 进程（随机性重新来过），但会复用同一次开机里
     * 已经探测到的 KASLR 偏移，省掉重复探测 —— 这也是 DFReroot 的做法。
     *
     * 想调快 / 调慢，改这张表就行（attempts = 尝试次数，
     * p0TimeoutSec = 第一次探测的时限，attemptTimeoutSec = 单次尝试的时限，
     * stallMillis = 多久没有新日志就算卡死，budgetMillis = 整轮的时间上限）。
     */
    static final Round[] LADDER = {
        new Round("第 1 轮 · 快",   6, 20,  60,  40_000L,  180_000L),
        new Round("第 2 轮 · 稳",  12, 35, 100,  70_000L,  480_000L),
        new Round("第 3 轮 · 耐心", 24, 60, 180, 110_000L, 900_000L),
    };

    /** 两轮之间的冷却，给内核一点时间清掉上一轮的残留。 */
    private static final long ROUND_COOLDOWN_MILLIS = 3_000L;

    /** helper 自身（-c / --late-load）的执行上限。 */
    private static final long HELPER_TIMEOUT_MILLIS = 120_000L;
    private static final long POLL_MILLIS = 250L;

    private static final String RECEIPT_PREFS = "rmg_receipt";
    private static final String RECEIPT_BOOT = "kernel_boot_id";
    private static final String RECEIPT_VERIFIED = "verified";
    private static final String RECEIPT_HELPER = "helper_root";

    private static final String P0_PREFS = "rmg_p0";
    private static final String P0_BOOT = "kernel_boot_id";
    private static final String P0_OFFSET = "offset";
    private static final String P0_OFFSET_ENV = "SLIDE_P0_OFFSET";
    private static final long P0_OFFSET_MAX = 0x1f0000L;
    private static final long P0_OFFSET_MASK = 0xffffL;

    private static final Pattern P0_PATTERN =
            Pattern.compile("slide-kaslr-ok[^\\n]*slide=([0-9a-fA-F]{16})");
    private static final Pattern ANSI_ESCAPE =
            Pattern.compile("\u001B\\[[0-?]*[ -/]*[@-~]");

    private RmgChain() {}

    // ---------------------------------------------------------------- 文件位置

    static File helper(Context ctx) {
        return new File(ctx.getApplicationInfo().nativeLibraryDir, HELPER_NAME);
    }

    /**
     * 开机时（LOCKED_BOOT_COMPLETED）用户还没解锁，CE 存储不可用，
     * 所以载荷、日志、状态一律放设备加密存储（DE）里，两个入口看到的才是同一份。
     */
    private static Context storage(Context ctx) {
        return ctx.createDeviceProtectedStorageContext();
    }

    static File payloadDir(Context ctx) {
        return new File(storage(ctx).getFilesDir(), "payloads");
    }

    static File payloadFile(Context ctx) {
        return new File(payloadDir(ctx), PAYLOAD_NAME);
    }

    static File ksudFile(Context ctx) {
        return new File(payloadDir(ctx), KSUD_NAME);
    }

    // ---------------------------------------------------------------- 状态判定

    /** 本轮（同一个 boot_id）已经成功装完 KernelSU。 */
    static boolean installedThisBoot(Context ctx) {
        String boot = bootId();
        if (boot == null) return false;
        SharedPreferences prefs =
                storage(ctx).getSharedPreferences(RECEIPT_PREFS, Context.MODE_PRIVATE);
        return boot.equals(prefs.getString(RECEIPT_BOOT, null))
                && prefs.getBoolean(RECEIPT_VERIFIED, false);
    }

    /**
     * 尽力而为地判断 kernelsu.ko 是否已经加载。
     * 未提权的 app 通常读不到 /proc/modules，这里读不到就当作 false，
     * 真正的“本轮已装过”由 installedThisBoot() 负责。
     */
    static boolean kernelSuLoaded() {
        if (new File("/sys/module/kernelsu").exists()) return true;
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader("/proc/modules"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("kernelsu ")) return true;
            }
        } catch (Throwable ignored) {
        } finally {
            if (reader != null) try { reader.close(); } catch (IOException ignored) {}
        }
        return false;
    }

    /** 返回 null 表示可以运行，否则返回中文原因。 */
    static String blockReason(Context ctx) {
        if (installedThisBoot(ctx)) {
            return "本轮已经成功安装过 KernelSU，重启手机前不需要再跑一次";
        }
        String su = DeviceCheck.existingSu();
        if (su != null) {
            return "检测到已有 root（" + su + " 存在），请先重启手机再运行本应用";
        }
        File helper = helper(ctx);
        if (!helper.isFile()) {
            return "缺少 helper：" + helper;
        }
        if (!helper.canExecute()) {
            return "helper 不可执行：" + helper;
        }
        return null;
    }

    static String report(Context ctx) {
        File helper = helper(ctx);
        StringBuilder sb = new StringBuilder();
        sb.append("* 方案    : CVE-2026-43499（Root My Galaxy 链路）\n");
        sb.append("* helper  : ").append(helper.getAbsolutePath())
          .append(helper.isFile() ? "（" + helper.length() + " B" + (helper.canExecute() ? "，可执行" : "，不可执行") + "）" : "（缺失）").append('\n');
        sb.append("* 内核    : ").append(DeviceCheck.release()).append('\n');
        sb.append("* 载荷    : ").append(PAYLOAD_NAME).append(" / ").append(KSUD_NAME).append('\n');
        sb.append("* 重试    : ");
        for (int i = 0; i < LADDER.length; i++) {
            Round round = LADDER[i];
            if (i > 0) sb.append(" → ");
            sb.append(round.label).append("（").append(round.attempts).append(" 次 × ")
              .append(round.attemptTimeoutSec).append(" 秒）");
        }
        sb.append('\n');
        sb.append("* 说明    : 载荷按内核版本匹配，当前内核若不是 6.6.98 可能失败\n");
        return sb.toString();
    }

    // ---------------------------------------------------------------- 主流程

    static void runLadder(Context ctx, Sink sink) throws Exception {
        File helper = helper(ctx);
        if (!helper.isFile() || !helper.canExecute()) {
            throw new IOException("helper 不可执行：" + helper);
        }

        File payload = stageAsset(ctx, PAYLOAD_ASSET, payloadFile(ctx));
        File ksud = stageAsset(ctx, KSUD_ASSET, ksudFile(ctx));
        sink.log("* helper  : " + helper.getAbsolutePath() + "（" + helper.length() + " B）\n");
        sink.log("* payload : " + payload.getAbsolutePath() + "（" + payload.length() + " B）\n");
        sink.log("* ksud    : " + ksud.getAbsolutePath() + "（" + ksud.length() + " B）\n");

        String boot = bootId();
        Exception last = null;
        for (int i = 0; i < LADDER.length; i++) {
            Round round = LADDER[i];
            if (i > 0) {
                sink.log("\n冷却 " + (ROUND_COOLDOWN_MILLIS / 1000) + " 秒，换下一轮……\n");
                Thread.sleep(ROUND_COOLDOWN_MILLIS);
            }
            sink.progress("正在获取 Root（" + round.label + "）…");
            sink.log("\n=== " + round.label + "：最多 " + round.attempts + " 次尝试，单次上限 "
                    + round.attemptTimeoutSec + " 秒，本轮上限 " + round.budgetSeconds()
                    + " 秒 ===\n");
            try {
                if (runExploitRound(ctx, sink, helper, payload, round, boot)) {
                    installKernelSu(ctx, sink, helper, ksud);
                    storeReceipt(ctx, true);
                    PostRoot.applyAsync(ctx, sink);
                    sink.progress("Root 已就绪");
                    return;
                }
                last = new IOException(round.label + "没命中（日志里没有出现成功标记）");
            } catch (Exception e) {
                last = e;
            }
            sink.log("\n[-] " + round.label + "，未成功：" + last.getMessage() + "\n");
        }
        throw last != null ? last : new IOException("没有可用的尝试轮次");
    }

    /**
     * 跑一轮尝试；返回 true 表示这一轮命中了。
     *
     * 每轮都是新的 helper 进程，随机性重新来过；但会复用同一次开机里已经
     * 探测到的 KASLR 偏移，省掉重复探测。
     */
    private static boolean runExploitRound(Context ctx, Sink sink, File helper, File payload,
                                           Round round, String boot) throws Exception {
        File logFile = new File(storage(ctx).getFilesDir(), "exploit.log");
        if (logFile.exists() && !logFile.delete()) {
            throw new IOException("无法删除上一次的日志：" + logFile);
        }

        sink.log("开始执行漏洞利用（请勿熄屏、别退出应用）……\n");
        ProcessBuilder builder = new ProcessBuilder(
                helper.getAbsolutePath(),
                "--run-payload",
                payload.getAbsolutePath(),
                helper.getAbsolutePath(),
                logFile.getAbsolutePath());
        builder.redirectErrorStream(true);
        builder.environment().put("EXPLOIT_ATTEMPTS", Integer.toString(round.attempts));
        builder.environment().put("P0_ATTEMPT_TIMEOUT_SEC", Integer.toString(round.p0TimeoutSec));
        builder.environment().put("EXPLOIT_ATTEMPT_TIMEOUT_SEC",
                Integer.toString(round.attemptTimeoutSec));
        String cachedOffset = cachedP0Offset(ctx, boot);
        if (cachedOffset != null) {
            builder.environment().put(P0_OFFSET_ENV, cachedOffset);
            sink.log("* 复用本次开机已探测到的 KASLR 偏移 " + cachedOffset + "（省掉重复探测）\n");
        }

        Process process = builder.start();
        StringBuilder captured = new StringBuilder();
        String published = "";
        long startedAt = SystemClock.elapsedRealtime();
        long lastProgressAt = startedAt;
        try {
            while (process.isAlive()) {
                drain(process, captured);
                String raw = readTextIfPresent(logFile);
                if (!raw.equals(published)) {
                    cacheP0Offset(ctx, boot, raw);
                    sink.log(delta(published, raw));
                    published = raw;
                    lastProgressAt = SystemClock.elapsedRealtime();
                }
                long now = SystemClock.elapsedRealtime();
                if (now - lastProgressAt > round.stallMillis) {
                    throw new IOException("漏洞利用停滞：超过 " + (round.stallMillis / 1000)
                            + " 秒没有新日志");
                }
                if (now - startedAt > round.budgetMillis) {
                    throw new IOException("本轮超时：超过 " + round.budgetSeconds() + " 秒");
                }
                Thread.sleep(POLL_MILLIS);
            }
            drain(process, captured);
            int exitCode = process.waitFor();
            String raw = readTextIfPresent(logFile);
            cacheP0Offset(ctx, boot, raw);
            sink.log(delta(published, raw));
            published = raw;
            if (raw.contains("exploit completed") && raw.contains("done=1 root=1")) {
                sink.log("\n[+] 提权成功（exploit completed / done=1 root=1）\n");
                return true;
            }
            if (exitCode != 0) {
                throw new IOException("payload 退出码 " + exitCode
                        + (captured.length() > 0 ? "：" + tail(captured.toString()) : ""));
            }
            return false;
        } finally {
            kill(process);
        }
    }

    private static void installKernelSu(Context ctx, Sink sink, File helper, File ksud)
            throws Exception {
        String stageCommand = "/system/bin/cp " + shellQuote(ksud.getAbsolutePath())
                + " " + REMOTE_KSUD
                + " && /system/bin/cp " + shellQuote(ksud.getAbsolutePath())
                + " " + REMOTE_KSUD_STAGE
                + " && /system/bin/chmod 755 " + REMOTE_KSUD + " " + REMOTE_KSUD_STAGE;
        sink.log("\n暂存 KernelSU 到 " + REMOTE_KSUD + " 与 " + REMOTE_KSUD_STAGE + " ……\n");
        CommandResult staged = runHelper(helper, "-c", stageCommand);
        if (staged.code != 0) {
            throw new IOException("暂存 ksud 失败（退出码 " + staged.code + "）"
                    + (staged.output.isEmpty() ? "" : "：" + staged.output));
        }
        if (!staged.output.isEmpty()) sink.log(staged.output + "\n");

        sink.log("执行 ksud late-load 安装 KernelSU ……\n");
        CommandResult lateLoad = runHelper(helper, "--late-load");
        if (lateLoad.code != 0) {
            throw new IOException("late-load 失败（退出码 " + lateLoad.code + "）"
                    + (lateLoad.output.isEmpty() ? "" : "：" + lateLoad.output));
        }
        if (!lateLoad.output.isEmpty()) sink.log(lateLoad.output + "\n");
        sink.log("[+] KernelSU 安装完成\n");
    }

    private static final class CommandResult {
        final int code;
        final String output;

        CommandResult(int code, String output) {
            this.code = code;
            this.output = output;
        }
    }

    private static CommandResult runHelper(File helper, String... arguments) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(helper.getAbsolutePath());
        command.addAll(Arrays.asList(arguments));
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        StringBuilder captured = new StringBuilder();
        long startedAt = SystemClock.elapsedRealtime();
        try {
            while (process.isAlive()) {
                drain(process, captured);
                if (SystemClock.elapsedRealtime() - startedAt > HELPER_TIMEOUT_MILLIS) {
                    throw new IOException("helper 超时（" + arguments[0] + "）");
                }
                Thread.sleep(POLL_MILLIS);
            }
            drain(process, captured);
            return new CommandResult(process.waitFor(), stripAnsi(captured.toString()).trim());
        } finally {
            kill(process);
        }
    }

    // ---------------------------------------------------------------- 辅助

    /** 把 asset 复制到 dest（先写 .tmp 再改名），并置为 0755。 */
    static File stageAsset(Context ctx, String assetPath, File dest) throws IOException {
        File dir = dest.getParentFile();
        if (dir != null && !dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("无法创建目录：" + dir);
        }
        File tmp = new File(dest.getPath() + ".tmp");
        try (InputStream in = ctx.getAssets().open(assetPath);
             OutputStream out = new FileOutputStream(tmp)) {
            byte[] buffer = new byte[8192];
            for (int n; (n = in.read(buffer)) > 0; ) out.write(buffer, 0, n);
        }
        if (!tmp.renameTo(dest)) {
            tmp.delete();
            throw new IOException("重命名失败：" + dest);
        }
        try {
            Os.chmod(dest.getAbsolutePath(), 0755);
        } catch (Throwable t) {
            dest.setExecutable(true, false);
        }
        return dest;
    }

    private static void drain(Process process, StringBuilder buffer) {
        try {
            InputStream stream = process.getInputStream();
            byte[] data = new byte[4096];
            while (stream.available() > 0) {
                int count = stream.read(data);
                if (count <= 0) break;
                buffer.append(new String(data, 0, count, java.nio.charset.StandardCharsets.UTF_8));
            }
        } catch (Throwable ignored) {
        }
    }

    private static void kill(Process process) {
        if (!process.isAlive()) return;
        process.destroy();
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (process.isAlive()) process.destroyForcibly();
    }

    /** 日志文件被追加时只回传新增的部分，被重写时回传全文。 */
    private static String delta(String published, String current) {
        if (current.startsWith(published)) return current.substring(published.length());
        return current;
    }

    private static String tail(String text) {
        String trimmed = stripAnsi(text).trim();
        int limit = 400;
        return trimmed.length() <= limit ? trimmed : "…" + trimmed.substring(trimmed.length() - limit);
    }

    private static String stripAnsi(String value) {
        return ANSI_ESCAPE.matcher(value).replaceAll("").replace("\r", "");
    }

    private static String readTextIfPresent(File file) {
        if (!file.isFile()) return "";
        try {
            byte[] data = java.nio.file.Files.readAllBytes(file.toPath());
            return new String(data, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Throwable t) {
            return "";
        }
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    static String bootId() {
        try {
            String value = new String(java.nio.file.Files.readAllBytes(
                    java.nio.file.Paths.get("/proc/sys/kernel/random/boot_id")),
                    java.nio.charset.StandardCharsets.US_ASCII).trim();
            return value.isEmpty() ? null : value;
        } catch (Throwable t) {
            return null;
        }
    }

    private static void storeReceipt(Context ctx, boolean helperRoot) {
        String boot = bootId();
        if (boot == null) {
            Log.w(TAG, "读不到 boot_id，跳过安装凭据记录");
            return;
        }
        storage(ctx).getSharedPreferences(RECEIPT_PREFS, Context.MODE_PRIVATE)
                .edit()
                .putString(RECEIPT_BOOT, boot)
                .putBoolean(RECEIPT_VERIFIED, true)
                .putBoolean(RECEIPT_HELPER, helperRoot)
                .commit();
    }

    /** 快通道走通时也记一笔「本轮已装好」，见 FastChain。 */
    static void storeFastReceipt(Context ctx) {
        storeReceipt(ctx, false);
    }

    /**
     * 本轮是「手动」方案（helper + payload）拿到的 root。
     *
     * 这时 helper 自带 root holder，`helper -c "<命令>"` 直接就是 root，
     * 不用等 KernelSU 的授权弹窗 —— 装完之后要跑的那两条系统设置优先走它。
     */
    static boolean helperRootThisBoot(Context ctx) {
        String boot = bootId();
        if (boot == null) return false;
        SharedPreferences prefs =
                storage(ctx).getSharedPreferences(RECEIPT_PREFS, Context.MODE_PRIVATE);
        return boot.equals(prefs.getString(RECEIPT_BOOT, null))
                && prefs.getBoolean(RECEIPT_HELPER, false);
    }

    private static String cachedP0Offset(Context ctx, String boot) {
        if (boot == null) return null;
        SharedPreferences prefs =
                storage(ctx).getSharedPreferences(P0_PREFS, Context.MODE_PRIVATE);
        if (!boot.equals(prefs.getString(P0_BOOT, null))) return null;
        return prefs.getString(P0_OFFSET, null);
    }

    /**
     * 记住本次启动的 KASLR 偏移（日志里的 slide-kaslr-ok … slide=xxxxxxxx）。
     * 同一个 boot 内重试时直接复用，能明显少走几轮探测。
     */
    private static void cacheP0Offset(Context ctx, String boot, String log) {
        if (boot == null || log == null || log.isEmpty()) return;
        Matcher matcher = P0_PATTERN.matcher(log);
        String found = null;
        while (matcher.find()) found = matcher.group(1);
        if (found == null) return;
        long offset;
        try {
            offset = Long.parseLong(found, 16);
        } catch (NumberFormatException e) {
            return;
        }
        if (offset < 0 || offset > P0_OFFSET_MAX) return;
        if ((offset & P0_OFFSET_MASK) != 0L) return;
        String value = "0x" + Long.toHexString(offset);
        SharedPreferences prefs =
                storage(ctx).getSharedPreferences(P0_PREFS, Context.MODE_PRIVATE);
        if (boot.equals(prefs.getString(P0_BOOT, null))
                && value.equals(prefs.getString(P0_OFFSET, null))) {
            return;
        }
        prefs.edit().putString(P0_BOOT, boot).putString(P0_OFFSET, value).apply();
    }
}
