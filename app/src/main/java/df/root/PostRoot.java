package df.root;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;
import android.os.UserManager;
import android.util.Log;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 拿到 root 之后顺手做的事：去掉三星「软件包安装程序」的广告。
 *
 * 这两条命令本来是 adb 里的：
 *
 *   cmd connectivity set-chain3-enabled true
 *   cmd connectivity set-package-networking-enabled false com.samsung.android.packageinstaller
 *
 * 现在由应用自己在拿到 root 之后跑一遍，命令、输出、退出码全部打到日志（界面上也能看到），
 * 所以「有没有执行成功」一眼就能确认。
 *
 * root 通道有两条，按当前状态挑：
 *   1. 手动方案（CVE-2026-43499）刚跑完 —— helper 自带 root holder，
 *      `helper -c "<命令>"` 直接就是 root，不用等 KernelSU 的授权弹窗；
 *   2. KernelSU 的 su —— 第一次会弹授权，在 KernelSU 管理器里允许一次，
 *      以后每次开机都能自动执行。
 *
 * 本轮开机成功执行过就跳过（用 boot_id 记）；没成功（还没解锁、没授权、还没 root）
 * 就留着，等「开机完成」广播或下次打开应用时再补一次。
 *
 * v1.8：只靠应用在开机那一刻去跑并不可靠 —— 那时 KernelSU 的 su 还没就绪（管理器没起来、
 * 授权弹窗弹不出来），实机上每次开机都失败，必须手动打开 KernelSU 再打开应用才行。
 * 所以现在每次真正跑成功之后，顺手把同样的两条命令写成 KernelSU 的开机脚本
 * （/data/adb/service.d/，见 BootScript），以后每次开机由 KernelSU 自己以 root 执行，
 * 应用在不在、有没有授权都无所谓。
 */
final class PostRoot {

    private static final String TAG = "dfroot";

    /** 按顺序执行的两条命令。 */
    static final String[] COMMANDS = {
        "cmd connectivity set-chain3-enabled true",
        "cmd connectivity set-package-networking-enabled false"
                + " com.samsung.android.packageinstaller",
    };

    private static final String PREFS = "post_root";
    private static final String KEY_BOOT = "kernel_boot_id";
    private static final String KEY_DONE = "applied";

    /**
     * 单条命令的上限。
     *
     * KernelSU 的 su 在等授权弹窗时会一直阻塞，不能无限等下去；两条命令加起来
     * 也不会把开机广播拖到超时。
     */
    private static final long TIMEOUT_MILLIS = 20_000L;

    /** 同一时间只跑一份，免得反复弹授权。 */
    private static final AtomicBoolean RUNNING = new AtomicBoolean();

    private PostRoot() {}

    /** 后台跑一遍，不阻塞调用方。 */
    static void applyAsync(Context ctx, Sink sink) {
        if (!RUNNING.compareAndSet(false, true)) return;
        new Thread(() -> {
            try {
                apply(ctx, sink);
            } finally {
                RUNNING.set(false);
            }
        }, "dfroot-postroot").start();
    }

    /**
     * 跑一遍那两条命令。
     *
     * 返回 true 表示本轮开机已经设置好了（这次跑成功，或者之前就跑过）。
     */
    static boolean apply(Context ctx, Sink sink) {
        if (appliedThisBoot(ctx)) {
            sink.log("* 安装界面广告设置：本轮已经设置过，跳过\n");
            return true;
        }
        if (!rootPresent(ctx)) {
            sink.log("* 安装界面广告设置：还没拿到 root，先跳过\n");
            return false;
        }
        if (!unlocked(ctx)) {
            sink.log("* 安装界面广告设置：手机还没解锁（授权弹窗弹不出来），等解锁后再补\n");
            return false;
        }

        sink.log("\n=== 安装界面广告设置（去掉三星安装器的广告）===\n");
        String installError = BootScript.install(ctx, channels(ctx), sink);
        if (installError != null) {
            sink.log("* 开机脚本：这次没装上（" + installError + "）—— 先直接执行，下次再补\n");
        }
        boolean allOk = true;
        for (String command : COMMANDS) {
            sink.log("$ " + command + "\n");
            Result result = run(ctx, command);
            String output = result.output.trim();
            sink.log("  " + (output.isEmpty() ? "（命令没有输出）" : output) + "\n");
            sink.log("  → " + (result.ok ? "成功" : "失败") + "（exit " + result.code
                    + "，通道 " + result.channel + "）\n");
            if (!result.ok) allOk = false;
        }
        if (allOk) {
            markApplied(ctx);
            sink.log("安装界面广告设置完成：两条命令都执行成功。\n");
        } else {
            sink.log("安装界面广告设置没全部成功：下次开机 / 下次打开应用会再试一次。\n");
        }
        return allOk;
    }

    /** 本轮开机已经成功设置过：应用自己跑成功过，或者 KernelSU 的开机脚本已经跑成功过。 */
    static boolean appliedThisBoot(Context ctx) {
        String boot = RmgChain.bootId();
        if (boot == null) return false;
        SharedPreferences prefs = prefs(ctx);
        if (boot.equals(prefs.getString(KEY_BOOT, null)) && prefs.getBoolean(KEY_DONE, false)) {
            return true;
        }
        return BootScript.ranThisBoot(ctx);
    }

    /**
     * root 大致已经就位（不保证一定能用）。
     *
     * 只看「本轮装好了」的凭据和 su 是否存在；/dev/df 只代表漏洞布防过，
     * 不代表真拿到了 root，所以不算。
     */
    static boolean rootPresent(Context ctx) {
        return RmgChain.installedThisBoot(ctx)
                || DeviceCheck.existingSu() != null;
    }

    /**
     * 现在能不能去补设置：已经有 root，而且用户已经解锁。
     *
     * 开机广播有两次机会（未解锁那次、解锁那次），但「未解锁」时 KernelSU 的授权弹窗
     * 根本弹不出来，跑也是白跑 —— 补设置的重试要等这个条件成立再开始。
     */
    static boolean readyForRetry(Context ctx) {
        return rootPresent(ctx) && unlocked(ctx);
    }

    // ---------------------------------------------------------------- 内部

    private static boolean unlocked(Context ctx) {
        UserManager users = ctx.getSystemService(UserManager.class);
        return users == null || users.isUserUnlocked();
    }

    private static SharedPreferences prefs(Context ctx) {
        return ctx.createDeviceProtectedStorageContext()
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static void markApplied(Context ctx) {
        String boot = RmgChain.bootId();
        if (boot == null) {
            Log.w(TAG, "读不到 boot_id，跳过安装界面广告设置的状态记录");
            return;
        }
        prefs(ctx).edit().putString(KEY_BOOT, boot).putBoolean(KEY_DONE, true).commit();
    }

    private static Result run(Context ctx, String command) {
        Result last = null;
        for (Channel channel : channels(ctx)) {
            Result result = channel.exec(command);
            if (result == null) continue;
            if (result.ok) return result;
            last = result;
        }
        return last == null ? new Result(false, -1, "没有可用的 root 通道", "无") : last;
    }

    /** 通道顺序：手动方案刚跑完就先用 helper（不用授权），否则用 KernelSU 的 su。 */
    static List<Channel> channels(Context ctx) {
        List<Channel> list = new ArrayList<>();
        if (RmgChain.helperRootThisBoot(ctx)) {
            File helper = RmgChain.helper(ctx);
            if (helper.isFile() && helper.canExecute()) {
                list.add(new Channel("helper", new String[] {helper.getAbsolutePath(), "-c"}));
            }
        }
        for (String su : suCandidates()) {
            list.add(new Channel("su(" + su + ")", new String[] {su, "-c"}));
        }
        return list;
    }

    /** 先试已知的 su 路径，最后交给 PATH 去找。 */
    private static List<String> suCandidates() {
        List<String> list = new ArrayList<>();
        for (String path : DeviceCheck.SU_PATHS) {
            File file = new File(path);
            if (file.isFile() && file.length() > 0) list.add(path);
        }
        list.add("su");
        return list;
    }

    private static Result exec(List<String> argv, String channel) {
        Process process = null;
        final StringBuilder captured = new StringBuilder();
        try {
            ProcessBuilder builder = new ProcessBuilder(argv);
            builder.redirectErrorStream(true);
            process = builder.start();
            final Process started = process;
            Thread reader = new Thread(() -> {
                try (InputStream in = started.getInputStream()) {
                    byte[] buffer = new byte[4096];
                    for (int n; (n = in.read(buffer)) > 0; ) {
                        String text = new String(buffer, 0, n, StandardCharsets.UTF_8);
                        synchronized (captured) {
                            captured.append(text);
                        }
                    }
                } catch (Throwable ignored) {
                }
            }, "dfroot-postroot-read");
            reader.setDaemon(true);
            reader.start();

            if (!process.waitFor(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)) {
                process.destroy();
                reader.join(500);
                return new Result(false, -1, tail(captured) + "\n（超过 "
                        + (TIMEOUT_MILLIS / 1000) + " 秒还没结束，多半是在等 KernelSU 的授权弹窗）",
                        channel);
            }
            reader.join(2000);
            int code = process.exitValue();
            return new Result(code == 0, code, tail(captured), channel);
        } catch (Throwable t) {
            return new Result(false, -1, String.valueOf(t), channel);
        } finally {
            if (process != null) process.destroy();
        }
    }

    /** 输出可能很长，只留最后一段。 */
    private static String tail(StringBuilder buffer) {
        String text;
        synchronized (buffer) {
            text = buffer.toString();
        }
        text = text.trim();
        return text.length() <= 800 ? text : text.substring(text.length() - 800);
    }

    /** 一条 root 通道：prefix + 命令 拼成完整 argv。 */
    static final class Channel {
        final String name;
        final String[] prefix;

        Channel(String name, String[] prefix) {
            this.name = name;
            this.prefix = prefix;
        }

        Result exec(String command) {
            List<String> argv = new ArrayList<>(Arrays.asList(prefix));
            argv.add(command);
            return PostRoot.exec(argv, name);
        }
    }

    static final class Result {
        final boolean ok;
        final int code;
        final String output;
        final String channel;

        Result(boolean ok, int code, String output, String channel) {
            this.ok = ok;
            this.code = code;
            this.output = output;
            this.channel = channel;
        }
    }
}
