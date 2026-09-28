package df.root;

import android.content.Context;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 开机自动执行那两条系统设置的「脚本通道」。
 *
 * v1.7 是在应用里用 root 通道（helper 或 KernelSU 的 su）去跑那两条命令。实机上这条路只在
 * 「先打开 KernelSU 管理器、再打开本应用」之后才成立：开机那一刻 KernelSU 的 su 还没就绪
 * （管理器没起来，授权弹窗也弹不出来），所以每次开机都必定失败。
 *
 * v1.8 换成 KernelSU 自己的开机脚本：脚本写进 /data/adb/service.d/，KernelSU 每次开机都会
 * 以 root 身份执行它 —— 不经过应用、不经过 su、不需要任何授权弹窗，开机必定执行。
 *
 * 脚本把运行结果写进应用自己的设备加密目录（应用一定读得到），应用据此判断「本轮开机是不是
 * 已经设置过了」，界面上也能直接看到脚本到底跑没跑。
 */
final class BootScript {

    private static final String TAG = "dfroot";

    /** KernelSU（以及 Magisk）每次开机都会以 root 执行这个目录里的 *.sh。 */
    static final String REMOTE_DIR = "/data/adb/service.d";
    static final String REMOTE_PATH = REMOTE_DIR + "/dfroot-ads.sh";

    /** 应用侧的脚本副本与运行记录，都放在设备加密存储里（开机未解锁时也能读写）。 */
    private static final String SCRIPT_NAME = "dfroot-ads.sh";
    private static final String LOG_NAME = "dfroot-ads.log";

    /** 脚本最后写的那行结果：RESULT boot=xxx chain3=0 pkgnet=0 */
    private static final Pattern RESULT =
            Pattern.compile("RESULT boot=(\\S+) chain3=(-?\\d+) pkgnet=(-?\\d+)");

    private BootScript() {}

    private static Context storage(Context ctx) {
        return ctx.createDeviceProtectedStorageContext();
    }

    static File scriptFile(Context ctx) {
        return new File(storage(ctx).getFilesDir(), SCRIPT_NAME);
    }

    static File logFile(Context ctx) {
        return new File(storage(ctx).getFilesDir(), LOG_NAME);
    }

    /** 脚本正文。两条命令与 PostRoot.COMMANDS 保持一致。 */
    private static String content(Context ctx) {
        String log = logFile(ctx).getAbsolutePath();
        StringBuilder sb = new StringBuilder();
        sb.append("#!/system/bin/sh\n");
        sb.append("# DFRoot：去掉三星「软件包安装程序」的安装界面广告。\n");
        sb.append("# 本文件由 DFRoot 安装；KernelSU 每次开机在 service.d 阶段以 root 执行它，\n");
        sb.append("# 不依赖应用是否打开，也不需要 KernelSU 的授权弹窗。\n");
        sb.append("LOG='").append(log).append("'\n");
        sb.append("BOOT=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)\n");
        sb.append("{\n");
        sb.append("  echo \"--- $(date '+%Y-%m-%d %H:%M:%S') boot=$BOOT ---\"\n");
        sb.append("  cmd connectivity set-chain3-enabled true\n");
        sb.append("  rc1=$?\n");
        sb.append("  echo \"set-chain3-enabled rc=$rc1\"\n");
        sb.append("  cmd connectivity set-package-networking-enabled false"
                + " com.samsung.android.packageinstaller\n");
        sb.append("  rc2=$?\n");
        sb.append("  echo \"set-package-networking-enabled rc=$rc2\"\n");
        sb.append("  echo \"RESULT boot=$BOOT chain3=$rc1 pkgnet=$rc2\"\n");
        sb.append("} >> \"$LOG\" 2>&1\n");
        sb.append("chmod 644 \"$LOG\" 2>/dev/null\n");
        sb.append("cp \"$LOG\" /data/local/tmp/dfroot-ads.log 2>/dev/null\n");
        return sb.toString();
    }

    /**
     * 把脚本装进 KernelSU 的开机脚本目录。
     *
     * 返回 null 表示成功，否则返回中文原因。按顺序试每一条 root 通道。
     */
    static String install(Context ctx, List<PostRoot.Channel> channels, Sink sink) {
        if (channels.isEmpty()) return "没有可用的 root 通道";
        File local = scriptFile(ctx);
        try {
            writeText(local, content(ctx));
            local.setReadable(true, false);
        } catch (IOException e) {
            return "写入脚本副本失败：" + e;
        }
        String command = "mkdir -p " + REMOTE_DIR
                + " && cp " + quote(local.getAbsolutePath()) + " " + REMOTE_PATH
                + " && chmod 755 " + REMOTE_PATH
                + " && echo dfroot-boot-script-ok";
        String last = null;
        for (PostRoot.Channel channel : channels) {
            PostRoot.Result result = channel.exec(command);
            if (result != null && result.ok) {
                sink.log("* 开机脚本：已写入 " + REMOTE_PATH
                        + "（以后每次开机由 KernelSU 以 root 自动执行，不用打开应用）\n");
                return null;
            }
            last = result == null ? "没有输出" : result.output;
        }
        return last == null ? "没有可用的 root 通道" : last.trim();
    }

    /** 本轮开机的脚本记录里，那两条命令是不是都成功了。 */
    static boolean ranThisBoot(Context ctx) {
        String boot = RmgChain.bootId();
        if (boot == null) return false;
        String text = readText(logFile(ctx));
        if (text == null) return false;
        Matcher matcher = RESULT.matcher(text);
        boolean ok = false;
        while (matcher.find()) {
            if (boot.equals(matcher.group(1))) {
                ok = "0".equals(matcher.group(2)) && "0".equals(matcher.group(3));
            }
        }
        return ok;
    }

    /** 界面用的一行摘要：最近一次开机脚本跑成什么样；没有任何记录时返回 null。 */
    static String summary(Context ctx) {
        String text = readText(logFile(ctx));
        if (text == null) return null;
        Matcher matcher = RESULT.matcher(text);
        String last = null;
        while (matcher.find()) last = matcher.group();
        if (last == null) return null;
        Matcher fields = RESULT.matcher(last);
        if (!fields.find()) return null;
        boolean ok = "0".equals(fields.group(2)) && "0".equals(fields.group(3));
        return (ok ? "上次已执行成功" : "上次有失败") + "（chain3=" + fields.group(2)
                + "，pkgnet=" + fields.group(3) + "）";
    }

    // ---------------------------------------------------------------- 内部

    private static void writeText(File file, String text) throws IOException {
        File dir = file.getParentFile();
        if (dir != null && !dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("无法创建目录：" + dir);
        }
        try (Writer writer =
                     new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)) {
            writer.write(text);
        }
    }

    private static String readText(File file) {
        if (!file.isFile()) return null;
        try (FileInputStream in = new FileInputStream(file)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            for (int n; (n = in.read(buffer)) > 0; ) out.write(buffer, 0, n);
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        } catch (Throwable t) {
            Log.w(TAG, "读不到开机脚本的运行记录：" + file, t);
            return null;
        }
    }

    private static String quote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }
}
