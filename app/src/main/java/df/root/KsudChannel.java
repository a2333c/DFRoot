package df.root;

import android.content.Context;
import android.os.SystemClock;
import android.util.Log;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 第三条 root 通道：直接用 APK 自带的 ksud。
 *
 * 为什么需要它（v1.9 对着 KernelSU 源码确认过）：
 *
 *   · KernelSU 的 su 是内核模块在「post-fs-data 阶段」才挂到 /system/bin 上的，
 *     而 ksud 的 late-load 只跑 late-load / post-mount / service / boot-completed
 *     这几个阶段（userspace/ksud/src/late_load.rs），post-fs-data 要等一次
 *     系统框架重启（ksud --soft-reboot）才会跑。所以只要不给 ksud 传 --soft-reboot，
 *     App 自己的进程里 `su -c ...` 永远是
 *     "Cannot run program \"su\": error=2, No such file or directory"。
 *
 *   · 但提权本身并不依赖那个挂载点：KernelSU 的 su 就是 ksud 自己
 *     （cli.rs：argv[0] 以 "su" 结尾就走 su 模式），真正的提权是
 *     `ioctl(KSU_IOCTL_GRANT_ROOT)`，由内核按管理器里的授权列表决定给不给 root。
 *
 *   · ksud 还留了一个不用改 argv[0] 的入口：`ksud debug su`
 *     → su.rs::grant_root() → ioctl 提权 → exec("sh")，把当前进程换成一个 root shell。
 *
 * 所以这里把 ksud 作为 jniLibs 里的 libksud.so 打进 APK（nativeLibraryDir 里的文件
 * App 可以直接 execve，和 helper 一个路子），开一个 `libksud.so debug su` 的 root shell，
 * 把命令写进它的 stdin —— 不需要 /system/bin/su、不需要授权弹窗、也不用重启系统框架。
 */
final class KsudChannel extends PostRoot.Channel {

    private static final String TAG = "dfroot";

    /** ksud 以 libksud.so 的形式打进 APK，落在 nativeLibraryDir 里（App 可执行）。 */
    static final String LIB_NAME = "libksud.so";

    /** 单条命令的上限。 */
    private static final long TIMEOUT_MILLIS = 20_000L;

    /** shell 回显的退出码：__DFROOT_RC=<code> */
    private static final Pattern RC = Pattern.compile("__DFROOT_RC=(-?\\d+)");

    private final Context context;

    KsudChannel(Context ctx) {
        super("ksud(debug su)");
        this.context = ctx.getApplicationContext();
    }

    /** ksud 本体（libksud.so）在设备上的绝对路径。 */
    static File binary(Context ctx) {
        return new File(ctx.getApplicationInfo().nativeLibraryDir, LIB_NAME);
    }

    static boolean available(Context ctx) {
        File file = binary(ctx);
        return file.isFile() && file.canExecute();
    }

    @Override
    PostRoot.Result exec(String command) {
        Process process = null;
        final StringBuilder captured = new StringBuilder();
        try {
            ProcessBuilder builder =
                    new ProcessBuilder(binary(context).getAbsolutePath(), "debug", "su");
            builder.redirectErrorStream(true);
            process = builder.start();
            final Process started = process;
            Thread reader = new Thread(() -> {
                try (InputStream in = started.getInputStream()) {
                    byte[] buffer = new byte[4096];
                    for (int n; (n = in.read(buffer)) > 0; ) {
                        synchronized (captured) {
                            captured.append(new String(buffer, 0, n, StandardCharsets.UTF_8));
                        }
                    }
                } catch (Throwable ignored) {
                }
            }, "dfroot-ksud-read");
            reader.setDaemon(true);
            reader.start();

            OutputStream stdin = process.getOutputStream();
            stdin.write(("( " + command + " ) 2>&1; echo \"__DFROOT_RC=$?\"\n")
                    .getBytes(StandardCharsets.UTF_8));
            stdin.write("exit\n".getBytes(StandardCharsets.UTF_8));
            stdin.flush();

            long deadline = SystemClock.elapsedRealtime() + TIMEOUT_MILLIS;
            while (SystemClock.elapsedRealtime() < deadline) {
                String text = snapshot(captured);
                Matcher matcher = RC.matcher(text);
                if (matcher.find()) {
                    int code = Integer.parseInt(matcher.group(1));
                    return new PostRoot.Result(code == 0, code, strip(text), name);
                }
                if (!process.isAlive()) {
                    // shell 已经退出：先把读线程收干净，再看一眼哨兵 —— 别把成功的当失败。
                    reader.join(500);
                    text = snapshot(captured);
                    matcher = RC.matcher(text);
                    if (matcher.find()) {
                        int code = Integer.parseInt(matcher.group(1));
                        return new PostRoot.Result(code == 0, code, strip(text), name);
                    }
                    int code = process.exitValue();
                    String out = strip(text);
                    return new PostRoot.Result(false, code,
                            out.isEmpty() ? "ksud 没有输出（退出码 " + code + "）" : out, name);
                }
                Thread.sleep(200);
            }
            process.destroy();
            reader.join(500);
            return new PostRoot.Result(false, -1,
                    strip(snapshot(captured)) + "\n（超过 " + (TIMEOUT_MILLIS / 1000)
                            + " 秒没有回退出码）", name);
        } catch (Throwable t) {
            Log.w(TAG, "ksud 通道失败", t);
            return new PostRoot.Result(false, -1, String.valueOf(t), name);
        } finally {
            if (process != null) process.destroy();
        }
    }

    private static String snapshot(StringBuilder buffer) {
        synchronized (buffer) {
            return buffer.toString();
        }
    }

    /** 去掉回显的哨兵行，只留命令本身的输出。 */
    private static String strip(String text) {
        String cleaned = text.replaceAll("__DFROOT_RC=-?\\d+\\s*", "").trim();
        return cleaned.length() <= 800 ? cleaned : cleaned.substring(cleaned.length() - 800);
    }
}
