package df.root;

import android.os.Build;
import android.system.Os;
import android.util.Log;

import java.io.File;

/**
 * 设备自检。
 *
 * 快通道 DirtyFrag 要改写三个固定路径的 page cache、还要加载与 KMI 匹配的内核模块，
 * 机型 / 固件 / 内核不对会在很莫名的地方失败（甚至把内核搞崩），所以动手之前先把
 * 机型、固件、内核、KMI 和 6 条必需路径全部列出来，缺硬性条件就直接中止。
 *
 * CVE-2026-43499 链路的载荷也是按内核匹配的，这里一并提示。
 */
final class DeviceCheck {

    static final String TAG = "dfroot";

    /** 快通道（DirtyFrag）适配的机型 / 固件 / 内核。 */
    static final String PROFILE_MODEL   = "SM-S938B";
    static final String PROFILE_DEVICE  = "pa3q";
    static final String PROFILE_DISPLAY = "BP4A.251205.006.S938BXXS9CZE1";
    static final String PROFILE_KMI     = "android15-6.6";
    static final String PROFILE_RELEASE = "6.6.98-android15-8-pe17667d-abogkiS938BXXS9CZE1-4k";

    /** 快通道要碰的每一个路径；缺任何一个都是硬性失败。 */
    static final String[] REQUIRED_PATHS = {
        "/vendor/lib64/libstagefrighthw.so",           // 内核模块的落点（exp.c / libc.S）
        "/vendor/bin/modprobe",                        // stage1 的执行目标（libcxx.S / libc.S）
        "/apex/com.android.runtime/bin/crash_dump64",  // splice helper（exp.c）
        "/system/lib64/libc.so",                       // __libc_init 挂钩
        "/system/lib64/libc++.so",                     // ostream sentry 挂钩
        "/system/bin/logcat",                          // ksud 的 bind mount 目标
    };

    /**
     * su 可能出现的路径。
     *
     * 前四个是传统位置（KernelSU / Magisk 把 su 挂到 /system/bin/su）；
     * 后面几个是各变体自己放 su 的目录 —— 实机上就出现过「/system/bin/su 不存在、
     * 只有别处有」的情况，所以多列几个，找不到还有 ksud 通道兜着。
     */
    static final String[] SU_PATHS = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/debug_ramdisk/su",
        "/data/adb/ksu/bin/su",
        "/data/adb/magisk/su",
        "/data/adb/ap/bin/su",
    };

    /** 执行 root 命令时额外塞进 PATH 的目录（有的变体只在这些目录里放 su）。 */
    static final String EXTRA_PATH = "/data/adb/ksu/bin:/debug_ramdisk:/data/adb/magisk"
            + ":/data/adb/ap/bin:/system/bin:/system/xbin";

    private DeviceCheck() {}

    static String release() {
        try {
            return Os.uname().release;
        } catch (Throwable t) {
            return "";
        }
    }

    /** 从 uname -r 里推出来的 KMI，例如 android15-6.6；识别不了时返回空串。 */
    static String kmi() {
        String r = release();
        int a = r.indexOf("android");
        if (a < 0) return "";
        String rest = r.substring(a + 7);
        int dash = rest.indexOf('-');
        String rel = dash > 0 ? rest.substring(0, dash) : rest;
        try {
            Integer.parseInt(rel);
        } catch (Throwable t) {
            return "";
        }
        String[] parts = r.split("\\.");
        if (parts.length < 2) return "";
        try {
            return "android" + rel + "-" + Integer.parseInt(parts[0]) + "." + Integer.parseInt(parts[1]);
        } catch (Throwable t) {
            return "";
        }
    }

    /** 必需路径里缺的那些（逗号分隔）。 */
    static String missingPaths() {
        StringBuilder sb = new StringBuilder();
        for (String p : REQUIRED_PATHS) {
            if (!new File(p).exists()) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(p);
            }
        }
        return sb.toString();
    }

    /** 硬性条件：缺了就没必要动手。 */
    static boolean criticalOk() {
        return missingPaths().isEmpty() && !kmi().isEmpty();
    }

    /** True 表示就是本 fork 适配的那个固件 + 内核组合。 */
    static boolean exactProfile() {
        return PROFILE_MODEL.equals(Build.MODEL) && PROFILE_RELEASE.equals(release());
    }

    static String report() {
        String rel = release();
        String kmi = kmi();
        String missing = missingPaths();
        StringBuilder sb = new StringBuilder();
        sb.append("* 机型    : ").append(Build.MANUFACTURER).append(' ').append(Build.MODEL)
          .append("（").append(Build.DEVICE).append("）\n");
        sb.append("* 固件    : ").append(Build.DISPLAY).append('\n');
        sb.append("* 内核    : ").append(rel).append('\n');
        sb.append("* KMI     : ").append(kmi.isEmpty() ? "无法识别" : kmi).append('\n');
        sb.append(missing.isEmpty()
                ? "* 依赖路径: " + REQUIRED_PATHS.length + " 条全部就位（快通道可用）\n"
                : "* 依赖路径: 缺失 -> " + missing + "（快通道不可用）\n");
        if (exactProfile()) {
            sb.append("* 适配档位: 精确匹配（").append(PROFILE_DISPLAY).append("）\n");
        } else {
            sb.append("* 适配档位: 不是已验证的组合（").append(PROFILE_MODEL).append(" / ")
              .append(PROFILE_RELEASE).append("）\n");
            sb.append("            两条链路的载荷都按内核版本匹配，内核不同可能失败，请谨慎\n");
        }
        if (!PROFILE_KMI.equals(kmi)) {
            sb.append("* 注意    : 当前 KMI 是 ").append(kmi.isEmpty() ? "未知" : kmi)
              .append("，本 fork 的两条链路都只针对 ").append(PROFILE_KMI).append(" 构建\n");
        }
        return sb.toString();
    }

    /** 打印自检报告；返回 true 表示可以动手。 */
    static boolean preflight(String where) {
        Log.i(TAG, "自检（" + where + "）\n" + report());
        if (!criticalOk()) {
            Log.e(TAG, "自检未通过（" + where + "）：依赖路径缺失（"
                    + missingPaths() + "）或内核 KMI 无法识别 —— 已放弃，不修改任何文件");
            return false;
        }
        return true;
    }

    /** 非 null 表示检测到之前留下的 su。 */
    static String existingSu() {
        for (String p : SU_PATHS) {
            File f = new File(p);
            if (f.exists() && f.length() > 0) return p;
        }
        return null;
    }

    /**
     * 非 null 表示现在不适合跑快通道：
     *
     *  - 本轮已经布防过（/dev/df 存在）：再跑一遍是在打已经打过的补丁；
     *  - 已经有别的 root 在生效：ksud 会跳过加载模块、停在 vendor_modprobe 域，
     *    "完成安装"会失败，还可能把 /system/bin/su 截成 0 字节（实测踩过）。
     */
    static String blockReason() {
        if (new File("/dev/df").exists()) {
            return "本轮已布防（/dev/df 存在），需要硬重启手机后才能再次运行";
        }
        String su = existingSu();
        if (su != null) {
            return "检测到已有 root（" + su + " 存在），请先重启手机再运行本应用";
        }
        return null;
    }
}
