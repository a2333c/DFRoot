package df.root;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.SystemClock;
import android.util.Log;

import java.io.File;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 开机自动获取 Root。
 *
 * v1.5 的做法是「收到广播 → 起前台服务，由服务去跑链路」，实机上不生效：Android 12+
 * 限制后台应用启动前台服务，LOCKED_BOOT_COMPLETED 那一刻 startForegroundService()
 * 会被系统直接拒掉，广播就静悄悄结束了 —— 开关是开的，但什么也没发生。
 *
 * 上游 DFRoot 的做法是**直接在广播里把快通道跑掉**，实机验证过可行，所以这里改回同一条
 * 路子，并且做得稳一点：
 *
 *   1. goAsync() 保住进程：广播没结束，系统不会把这个进程当缓存进程回收；
 *   2. 后台线程里直接跑快通道（通常几秒到几十秒），最多等 INLINE_BUDGET_MILLIS；
 *   3. 快通道没成、也没布防时，再起前台服务去跑 CVE-2026-43499 链路（十几分钟，广播装不下），
 *      系统连前台服务也不让起的话，发条通知提醒手动运行；
 *   4. 每一步都写一笔 BootLog，界面上能直接看到「上次开机自动做了什么」。
 */
public class BootReceiver extends BroadcastReceiver {

    private static final String TAG = "dfroot";

    /** 广播里最多等快通道这么久；超时就放手，别把广播拖到超时。 */
    private static final long INLINE_BUDGET_MILLIS = 45_000L;

    /**
     * 正在跑的开机自动任务数。
     *
     * LOCKED_BOOT_COMPLETED 和 BOOT_COMPLETED 会先后各来一次，快通道超时后线程还可能
     * 多活一会儿 —— 用它挡住重复进入，免得两条链路（或两个漏洞）同时在内核里动手。
     */
    private static final AtomicInteger INFLIGHT = new AtomicInteger();

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent == null || intent.getAction() == null
                ? "开机广播" : intent.getAction();
        String where = label(action);

        // 本轮已经有 root（装过了，或者别的 root 还在）：不再跑漏洞，
        // 只把「安装界面广告设置」补一次。
        if (PostRoot.rootPresent(context)) {
            if (PostRoot.appliedThisBoot(context)) {
                Log.i(TAG, "boot: 本轮已经获取过 Root，跳过（" + action + "）");
                BootLog.record(context, where, "跳过：本轮已经获取过 Root");
                return;
            }
            Log.i(TAG, "boot: 本轮已经有 root，补一次安装界面广告设置（" + action + "）");
            BootLog.record(context, where, "本轮已有 root，补安装界面广告设置");
            final PendingResult postRootPending = goAsync();
            new Thread(() -> {
                boolean ok;
                try {
                    ok = PostRoot.apply(context, new LogSink());
                } catch (Throwable t) {
                    Log.e(TAG, "boot: 安装界面广告设置异常", t);
                    ok = false;
                } finally {
                    postRootPending.finish();
                }
                RmgService.post(context, "DFRoot", ok
                        ? "开机自动：安装界面广告设置已生效（安装器广告已去掉）"
                        : "开机自动：安装界面广告设置没成功，打开 DFRoot 可重试");
            }, "dfroot-postroot-boot").start();
            return;
        }
        if (new File("/dev/df").exists()) {
            Log.i(TAG, "boot: 本轮已经布防过（/dev/df），跳过（" + action + "）");
            BootLog.record(context, where, "跳过：本轮已经布防过（/dev/df）");
            return;
        }
        if (RmgService.busy()) {
            Log.i(TAG, "boot: 前台服务正在跑，跳过（" + action + "）");
            BootLog.record(context, where, "跳过：前台服务正在跑");
            return;
        }
        if (INFLIGHT.getAndIncrement() != 0) {
            INFLIGHT.decrementAndGet();
            Log.i(TAG, "boot: 上一次开机自动还在跑，跳过（" + action + "）");
            BootLog.record(context, where, "跳过：上一次还在跑");
            return;
        }
        Log.i(TAG, "boot: " + action + " → 直接在广播里跑快通道");
        BootLog.record(context, where, "收到广播，开始跑快通道");
        final PendingResult pending = goAsync();
        new Thread(() -> {
            try {
                run(context, action, where);
            } catch (Throwable t) {
                Log.e(TAG, "boot: 开机自动异常", t);
                BootLog.record(context, where, "异常：" + t);
            } finally {
                INFLIGHT.decrementAndGet();
                pending.finish();
            }
        }, "dfroot-boot").start();
    }

    private static String label(String action) {
        if (Intent.ACTION_LOCKED_BOOT_COMPLETED.equals(action)) return "开机（未解锁）";
        if (Intent.ACTION_BOOT_COMPLETED.equals(action)) return "开机完成";
        return action;
    }

    /** 快通道优先，不成再交给前台服务跑 CVE-2026-43499 链路。 */
    private static void run(Context context, String action, String where) {
        boolean manualOnly = Engine.selected(context) == Engine.MANUAL;
        String fastBlock = DeviceCheck.blockReason();
        boolean fastAvailable = !manualOnly && fastBlock == null && DeviceCheck.criticalOk();

        if (fastAvailable) {
            long started = SystemClock.elapsedRealtime();
            FastChain.Result result = runFastInline(context, where);
            long spentMillis = SystemClock.elapsedRealtime() - started;
            if (result == null) {
                long limit = INLINE_BUDGET_MILLIS / 1000;
                Log.w(TAG, "boot: 快通道超过 " + limit + " 秒还没结束，本轮不再叠加第二条链路");
                BootLog.record(context, where,
                        "快通道超过 " + limit + " 秒还在跑，本轮不再叠加第二条链路");
                return;
            }
            Log.i(TAG, "boot: 快通道结果 " + result + "（" + spentMillis + " ms）");
            if (result == FastChain.Result.SUCCESS) {
                BootLog.record(context, where, "快通道走通，ksud 已启动");
                RmgService.post(context, "DFRoot", "开机自动：Root 已就绪（快通道）");
                return;
            }
            if (result == FastChain.Result.FAILED_ARMED) {
                BootLog.record(context, where, "快通道已布防但没走完，本次开机停止");
                RmgService.post(context, "DFRoot",
                        "快通道已布防但没走完，本次开机不再重试（重启手机后再试）");
                return;
            }
            BootLog.record(context, where,
                    "快通道没成（" + (spentMillis / 1000) + " 秒）→ 接着跑 CVE-2026-43499");
        } else if (manualOnly) {
            BootLog.record(context, where, "方案是「手动」，直接跑 CVE-2026-43499 链路");
        } else {
            BootLog.record(context, where, "快通道不可用（"
                    + (fastBlock == null ? "依赖路径缺失" : fastBlock)
                    + "）→ 直接跑 CVE-2026-43499 链路");
        }

        if (Intent.ACTION_LOCKED_BOOT_COMPLETED.equals(action)) {
            // CVE-2026-43499 链路要把 ksud 落到 /data/local/tmp，那是凭据加密存储，解锁前写不进去，
            // 现在跑只会白跑一轮。等「开机完成」（用户解锁）那个广播再来。
            BootLog.record(context, where, "还没解锁，CVE-2026-43499 链路等解锁后再跑");
            return;
        }

        if (RmgService.start(context, "开机自动")) {
            BootLog.record(context, where, "已交给前台服务跑 CVE-2026-43499 链路");
        } else {
            BootLog.record(context, where,
                    "系统不让起前台服务，CVE-2026-43499 链路本次跳过（可打开应用手动跑）");
            RmgService.post(context, "DFRoot", "开机自动：系统不让起前台服务，请打开 DFRoot 手动运行");
        }
    }

    /**
     * 快通道直接在广播里跑（上游 DFRoot 实机验证过的路子）。
     *
     * 返回 null 表示到了时限还没结束 —— 这时不能接着跑第二条链路：两条链路都在内核里
     * 动手，叠在一起太危险。线程继续跑完，结果照样补写进 BootLog。
     */
    private static FastChain.Result runFastInline(Context context, String where) {
        final AtomicReference<FastChain.Result> box = new AtomicReference<>(null);
        final AtomicBoolean gaveUp = new AtomicBoolean(false);
        INFLIGHT.incrementAndGet();
        Thread worker = new Thread(() -> {
            FastChain.Result result = null;
            try {
                result = FastChain.run(context, new LogSink());
            } catch (Throwable t) {
                Log.e(TAG, "boot: 快通道异常", t);
            } finally {
                box.set(result);
                INFLIGHT.decrementAndGet();
                if (gaveUp.get()) {
                    BootLog.record(context, where,
                            "快通道（超时后才结束）结果：" + (result == null ? "异常" : result));
                }
            }
        }, "dfroot-fast");
        worker.start();
        try {
            worker.join(INLINE_BUDGET_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        FastChain.Result result = box.get();
        if (result == null) {
            gaveUp.set(true);
            Log.w(TAG, "boot: 快通道还在跑（已等 " + (INLINE_BUDGET_MILLIS / 1000) + " 秒）");
        }
        return result;
    }

    /** 广播里没有界面，快通道的输出直接进 logcat。 */
    private static final class LogSink implements Sink {
        @Override
        public void report(String message) {
            log(message);
        }

        @Override
        public void log(String message) {
            if (message == null || message.trim().isEmpty()) return;
            Log.i(TAG, message.trim());
        }

        @Override
        public void progress(String status) {
            if (status != null && !status.isEmpty()) Log.i(TAG, status);
        }
    }
}
