package df.root;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

import java.io.File;

// 前台服务：跑链路（CVE-2026-43499 那条最长十几分钟，装不进广播的执行窗口，必须有它兜着）。
//
// 开机自动时由 BootReceiver 在广播里先把快通道跑掉（几秒），没成再把它叫起来接着跑
// CVE-2026-43499 链路；手动点按钮时由 MainActivity 直接跑，不经过这里。
//
// 顺序与手动点按钮一致：
//   · 方案「自动」→ 先快通道 DirtyFrag（几秒），它没成再跑 CVE-2026-43499 的三轮阶梯；
//   · 方案「手动」→ 直接跑三轮阶梯。
// 快通道如果布防了（/dev/df）却没走完，本轮就不再叠加第二个漏洞，只发通知提醒重启。
public class RmgService extends Service implements Sink {

    private static final String TAG = "dfroot";
    private static final String CHANNEL_ID = "dfroot-root";
    private static final int NOTIFICATION_ID = 0x52;
    private static final String EXTRA_SOURCE = "source";

    private volatile Thread worker;

    /** 正在跑链路。开机广播拿它做互斥，免得两条链路同时在内核里动手。 */
    private static volatile boolean busy;

    static boolean busy() {
        return busy;
    }

    /**
     * 起前台服务跑链路。
     *
     * 返回 false 表示系统不让起（Android 12+ 的后台启动限制）—— 调用方得自己想办法，
     * 不能当没事发生：v1.5 就是在这里静悄悄失败的。
     */
    static boolean start(Context context, String source) {
        Intent intent = new Intent(context, RmgService.class);
        intent.putExtra(EXTRA_SOURCE, source);
        try {
            context.startForegroundService(intent);
            return true;
        } catch (Throwable t) {
            Log.e(TAG, "起前台服务被系统拒绝", t);
            BootLog.record(context, source, "前台服务被系统拒绝：" + t.getClass().getSimpleName());
            return false;
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        ensureChannel(getSystemService(NotificationManager.class));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        try {
            startForeground(NOTIFICATION_ID, buildNotification("正在获取 Root…"));
        } catch (Throwable t) {
            Log.e(TAG, "前台服务启动失败", t);
            BootLog.record(this, "前台服务", "startForeground 失败：" + t);
            stopSelf();
            return START_NOT_STICKY;
        }
        if (worker != null && worker.isAlive()) return START_NOT_STICKY;
        String source = intent == null ? null : intent.getStringExtra(EXTRA_SOURCE);
        final String label = source == null ? "手动运行" : source;
        busy = true;
        Thread thread = new Thread(() -> runChain(label), "dfroot-root");
        worker = thread;
        thread.start();
        return START_NOT_STICKY;
    }

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
        if (status == null || status.isEmpty()) return;
        Log.i(TAG, status);
        notify(status);
    }

    private void runChain(String source) {
        try {
            if (RmgChain.installedThisBoot(this)) {
                Log.i(TAG, source + "：本轮已经装过 KernelSU，跳过");
                BootLog.record(this, source, "跳过：本轮已经装过 KernelSU");
                return;
            }
            if (new File("/dev/df").exists()) {
                Log.i(TAG, source + "：本轮已经布防过（/dev/df），跳过");
                BootLog.record(this, source, "跳过：本轮已经布防过（/dev/df）");
                return;
            }

            String fastBlock = DeviceCheck.blockReason();
            boolean fastAvailable = Engine.selected(this) == Engine.AUTO
                    && fastBlock == null && DeviceCheck.criticalOk();

            if (fastAvailable) {
                Log.i(TAG, source + "：先跑快通道 DirtyFrag");
                notify("正在获取 Root（快通道 DirtyFrag）…");
                FastChain.Result result = FastChain.run(this, this);
                if (result == FastChain.Result.SUCCESS) {
                    Log.i(TAG, source + "：快通道走通（ksud 已启动）");
                    BootLog.record(this, source, "快通道走通，ksud 已启动");
                    notify("Root 已就绪（快通道）");
                    return;
                }
                if (result == FastChain.Result.FAILED_ARMED) {
                    Log.w(TAG, source + "：快通道已布防但没走完，本轮不再叠加第二个漏洞");
                    BootLog.record(this, source, "快通道已布防但没走完，本轮停止");
                    notify("快通道已布防但没走完，本次开机不再重试（重启手机后再试）");
                    return;
                }
                Log.i(TAG, source + "：快通道没成 → 改用 CVE-2026-43499（手动方案）");
            }

            String reason = RmgChain.blockReason(this);
            if (reason != null) {
                Log.w(TAG, source + "：已中止 —— " + reason);
                BootLog.record(this, source, "已中止：" + reason);
                notify("已中止：" + reason);
                return;
            }
            log(RmgChain.report(this));
            RmgChain.runLadder(this, this);
            BootLog.record(this, source, "CVE-2026-43499 链路走通，KernelSU 已安装");
            notify("Root 已就绪");
        } catch (Throwable t) {
            Log.e(TAG, source + "：获取 Root 失败", t);
            log("[-] 获取 Root 失败：" + t);
            BootLog.record(this, source, "失败：" + t);
            notify("获取 Root 失败：" + t.getMessage() + "（下次开机会自动再试）");
        } finally {
            busy = false;
            worker = null;
            stopForeground(STOP_FOREGROUND_DETACH);
            stopSelf();
        }
    }

    private static void ensureChannel(NotificationManager manager) {
        if (manager == null || manager.getNotificationChannel(CHANNEL_ID) != null) return;
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "DFRoot", NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("获取 Root 的进度");
        manager.createNotificationChannel(channel);
    }

    /** 不启动服务，只发一条普通通知（失败时提醒用）。 */
    static void post(Context context, String title, String text) {
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        if (manager == null) return;
        ensureChannel(manager);
        Notification notification = new Notification.Builder(context, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .build();
        manager.notify(NOTIFICATION_ID + 1, notification);
    }

    private Notification buildNotification(String text) {
        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_download)
                .setContentTitle("DFRoot")
                .setContentText(text)
                .setOngoing(true)
                .build();
    }

    private void notify(String text) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager == null) return;
        manager.notify(NOTIFICATION_ID, buildNotification(text));
    }
}
