package df.root;

import android.content.Context;
import android.content.SharedPreferences;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * 记录"上次开机自动到底做了什么"。
 *
 * 开机自动出问题时最难判断的就是"广播到底有没有收到"。这里每一步都写一笔，
 * 界面上直接把最后一条显示出来 —— 看到"还没有记录"就说明广播压根没到
 * （应用没被启动过、被电池策略冻住、或者开关没开）。
 *
 * 记录放设备加密存储（DE），因为开机时用户还没解锁。
 */
final class BootLog {

    private static final String PREFS = "boot_log";
    private static final String KEY_TIME = "time";
    private static final String KEY_ACTION = "action";
    private static final String KEY_RESULT = "result";

    private BootLog() {}

    static void record(Context context, String action, String result) {
        SharedPreferences prefs = context.createDeviceProtectedStorageContext()
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        // 用 commit 而不是 apply：最后一条记录后面很可能紧跟一次 soft reboot（ksud 重启
        // 系统框架），异步写盘会被一起带走，界面上就看不到这次开机到底跑到哪一步了。
        prefs.edit()
                .putString(KEY_TIME, new SimpleDateFormat("MM-dd HH:mm:ss", Locale.US)
                        .format(new Date()))
                .putString(KEY_ACTION, action)
                .putString(KEY_RESULT, result)
                .commit();
    }

    /** 界面用的一行摘要；没有任何记录时返回 null。 */
    static String summary(Context context) {
        SharedPreferences prefs = context.createDeviceProtectedStorageContext()
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String time = prefs.getString(KEY_TIME, null);
        if (time == null) return null;
        return time + "　" + prefs.getString(KEY_ACTION, "?")
                + "　" + prefs.getString(KEY_RESULT, "?");
    }
}
