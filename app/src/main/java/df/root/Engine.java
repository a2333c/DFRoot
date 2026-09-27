package df.root;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Root 方案。现在只有两个：
 *
 *   自动 —— 先跑快通道 DirtyFrag（CVE-2026-43284，几秒），不成再自动接 CVE-2026-43499；
 *   手动 —— 只跑 CVE-2026-43499（Root My Galaxy 那条，三轮阶梯，最长十几分钟），
 *           自动没成功时用它手动再试。
 *
 * 以前还有一个「只用快通道」的选项，已经去掉：自动模式的第一步就是快通道，
 * 单独留着那一项没有意义。
 *
 * 读写一律走设备加密存储（DE）：开机自动是在用户解锁之前触发的，
 * 那时凭据加密存储（CE）读不出来，方案就会退回默认值（自动）。
 */
enum Engine {

    AUTO,
    MANUAL;

    private static final String PREFS = "dfroot";
    private static final String KEY = "engine";

    static Engine selected(Context ctx) {
        SharedPreferences prefs = ctx.createDeviceProtectedStorageContext()
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        // 老版本存过 "rmg"（手动方案）和 "dirtyfrag"（已取消的方案）：
        // 前者就是「手动」，后者当成「自动」—— 自动的第一步照样是快通道。
        String stored = prefs.getString(KEY, null);
        return "manual".equals(stored) || "rmg".equals(stored) ? MANUAL : AUTO;
    }

    static void select(Context ctx, Engine engine) {
        ctx.createDeviceProtectedStorageContext()
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .putString(KEY, engine == MANUAL ? "manual" : "auto")
                .apply();
    }
}
