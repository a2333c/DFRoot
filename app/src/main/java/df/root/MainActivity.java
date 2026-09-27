package df.root;

import android.Manifest;
import android.content.ComponentName;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;

import androidx.appcompat.app.AppCompatActivity;

import df.root.databinding.ActivityMainBinding;

import java.io.File;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * 两条链路，一个界面：
 *
 *   快通道  DirtyFrag（CVE-2026-43284）—— 上游 diabl0w/DFRoot 那条，几秒到几十秒
 *   CVE-2026-43499（Root My Galaxy）—— 概率型，三轮阶梯，最长十几分钟
 *
 * 默认「自动」：先跑快通道；它没成、而且没留下布防痕迹（/dev/df 不存在）时，才自动
 * 接 CVE-2026-43499。已经布防过就不再叠加第二个漏洞 —— 两条链路都在内核里动手，
 * 在脏状态上叠着跑是自找麻烦。
 *
 * 方案只有「自动」和「手动」两项：以前那个「只用快通道」已经去掉，自动模式的第一步
 * 就是快通道，单独留着那一项没有意义；自动没成功时，切到「手动」再试那条概率型链路。
 */
public class MainActivity extends AppCompatActivity implements Sink {

    private static final String TAG = "dfroot";
    private static final int REQ_NOTIFICATIONS = 0x52;

    static { System.loadLibrary("exp"); }

    private ActivityMainBinding binding;
    private final Handler mMain = new Handler(Looper.getMainLooper());
    private final Executor mExec = Executors.newSingleThreadExecutor();
    private volatile boolean running;

    /** 快通道的原生回调。 */
    @Override
    public void report(String message) {
        log(message);
    }

    @Override
    public void log(String message) {
        if (message == null || message.isEmpty()) return;
        mMain.post(() -> {
            binding.outputView.append(message);
            binding.outputScroll.post(() -> binding.outputScroll.fullScroll(View.FOCUS_DOWN));
        });
    }

    @Override
    public void progress(String status) {
        if (status == null) return;
        mMain.post(() -> binding.statusText.setText(status));
    }

    static native int nativeRunAll(IReporter reporter, int encapPort, int spi,
                                   byte[] aesCbcKey, byte[] hmacKey, int icvLen,
                                   int senderPort, String ksudPath, boolean skipSoftReboot);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        setSupportActionBar(binding.toolbar);

        requestNotificationPermission();
        refreshRunState();
        refreshBootLog();

        Engine selectedEngine = Engine.selected(this);
        binding.engineAuto.setChecked(selectedEngine == Engine.AUTO);
        binding.engineManual.setChecked(selectedEngine == Engine.MANUAL);
        binding.engineGroup.setOnCheckedChangeListener((group, checkedId) -> {
            Engine.select(this, checkedId == R.id.engineManual ? Engine.MANUAL : Engine.AUTO);
            binding.outputView.setText("");
            refreshRunState();
        });

        binding.btnRun.setOnClickListener(v -> {
            if (running) return;
            running = true;
            binding.btnRun.setEnabled(false);
            binding.btnRun.setText(R.string.btn_run_running);
            binding.outputView.setText("");
            mExec.execute(this::runSelected);
        });

        ComponentName bootReceiver = new ComponentName(this, BootReceiver.class);
        int state = getPackageManager().getComponentEnabledSetting(bootReceiver);
        binding.switchBootStart.setChecked(state != PackageManager.COMPONENT_ENABLED_STATE_DISABLED);
        binding.switchBootStart.setOnCheckedChangeListener((btn, checked) ->
                getPackageManager().setComponentEnabledSetting(bootReceiver,
                        checked ? PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                                : PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                        PackageManager.DONT_KILL_APP));
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (!running) {
            refreshRunState();
            refreshBootLog();
        }
        retryPostRoot();
    }

    /**
     * 打开应用时补一次「安装界面广告设置」：root 已经就位、但本轮还没设置成功时再来一次
     * （顺便让 KernelSU 的授权弹窗有机会弹出来，用户点一下就好了）。
     */
    private void retryPostRoot() {
        if (PostRoot.appliedThisBoot(this) || !PostRoot.rootPresent(this)) return;
        PostRoot.applyAsync(this, this);
    }

    private void runSelected() {
        try {
            String reason = blockReason();
            if (reason != null) {
                log("已中止：" + reason + "\n");
                return;
            }
            Engine engine = Engine.selected(this);
            if (engine == Engine.MANUAL) {
                log(DeviceCheck.report());
                runRmg();
                return;
            }
            runAuto();
        } finally {
            running = false;
            mMain.post(() -> {
                binding.btnRun.setText(runButtonLabel());
                binding.btnRun.setEnabled(true);
                refreshRunState();
            });
        }
    }

    /** 自动：快通道优先，不成再接 CVE-2026-43499。 */
    private void runAuto() {
        log(DeviceCheck.report());
        String fastBlock = DeviceCheck.blockReason();
        if (fastBlock != null) {
            log("\n自动模式：快通道不可用（" + fastBlock + "）→ 直接用 CVE-2026-43499。\n");
            runRmg();
            return;
        }
        log("\n=== 自动模式 · 第 1 步：快通道 DirtyFrag（几秒到几十秒）===\n");
        FastChain.Result result = FastChain.run(this, this);
        reportFastResult(result);
        if (result == FastChain.Result.SUCCESS) return;
        if (result == FastChain.Result.FAILED_ARMED) return;
        log("\n快通道没成，内核也没有留下布防痕迹 → 自动接 CVE-2026-43499。\n");
        runRmg();
    }

    private void reportFastResult(FastChain.Result result) {
        switch (result) {
            case SUCCESS:
                log("\n成功：快通道走通，ksud 已启动，KernelSU 正在加载。\n");
                break;
            case FAILED_ARMED:
                log("\n失败：已经布防（/dev/df 存在）但没走完。两条链路都在内核里动手，"
                        + "不在脏状态上叠加第二个漏洞 —— 请重启手机后再试。\n");
                break;
            default:
                log("\n失败：快通道没走通，也没有留下布防痕迹。\n");
                break;
        }
    }

    /** CVE-2026-43499 链路（手动方案，三轮阶梯）。 */
    private void runRmg() {
        try {
            String reason = RmgChain.blockReason(this);
            if (reason != null) {
                log("已中止：" + reason + "\n");
                return;
            }
            log(RmgChain.report(this));
            log("\n开始执行 CVE-2026-43499 链路（手动方案），共 " + RmgChain.LADDER.length
                    + " 轮，先快后慢，成功即停……\n");
            RmgChain.runLadder(this, this);
            log("\n成功：KernelSU 已安装。打开 KernelSU 管理器确认状态。\n");
        } catch (Throwable t) {
            Log.e(TAG, "rmg chain failed", t);
            log("\n失败：" + t + "\n");
            log("提示：这条链路是概率型的，本轮已经自动按“快 → 稳 → 耐心”重试过。"
                    + "重启手机后，本应用会在开机时自动再试一次。\n");
        }
    }

    /** 能不能跑；不能跑时把原因显示在状态栏。 */
    private void refreshRunState() {
        if (RmgChain.installedThisBoot(this)) {
            binding.statusText.setText(R.string.status_done);
            binding.statusText.setTextColor(Color.parseColor("#1B8A2E"));
            binding.btnRun.setEnabled(false);
            binding.btnRun.setText(R.string.btn_run_done);
            return;
        }
        String reason = blockReason();
        if (reason == null) {
            binding.statusText.setText(R.string.status_ready);
            binding.statusText.setTextColor(Color.parseColor("#1B8A2E"));
            binding.btnRun.setEnabled(true);
            binding.btnRun.setText(runButtonLabel());
        } else {
            binding.statusText.setText(reason);
            binding.statusText.setTextColor(Color.parseColor("#C62828"));
            binding.btnRun.setEnabled(false);
            binding.btnRun.setText(R.string.btn_run_blocked);
        }
    }

    private int runButtonLabel() {
        return Engine.selected(this) == Engine.MANUAL ? R.string.btn_run : R.string.btn_run_auto;
    }

    /** null 表示可以跑。 */
    private String blockReason() {
        String su = DeviceCheck.existingSu();
        if (su != null) {
            return "检测到已有 root（" + su + " 存在），请先重启手机再运行本应用";
        }
        if (RmgChain.installedThisBoot(this)) {
            return "本轮已经成功安装过 KernelSU，重启手机前不需要再跑一次";
        }
        if (new File("/dev/df").exists()) {
            return "本轮已布防（/dev/df 存在），需要硬重启手机后才能再次运行";
        }
        Engine engine = Engine.selected(this);
        if (engine == Engine.MANUAL) return RmgChain.blockReason(this);
        // 自动：两条里有一条能用就行
        if (DeviceCheck.criticalOk()) return null;
        return RmgChain.blockReason(this);
    }

    /** 界面上那一行「上次开机自动：…」，出问题时一眼就能看出广播有没有到。 */
    private void refreshBootLog() {
        String last = BootLog.summary(this);
        binding.bootLog.setText(getString(R.string.boot_log_label)
                + (last == null ? getString(R.string.boot_log_none) : last));
    }

    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT < 33) return;
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                == PackageManager.PERMISSION_GRANTED) return;
        requestPermissions(new String[] { Manifest.permission.POST_NOTIFICATIONS }, REQ_NOTIFICATIONS);
    }
}
