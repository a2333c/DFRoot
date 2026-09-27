package df.root;

/**
 * 链路把进度回传给界面的通道。
 *
 * 继承 IReporter 是因为快通道的原生代码只会通过 report() 回调。
 */
interface Sink extends IReporter {

    void log(String message);

    /** 进度（给通知栏 / 状态栏用），不关心可以不实现。 */
    default void progress(String status) {
    }
}
