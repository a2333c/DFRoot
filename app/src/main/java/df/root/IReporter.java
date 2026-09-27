package df.root;

/** 快通道（DirtyFrag）的原生代码用它把进度回传给 Java。 */
public interface IReporter {
    void report(String msg);
}
