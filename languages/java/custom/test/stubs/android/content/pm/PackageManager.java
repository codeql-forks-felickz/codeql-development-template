package android.content.pm;

import java.util.List;

public abstract class PackageManager {
    public static class NameNotFoundException extends Exception { }
    public abstract List<PackageInfo> getInstalledPackages(int flags);
}
