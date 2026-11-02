import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;

class Permissions {
  void chmodStringConcat(File batFile) throws IOException {
    batFile.setExecutable(true);
    Runtime runtime = Runtime.getRuntime();
    runtime.exec("chmod 777 " + batFile.getAbsolutePath()); // $ Alert
  }

  void chmodRecursive(String dir) throws IOException {
    Runtime.getRuntime().exec("/bin/chmod -R 0666 " + dir); // $ Alert
  }

  void chmodSymbolic(String path) throws IOException {
    Runtime.getRuntime().exec("chmod a+rwx " + path); // $ Alert
  }

  void chmodTokens(String path) throws IOException {
    Runtime.getRuntime().exec(new String[] {"chmod", "o+w", path}); // $ Alert
    new ProcessBuilder("chmod", "-R", "777", path).start(); // $ Alert
    new ProcessBuilder(Arrays.asList("chmod", "1777", path)).start(); // $ Alert
  }

  void setWritableForAll(File f) {
    f.setWritable(true, false); // $ Alert
  }

  void posixOthersWrite(Path p) throws IOException {
    Files.setPosixFilePermissions(p, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OTHERS_WRITE)); // $ Alert
  }

  void posixFromString(Path p) throws IOException {
    Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwxrwxrwx"); // $ Alert
    Files.setPosixFilePermissions(p, perms);
  }

  // Safe cases below.

  void chmodRestrictive(File f, String path, String mode) throws IOException {
    Runtime.getRuntime().exec("chmod 755 " + f.getAbsolutePath());
    Runtime.getRuntime().exec("chmod 0700 " + path);
    Runtime.getRuntime().exec("chmod u+x " + path);
    Runtime.getRuntime().exec("chmod go-w " + path);
    Runtime.getRuntime().exec("chmod " + mode + " " + path);
    Runtime.getRuntime().exec(new String[] {"chmod", "750", path});
    new ProcessBuilder("chmod", "-R", "u+rwx,o+r", path).start();
    new ProcessBuilder("ls", "777").start();
  }

  void setWritableOwnerOnly(File f) {
    f.setWritable(true);
    f.setWritable(true, true);
    f.setWritable(false, false);
  }

  void posixOwnerOnly(Path p) throws IOException {
    Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwxr-xr-x"));
    Files.setPosixFilePermissions(p, EnumSet.of(PosixFilePermission.OWNER_WRITE, PosixFilePermission.OTHERS_READ));
  }
}
