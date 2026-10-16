package test;

// Daemon loops outside of request handlers are out of scope.
public class NotAHandler implements Runnable {
  @Override
  public void run() {
    while (true) {
      System.out.println("tick");
    }
  }

  public static void main(String[] args) {
    for (;;) {
      System.out.println("serve");
    }
  }
}
