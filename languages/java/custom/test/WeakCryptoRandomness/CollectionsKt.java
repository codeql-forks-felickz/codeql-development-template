package kotlin.collections;

import java.util.List;
import java.util.Random;

public class CollectionsKt {
  public static <T> List<T> shuffled(List<T> values) {
    return values;
  }

  public static <T> List<T> shuffled(List<T> values, Random random) {
    return values;
  }

  public static <T> T first(List<T> values) {
    return values.get(0);
  }
}
