package org.springframework.util;

import java.util.List;
import java.util.Map;

public interface MultiValueMap<K, V> extends Map<K, List<V>> {
  void add(K key, V value);

  void set(K key, V value);
}
