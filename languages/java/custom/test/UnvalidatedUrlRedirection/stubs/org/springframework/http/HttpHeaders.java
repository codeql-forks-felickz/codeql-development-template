package org.springframework.http;

import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.util.MultiValueMap;

public class HttpHeaders implements MultiValueMap<String, String> {
  public static final String LOCATION = "Location";

  public void add(String key, String value) {}

  public void set(String key, String value) {}

  public void setLocation(URI location) {}

  public int size() { return 0; }

  public boolean isEmpty() { return true; }

  public boolean containsKey(Object key) { return false; }

  public boolean containsValue(Object value) { return false; }

  public List<String> get(Object key) { return null; }

  public List<String> put(String key, List<String> value) { return null; }

  public List<String> remove(Object key) { return null; }

  public void putAll(Map<? extends String, ? extends List<String>> m) {}

  public void clear() {}

  public Set<String> keySet() { return null; }

  public Collection<List<String>> values() { return null; }

  public Set<Map.Entry<String, List<String>>> entrySet() { return null; }
}
