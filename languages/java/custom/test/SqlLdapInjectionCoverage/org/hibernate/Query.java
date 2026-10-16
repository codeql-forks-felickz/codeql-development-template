package org.hibernate;

public interface Query {
  java.util.List list();

  Query setParameter(String name, Object value);
}
