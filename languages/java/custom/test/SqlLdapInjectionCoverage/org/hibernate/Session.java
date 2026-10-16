package org.hibernate;

public interface Session {
  Query createQuery(String queryString);
}
