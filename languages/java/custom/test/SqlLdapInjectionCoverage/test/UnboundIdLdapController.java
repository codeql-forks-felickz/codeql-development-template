package test;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import org.springframework.web.bind.annotation.RequestParam;
import test.annotations.AppRequestMapping;
import test.annotations.AppRestController;

// Spring controller declared through custom meta-annotations, searching with UnboundID.
@AppRestController("LDAPInjection")
public class UnboundIdLdapController {
  private LDAPConnection connection;

  private SearchResult searchUsers(String filter) throws Exception {
    return connection.search("dc=example,dc=org", SearchScope.SUB, filter); // $ Alert[java/ldap-injection]
  }

  @AppRequestMapping("LEVEL_1")
  public Object level1(@RequestParam(required = false) String username) // $ Source[java/ldap-injection]
      throws Exception {
    return searchUsers("(uid=" + username + ")");
  }

  @AppRequestMapping("LEVEL_2")
  public Object level2Secure(@RequestParam(required = false) String username) throws Exception {
    return searchUsers("(uid=" + Filter.encodeValue(username) + ")");
  }
}
