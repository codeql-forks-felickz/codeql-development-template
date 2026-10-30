package org.example.spring.bio;

public class Bio {
  private int id;
  private int userId;
  private String bioText;

  public Bio(int id, int userId, String bioText) {
    this.id = id;
    this.userId = userId;
    this.bioText = bioText;
  }

  public Bio(int userId, String bioText) {
    this.userId = userId;
    this.bioText = bioText;
  }

  public int getId() {
    return id;
  }

  public void setId(int id) {
    this.id = id;
  }

  public int getUserId() {
    return userId;
  }

  public String getBioText() {
    return bioText;
  }
}
