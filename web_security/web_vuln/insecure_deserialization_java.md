# Insecure Deserialization - Java

## Serialization
The fundamental purpose of serialization is to convert the state of an object into a format (i.e, `byte stream`) that can be stored and transmitted over a network link for future consumption.

> Serializable is a **marker interface**. It has no `data member` and `method`. It is only used to "mark" java classes so that objects of these classes may get a certain capability.

Create a `User` class and make it `serializable`.

```java
public class User implements java.io.Serializable {
  private String name;
  private final String nickname;
  static int uid;
  private transient String password;
  private double weight;

  public User(String name, String nickname, int uid, String password, double weight) {
    this.name = name;
    this.nickname = nickname;
    this.uid = uid;
    this.password = password;
    this.weight = weight;
  }

  }

  // this method will be called when we try to print the object
  public String toString() {
    return name + " : " + nickname + " : " + uid + " : " + password + " : " + weight + " : ";
  }
}
```

Create an object of the `User` class and save it into the file system in `.ser` format.

## Deserialization
Deserialization is the reverse process where the byte stream is used to recreate the actual java object in memory.
