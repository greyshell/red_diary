# Insecure Deserialization - Java

## Serialization

The fundamental purpose of serialization is to convert the state of an object into a format (i.e, `byte stream`) that can be stored and transmitted over a network link for future consumption.

> `Serializable` is a `marker interface`. It has no `data member` and `method`. 
> It is only used to `mark` java classes so that objects of these type of classes may get a certain capability.

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

  public String toString() {
    return name + " : " + nickname + " : " + uid + " : " + password + " : " + weight + " : ";
  }
}
```

Create an object of the `User` class and save into the file system in `.ser` format.

```java
import java.io.*;

public class BasicSerialize {
    public static void main(String[] args) {
        try {
            User asinha = new User("bob", "shell", 2, "splunk", 80.5);
            System.out.println(asinha); // invokes User.toString() method

            String file_name = "serialized_object.ser";
            FileOutputStream fout = new FileOutputStream(file_name);
            ObjectOutputStream oout = new ObjectOutputStream(fout);
            oout.writeObject(asinha);

            oout.close();
            fout.close();
            System.out.println("User object is written to disk as " + file_name);
        } 
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

## Deserialization
Deserialization is the reverse process where the byte stream is used to recreate the actual java object in memory.
