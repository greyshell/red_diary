## Insecure Deserialization - Java

> Serializable is a **marker interface**. It has no `data member` and `method`. It is only used to "mark" java classes so that objects of these classes may get a certain capability.

The fundamental purpose of serialization is to convert the state of an object into a format (for example, `byte stream`) that can be stored and transmitted over a network link for future consumption.

