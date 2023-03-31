---
layout: post
title: "Insecure Deserialization in Java"
date: 2019-11-22 22:17:55 -0800
comments: true
categories: web-security
---

I was always curious about how the actual remote code execution occurs during the Insecure `Deserialization` process. So I thought of giving a try to understand the known harmful `gadgets` from `commons-collections-3.2.2.jar` and develop the entire chain from scratch.

<!-- more -->

## Serialization

Before directly jump into the `gadget chain` preparation, let's try to understand the root cause of "Insecure Deserialization".

> Serializable is a **marker interface**. It has no `data member` and `method.`
> It is used to "mark" java classes so that objects of these classes may get a certain capability.

The fundamental `purpose` of serialization is to `convert` the `data structure` (i.e., state of an object) into a `format` (for Example: `byte stream`) that can be `stored` and `transmitted` over a network link for future `consumption.`

**Example**:

Serialize the `User` class.

{% include_code ../insecure_deserialization_java.assets/User.java %}

{% include_code ../insecure_deserialization_java.assets/BasicSerialize.java %}

![ser](insecure_deserialization_java.assets/ser.png)

## Deserialization

Deserialization is the reverse process where the `byte stream` is used to `recreate` the `actual` Java object in memory.

**Example**:

Deserialize `User` class.

{% include_code ../insecure_deserialization_java.assets/BasicDeserialize.java %}

![dser](insecure_deserialization_java.assets/dser.png)

Recreate the same `asinha` object in the memory.

However, due to `transient` and `static` keyword, the `uid` and `password` fields have only the default values.

## The Bug

1. The `readObject` method of `java.io.ObjectInputStream` is vulnerable.

2. During the Deserialization process, the `readObject()` method is always being called, and it can `construct` any sort of `Serializable` object that can be found on the Java `classpath` before passing it back to the `caller` for the `type_check.`

3. `Exception` can only happen if a type miss-match occurs between the return object and the expected object.

![bad_dser](insecure_deserialization_java.assets/bad_dser.png)

```bash
java.lang.ClassCastException: class java.lang.String cannot be cast to class User (java.lang.String is in module java.base of loader 'bootstrap'; User is in unnamed module of loader 'app')
    at BasicDeserialize.main(BasicDeserialize.java:20)
```

So if the constructed object `happens to do anything dangerous` during its construction, then it is too late to stop at the point of type ` checking ` of that `returned` object.

## Impact

- Remote code execution through property oriented programming(i.e `Property Oriented Programming`) / Gadget Chaining.
- Bypass authorization / escalate privilege via Insecure Direct Object Reference if the object's signature is not verified.
- DoS like consuming the `Heap` memory.

### Perform DoS Attack

Producer Application:

{% include_code ../insecure_deserialization_java.assets/BasicDosExploit.java %}

Consumer Application:

{% include_code ../insecure_deserialization_java.assets/BasicDosDeserialize.java %}

Result:

If we supply that `base64` encoded evil object through command_line argument, then during the Deserialization process, it consumes `100%` CPU cycle.

Following interesting payloads will directly `kill` the process.

```
[+] payload 1:
cat ../../../../../../web-attacks/insecure_deserialization/java_dos/topolik/8gb-nested-hashmap
rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABBAAAAAc3EAfgAAP0AAAAAAAAx3CAAAABBAAAAAcHB4cHg=

[*] result:
Exception in thread "main" java.lang.OutOfMemoryError: Java heap space

[+] payload 2:
cat ../../../../../../web-attacks/insecure_deserialization/java_dos/topolik/8gb-generic
rO0ABX1////3

[*] result:
java.io.InvalidObjectException: interface limit exceeded: 2147483639
```

## How to Identify

1. From Blackbox perceptive:
    - Check for `AC ED 00 05` or `rO0A` (base64 encoded format) magic numbers in request / response, to know that the application deals with a `serialized` object.

2. `Content-type` header of an HTTP response set to `application/x-java-serialized-object`.

3. From Whitebox perceptive:
    - Search for the Java Serialization APIs such as `ObjectInputStream` with `readObject` keywords through out the code base and check how the `ObjectInputStream` is used.
    - Before the `readObject()` method call, does the code check for all expected classes from the `serialized` object through a `whitelist`.

## How to Exploit

The black box angle uses `ysoserial.jar` and iterates different payloads to generate the serialized object.

```bash
java -jar ysoserial-master-30099844c6-1.jar CommonsCollections5 gnome-calculator > /root/code-dev/java/demo_insecure_deserialization/Serialization/bad_serialized_object_ysoserial.ser
```

![ysoserial](insecure_deserialization_java.assets/ysoserial_cal.png)

Alternate:

- Burp Suite Plug-in: [Java Serial Killer](https://blog.netspi.com/java-deserialization-attacks-burp/)

## How to Fix

- Don't blindly accept serialized objects from `untrusted` sources. Implement integrity check / sign the serialized object to prevent hostile object creation/tampering.
- Whitelist based approach to harden own `java.io.ObjectInputStream`:
   1. Create a `HashSet` using all `excepted` classes wrapped in the Object.
   2. Create a `SafeObjectInputStream` class by `extending` the `ObjectInputStream` class.
   3. Overwrite the `resolveClass()` method and check if the `cls.getName()` exists within the `HashSet` else throw `InvalidClassException` exception.

{% include_code ../insecure_deserialization_java.assets/SafeDeserialize.java %}

{% include_code ../insecure_deserialization_java.assets/SafeObjectInputStream.java %}

![fix](insecure_deserialization_java.assets/fix.png)

- Virtual patching / JVM wide fix: Harden, all `java.io.ObjectInputStream` usage with an Agent through a blacklist. Example: `contrast-rO0`.
- The `readObject()` method should be inside the `try/catch` block because any mismatch occurs between the `serialized` object and `expected` object during type_check, then the `Exception` has to be handled properly.
- `transient` keyword is used not to `serialize` a variable like the `password` field. When JVM comes across `transient` or `static` keyword, it ignores the original value of the variable and saves the `default` value of that variable data type.
- Some objects may be forced to implement `Serializable` due to their hierarchy. To guarantee that your application objects can't be deserialized, a `readObject()` method should be declared (with a `final` modifier) which always throws an exception:
```java
private final void readObject(ObjectInputStream in) throws java.io.IOException {
   throw new java.io.IOException("Cannot be deserialized");
}
```

- You can use Java Security Manager to block specific classes.
- Detective control: `Log` the exceptions and failures that happen during deserialization.

> DoS is unavoidable if the expected object type is HashSet / HashMap / ArrayList.

## How to inspect Java libraries and `classpaths` for Gadget Chains

**Automated approach**: To find the existence of one / more gadget chains, run `Gadget Inspector` on all libraries (i.e. `commons-collections-3.2.2.jar`) present in the Java classpaths.

```
java -Xmx2G -jar build/libs/gadget-inspector-all.jar /root/code-dev/java/JavaExternalLibs/commons-collections-3.2.2.jar
```

The tool found 1 `gadget chains` and saved the result in `gadget-chains.txt.`

![](insecure_deserialization_java.assets/gadget-inspector.png)

**Limitation of the tool**:

- Not always an `exploit` can be built from the result.
- It can produce a `false negative` result.

## Demystifying a Known Gadget Chain

> - Technique is called property oriented programming.
>- JRE System Libraries (default, available in every Java program):
>   - HashMap
>- commons-collections-3.2.2.jar:
>    - Transformer, ConstantTransformer, InvokerTransformer, ChainedTransformer
>    - LazyMap, TiedMapEntry, HashBag

### Command Execution using `Runtime`

> First, let's understand how we can execute a command in Java.

- We can use the `Runtime` Object in Java to execute system command (i.e., Running the gnome-calculator)

{% include_code ../insecure_deserialization_java.assets/Concept01.java %}

### Reflection API

> What are the other ways we can execute a command in Java.

- Reflection is an API that is used to `examine` or `modify` the behavior of methods, classes, interfaces at `runtime.`

- **Key Point:** Through reflection API, we can `invoke` `methods` at `runtime` irrespective of the access specifier used.

{% include_code ../insecure_deserialization_java.assets/Concept02.java %}

Execute the gnome-calculator using Reflection API.

### Transformer

- **Key Point:** A Transformer transforms an `input` object to an `output` object through `transform()` method.
- It doesn't change the input object.
- Mainly used for:
  1. Type conversion
  2. Extracting parts of an object

{% include_code ../insecure_deserialization_java.assets/MyReverse.java %}

{% include_code ../insecure_deserialization_java.assets/Concept03.java %}

Passing a `String `object to a `Transformer` and `transform()` method reverses the input `String` and finally returns the `String` object.

Different categories of `Transformers`:

### ConstantTransformer

- **Key Point:** Always returns the `same` object `specified during initialization.`

{% include_code ../insecure_deserialization_java.assets/Concept04.java %}

Initializing a `ConstantTransformar` with `Runtime.class` so that we can call the `transform()` method with any object and expecting `Runtime.class` returns type.

### InvokerTransformer

- It takes a `method name` with optional parameters during initialization.
- On `transform,` calls that `method` for the `object` provided with the parameters.

{% include_code ../insecure_deserialization_java.assets/Concept05.java %}

Invoke the `toString()` method of a Dashboard object via `InvokerTransformer.`

While initializing the `InvokerTransformer,` we need to install a method by supplying method_name, argument_type, and argument.

We can't install any arbitrary method here. The method should be present in the same class whose object we are going to pass on the transform() method.

### Command Execution by `combining` reflection API, ConstantTransformer and InvokerTransformer

{% include_code ../insecure_deserialization_java.assets/Concept06.java %}

Open the `gnome-calculator` by chaining three transformers and executing the `transform()` method.

### ChainedTransformer

- Shorten the code for code execution.
- **Key Point:** Takes an `array of transformers` during initialization and `chains` them carefully maintaining their execution order.

{% include_code ../insecure_deserialization_java.assets/Concept07.java %}

> - In order to trigger the command execution, somehow we need to execute `ChainedTransformer.transform("any_key")` method.

> - However, we still need to understand a few more data structures to connect the dots.

### HashMap

> **public** **class** HashMap<K,V> **extends** AbstractMap<K,V> **implements** Map<K,V>, Cloneable, Serializable

1. HashMap class contains `values` based on the `key`.
2. Contains only unique `keys`.
3. Maintains no order.
4. **Key Point:** Returns `null` if there’s `no` value is present for the requested `key`.

{% include_code ../insecure_deserialization_java.assets/Concept08.java %}

### LazyMap

1. A type of `Map` which `creates` a `value` if there’s `no` value is present for the `requested` key.
2. This `generation` is done through a `transformation` (i.e transformer.`transform()` method) on the requested `Key`.
3. **Key Point:** `lazyMap.get("invalid_key")` calls `transformer.transform("invalid_key")` method when the key is not found.

{% include_code ../insecure_deserialization_java.assets/Concept09.java %}

![image-20191120223312696](insecure_deserialization_java.assets/image-20191120223312696.png)

![image-20191120222926864](insecure_deserialization_java.assets/image-20191120222926864.png)

![image-20191120223152778](insecure_deserialization_java.assets/image-20191120223152778.png)

### Command Execution by `combining` ChainedTransformer and LazyMap

{% include_code ../insecure_deserialization_java.assets/Concept10.java %}

### TiedMapEntry

1. This can be used to `enable` a `Map` entry to `make changes` on the `underlying` map.
2. `tiedmapentry.getValue()` method => `lazymap.get(this.key)` method.
3. **Key Point:** `tiedmapentry.hashcode()` method => `tiedmapentry.getValue()` method.

{% include_code ../insecure_deserialization_java.assets/Concept11.java %}

![image-20191120230402262](insecure_deserialization_java.assets/image-20191120230402262.png)

![image-20191120230500084](insecure_deserialization_java.assets/image-20191120230500084.png)

![image-20191120230532545](insecure_deserialization_java.assets/image-20191120230532545.png)

### HashBag

1. A Collection that `counts` the number of times an object `appears` in the collection.
2. Backed by an internal `HashMap` object.
3. While adding any Object, first it's `hashcode()` is calculated. Based on that hashcode/index, it updates the underlying `HashMap` table entry.
4. **Key Point:** `hashbag.add(tiedmapentry)` method => `tiedmapentry.hashcode()` method.

{% include_code ../insecure_deserialization_java.assets/Concept12.java %}

![image-20191120232856545](insecure_deserialization_java.assets/image-20191120232856545.png)

### Recap

1. Create a `TiedMapEntry` with a underlying `lazyMap` and key is `String` -> 'invalid_key'.

> 1. This `LazyMap` is backed by an empty `HashMap.`
> 2. This `LazyMap` can also use the factory class `ChainedTransformer` that generates a value dynamically through the `transform()` method when presented with an `invalid` key.
> 3. **Key Point:** Finally it updates that entry(i.e key:value pair) into the `HashMap`.
> 4. As the initial `HashMap` is empty, so any `key` supplied through `TiedMapEntry` can trigger the `transform()` method.

2. Then `add` the `tiedmapentry` Object into a `HashBag` instance.

3. `hashbag.add(tiedmapentry)` => `tiedmapentry.hashcode()` => `lazymap.get(this.key)` => `chainedtransformer.transform(key)` => `Runtime.getRuntime().exec("/usr/bin/gnome-calculator");`

### Detailed Back-trace

```java
add(Object object)  // IMP
    => add(Object object, int nCopies)
        => HashMap.get(Object)
            => int hash(Object key)
                => tidemapentry.hashCode();  // IMP
                    => tidemapentry.getValue();
                        => lazymap.get(this.key);  // IMP
                            => this.factory.transform(key);  // IMP
                                => Runtime.getRuntime().exec("/usr/bin/gnome-calculator")
```

### The Problem

We can serialize this `HashBag` object to generate the payload but during the serialization process, `lazymap.get("invalid_key")` is called once. So the underlying `HashMap` is `updated` with the `invalid_key:derived_value` entry.

During deserialization process, when `TiedMapEntry.hashcode()` => `lazymap.get(this.key)` call occurs, then `ChainedTransformer.transform(key)` method will not be called because `LazyMap` does not need to derive the value for that key again through the `transform()` method. Underlying `HashMap` is already `updated` with the entry.

### The Solution

The most important thing to taken care is

1. During the serialization process, we need to wrap a `TiedMapEntry` Object inside a `HashBag` object, but somehow we need to `stop` the invocation of `TiedMapEntry.hashcode()` method when we add the TidemapEntry object into the `HashBag's` `HashMap` via  `add()` method.
2. If we can do this, then the underlying `LazyMap's` `HashMap` won't get `updated` with the `invalid_key:derived_value` entry.

#### Strategy to overcome the challenge

1. Create a `HashBag` instance and add any `Object` into it.
2. This will invoke Object’s `hashcode()` method and based on the hashcode / index, the underlying `HashBag's` => `HashMap` table entry will be updated with `key = Object` and `value / count = 1`.
3. Now using `mokito` library, modify that `HashBag's` => `HashMap’s` `first` entry in `memory`.
   - Replace that `Object` with `TiedMapEntry` Object.
   - We have added only one entry due to that we are modifying the `first` entry.
4. As you can observe, till this point, `TiedMapEntry.hashcode()` is not called anywhere.
5. Serialize this `HashBag` Object.
6. During the deserialization process, the program tries to recreate the same object(i.e., `HashBag`) in the process memory.
7. This `HashBag` => underlying `HashMap` table should be having one entry, where key= `TiedMapEntry` Object and count/ value =1. So, to recreate that entry inside the `HashBag's` HashMap's table, the table's index needs to be known. Due to this, `TiedMapEntry.hashcode()` is called to calculate that index dynamically.
8. Here the key point is, `TiedMapEntry.hashcode()` method is getting called the first time, which triggers the code execution.

{% include_code ../insecure_deserialization_java.assets/Concept13.java %}

However, the above code does not produce the serialized object properly.

It throws `java.lang.UnsupportedOperationException`.

```bash
[SNIPPED]
java.lang.UnsupportedOperationException: Serialization support for org.apache.commons.collections.functors.InvokerTransformer is disabled for security reasons. To enable it set system property 'org.apache.commons.collections.enableUnsafeSerialization' to 'true', but you must ensure that your application does not de-serialize objects from untrusted sources.
    at org.apache.commons.collections.functors.FunctorUtils.checkUnsafeSerialization(FunctorUtils.java:183)
    at org.apache.commons.collections.functors.InvokerTransformer.writeObject(InvokerTransformer.java:155)
    at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
    at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)

[SNIPPED]
```

By default, serialization support for `org.apache.commons.collections.functors.InvokerTransformer` is `disabled`.

```java
// enable the support in both producer and consumer programs to serialize / deserialize the object without any exception
System.setProperty(
                    "org.apache.commons.collections.enableUnsafeSerialization",
                    "true");
```

### Final Exploit Code

{% include_code ../insecure_deserialization_java.assets/Concept14.java %}

![](insecure_deserialization_java.assets/image-20191121213224578.png)

### Video Walkthrough: Debugging the Deserialization Flow

[![Demystifying a Gadget Chain - Java Deserialization](insecure_deserialization_java.assets/image-20191121223509399.png)](https://vimeo.com/374834418)

## Final Thoughts

If we fix our code and use the `safeObjectInputStream` during deserialization, then the following things happen while unwrapping the serialized object:

1. First, it resolves the `HashBag` Class.
2. Then it checks if that class is present inside the `whitelist.`
    - If that class `IS_NOT_FOUND` inside the `whitelist,` then it throws `Exception.`
    - We don't have `HashBag` in our whitelist. So then we'll get the `Exception,` and the attack won't be successful.

However, if that class `IS_FOUND` inside the `whitelist,` then it tries to resolve the next wrapped class (in our case that is `TiedMapEntry`) and repeats step 2.

> If all classes wrapped in the `serialized` object are present inside our `whitelist,` then the entire process won't continue, and we can anticipate the `calculator` again.

`whitelist` the following classes to run `calculator`.

{% include_code ../insecure_deserialization_java.assets/SafeDeserializeRCE.java %}

![](insecure_deserialization_java.assets/calc_rce.png)

## References

- https://speakerdeck.com/dhavalkapil/magichat-insomnihack-teaser-2018-writeup
- https://www.youtube.com/watch?v=t-zVC-CxYjw&t=1206s
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- https://github.com/JackOfMostTrades/gadgetinspector
- https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections1.java
