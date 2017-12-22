# Nannoq Auth

nannoq-auth is a collection of classes for managing JWT based authentication and authorization on a vertx environment.

It supports:
 - JWT Creation
 - JWT Verification
 - JWT Revocation
 - OAuth Login
 - Direct Token Conversion
 
Current providers:
 
 - Facebook
 - Google
 - Instagram
 
### Prerequisites

Vert.x >= 3.5.0

Java >= 1.8

Maven

Redis

## Installing

mvn clean package -Dgpg.skip=true

### Running the tests

mvn clean test -Dgpg.skip=true

### Running the integration tests

mvn clean verify -Dgpg.skip=true

## Usage

First install with either Maven:

```xml
<dependency>
    <groupId>com.nannoq</groupId>
    <artifactId>auth</artifactId>
    <version>1.0.0</version>
</dependency>
```

or Gradle:

```groovy
dependencies {
    compile group: 'nannoq.com:auth:1.0.0'
}
```

### Implementation and Use

Please consult the [Wiki](https://github.com/NoriginMedia/nannoq-auth/wiki) for guides on implementations and use.

## Contributing

Please read [CONTRIBUTING.md](https://github.com/NoriginMedia/nannoq-auth/blob/master/CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/NoriginMedia/nannoq-auth/tags)

## Authors

* **Anders Mikkelsen** - *Initial work* - [Norigin Media](http://noriginmedia.com/)

See also the list of [contributors](https://github.com/NoriginMedia/nannoq-auth/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/NoriginMedia/nannoq-auth/blob/master/LICENSE) file for details
