# Konfigyr Crypto

![CI Build](https://github.com/konfigyr/konfigyr-crypto/actions/workflows/continuous-integration.yml/badge.svg)
[![Join the chat at https://gitter.im/konfigyr/konfigyr-plugin](https://badges.gitter.im/konfigyr/konfigyr-plugin.svg)](https://gitter.im/konfigyr/konfigyr-crypt?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## Building from Source
Konfigyr Crypto uses a Gradle-based build system. In the instructions below, `./gradlew` is invoked from the root of the source tree and serves as a cross-platform, self-contained bootstrap mechanism for the build.

### Prerequisites
Git and the JDK 17 build.

### Check out sources
```shell
git clone git@github.com:konfigyr/konfigyr-crypto.git
```

### Publish to your local Maven repository
```shell
./gradlew publishToMavenLocal
```

### Compile and test
```shell
./gradlew build
```

Discover more commands with `./gradlew tasks`.

## Getting Support
Try reaching out to the maintainers in our [Gitter chat](https://gitter.im/konfigyr/konfigyr-crypt). Commercial support is available too.

## Contributing
[Pull requests](https://help.github.com/articles/creating-a-pull-request) are more than welcome; see the [contributor](CONTRIBUTING.md) guidelines for details.

## License
Konfigyr Crypto library is Open Source software released under the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0.html).
