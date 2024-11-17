Change Log
==========

All notable changes to this project will be documented in this file, which
follows the conventions of [keepachangelog.com](http://keepachangelog.com/).
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

...


## [1.1.2] - 2024-11-16

### Changed
- Add handling for empty `PGPEncryptedDataList` packets.
  [PR#30](https://github.com/greglook/clj-pgp/pull/30)

## [1.1.1] - 2023-11-30

### Changed
- Upgrade BouncyCastle and other dependencies to fix a CVE.
  [#26](https://github.com/greglook/clj-pgp/issues/26)
  [PR#28](https://github.com/greglook/clj-pgp/pull/28)

## [1.1.0] - 2022-02-11

### Changed
- Renamed `master` branch to `main`.
- Upgrade BouncyCastle and other dependencies to fix a CVE.
  [#25](https://github.com/greglook/clj-pgp/issues/25)
  [PR#24](https://github.com/greglook/clj-pgp/pull/24)


## [1.0.0] - 2020-09-24

Finally admitting that this project is stable.

### Changed
- Upgrade BouncyCastle and other dependencies.
- `clj-pgp.core/read-objects` now returns an `IReduceInit` instead of a lazy
  sequence for improved performance and control of message consumption.
  [PR#23](https://github.com/greglook/clj-pgp/pull/23)


## [0.10.2] - 2020-04-19

### Changed
- Upgrade various dependencies.
- Update CI style and linter checks.


## [0.10.1] - 2019-08-17

### Added
- Support for a dynamically-bindable error handling function.
  [PR#22](https://github.com/greglook/clj-pgp/pull/22)

### Fixed
- Ignore `PGPMarker` messages which are used as a light compatibility check
  against very old PGP implementations.
  [#12](https://github.com/greglook/clj-pgp/issues/12)
  [PR#21](https://github.com/greglook/clj-pgp/pull/21)


## [0.10.0] - 2019-03-26

### Changed
- Update BouncyCastle to 1.61.
  [PR#18](//github.com/greglook/clj-pgp/pull/18)

### Added
- A new `clj-pgp.message/reduce-messages` function allows for consuming
  encrypted data without buffering the entire message in memory. This makes it
  possible to handle very large messages in a streaming fashion.
  [PR#19](//github.com/greglook/clj-pgp/pull/19)


## [0.9.0] - 2017-11-04

### Changed
- Make private and public keyrings encodable.
- Simplify fuzzing tool.
- Improve coverage generation.


## [0.8.3] - 2015-12-30

Start of CHANGELOG.


[Unreleased]: https://github.com/greglook/clj-pgp/compare/1.1.1...HEAD
[1.1.1]: https://github.com/greglook/clj-pgp/compare/1.1.0...1.1.1
[1.1.0]: https://github.com/greglook/clj-pgp/compare/1.0.0...1.1.0
[1.0.0]: https://github.com/greglook/clj-pgp/compare/0.10.2...1.0.0
[0.10.2]: https://github.com/greglook/clj-pgp/compare/0.10.1...0.10.2
[0.10.1]: https://github.com/greglook/clj-pgp/compare/0.10.0...0.10.1
[0.10.0]: https://github.com/greglook/clj-pgp/compare/0.9.0...0.10.0
[0.9.0]: https://github.com/greglook/clj-pgp/compare/0.8.3...0.9.0
[0.8.3]: https://github.com/greglook/clj-pgp/compare/0.8.2...0.8.3
