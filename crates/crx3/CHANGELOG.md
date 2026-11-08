# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0](https://github.com/imputnet/omaha/compare/crx3-v0.3.1...crx3-v1.0.0) - 2026-11-08

### Changed

- crx3, cup2: stabilize for 1.0.0
- bug fixes and improvements

## [0.3.1](https://github.com/imputnet/omaha/compare/crx3-v0.3.0...crx3-v0.3.1) - 2026-11-08

### Changed

- document every public item and deny missing docs

## [0.3.0](https://github.com/imputnet/omaha/compare/crx3-v0.2.0...crx3-v0.3.0) - 2026-11-08

### Changed

- bump crx3 and cup2 to 0.3.0
- deny panicking calls in library code
- release ([#5](https://github.com/imputnet/omaha/pull/5))
- reformat
- correct the chromium differences in docs
- reject overlong protobuf varints like chromium

## [0.2.0](https://github.com/imputnet/omaha/compare/crx3-v0.1.1...crx3-v0.2.0) - 2026-11-08

### Changed

- move chromium test data helper into a crate
- stream archives and sign only typed digests

### Removed

- remove redundant comments

## [0.1.1](https://github.com/imputnet/omaha/compare/crx3-v0.1.0...crx3-v0.1.1) - 2026-11-08

### Added

- add readme

## [0.1.0](https://github.com/imputnet/omaha/compare/crx3-v0.0.1...crx3-v0.1.0) - 2026-11-08

### Changed

- set repository url
- build, sign and verify crx3 files
- set up workspace and crate stubs
