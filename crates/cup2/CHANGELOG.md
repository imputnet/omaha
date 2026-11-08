# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1](https://github.com/imputnet/omaha/compare/cup2-v0.3.0...cup2-v0.3.1) - 2026-11-08

### Changed

- document every public item and deny missing docs

## [0.3.0](https://github.com/imputnet/omaha/compare/cup2-v0.2.0...cup2-v0.3.0) - 2026-11-08

### Changed

- bump crx3 and cup2 to 0.3.0
- deny panicking calls in library code
- release ([#5](https://github.com/imputnet/omaha/pull/5))
- reformat
- refuse empty bodies and wrongly sized signatures
- treat an empty cup2hreq as absent
- raise msrv to 1.95

## [0.2.0](https://github.com/imputnet/omaha/compare/cup2-v0.1.0...cup2-v0.2.0) - 2026-11-08

### Changed

- move chromium test data helper into a crate
- sign only typed proof data

### Removed

- remove redundant comments

## [0.1.0](https://github.com/imputnet/omaha/compare/cup2-v0.0.1...cup2-v0.1.0) - 2026-11-08

### Changed

- sign and verify update responses
- set repository url
- set up workspace and crate stubs
