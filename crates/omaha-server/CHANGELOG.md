# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.7](https://github.com/imputnet/omaha/compare/omaha-server-v0.1.6...omaha-server-v0.1.7) - 2026-11-09

### Added

- add a serve loop for libraries

### Changed

- crx3, cup2: load either key type from pkcs8

## [0.1.6](https://github.com/imputnet/omaha/compare/omaha-server-v0.1.5...omaha-server-v0.1.6) - 2026-11-09

### Added

- add index::answer for releases kept outside an index

## [0.1.5](https://github.com/imputnet/omaha/compare/omaha-server-v0.1.4...omaha-server-v0.1.5) - 2026-11-08

### Changed

- crx3, cup2: stabilize for 1.0.0
- bug fixes and improvements

## [0.1.4](https://github.com/imputnet/omaha/compare/omaha-server-v0.1.3...omaha-server-v0.1.4) - 2026-11-08

### Changed

- count requests, outcomes and daily actives

## [0.1.3](https://github.com/imputnet/omaha/compare/omaha-server-v0.1.2...omaha-server-v0.1.3) - 2026-11-08

### Changed

- serve a feed from the command line

## [0.1.2](https://github.com/imputnet/omaha/compare/omaha-server-v0.1.1...omaha-server-v0.1.2) - 2026-11-08

### Changed

- document every public item and deny missing docs

## [0.1.1](https://github.com/imputnet/omaha/compare/omaha-server-v0.1.0...omaha-server-v0.1.1) - 2026-11-08

### Changed

- check an index's signatures without its expiry

## [0.1.0](https://github.com/imputnet/omaha/compare/omaha-server-v0.0.1...omaha-server-v0.1.0) - 2026-11-08

### Added

- add a signed release index

### Changed

- serve a release index that can be replaced at runtime
- build the index tests only with aws-lc
- turn off cup2 default features in the workspace
- tell sources which protocol a request came in
- route unknown apps to a fallback source
- pass request headers to sources
- answer update checks and ping-backs
- set repository url
- set up workspace and crate stubs
