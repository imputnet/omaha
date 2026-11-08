# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
