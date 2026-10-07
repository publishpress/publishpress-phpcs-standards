# Changelog

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

### Added

- `PublishPressStandards.Libraries.DisallowDirectAutoload` sniff to require
  `publishpress/*/lib/include.php` instead of `autoload.php` when loading
  bundled PublishPress libraries ([#10](https://github.com/publishpress/publishpress-phpcs-standards/issues/10)).
- PHPUnit tests with dummy PHP fixtures under `tests/fixtures/` and `composer test`.

[1.1.0] - 31 July, 2026

### Added

- Vendored WordPress.org Plugin Check PHPCS rulesets and sniffs from `WordPress/plugin-check` 2.0.0.
- `scripts/sync-plugin-check.sh` to refresh bundled Plugin Check assets from upstream tags.

[1.0.0] - 18 March, 2024

Initial commit
