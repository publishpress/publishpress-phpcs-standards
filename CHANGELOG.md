# Changelog

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

### Fixed

- `PublishPressStandards.Security.RequireDirectAccessGuard` no longer reports
  `WrongPosition` when a closure `use` clause follows a correctly placed
  direct-access guard.
- `PublishPressStandards.Security.RequireDirectAccessGuard` autofix keeps the
  file header docblock above the guard and inserts the guard above a class,
  interface, trait, or function docblock.

### Added

- `PublishPressStandards.Security.RequireDirectAccessGuard` sniff to require
  `if (!defined('ABSPATH')) exit;` after `declare`, `namespace`, and `use`
  ([#2](https://github.com/publishpress/publishpress-phpcs-standards/issues/2)).
- `PublishPressStandards.Composer.RequirePluginExtra` sniff to warn when
  `composer.json` `extra` metadata required by dev-workspace is missing or empty
  ([#4](https://github.com/publishpress/publishpress-phpcs-standards/issues/4)).
- `PublishPressStandards.Files.RequireGitAttributes` sniff to require a plugin-root
  `.gitattributes` and `export-ignore` for common dev paths that exist in the
  repository ([#5](https://github.com/publishpress/publishpress-phpcs-standards/issues/5)).
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
