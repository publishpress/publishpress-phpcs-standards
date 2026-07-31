# publishpress-phpcs-standards

PHPCS standards for PublishPress projects.

## Standards

| Standard | Path | Purpose |
|----------|------|---------|
| `PublishPressStandards` | `standards/PublishPressStandards/` | PublishPress-specific sniffs |
| `PluginCheck` | `standards/PluginCheck/` | WordPress.org Plugin Check sniffs (vendored) |
| Plugin Check rulesets | `standards/plugin-check-rulesets/` | Org-review PHPCS rulesets for consuming plugins |

## Plugin Check

WordPress.org Plugin Check PHPCS rules are vendored from [WordPress/plugin-check](https://github.com/WordPress/plugin-check). See `standards/plugin-check-rulesets/SOURCE.md` for the upstream version.

Consuming projects reference:

```xml
<rule ref="vendor/publishpress/publishpress-phpcs-standards/standards/plugin-check-rulesets/plugin-review.xml"/>
```

Refresh from upstream:

```bash
./scripts/sync-plugin-check.sh 2.0.0
```
