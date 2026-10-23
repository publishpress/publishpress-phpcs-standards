# PublishPress coding standards

Rules PublishPress applies to its own PHP, enforced as PHPCS standards.

## Language

**Copyright notice**:
The exact character sequence `Copyright (c) <current calendar year>, PublishPress`.
_Avoid_: copyright header, copyright comment

**File header docblock**:
The first `/** */` comment in a PHP file, before any code.
_Avoid_: class docblock, method docblock, block comment

**Direct-access guard**:
`defined('ABSPATH') || exit;` as the first executable code after `declare`, `namespace`, and `use` in a PHP file. Whitespace and an optional trailing comment do not matter. In a namespaced file without `use function defined;`, the call must be `\defined('ABSPATH') || exit;`.
_Avoid_: direct access check, ABSPATH guard, `if (!defined('ABSPATH'))`, `die`, `exit()`, `exit('...')`

## Relationships

- A **Copyright notice** must appear in the **File header docblock**.
- Other text in that same docblock is allowed, before or after the notice.
- The year is the current calendar year only. The previous year is not a **Copyright notice**.
- `namespace`, a **Direct-access guard**, or any other code before the docblock means there is no **File header docblock**.
- A **Direct-access guard** comes after every `declare`, `namespace`, and `use` in the file preamble, and before any other executable code.
- The fixer leaves a **File header docblock** above the guard. A docblock on the following class, interface, trait, or function stays below the guard.
- A valid **Direct-access guard** elsewhere in the file (for example before `use`, or after a class) is still a violation.

## Example dialogue

> **Dev:** "The view starts with `defined('ABSPATH')`, then a docblock with the **Copyright notice**. Good?"
> **Domain expert:** "No. The notice has to be in the **File header docblock**, and that docblock has to come before the guard. On 1 January the year in the notice is wrong until someone bumps it."

> **Dev:** "This template has `if (!defined('ABSPATH')) { exit; }` right after the `use` lines. Does it need the short-circuit form?"
> **Domain expert:** "Yes. Use `defined('ABSPATH') || exit;` (or `\defined` in a namespace). The `if` form is legacy; the sniff warns but does not autofix it."

## Flagged ambiguities

- "valid copyright comment or header" (issue #3) — resolved: a **Copyright notice** in the **File header docblock**. Not a free-form copyright line, not `(C)`, not a previous year, and not a class docblock.
- Issue #2 wording vs legacy plugins — resolved: only `exit;` (not `die`, not `exit()`), with flexible whitespace and optional comment; `declare` is allowed before `namespace`.
- Legacy `defined('ABSPATH') or/|| die/exit` and `if (!defined('ABSPATH')) die(...)` in the file preamble — warning (`NonStandardSyntax`), not autofixed; preamble-only (not inside functions or HTML-first embedded blocks).
- `\defined('ABSPATH') || exit;` after `use function defined` — warning (`FullyQualifiedAfterFunctionImport`), not autofixed. The import already brings in the global function, so the guard must call `defined`.
