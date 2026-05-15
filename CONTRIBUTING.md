# Contributing

Thanks for considering a contribution!

## Adding a check

1. Pick a category from `src/Support/Category.php`
2. Create `src/Checks/{Category}/{CheckName}Check.php` extending `AbstractCheck`
3. Implement: `id()`, `category()`, `severity()`, `name()`, `isApplicable()` (optional, defaults to true), `run(): iterable<Finding>`
4. Add a test in `tests/Unit/Checks/{Category}/{CheckName}CheckTest.php`
5. Register in `LarascanServiceProvider::shippedChecks()` (and `packageRegistered()` if it needs path-based deps)
6. Add to default `config/larascan.php` if it should be enabled by default
7. Bump the ServiceProviderTest count assertion
8. Update README's check list

## Running tests

```bash
composer install
vendor/bin/pest
vendor/bin/phpstan analyse
vendor/bin/pint --test
```

Tests must pass; PHPStan must be clean at level 8; Pint must be clean.
