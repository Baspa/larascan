<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Dependencies\OutdatedPhpCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new OutdatedPhpCheck($this->app);

    expect($check->id())->toBe('dependencies.outdated-php')
        ->and($check->category())->toBe(Category::Dependencies)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when PHP version is 8.2 or higher', function () {
    $check = new class($this->app) extends OutdatedPhpCheck
    {
        protected function phpVersionId(): int
        {
            return 80200;
        }

        protected function phpVersionString(): string
        {
            return '8.2.0';
        }
    };

    expect(iterator_to_array($check->run()))->toBeEmpty();
});

it('fails with declared severity in production when PHP version is below 8.2', function () {
    config()->set('app.env', 'production');

    $check = new class($this->app) extends OutdatedPhpCheck
    {
        protected function phpVersionId(): int
        {
            return 80110;
        }

        protected function phpVersionString(): string
        {
            return '8.1.10';
        }
    };

    $findings = iterator_to_array($check->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('dependencies.outdated-php')
        ->and($findings[0]->message)->toContain('8.1.10')
        ->and($findings[0]->message)->toContain('end-of-life');
});

it('fails with downgraded severity in non-production when PHP version is below 8.2', function () {
    config()->set('app.env', 'local');

    $check = new class($this->app) extends OutdatedPhpCheck
    {
        protected function phpVersionId(): int
        {
            return 80020;
        }

        protected function phpVersionString(): string
        {
            return '8.0.20';
        }
    };

    $findings = iterator_to_array($check->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Info);
});
