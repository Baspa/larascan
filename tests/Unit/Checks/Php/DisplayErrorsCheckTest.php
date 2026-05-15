<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Php\DisplayErrorsCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new DisplayErrorsCheck($this->app);

    expect($check->id())->toBe('php.display-errors')
        ->and($check->category())->toBe(Category::Php)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when display_errors is off', function () {
    $check = new class($this->app) extends DisplayErrorsCheck
    {
        protected function iniValue(): string|false
        {
            return '0';
        }
    };

    expect(iterator_to_array($check->run()))->toBeEmpty();
});

it('fails with declared severity in production when display_errors is on', function () {
    config()->set('app.env', 'production');

    $check = new class($this->app) extends DisplayErrorsCheck
    {
        protected function iniValue(): string|false
        {
            return '1';
        }
    };

    $findings = iterator_to_array($check->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('php.display-errors');
});

it('fails with downgraded severity in non-production when display_errors is on', function () {
    config()->set('app.env', 'local');

    $check = new class($this->app) extends DisplayErrorsCheck
    {
        protected function iniValue(): string|false
        {
            return '1';
        }
    };

    $findings = iterator_to_array($check->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Info);
});
