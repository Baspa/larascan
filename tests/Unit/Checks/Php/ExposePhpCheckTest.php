<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Php\ExposePhpCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new ExposePhpCheck($this->app);

    expect($check->id())->toBe('php.expose-php')
        ->and($check->category())->toBe(Category::Php)
        ->and($check->severity())->toBe(Severity::Low);
});

it('passes when expose_php is off', function () {
    $check = new class($this->app) extends ExposePhpCheck
    {
        protected function iniValue(): string|false
        {
            return '0';
        }
    };

    expect(iterator_to_array($check->run()))->toBeEmpty();
});

it('fails when expose_php is on', function () {
    $check = new class($this->app) extends ExposePhpCheck
    {
        protected function iniValue(): string|false
        {
            return '1';
        }
    };

    $findings = iterator_to_array($check->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low)
        ->and($findings[0]->checkId)->toBe('php.expose-php');
});
