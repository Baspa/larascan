<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Php\AllowUrlFopenCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new AllowUrlFopenCheck($this->app);

    expect($check->id())->toBe('php.allow-url-fopen')
        ->and($check->category())->toBe(Category::Php)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('passes when allow_url_fopen is off', function () {
    $check = new class($this->app) extends AllowUrlFopenCheck
    {
        protected function iniValue(): string|false
        {
            return '0';
        }
    };

    expect(iterator_to_array($check->run()))->toBeEmpty();
});

it('fails when allow_url_fopen is on', function () {
    $check = new class($this->app) extends AllowUrlFopenCheck
    {
        protected function iniValue(): string|false
        {
            return '1';
        }
    };

    $findings = iterator_to_array($check->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('php.allow-url-fopen');
});
