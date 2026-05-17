<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Headers\CspBaseUriCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new CspBaseUriCheck($this->app);

    expect($check->id())->toBe('headers.csp-base-uri')
        ->and($check->category())->toBe(Category::Headers)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('is not applicable when spatie/laravel-csp is not installed', function () {
    $check = new CspBaseUriCheck($this->app);
    expect($check->isApplicable())->toBeFalse();
});

it('short-circuits run when not applicable', function () {
    $findings = iterator_to_array((new CspBaseUriCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});
