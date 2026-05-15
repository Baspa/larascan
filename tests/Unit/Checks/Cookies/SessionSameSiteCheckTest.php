<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Cookies\SessionSameSiteCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new SessionSameSiteCheck($this->app);

    expect($check->id())->toBe('cookies.session-same-site')
        ->and($check->category())->toBe(Category::Cookies)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when session.same_site is lax', function () {
    config()->set('session.same_site', 'lax');
    expect(iterator_to_array((new SessionSameSiteCheck($this->app))->run()))->toBeEmpty();
});

it('passes when session.same_site is strict', function () {
    config()->set('session.same_site', 'strict');
    expect(iterator_to_array((new SessionSameSiteCheck($this->app))->run()))->toBeEmpty();
});

it('fails when session.same_site is none', function () {
    config()->set('session.same_site', 'none');
    $findings = iterator_to_array((new SessionSameSiteCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High);
});

it('fails when session.same_site is null', function () {
    config()->set('session.same_site', null);
    $findings = iterator_to_array((new SessionSameSiteCheck($this->app))->run());
    expect($findings)->toHaveCount(1);
});
