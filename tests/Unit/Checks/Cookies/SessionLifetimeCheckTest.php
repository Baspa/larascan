<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Cookies\SessionLifetimeCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new SessionLifetimeCheck($this->app);

    expect($check->id())->toBe('cookies.session-lifetime')
        ->and($check->category())->toBe(Category::Cookies)
        ->and($check->severity())->toBe(Severity::Low);
});

it('passes when lifetime is within a sensible range', function () {
    config()->set('session.lifetime', 120);
    expect(iterator_to_array((new SessionLifetimeCheck($this->app))->run()))->toBeEmpty();
});

it('fails when lifetime is zero', function () {
    config()->set('session.lifetime', 0);
    $findings = iterator_to_array((new SessionLifetimeCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain('lifetime');
});

it('fails when lifetime is over one year', function () {
    config()->set('session.lifetime', 525601);
    $findings = iterator_to_array((new SessionLifetimeCheck($this->app))->run());
    expect($findings)->toHaveCount(1);
});

it('passes at the upper boundary (1 year)', function () {
    config()->set('session.lifetime', 525600);
    expect(iterator_to_array((new SessionLifetimeCheck($this->app))->run()))->toBeEmpty();
});
