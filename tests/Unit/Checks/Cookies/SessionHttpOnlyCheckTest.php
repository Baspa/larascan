<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Cookies\SessionHttpOnlyCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new SessionHttpOnlyCheck($this->app);

    expect($check->id())->toBe('cookies.session-http-only')
        ->and($check->category())->toBe(Category::Cookies)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when session.http_only is true', function () {
    config()->set('session.http_only', true);
    expect(iterator_to_array((new SessionHttpOnlyCheck($this->app))->run()))->toBeEmpty();
});

it('fails when session.http_only is false', function () {
    config()->set('session.http_only', false);
    $findings = iterator_to_array((new SessionHttpOnlyCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->message)->toContain('HttpOnly');
});

it('fails when session.http_only is null/missing', function () {
    config()->set('session.http_only', null);
    $findings = iterator_to_array((new SessionHttpOnlyCheck($this->app))->run());
    expect($findings)->toHaveCount(1);
});
