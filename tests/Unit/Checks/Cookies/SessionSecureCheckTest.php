<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Cookies\SessionSecureCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new SessionSecureCheck($this->app);

    expect($check->id())->toBe('cookies.session-secure')
        ->and($check->category())->toBe(Category::Cookies)
        ->and($check->severity())->toBe(Severity::Critical);
});

it('passes when session.secure is true', function () {
    config()->set('app.env', 'production');
    config()->set('session.secure', true);

    expect(iterator_to_array((new SessionSecureCheck($this->app))->run()))->toBeEmpty();
});

it('fails with Critical severity in production when session.secure is false', function () {
    config()->set('app.env', 'production');
    config()->set('session.secure', false);

    $findings = iterator_to_array((new SessionSecureCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical);
});

it('fails with Info severity in dev when session.secure is false', function () {
    config()->set('app.env', 'local');
    config()->set('session.secure', false);

    $findings = iterator_to_array((new SessionSecureCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Info);
});
