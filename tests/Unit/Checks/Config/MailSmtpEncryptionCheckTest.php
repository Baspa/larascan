<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Config\MailSmtpEncryptionCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new MailSmtpEncryptionCheck($this->app);

    expect($check->id())->toBe('config.mail-smtp-encryption')
        ->and($check->category())->toBe(Category::Config)
        ->and($check->severity())->toBe(Severity::Low)
        ->and($check->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/checks/config/mail-smtp-encryption.md');
});

it('passes on testbench defaults (local smtp host is excluded)', function () {
    $findings = iterator_to_array((new MailSmtpEncryptionCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('skips local development hosts', function (string $host) {
    config()->set('app.env', 'production');
    config()->set('mail.mailers.smtp.host', $host);

    $findings = iterator_to_array((new MailSmtpEncryptionCheck($this->app))->run());
    expect($findings)->toBeEmpty();
})->with(['localhost', '127.0.0.1', 'mailpit', 'mailhog']);

it('fails Low in production when a remote smtp mailer does not force TLS', function () {
    config()->set('app.env', 'production');
    config()->set('mail.mailers.smtp.host', 'smtp.example.com');
    config()->set('mail.mailers.smtp.port', 587);
    config()->set('mail.mailers.smtp.scheme', null);

    $findings = iterator_to_array((new MailSmtpEncryptionCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low)
        ->and($findings[0]->checkId)->toBe('config.mail-smtp-encryption')
        ->and($findings[0]->message)->toContain('STARTTLS');
});

it('downgrades to Info outside production', function () {
    config()->set('app.env', 'testing');
    config()->set('mail.mailers.smtp.host', 'smtp.example.com');
    config()->set('mail.mailers.smtp.port', 587);

    $findings = iterator_to_array((new MailSmtpEncryptionCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Info);
});

it('passes when encryption is tls', function () {
    config()->set('app.env', 'production');
    config()->set('mail.mailers.smtp.host', 'smtp.example.com');
    config()->set('mail.mailers.smtp.port', 587);
    config()->set('mail.mailers.smtp.encryption', 'tls');

    $findings = iterator_to_array((new MailSmtpEncryptionCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('passes when scheme is smtps', function () {
    config()->set('app.env', 'production');
    config()->set('mail.mailers.smtp.host', 'smtp.example.com');
    config()->set('mail.mailers.smtp.port', 587);
    config()->set('mail.mailers.smtp.scheme', 'smtps');

    $findings = iterator_to_array((new MailSmtpEncryptionCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('passes when port is 465', function () {
    config()->set('app.env', 'production');
    config()->set('mail.mailers.smtp.host', 'smtp.example.com');
    config()->set('mail.mailers.smtp.port', 465);
    config()->set('mail.mailers.smtp.scheme', null);

    $findings = iterator_to_array((new MailSmtpEncryptionCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('ignores non-smtp transports', function () {
    config()->set('app.env', 'production');
    config()->set('mail.mailers.custom', [
        'transport' => 'ses',
        'host' => 'smtp.example.com',
    ]);

    $findings = iterator_to_array((new MailSmtpEncryptionCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});
