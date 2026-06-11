<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Config;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class MailSmtpEncryptionCheck extends AbstractCheck
{
    private const LOCAL_HOSTS = ['localhost', '127.0.0.1', 'mailpit', 'mailhog'];

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'config.mail-smtp-encryption';
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function name(): string
    {
        return 'SMTP mailers talking to remote hosts should force TLS';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');
        $env = (string) ($config->get('app.env') ?? '');

        /** @var array<string, mixed> $mailers */
        $mailers = (array) $config->get('mail.mailers', []);

        foreach ($mailers as $name => $mailer) {
            if (! is_array($mailer) || ($mailer['transport'] ?? null) !== 'smtp') {
                continue;
            }

            $host = $mailer['host'] ?? null;
            if (! is_string($host) || $host === '' || in_array(strtolower($host), self::LOCAL_HOSTS, true)) {
                continue;
            }

            if ($this->forcesTls($mailer)) {
                continue;
            }

            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity()->downgradeIfNotProduction($env),
                message: "SMTP mailer '{$name}' ({$host}) does not force TLS — Symfony Mailer attempts opportunistic STARTTLS, but that is downgrade-able by an active attacker. Set 'scheme' => 'smtps' or use port 465.",
            );
        }
    }

    /**
     * Deliberately lenient: legacy `encryption` values (tls/ssl) are trusted
     * even though Laravel only maps them to a forced-TLS (smtps) scheme on
     * port 465 — on port 587 they still yield opportunistic STARTTLS. Almost
     * every standard Laravel mail config uses `encryption => 'tls'` on 587,
     * so flagging it would make this Low-severity check fire on virtually
     * every app; the noise would outweigh the signal.
     *
     * @param  array<mixed>  $mailer
     */
    private function forcesTls(array $mailer): bool
    {
        $encryption = $mailer['encryption'] ?? null;
        if (is_string($encryption) && in_array(strtolower($encryption), ['tls', 'ssl'], true)) {
            return true;
        }

        $scheme = $mailer['scheme'] ?? null;
        if (is_string($scheme) && strtolower($scheme) === 'smtps') {
            return true;
        }

        return (int) ($mailer['port'] ?? 0) === 465;
    }
}
