<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Auth;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class BcryptRoundsCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'auth.bcrypt-rounds';
    }

    public function category(): Category
    {
        return Category::Auth;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'BCRYPT_ROUNDS must be at least 12 to slow password hashing';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        $rounds = $config->get('hashing.bcrypt.rounds');

        if (! is_numeric($rounds)) {
            return;
        }

        $value = (int) $rounds;

        if ($value < 12) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: "BCRYPT_ROUNDS is {$value} — below the recommended minimum of 12. Password hashing is too fast, easing brute-force attacks.",
            );
        }
    }
}
