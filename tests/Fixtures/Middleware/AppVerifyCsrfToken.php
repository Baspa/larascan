<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tests\Fixtures\Middleware;

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;

final class AppVerifyCsrfToken extends VerifyCsrfToken
{
    protected $except = [
        '/admin/*',
        '/webhook/stripe',
    ];
}
