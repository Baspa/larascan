<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tests\Fixtures\Middleware;

use Illuminate\Cookie\Middleware\EncryptCookies;

final class AppEncryptCookies extends EncryptCookies
{
    protected $except = [
        'auth_session',
        'ui_theme',
    ];
}
