<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

enum Category: string
{
    case Config = 'config';
    case Cookies = 'cookies';
    case Headers = 'headers';
    case Auth = 'auth';
    case Csrf = 'csrf';
    case Routing = 'routing';
    case Models = 'models';
    case Sql = 'sql';
    case Xss = 'xss';
    case Files = 'files';
    case Injection = 'injection';
    case Crypto = 'crypto';
    case Dependencies = 'dependencies';
    case Php = 'php';
    case Logging = 'logging';
    case Repo = 'repo';

    public function label(): string
    {
        return match ($this) {
            self::Config => 'Application configuration',
            self::Cookies => 'Cookies & sessions',
            self::Headers => 'HTTP headers',
            self::Auth => 'Authentication',
            self::Csrf => 'CSRF',
            self::Routing => 'Routing',
            self::Models => 'Eloquent models',
            self::Sql => 'SQL queries',
            self::Xss => 'XSS',
            self::Files => 'File handling',
            self::Injection => 'Injection',
            self::Crypto => 'Crypto & secrets',
            self::Dependencies => 'Dependencies',
            self::Php => 'PHP & build',
            self::Logging => 'Logging & errors',
            self::Repo => 'Repo & CI',
        };
    }
}
