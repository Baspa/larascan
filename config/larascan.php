<?php

declare(strict_types=1);

return [
    'fail_on' => 'high',

    'checks' => [
        'config.app-key' => ['enabled' => true],
        'config.app-env' => ['enabled' => true],
        'config.env-not-committed' => ['enabled' => true],
        'config.env-example-sync' => ['enabled' => true],
        'config.log-level' => ['enabled' => true],
        'config.env-calls-outside-config' => ['enabled' => true],
        'config.debug-blacklist' => ['enabled' => true],
        'config.trusted-proxies' => ['enabled' => true],
        'cookies.session-secure' => ['enabled' => true],
        'cookies.session-http-only' => ['enabled' => true],
        'cookies.session-same-site' => ['enabled' => true],
        'cookies.session-encrypt' => ['enabled' => true],
        'cookies.session-lifetime' => ['enabled' => true],
        'cookies.encrypt-middleware' => ['enabled' => true],
        'cookies.encrypt-excludes' => ['enabled' => true],
        'headers.cors-wildcard' => ['enabled' => true],
        'dependencies.composer-audit' => ['enabled' => true],
        'dependencies.npm-audit' => ['enabled' => true],
    ],

    'ignore' => [
        'vendor/*',
        'node_modules/*',
        'storage/*',
        'bootstrap/cache/*',
    ],

    'tools' => [
        'composer' => env('LARASCAN_COMPOSER_BIN', 'composer'),
        'npm' => env('LARASCAN_NPM_BIN', 'npm'),
        'semgrep' => env('LARASCAN_SEMGREP_BIN', 'semgrep'),
    ],

    'baseline' => null,
];
