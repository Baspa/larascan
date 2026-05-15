<?php

declare(strict_types=1);

return [
    'fail_on' => 'high',

    'checks' => [
        'config.app-key' => ['enabled' => true],
        'config.app-env' => ['enabled' => true],
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
