<?php

declare(strict_types=1);

return [
    'fail_on' => 'high',

    'checks' => [
        'dependencies.composer-audit' => ['enabled' => true],
    ],

    'ignore' => [
        'vendor/*',
        'node_modules/*',
        'storage/*',
        'bootstrap/cache/*',
    ],

    'tools' => [
        'semgrep' => env('LARASCAN_SEMGREP_BIN', 'semgrep'),
        'npm' => env('LARASCAN_NPM_BIN', 'npm'),
        'timeout' => 60,
    ],

    'baseline' => null,
];
