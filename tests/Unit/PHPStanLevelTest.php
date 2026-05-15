<?php

declare(strict_types=1);

it('keeps PHPStan analysis at level 8', function () {
    $config = file_get_contents(__DIR__.'/../../phpstan.neon.dist');
    expect($config)->toContain('level: 8');
});
