<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Config\EnvExampleSyncCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

beforeEach(function () {
    $this->tmpDir = sys_get_temp_dir().'/larascan-envsync-'.uniqid();
    mkdir($this->tmpDir);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    if (! is_dir($tmpDir)) {
        return;
    }
    foreach (scandir($tmpDir) ?: [] as $f) {
        if ($f === '.' || $f === '..') {
            continue;
        }
        $full = $tmpDir.'/'.$f;
        if (is_file($full)) {
            unlink($full);
        }
    }
    rmdir($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new EnvExampleSyncCheck($this->tmpDir);

    expect($check->id())->toBe('config.env-example-sync')
        ->and($check->category())->toBe(Category::Config)
        ->and($check->severity())->toBe(Severity::Low);
});

it('is skipped when either file is absent', function () {
    $check = new EnvExampleSyncCheck($this->tmpDir);
    expect($check->isApplicable())->toBeFalse();

    file_put_contents("{$this->tmpDir}/.env", "FOO=1\n");
    expect((new EnvExampleSyncCheck($this->tmpDir))->isApplicable())->toBeFalse();
});

it('passes when both files have identical key sets', function () {
    file_put_contents("{$this->tmpDir}/.env", "APP_KEY=secret\nAPP_DEBUG=false\n");
    file_put_contents("{$this->tmpDir}/.env.example", "APP_KEY=\nAPP_DEBUG=true\n");

    $findings = iterator_to_array((new EnvExampleSyncCheck($this->tmpDir))->run());
    expect($findings)->toBeEmpty();
});

it('reports keys missing from .env.example', function () {
    file_put_contents("{$this->tmpDir}/.env", "APP_KEY=a\nNEW_KEY=b\n");
    file_put_contents("{$this->tmpDir}/.env.example", "APP_KEY=\n");

    $findings = iterator_to_array((new EnvExampleSyncCheck($this->tmpDir))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain('NEW_KEY')
        ->and($findings[0]->message)->toContain('.env.example');
});

it('reports keys missing from .env', function () {
    file_put_contents("{$this->tmpDir}/.env", "APP_KEY=a\n");
    file_put_contents("{$this->tmpDir}/.env.example", "APP_KEY=\nFEATURE_FLAG=\n");

    $findings = iterator_to_array((new EnvExampleSyncCheck($this->tmpDir))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain('FEATURE_FLAG')
        ->and($findings[0]->message)->toContain('.env');
});

it('ignores comment and blank lines', function () {
    file_put_contents("{$this->tmpDir}/.env", "# comment\n\nAPP_KEY=a\n");
    file_put_contents("{$this->tmpDir}/.env.example", "# other comment\nAPP_KEY=\n");

    expect(iterator_to_array((new EnvExampleSyncCheck($this->tmpDir))->run()))->toBeEmpty();
});
