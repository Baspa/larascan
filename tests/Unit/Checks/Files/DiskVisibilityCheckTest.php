<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Files\DiskVisibilityCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new DiskVisibilityCheck($this->app);

    expect($check->id())->toBe('files.disk-visibility')
        ->and($check->category())->toBe(Category::Files)
        ->and($check->severity())->toBe(Severity::Medium)
        ->and($check->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/checks/files/disk-visibility.md');
});

it('passes on testbench default disks', function () {
    $findings = iterator_to_array((new DiskVisibilityCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails Medium for a public-visibility disk with a sensitive name', function () {
    config()->set('filesystems.disks.invoices', [
        'driver' => 'local',
        'root' => '/srv/storage/invoices',
        'visibility' => 'public',
    ]);

    $findings = iterator_to_array((new DiskVisibilityCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('files.disk-visibility')
        ->and($findings[0]->message)->toContain("'invoices'");
});

it('fails Medium for a public-visibility disk with a sensitive root path', function () {
    config()->set('filesystems.disks.uploads', [
        'driver' => 'local',
        'root' => '/srv/storage/private/uploads',
        'visibility' => 'public',
    ]);

    $findings = iterator_to_array((new DiskVisibilityCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium);
});

it('exempts the disk literally named public', function () {
    config()->set('filesystems.disks.public', [
        'driver' => 'local',
        'root' => '/srv/storage/documents',
        'visibility' => 'public',
    ]);

    $findings = iterator_to_array((new DiskVisibilityCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('does not flag a public-visibility disk without sensitive keywords', function () {
    config()->set('filesystems.disks.avatars', [
        'driver' => 'local',
        'root' => '/srv/storage/avatars',
        'visibility' => 'public',
    ]);

    $findings = iterator_to_array((new DiskVisibilityCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails Low for a configured s3 disk without a visibility key', function () {
    config()->set('filesystems.disks.s3', [
        'driver' => 's3',
        'bucket' => 'my-app-bucket',
    ]);

    $findings = iterator_to_array((new DiskVisibilityCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low)
        ->and($findings[0]->message)->toContain('Flysystem defaults to private');
});

it('skips an unconfigured s3 disk (no bucket)', function () {
    config()->set('filesystems.disks.s3', [
        'driver' => 's3',
        'bucket' => null,
    ]);

    $findings = iterator_to_array((new DiskVisibilityCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('passes for an s3 disk with explicit visibility', function () {
    config()->set('filesystems.disks.s3', [
        'driver' => 's3',
        'bucket' => 'my-app-bucket',
        'visibility' => 'private',
    ]);

    $findings = iterator_to_array((new DiskVisibilityCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});
