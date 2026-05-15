<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Php\PublicSensitiveFilesCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

function publicSensitiveRecursiveRemove(string $dir): void
{
    if (! is_dir($dir)) {
        return;
    }
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );
    foreach ($it as $f) {
        $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
    }
    rmdir($dir);
}

beforeEach(function () {
    $this->tmpDir = sys_get_temp_dir().'/larascan-publicsensitive-'.uniqid();
    mkdir($this->tmpDir.'/public', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    publicSensitiveRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new PublicSensitiveFilesCheck($this->tmpDir.'/public');

    expect($check->id())->toBe('php.public-sensitive-files')
        ->and($check->category())->toBe(Category::Php)
        ->and($check->severity())->toBe(Severity::Critical);
});

it('is skipped when public/ is missing', function () {
    publicSensitiveRecursiveRemove($this->tmpDir.'/public');

    $check = new PublicSensitiveFilesCheck($this->tmpDir.'/public');
    expect($check->isApplicable())->toBeFalse();
});

it('passes when public/ has no sensitive files', function () {
    file_put_contents($this->tmpDir.'/public/index.php', "<?php\n");
    file_put_contents($this->tmpDir.'/public/robots.txt', "User-agent: *\n");
    file_put_contents($this->tmpDir.'/public/favicon.ico', '');

    $findings = iterator_to_array((new PublicSensitiveFilesCheck($this->tmpDir.'/public'))->run());
    expect($findings)->toBeEmpty();
});

it('fails when .env is in public/', function () {
    file_put_contents($this->tmpDir.'/public/.env', "APP_KEY=secret\n");

    $findings = iterator_to_array((new PublicSensitiveFilesCheck($this->tmpDir.'/public'))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('php.public-sensitive-files')
        ->and($findings[0]->message)->toContain('.env')
        ->and($findings[0]->message)->toContain('public/');
});

it('fails when a .sql.gz backup is in public/', function () {
    file_put_contents($this->tmpDir.'/public/db-backup-2024.sql.gz', 'fake gzip');

    $findings = iterator_to_array((new PublicSensitiveFilesCheck($this->tmpDir.'/public'))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->message)->toContain('db-backup-2024.sql.gz');
});
