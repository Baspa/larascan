<?php

declare(strict_types=1);

use Baspa\Larascan\Advices\Config\ConfigValidatedAtBootAdvice;
use Baspa\Larascan\Support\AdviceStatus;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;

function configValidatedTmpDirRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-advise-cfg-validate-'.uniqid();
    mkdir($this->tmpDir.'/app/Providers', recursive: true);
});

afterEach(function () {
    configValidatedTmpDirRemove($this->tmpDir);
});

it('exposes correct metadata', function () {
    $advice = new ConfigValidatedAtBootAdvice($this->tmpDir.'/app', new FileParser);

    expect($advice->id())->toBe('advise.config-validated-at-boot')
        ->and($advice->category())->toBe(Category::Config);
});

it('is skipped when app/Providers does not exist', function () {
    $bogus = sys_get_temp_dir().'/no-such-dir-'.uniqid();
    $advice = new ConfigValidatedAtBootAdvice($bogus, new FileParser);
    expect($advice->run()->status)->toBe(AdviceStatus::Skipped);
});

it('surfaces when no provider has throw + config in the same method', function () {
    file_put_contents(
        $this->tmpDir.'/app/Providers/AppServiceProvider.php',
        "<?php\nnamespace App\\Providers;\nclass AppServiceProvider {\n    public function boot() { echo 'hi'; }\n}\n",
    );

    $outcome = (new ConfigValidatedAtBootAdvice($this->tmpDir.'/app', new FileParser))->run();
    expect($outcome->status)->toBe(AdviceStatus::Surfaced);
});

it('does not surface when a provider has throw + config in the same method', function () {
    file_put_contents(
        $this->tmpDir.'/app/Providers/AppServiceProvider.php',
        "<?php\nnamespace App\\Providers;\nclass AppServiceProvider {\n    public function boot() { if (! config('app.key')) { throw new \\RuntimeException('missing app.key'); } }\n}\n",
    );

    $outcome = (new ConfigValidatedAtBootAdvice($this->tmpDir.'/app', new FileParser))->run();
    expect($outcome->status)->toBe(AdviceStatus::NotSurfaced);
});
