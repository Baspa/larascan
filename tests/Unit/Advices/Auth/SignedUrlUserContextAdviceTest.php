<?php

declare(strict_types=1);

use Baspa\Larascan\Advices\Auth\SignedUrlUserContextAdvice;
use Baspa\Larascan\Support\AdviceStatus;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;

function signedUrlUserContextTmpDirRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-advise-signed-url-ctx-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    signedUrlUserContextTmpDirRemove($this->tmpDir);
});

it('exposes correct metadata', function () {
    $advice = new SignedUrlUserContextAdvice($this->tmpDir.'/app', new FileParser);

    expect($advice->id())->toBe('advise.signed-url-user-context')
        ->and($advice->category())->toBe(Category::Auth);
});

it('does not surface when signed URLs include user-bound params', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nuse Illuminate\Support\Facades\URL;\nclass X { public function go() { return URL::signedRoute('invite', ['user_id' => 1]); } }\n",
    );

    $outcome = (new SignedUrlUserContextAdvice($this->tmpDir.'/app', new FileParser))->run();

    expect($outcome->status)->toBe(AdviceStatus::NotSurfaced);
});

it('surfaces when signed URLs have params but no user-bound key', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nuse Illuminate\Support\Facades\URL;\nclass X { public function go() { return URL::signedRoute('invite', ['code' => 'abc']); } }\n",
    );

    $outcome = (new SignedUrlUserContextAdvice($this->tmpDir.'/app', new FileParser))->run();

    expect($outcome->status)->toBe(AdviceStatus::Surfaced)
        ->and($outcome->evidence)->toHaveCount(1)
        ->and($outcome->evidence[0]->file)->toContain('X.php')
        ->and($outcome->evidence[0]->line)->toBe(3);
});

it('does not surface when params arg is a variable (assumed user-bound)', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nuse Illuminate\Support\Facades\URL;\nclass X { public function go(\$params) { return URL::signedRoute('invite', \$params); } }\n",
    );

    $outcome = (new SignedUrlUserContextAdvice($this->tmpDir.'/app', new FileParser))->run();

    expect($outcome->status)->toBe(AdviceStatus::NotSurfaced);
});

it('does not surface when there are no signed URLs (covered by check, not advice)', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nuse Illuminate\Support\Facades\URL;\nclass X { public function go() { return URL::signedRoute('invite'); } }\n",
    );

    $outcome = (new SignedUrlUserContextAdvice($this->tmpDir.'/app', new FileParser))->run();

    expect($outcome->status)->toBe(AdviceStatus::NotSurfaced);
});
