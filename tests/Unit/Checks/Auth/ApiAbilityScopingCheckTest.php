<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Auth\ApiAbilityScopingCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function apiAbilityScopingRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-api-ability-scoping-'.uniqid();
    mkdir($this->tmpDir.'/app', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    apiAbilityScopingRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new ApiAbilityScopingCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('auth.api-ability-scoping')
        ->and($check->category())->toBe(Category::Auth)
        ->and($check->severity())->toBe(Severity::Low)
        ->and($check->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/checks/auth/api-ability-scoping.md');
});

it('is not applicable when Sanctum is not installed', function () {
    if (class_exists('Laravel\\Sanctum\\Sanctum')) {
        $this->markTestSkipped('Sanctum is installed; cannot test the not-installed branch.');
    }

    $check = new ApiAbilityScopingCheck($this->tmpDir.'/app', new FileParser);
    expect($check->isApplicable())->toBeFalse();
});

it('passes when there are no createToken calls', function () {
    if (! class_exists('Laravel\\Sanctum\\Sanctum')) {
        $this->markTestSkipped('Sanctum is not installed.');
    }

    file_put_contents(
        $this->tmpDir.'/app/Example.php',
        "<?php\nnamespace App;\nclass Example {\n    public function handle() {\n        return 'ok';\n    }\n}\n",
    );

    $findings = iterator_to_array((new ApiAbilityScopingCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when createToken is called with an empty abilities array', function () {
    if (! class_exists('Laravel\\Sanctum\\Sanctum')) {
        $this->markTestSkipped('Sanctum is not installed.');
    }

    file_put_contents(
        $this->tmpDir.'/app/TokenIssuer.php',
        "<?php\nnamespace App;\nclass TokenIssuer {\n    public function handle(\$user) {\n        return \$user->createToken('api', []);\n    }\n}\n",
    );

    $findings = iterator_to_array((new ApiAbilityScopingCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low)
        ->and($findings[0]->checkId)->toBe('auth.api-ability-scoping')
        ->and($findings[0]->file)->toContain('TokenIssuer.php')
        ->and($findings[0]->message)->toContain('createToken');
});

it('fails when createToken is called without a second argument', function () {
    if (! class_exists('Laravel\\Sanctum\\Sanctum')) {
        $this->markTestSkipped('Sanctum is not installed.');
    }

    file_put_contents(
        $this->tmpDir.'/app/TokenIssuer.php',
        "<?php\nnamespace App;\nclass TokenIssuer {\n    public function handle(\$user) {\n        return \$user->createToken('api');\n    }\n}\n",
    );

    $findings = iterator_to_array((new ApiAbilityScopingCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low)
        ->and($findings[0]->checkId)->toBe('auth.api-ability-scoping')
        ->and($findings[0]->file)->toContain('TokenIssuer.php')
        ->and($findings[0]->message)->toContain('scoped abilities');
});
