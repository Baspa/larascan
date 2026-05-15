<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Files\PublicExecutableUploadsCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function publicExecutableUploadsRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-public-executable-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Requests', recursive: true);
    mkdir($this->tmpDir.'/public', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    publicExecutableUploadsRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new PublicExecutableUploadsCheck($this->tmpDir.'/app', new FileParser, $this->tmpDir.'/public');

    expect($check->id())->toBe('files.public-executable-uploads')
        ->and($check->category())->toBe(Category::Files)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when no validation rules are present', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Requests/StoreRequest.php',
        "<?php\nclass StoreRequest {\n    public function rules() {\n        return [];\n    }\n}\n",
    );

    $findings = iterator_to_array((new PublicExecutableUploadsCheck($this->tmpDir.'/app', new FileParser, $this->tmpDir.'/public'))->run());
    expect($findings)->toBeEmpty();
});

it('passes when mimes: only allows safe extensions', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Requests/StoreRequest.php',
        "<?php\nclass StoreRequest {\n    public function rules() {\n        return ['file' => 'required|mimes:jpg,png'];\n    }\n}\n",
    );

    $findings = iterator_to_array((new PublicExecutableUploadsCheck($this->tmpDir.'/app', new FileParser, $this->tmpDir.'/public'))->run());
    expect($findings)->toBeEmpty();
});

it('fails when mimes: includes one executable extension', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Requests/StoreRequest.php',
        "<?php\nclass StoreRequest {\n    public function rules() {\n        return ['file' => 'required|mimes:jpg,php,png'];\n    }\n}\n",
    );

    $findings = iterator_to_array((new PublicExecutableUploadsCheck($this->tmpDir.'/app', new FileParser, $this->tmpDir.'/public'))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('files.public-executable-uploads')
        ->and($findings[0]->message)->toContain("'php'");
});

it('fails when mimes: includes multiple executable extensions', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Requests/StoreRequest.php',
        "<?php\nclass StoreRequest {\n    public function rules() {\n        return ['file' => 'required|mimes:phtml,phar,jpg'];\n    }\n}\n",
    );

    $findings = iterator_to_array((new PublicExecutableUploadsCheck($this->tmpDir.'/app', new FileParser, $this->tmpDir.'/public'))->run());

    expect($findings)->toHaveCount(2)
        ->and($findings[0]->message)->toContain("'phtml'")
        ->and($findings[1]->message)->toContain("'phar'");
});
