<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Files\UploadMimesValidationCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function uploadMimesValidationRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-upload-mimes-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Requests', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    uploadMimesValidationRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new UploadMimesValidationCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('files.upload-mimes-validation')
        ->and($check->category())->toBe(Category::Files)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when no validation rules are present', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Requests/StoreRequest.php',
        "<?php\nclass StoreRequest {\n    public function rules() {\n        return [];\n    }\n}\n",
    );

    $findings = iterator_to_array((new UploadMimesValidationCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('passes when validation uses mimes: rule', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Requests/StoreRequest.php',
        "<?php\nclass StoreRequest {\n    public function rules() {\n        return ['file' => 'required|mimes:jpg,png,pdf'];\n    }\n}\n",
    );

    $findings = iterator_to_array((new UploadMimesValidationCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when validation uses extensions: rule', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Requests/StoreRequest.php',
        "<?php\nclass StoreRequest {\n    public function rules() {\n        return ['file' => 'required|extensions:jpg,png'];\n    }\n}\n",
    );

    $findings = iterator_to_array((new UploadMimesValidationCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('files.upload-mimes-validation')
        ->and($findings[0]->message)->toContain('extensions:');
});

it('reports the correct line number', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Requests/StoreRequest.php',
        "<?php\nclass StoreRequest {\n    public function rules() {\n        return [\n            'avatar' => 'required|extensions:jpg,png',\n        ];\n    }\n}\n",
    );

    $findings = iterator_to_array((new UploadMimesValidationCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->line)->toBe(5);
});
