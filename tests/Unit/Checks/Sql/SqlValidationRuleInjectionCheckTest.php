<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Sql\SqlValidationRuleInjectionCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function sqlValidationRuleInjectionRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-sql-validation-rule-injection-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    sqlValidationRuleInjectionRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new SqlValidationRuleInjectionCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('sql.validation-rule-injection')
        ->and($check->category())->toBe(Category::Sql)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('passes when there are no validate() calls', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return ['ok' => true];\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlValidationRuleInjectionCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('passes when validate() uses a literal array of rules', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function store(\$request) {\n        \$request->validate(\$request, ['name' => 'required']);\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlValidationRuleInjectionCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when validate() uses a variable as rules', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function store(\$request, \$rules) {\n        \$request->validate(\$request, \$rules);\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlValidationRuleInjectionCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('sql.validation-rule-injection')
        ->and($findings[0]->message)->toContain('Validation rules sourced from a variable')
        ->and($findings[0]->message)->toContain('exists:table');
});

it('fails when Validator::make() uses a variable as rules', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nuse Illuminate\\Support\\Facades\\Validator;\nclass UserController {\n    public function store(\$data, \$rules) {\n        Validator::make(\$data, \$rules);\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlValidationRuleInjectionCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('sql.validation-rule-injection')
        ->and($findings[0]->message)->toContain('Validation rules sourced from a variable');
});
