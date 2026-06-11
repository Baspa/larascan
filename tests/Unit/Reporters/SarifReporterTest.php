<?php

declare(strict_types=1);

use Baspa\Larascan\Reporters\SarifReporter;
use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\CheckRegistry;
use Baspa\Larascan\Support\CheckStatus;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ScanResult;
use Baspa\Larascan\Support\Severity;
use Symfony\Component\Console\Output\BufferedOutput;

final class SarifStubCheck extends AbstractCheck
{
    public function __construct(
        private string $id,
        private Category $category = Category::Config,
        private Severity $severity = Severity::High,
        private string $name = 'Stub check',
    ) {}

    public function id(): string
    {
        return $this->id;
    }

    public function category(): Category
    {
        return $this->category;
    }

    public function severity(): Severity
    {
        return $this->severity;
    }

    public function name(): string
    {
        return $this->name;
    }

    /** @return iterable<Finding> */
    public function run(): iterable
    {
        return [];
    }
}

/**
 * @return array<string, mixed>
 */
function renderSarif(ScanResult $result, CheckRegistry $registry): array
{
    $output = new BufferedOutput;
    (new SarifReporter($registry))->render($result, $output);

    return json_decode($output->fetch(), true);
}

it('renders valid SARIF 2.1.0 with a single run and tool driver', function () {
    $registry = new CheckRegistry;
    $registry->register(new SarifStubCheck('config.app-debug'));

    $result = (new ScanResult)->record('config.app-debug', CheckStatus::Failed, [
        new Finding('config.app-debug', Severity::Critical, 'APP_DEBUG is true'),
    ]);

    $sarif = renderSarif($result, $registry);

    expect($sarif)->toBeArray()
        ->and($sarif['$schema'])->toBe('https://json.schemastore.org/sarif-2.1.0.json')
        ->and($sarif['version'])->toBe('2.1.0')
        ->and($sarif['runs'])->toHaveCount(1)
        ->and($sarif['runs'][0]['tool']['driver']['name'])->toBe('Larascan')
        ->and($sarif['runs'][0]['tool']['driver']['informationUri'])->toBe('https://github.com/baspa/larascan')
        ->and($sarif['runs'][0]['tool']['driver']['version'])->toBeString();
});

it('maps each severity to the correct level and security-severity', function (Severity $severity, string $level, string $score) {
    $registry = new CheckRegistry;
    $registry->register(new SarifStubCheck('config.stub', severity: $severity));

    $result = (new ScanResult)->record('config.stub', CheckStatus::Failed, [
        new Finding('config.stub', $severity, 'finding'),
    ]);

    $run = renderSarif($result, $registry)['runs'][0];

    expect($run['results'][0]['level'])->toBe($level)
        ->and($run['tool']['driver']['rules'][0]['defaultConfiguration']['level'])->toBe($level)
        ->and($run['tool']['driver']['rules'][0]['properties']['security-severity'])->toBe($score);
})->with([
    [Severity::Critical, 'error', '9.8'],
    [Severity::High, 'error', '8.0'],
    [Severity::Medium, 'warning', '5.5'],
    [Severity::Low, 'note', '3.0'],
    [Severity::Info, 'note', '0.0'],
]);

it('only includes rules that produced findings and links results via ruleIndex', function () {
    $registry = new CheckRegistry;
    $registry->register(new SarifStubCheck('config.clean'));
    $registry->register(new SarifStubCheck('config.dirty-a'));
    $registry->register(new SarifStubCheck('cookies.dirty-b', Category::Cookies));

    $result = (new ScanResult)
        ->record('config.clean', CheckStatus::Passed, [])
        ->record('config.dirty-a', CheckStatus::Failed, [
            new Finding('config.dirty-a', Severity::High, 'a1'),
            new Finding('config.dirty-a', Severity::High, 'a2'),
        ])
        ->record('cookies.dirty-b', CheckStatus::Failed, [
            new Finding('cookies.dirty-b', Severity::Medium, 'b1'),
        ]);

    $run = renderSarif($result, $registry)['runs'][0];
    $rules = $run['tool']['driver']['rules'];

    expect($rules)->toHaveCount(2)
        ->and(array_column($rules, 'id'))->toBe(['config.dirty-a', 'cookies.dirty-b'])
        ->and($run['results'])->toHaveCount(3);

    foreach ($run['results'] as $sarifResult) {
        expect($rules[$sarifResult['ruleIndex']]['id'])->toBe($sarifResult['ruleId']);
    }
});

it('emits a minimal rule for an unknown check id', function () {
    $result = (new ScanResult)->record('thirdparty.unknown', CheckStatus::Failed, [
        new Finding('thirdparty.unknown', Severity::Low, 'from a third-party check'),
    ]);

    $run = renderSarif($result, new CheckRegistry)['runs'][0];

    expect($run['tool']['driver']['rules'])->toBe([['id' => 'thirdparty.unknown']])
        ->and($run['results'][0]['ruleId'])->toBe('thirdparty.unknown')
        ->and($run['results'][0]['ruleIndex'])->toBe(0);
});

it('carries helpUri from docsUrl and a category tag on rules', function () {
    $check = new SarifStubCheck('cookies.session-secure', Category::Cookies, Severity::High, 'Session cookie is secure');
    $registry = new CheckRegistry;
    $registry->register($check);

    $result = (new ScanResult)->record('cookies.session-secure', CheckStatus::Failed, [
        new Finding('cookies.session-secure', Severity::High, 'SESSION_SECURE_COOKIE is false'),
    ]);

    $rule = renderSarif($result, $registry)['runs'][0]['tool']['driver']['rules'][0];

    expect($rule['helpUri'])->toBe($check->docsUrl())
        ->and($rule['name'])->toBe('Session cookie is secure')
        ->and($rule['shortDescription']['text'])->toBe('Session cookie is secure')
        ->and($rule['properties']['tags'])->toBe(['security', 'cookies']);
});

it('renders physical location with uri, startLine and snippet', function () {
    $registry = new CheckRegistry;
    $registry->register(new SarifStubCheck('sql.raw'));

    $result = (new ScanResult)->record('sql.raw', CheckStatus::Failed, [
        new Finding('sql.raw', Severity::Critical, 'Raw SQL', file: 'app/Foo.php', line: 42, snippet: 'DB::raw($input)'),
    ]);

    $location = renderSarif($result, $registry)['runs'][0]['results'][0]['locations'][0]['physicalLocation'];

    expect($location['artifactLocation']['uri'])->toBe('app/Foo.php')
        ->and($location['region']['startLine'])->toBe(42)
        ->and($location['region']['snippet']['text'])->toBe('DB::raw($input)');
});

it('synthesizes a composer.json anchor for findings without a file', function () {
    $registry = new CheckRegistry;
    $registry->register(new SarifStubCheck('config.app-debug'));

    $result = (new ScanResult)->record('config.app-debug', CheckStatus::Failed, [
        new Finding('config.app-debug', Severity::Critical, 'APP_DEBUG is true'),
    ]);

    $sarifResult = renderSarif($result, $registry)['runs'][0]['results'][0];
    $location = $sarifResult['locations'][0]['physicalLocation'];

    expect($location['artifactLocation']['uri'])->toBe('composer.json')
        ->and($location['region']['startLine'])->toBe(1)
        ->and($sarifResult['properties']['larascan']['synthesizedLocation'])->toBeTrue();
});

it('substitutes invalid UTF-8 in messages instead of producing an empty report', function () {
    $registry = new CheckRegistry;
    $registry->register(new SarifStubCheck('config.app-debug'));

    $result = (new ScanResult)->record('config.app-debug', CheckStatus::Failed, [
        new Finding('config.app-debug', Severity::Critical, "Invalid \xC3 byte"),
    ]);

    $output = new BufferedOutput;
    (new SarifReporter($registry))->render($result, $output);
    $raw = $output->fetch();

    $sarif = json_decode($raw, true);

    expect($raw)->not->toBe('')
        ->and($sarif)->toBeArray()
        ->and($sarif['runs'][0]['results'][0]['message']['text'])->toBe("Invalid \u{FFFD} byte");
});

it('keeps console-style tags in messages verbatim', function () {
    $registry = new CheckRegistry;
    $registry->register(new SarifStubCheck('config.app-debug'));

    $result = (new ScanResult)->record('config.app-debug', CheckStatus::Failed, [
        new Finding('config.app-debug', Severity::Critical, 'Found <error>Oops</error> in view'),
    ]);

    $sarif = renderSarif($result, $registry);

    expect($sarif['runs'][0]['results'][0]['message']['text'])->toBe('Found <error>Oops</error> in view');
});

it('synthesizes a composer.json anchor for findings with an empty-string file', function () {
    $registry = new CheckRegistry;
    $registry->register(new SarifStubCheck('config.app-debug'));

    $result = (new ScanResult)->record('config.app-debug', CheckStatus::Failed, [
        new Finding('config.app-debug', Severity::Critical, 'APP_DEBUG is true', file: '', line: 12),
    ]);

    $sarifResult = renderSarif($result, $registry)['runs'][0]['results'][0];
    $location = $sarifResult['locations'][0]['physicalLocation'];

    expect($location['artifactLocation']['uri'])->toBe('composer.json')
        ->and($location['region']['startLine'])->toBe(1)
        ->and($sarifResult['properties']['larascan']['synthesizedLocation'])->toBeTrue();
});

it('falls back to the synthesized anchor for absolute paths outside base_path', function () {
    $registry = new CheckRegistry;
    $registry->register(new SarifStubCheck('php.display-errors'));

    $result = (new ScanResult)->record('php.display-errors', CheckStatus::Failed, [
        new Finding('php.display-errors', Severity::High, 'display_errors is on', file: '/etc/php/php.ini', line: 99),
    ]);

    $sarifResult = renderSarif($result, $registry)['runs'][0]['results'][0];
    $location = $sarifResult['locations'][0]['physicalLocation'];

    expect($location['artifactLocation']['uri'])->toBe('composer.json')
        ->and($location['region']['startLine'])->toBe(1)
        ->and($sarifResult['properties']['larascan']['synthesizedLocation'])->toBeTrue();
});

it('relativizes absolute paths under base_path and normalizes backslashes', function () {
    $registry = new CheckRegistry;
    $registry->register(new SarifStubCheck('xss.blade'));

    $result = (new ScanResult)->record('xss.blade', CheckStatus::Failed, [
        new Finding('xss.blade', Severity::Medium, 'absolute', file: base_path('app/Http/Kernel.php'), line: 3),
        new Finding('xss.blade', Severity::Medium, 'backslashes', file: 'resources\\views\\welcome.blade.php', line: 7),
    ]);

    $results = renderSarif($result, $registry)['runs'][0]['results'];

    expect($results[0]['locations'][0]['physicalLocation']['artifactLocation']['uri'])->toBe('app/Http/Kernel.php')
        ->and($results[1]['locations'][0]['physicalLocation']['artifactLocation']['uri'])->toBe('resources/views/welcome.blade.php');
});

it('produces zero results for passed, skipped and errored checks', function () {
    $registry = new CheckRegistry;
    $registry->register(new SarifStubCheck('config.passed'));
    $registry->register(new SarifStubCheck('config.skipped'));
    $registry->register(new SarifStubCheck('config.errored'));

    $result = (new ScanResult)
        ->record('config.passed', CheckStatus::Passed, [])
        ->record('config.skipped', CheckStatus::Skipped, [], 'not applicable')
        ->recordError('config.errored', new RuntimeException('boom'));

    $run = renderSarif($result, $registry)['runs'][0];

    expect($run['results'])->toBe([])
        ->and($run['tool']['driver']['rules'])->toBe([]);
});

it('includes every required key on rules and results', function () {
    $registry = new CheckRegistry;
    $registry->register(new SarifStubCheck('config.app-debug'));

    $result = (new ScanResult)->record('config.app-debug', CheckStatus::Failed, [
        new Finding('config.app-debug', Severity::Critical, 'APP_DEBUG is true', file: 'config/app.php', line: 5),
    ]);

    $run = renderSarif($result, $registry)['runs'][0];

    expect($run['tool']['driver']['rules'][0])->toHaveKeys([
        'id', 'name', 'shortDescription', 'helpUri', 'defaultConfiguration', 'properties',
    ])->and($run['results'][0])->toHaveKeys([
        'ruleId', 'ruleIndex', 'level', 'message', 'locations',
    ])->and($run['results'][0]['message'])->toHaveKey('text')
        ->and($run['results'][0]['locations'][0]['physicalLocation'])->toHaveKeys([
            'artifactLocation', 'region',
        ]);
});
