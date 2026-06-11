<?php

declare(strict_types=1);

use Baspa\Larascan\Exceptions\BaselineException;
use Baspa\Larascan\Support\Baseline;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\FindingHasher;
use Baspa\Larascan\Support\Severity;

beforeEach(function () {
    $this->baselinePath = sys_get_temp_dir().'/larascan-baseline-test-'.uniqid().'.json';
});

afterEach(function () {
    /** @var string $path */
    $path = $this->baselinePath;
    if (is_file($path)) {
        unlink($path);
    }
});

it('round-trips findings through toJson and fromFile', function () {
    $hasher = new FindingHasher;
    $findings = [
        new Finding('config.app-debug', Severity::Critical, 'APP_DEBUG is true in production'),
        new Finding('sql.raw-user-input', Severity::Critical, 'Raw SQL', file: 'app/Foo.php', line: 12),
    ];

    $baseline = Baseline::fromFindings($findings, $hasher);
    file_put_contents($this->baselinePath, $baseline->toJson());

    $loaded = Baseline::fromFile($this->baselinePath, $hasher);

    expect($loaded->count())->toBe(2);

    $matcher = $loaded->matcher();
    expect($matcher->suppresses($findings[0]))->toBeTrue()
        ->and($matcher->suppresses($findings[1]))->toBeTrue()
        ->and($matcher->staleCount())->toBe(0);
});

it('round-trips a finding whose message contains invalid UTF-8', function () {
    $hasher = new FindingHasher;
    $finding = new Finding('config.app-debug', Severity::Critical, "Invalid byte \xC3 from a scanned file");

    $baseline = Baseline::fromFindings([$finding], $hasher);
    $json = $baseline->toJson();

    expect($json)->not->toBe('');

    file_put_contents($this->baselinePath, $json);
    $loaded = Baseline::fromFile($this->baselinePath, $hasher);

    expect($loaded->count())->toBe(1);
});

it('merges separate file entries that hash identically', function () {
    // The two messages differ only in an embedded :line number, which the
    // hasher normalizes away, so both entries collapse into one hash.
    file_put_contents($this->baselinePath, (string) json_encode([
        'version' => 1,
        'findings' => [
            ['check' => 'auth.api-ability-scoping', 'file' => 'app/Foo.php', 'message' => 'createToken() at app/Foo.php:12 is unscoped', 'severity' => 'low', 'count' => 1],
            ['check' => 'auth.api-ability-scoping', 'file' => 'app/Foo.php', 'message' => 'createToken() at app/Foo.php:99 is unscoped', 'severity' => 'low', 'count' => 2],
        ],
    ]));

    $loaded = Baseline::fromFile($this->baselinePath, new FindingHasher);

    expect($loaded->count())->toBe(3);

    $matcher = $loaded->matcher();
    $finding = new Finding('auth.api-ability-scoping', Severity::Low, 'createToken() at app/Foo.php:55 is unscoped', file: 'app/Foo.php');

    expect($matcher->suppresses($finding))->toBeTrue()
        ->and($matcher->suppresses($finding))->toBeTrue()
        ->and($matcher->suppresses($finding))->toBeTrue()
        ->and($matcher->suppresses($finding))->toBeFalse();
});

it('writes a versioned, sorted JSON document', function () {
    $hasher = new FindingHasher;
    $baseline = Baseline::fromFindings([
        new Finding('sql.raw-user-input', Severity::Critical, 'Raw SQL', file: 'app/Foo.php'),
        new Finding('config.app-debug', Severity::Critical, 'APP_DEBUG is true'),
    ], $hasher);

    $decoded = json_decode($baseline->toJson(), true);

    expect($decoded['version'])->toBe(1)
        ->and($decoded['generated_at'])->toBeString()
        ->and($decoded['findings'])->toHaveCount(2)
        // Sorted by check id: config.* before sql.*
        ->and($decoded['findings'][0]['check'])->toBe('config.app-debug')
        ->and($decoded['findings'][1]['check'])->toBe('sql.raw-user-input')
        ->and($decoded['findings'][1])->toBe([
            'check' => 'sql.raw-user-input',
            'file' => 'app/Foo.php',
            'message' => 'Raw SQL',
            'severity' => 'critical',
            'count' => 1,
        ]);
});

it('aggregates duplicate findings into a single entry with count 2', function () {
    $hasher = new FindingHasher;
    $baseline = Baseline::fromFindings([
        new Finding('sql.raw-user-input', Severity::Critical, 'Raw SQL', file: 'app/Foo.php', line: 12),
        new Finding('sql.raw-user-input', Severity::Critical, 'Raw SQL', file: 'app/Foo.php', line: 80),
    ], $hasher);

    $decoded = json_decode($baseline->toJson(), true);

    expect($baseline->count())->toBe(2)
        ->and($decoded['findings'])->toHaveCount(1)
        ->and($decoded['findings'][0]['count'])->toBe(2);
});

it('throws when the baseline file is missing', function () {
    Baseline::fromFile('/nonexistent/larascan-baseline.json', new FindingHasher);
})->throws(BaselineException::class, 'Baseline file not found');

it('throws on malformed JSON', function () {
    file_put_contents($this->baselinePath, '{not json');

    Baseline::fromFile($this->baselinePath, new FindingHasher);
})->throws(BaselineException::class, 'invalid JSON');

it('throws on an unsupported version', function () {
    file_put_contents($this->baselinePath, (string) json_encode([
        'version' => 99,
        'findings' => [],
    ]));

    Baseline::fromFile($this->baselinePath, new FindingHasher);
})->throws(BaselineException::class, 'Unsupported baseline version');

it('throws on a malformed finding entry', function () {
    file_put_contents($this->baselinePath, (string) json_encode([
        'version' => 1,
        'findings' => [
            ['check' => 'config.app-debug'],
        ],
    ]));

    Baseline::fromFile($this->baselinePath, new FindingHasher);
})->throws(BaselineException::class, 'malformed finding entry');

it('suppresses exactly count occurrences then reports new ones', function () {
    $hasher = new FindingHasher;
    $finding = new Finding('sql.raw-user-input', Severity::Critical, 'Raw SQL', file: 'app/Foo.php');

    $matcher = Baseline::fromFindings([$finding, $finding], $hasher)->matcher();

    expect($matcher->suppresses($finding))->toBeTrue()
        ->and($matcher->suppresses($finding))->toBeTrue()
        ->and($matcher->suppresses($finding))->toBeFalse();
});

it('reports stale counts for unconsumed entries', function () {
    $hasher = new FindingHasher;
    $consumed = new Finding('config.app-debug', Severity::Critical, 'APP_DEBUG is true');
    $stale = new Finding('sql.raw-user-input', Severity::Critical, 'Raw SQL', file: 'app/Foo.php');

    $matcher = Baseline::fromFindings([$consumed, $stale, $stale], $hasher)->matcher();
    $matcher->suppresses($consumed);

    expect($matcher->staleCount())->toBe(2);
});

it('reports zero stale count when fully consumed', function () {
    $hasher = new FindingHasher;
    $finding = new Finding('config.app-debug', Severity::Critical, 'APP_DEBUG is true');

    $matcher = Baseline::fromFindings([$finding], $hasher)->matcher();
    $matcher->suppresses($finding);

    expect($matcher->staleCount())->toBe(0);
});
