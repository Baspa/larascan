<?php

declare(strict_types=1);

use Baspa\Larascan\Advices\Crypto\StagingKeyInProductionAdvice;
use Baspa\Larascan\Support\AdviceStatus;
use Baspa\Larascan\Support\Category;

beforeEach(function () {
    $this->tmpDir = sys_get_temp_dir().'/larascan-advise-staging-'.uniqid();
    mkdir($this->tmpDir, recursive: true);
});

afterEach(function () {
    @unlink($this->tmpDir.'/.env');
    @rmdir($this->tmpDir);
});

it('exposes correct metadata', function () {
    $advice = new StagingKeyInProductionAdvice($this->tmpDir);

    expect($advice->id())->toBe('advise.staging-key-in-production')
        ->and($advice->category())->toBe(Category::Crypto);
});

it('is skipped when .env does not exist', function () {
    $outcome = (new StagingKeyInProductionAdvice($this->tmpDir))->run();
    expect($outcome->status)->toBe(AdviceStatus::Skipped);
});

it('does not surface when no test prefixes are present', function () {
    file_put_contents($this->tmpDir.'/.env', "APP_ENV=production\nAPP_KEY=base64:abc=\n");

    $outcome = (new StagingKeyInProductionAdvice($this->tmpDir))->run();
    expect($outcome->status)->toBe(AdviceStatus::NotSurfaced);
});

it('surfaces when a test-prefixed value is present', function () {
    file_put_contents($this->tmpDir.'/.env', "APP_ENV=production\nSTRIPE_KEY=sk_test_abc123def456\n");

    $outcome = (new StagingKeyInProductionAdvice($this->tmpDir))->run();

    expect($outcome->status)->toBe(AdviceStatus::Surfaced)
        ->and($outcome->evidence)->toHaveCount(1)
        ->and($outcome->evidence[0]->message)->toContain('STRIPE_KEY')
        ->and($outcome->summary)->toContain('likely active in production');
});

it('mentions test key but does not escalate when APP_ENV is not production', function () {
    file_put_contents($this->tmpDir.'/.env', "APP_ENV=local\nSTRIPE_KEY=sk_test_abc123\n");

    $outcome = (new StagingKeyInProductionAdvice($this->tmpDir))->run();

    expect($outcome->status)->toBe(AdviceStatus::Surfaced)
        ->and($outcome->summary)->not->toContain('likely active in production');
});

it('surfaces values containing _test_ even without an sk_/pk_/whsec_ prefix', function () {
    file_put_contents($this->tmpDir.'/.env', "APP_ENV=production\nSOME_TOKEN=abc_test_xyz789\n");

    $outcome = (new StagingKeyInProductionAdvice($this->tmpDir))->run();

    expect($outcome->status)->toBe(AdviceStatus::Surfaced)
        ->and($outcome->evidence)->toHaveCount(1)
        ->and($outcome->evidence[0]->message)->toContain("contains '_test_'")
        ->and($outcome->evidence[0]->message)->toContain('SOME_TOKEN');
});
