<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Dependencies\OutdatedPhpCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Foundation\Application;

function outdatedPhpCheckAt(Application $app, string $version, string $today): OutdatedPhpCheck
{
    return new class($app, $version, $today) extends OutdatedPhpCheck
    {
        public function __construct(
            Application $app,
            private readonly string $version,
            private readonly string $date,
        ) {
            parent::__construct($app);
        }

        protected function phpVersionId(): int
        {
            [$major, $minor, $patch] = array_map(intval(...), explode('.', $this->version));

            return $major * 10000 + $minor * 100 + $patch;
        }

        protected function phpVersionString(): string
        {
            return $this->version;
        }

        protected function today(): DateTimeImmutable
        {
            return new DateTimeImmutable($this->date);
        }
    };
}

beforeEach(function () {
    config()->set('app.env', 'production');
});

it('exposes correct metadata', function () {
    $check = new OutdatedPhpCheck($this->app);

    expect($check->id())->toBe('dependencies.outdated-php')
        ->and($check->category())->toBe(Category::Dependencies)
        ->and($check->severity())->toBe(Severity::High)
        ->and($check->name())->toBe('PHP version past active support or near end-of-life');
});

it('flags a branch whose security support has ended as end-of-life', function () {
    $findings = iterator_to_array(outdatedPhpCheckAt($this->app, '8.3.30', '2028-01-01')->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('dependencies.outdated-php')
        ->and($findings[0]->message)->toBe('PHP 8.3.30 is end-of-life: security support ended on 2027-12-31 — upgrade to PHP 8.6, the oldest branch still in active support.');
});

it('flags a branch whose security support ends within 12 months as near end-of-life', function () {
    $findings = iterator_to_array(outdatedPhpCheckAt($this->app, '8.3.30', '2027-01-01')->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->message)->toBe('PHP 8.3.30 is near end-of-life: security support ends on 2027-12-31 — upgrade to PHP 8.5, the oldest branch still in active support.');
});

it('flags a branch that only receives security fixes as medium', function () {
    $findings = iterator_to_array(outdatedPhpCheckAt($this->app, '8.3.14', '2026-11-18')->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->message)->toBe('PHP 8.3.14 only receives security fixes, which stop on 2027-12-31 — upgrade to PHP 8.4, the oldest branch still in active support.');
});

it('passes for a branch in active support', function (string $version) {
    expect(iterator_to_array(outdatedPhpCheckAt($this->app, $version, '2026-11-18')->run()))->toBeEmpty();
})->with(['8.4.15', '8.5.0', '8.6.0']);

it('passes for a branch newer than the support table', function (string $version, string $today) {
    expect(iterator_to_array(outdatedPhpCheckAt($this->app, $version, $today)->run()))->toBeEmpty();
})->with([
    ['8.7.0', '2026-11-18'],
    ['9.0.0', '2035-01-01'],
]);

it('switches findings on the support end dates', function (string $today, Severity $severity, string $status) {
    $findings = iterator_to_array(outdatedPhpCheckAt($this->app, '8.3.30', $today)->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe($severity)
        ->and($findings[0]->message)->toContain($status);
})->with([
    'day before the near end-of-life window' => ['2026-12-30', Severity::Medium, 'only receives security fixes'],
    'first day of the near end-of-life window' => ['2026-12-31', Severity::High, 'is near end-of-life'],
    'last day of security support' => ['2027-12-31', Severity::High, 'is near end-of-life'],
    'first day after security support' => ['2028-01-01', Severity::High, 'is end-of-life'],
]);

it('advises a newer branch when no listed branch is in active support', function () {
    $findings = iterator_to_array(outdatedPhpCheckAt($this->app, '8.6.5', '2030-06-01')->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toBe('PHP 8.6.5 is near end-of-life: security support ends on 2030-12-31 — upgrade to a newer PHP branch.');
});

it('downgrades the finding to info outside production', function (string $today) {
    config()->set('app.env', 'local');

    $findings = iterator_to_array(outdatedPhpCheckAt($this->app, '8.3.30', $today)->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Info);
})->with([
    'end-of-life' => '2028-01-01',
    'security fixes only' => '2026-11-18',
]);
