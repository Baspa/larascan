<?php

declare(strict_types=1);

use Baspa\Larascan\Contracts\Advice;
use Baspa\Larascan\Reporters\AdviceJsonReporter;
use Baspa\Larascan\Support\AdviceEvidence;
use Baspa\Larascan\Support\AdviceOutcome;
use Baspa\Larascan\Support\AdviceRegistry;
use Baspa\Larascan\Support\AdviceResult;
use Baspa\Larascan\Support\Category;
use Symfony\Component\Console\Output\BufferedOutput;

function makeReportableAdvice(string $id): Advice
{
    return new class($id) implements Advice
    {
        public function __construct(private string $idValue) {}

        public function id(): string
        {
            return $this->idValue;
        }

        public function category(): Category
        {
            return Category::Auth;
        }

        public function name(): string
        {
            return 'A descriptive name';
        }

        public function isApplicable(): bool
        {
            return true;
        }

        public function docsUrl(): string
        {
            return 'https://example.test';
        }

        public function run(): AdviceOutcome
        {
            return AdviceOutcome::notSurfaced();
        }
    };
}

it('renders the json shape from the design', function () {
    $registry = new AdviceRegistry;
    $registry->register(makeReportableAdvice('advise.foo'));

    $result = new AdviceResult;
    $result->record('advise.foo', AdviceOutcome::surfaced(
        '2 things found',
        [new AdviceEvidence('first', 'app/A.php', 12), new AdviceEvidence('second', 'app/B.php')],
    ));

    $output = new BufferedOutput;
    (new AdviceJsonReporter)->render($result, $registry, $output);

    /** @var array<string, mixed> $decoded */
    $decoded = json_decode($output->fetch(), true, flags: JSON_THROW_ON_ERROR);

    expect($decoded['version'])->toBe('2.1.0')
        ->and($decoded['summary'])->toBe([
            'surfaced' => 1, 'not_surfaced' => 0, 'skipped' => 0, 'errored' => 0,
        ])
        ->and($decoded['advices'])->toHaveCount(1)
        ->and($decoded['advices'][0]['id'])->toBe('advise.foo')
        ->and($decoded['advices'][0]['category'])->toBe('auth')
        ->and($decoded['advices'][0]['status'])->toBe('surfaced')
        ->and($decoded['advices'][0]['summary'])->toBe('2 things found')
        ->and($decoded['advices'][0]['evidence'])->toHaveCount(2);
});
