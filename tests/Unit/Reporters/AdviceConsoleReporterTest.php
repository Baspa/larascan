<?php

declare(strict_types=1);

use Baspa\Larascan\Contracts\Advice;
use Baspa\Larascan\Reporters\AdviceConsoleReporter;
use Baspa\Larascan\Support\AdviceEvidence;
use Baspa\Larascan\Support\AdviceOutcome;
use Baspa\Larascan\Support\AdviceRegistry;
use Baspa\Larascan\Support\AdviceResult;
use Baspa\Larascan\Support\Category;
use Symfony\Component\Console\Output\BufferedOutput;

function makeConsoleReportableAdvice(string $id): Advice
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

it('renders surfaced advices with the flag glyph and evidence list', function () {
    $registry = new AdviceRegistry;
    $registry->register(makeConsoleReportableAdvice('advise.foo'));

    $result = new AdviceResult;
    $result->record('advise.foo', AdviceOutcome::surfaced('summary text', [
        new AdviceEvidence('first', 'app/A.php', 10),
        new AdviceEvidence('second', 'app/B.php', 20),
    ]));

    $output = new BufferedOutput;
    (new AdviceConsoleReporter)->render($result, $registry, $output);

    $text = $output->fetch();
    expect($text)->toContain('advise.foo')
        ->and($text)->toContain('summary text')
        ->and($text)->toContain('app/A.php:10')
        ->and($text)->toContain('app/B.php:20')
        ->and($text)->toContain('Manual security review');
});

it('prints a friendly message when no advices surfaced', function () {
    $registry = new AdviceRegistry;
    $result = new AdviceResult;

    $output = new BufferedOutput;
    (new AdviceConsoleReporter)->render($result, $registry, $output);

    $text = $output->fetch();
    expect($text)->toContain('no advices configured');
});
