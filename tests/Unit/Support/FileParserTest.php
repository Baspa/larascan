<?php

declare(strict_types=1);

use Baspa\Larascan\Support\FileParser;

it('parses a php file into a node list', function () {
    $path = __DIR__.'/fixtures/simple.php';
    @mkdir(dirname($path), 0755, true);
    file_put_contents($path, "<?php\necho 'hi';\n");

    $parser = new FileParser;
    $ast = $parser->parse($path);

    expect($ast)->toBeArray()->and($ast)->not->toBeEmpty();
    unlink($path);
});

it('returns null on syntax error', function () {
    $path = __DIR__.'/fixtures/broken.php';
    @mkdir(dirname($path), 0755, true);
    file_put_contents($path, "<?php\nthis is not php\n");

    $parser = new FileParser;
    $ast = $parser->parse($path);

    expect($ast)->toBeNull();
    unlink($path);
});

it('caches parsed AST per path', function () {
    $path = __DIR__.'/fixtures/cached.php';
    @mkdir(dirname($path), 0755, true);
    file_put_contents($path, "<?php\necho 1;\n");

    $parser = new FileParser;
    $first = $parser->parse($path);

    file_put_contents($path, "<?php\necho 2;\n"); // mutate after first parse
    $second = $parser->parse($path);

    expect($second)->toBe($first); // same array → cache hit
    unlink($path);
});

it('drops cached AST on flush', function () {
    $path = __DIR__.'/fixtures/flushed.php';
    @mkdir(dirname($path), 0755, true);
    file_put_contents($path, "<?php\necho 1;\n");

    $parser = new FileParser;
    $first = $parser->parse($path);

    $parser->flush();

    file_put_contents($path, "<?php\necho 2;\n"); // mutate, then re-parse after flush
    $second = $parser->parse($path);

    expect($second)->not->toBe($first); // cache cleared → fresh parse
    unlink($path);
});
