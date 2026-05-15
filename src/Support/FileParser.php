<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\Parser;
use PhpParser\ParserFactory;

final class FileParser
{
    private readonly Parser $parser;

    /** @var array<string, array<int, Node>|null> */
    private array $cache = [];

    public function __construct()
    {
        $this->parser = (new ParserFactory)->createForHostVersion();
    }

    /**
     * @return array<int, Node>|null
     */
    public function parse(string $path): ?array
    {
        if (array_key_exists($path, $this->cache)) {
            return $this->cache[$path];
        }

        $source = @file_get_contents($path);
        if ($source === false) {
            return $this->cache[$path] = null;
        }

        try {
            $ast = $this->parser->parse($source);
        } catch (Error) {
            return $this->cache[$path] = null;
        }

        return $this->cache[$path] = $ast;
    }
}
