<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

final readonly class ProbeContext
{
    /**
     * @param  array<string, array<int, string>>  $headers  Lower-cased header names mapped to their value list.
     * @param  array<int, array{name: string, secure: bool, httponly: bool, samesite: ?string}>  $cookies
     * @param  array{status: int, location: ?string}|null  $httpRedirect  Null when the target was already http.
     */
    public function __construct(
        public string $url,
        public bool $isHttps,
        public bool $isLocal,
        public int $status,
        public array $headers = [],
        public array $cookies = [],
        public ?array $httpRedirect = null,
    ) {}

    public function header(string $name): ?string
    {
        $values = $this->headers[strtolower($name)] ?? [];

        return $values[0] ?? null;
    }

    public function hasHeader(string $name): bool
    {
        return isset($this->headers[strtolower($name)]);
    }
}
