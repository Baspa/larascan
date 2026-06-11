<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use Throwable;

final class ProbeContextFactory
{
    private const USER_AGENT = 'larascan-probe';

    private const MAX_REDIRECTS = 5;

    public function fromUrl(string $url, int $timeout, bool $insecure): ProbeContext
    {
        $scheme = strtolower((string) (parse_url($url, PHP_URL_SCHEME) ?: ''));
        $host = strtolower((string) (parse_url($url, PHP_URL_HOST) ?: ''));
        $isHttps = $scheme === 'https';

        $request = Http::withUserAgent(self::USER_AGENT)
            ->timeout($timeout)
            ->withOptions(['allow_redirects' => ['max' => self::MAX_REDIRECTS]]);

        if ($insecure) {
            $request = $request->withoutVerifying();
        }

        $response = $request->get($url);

        $httpRedirect = $isHttps
            ? $this->captureHttpRedirect($url, $timeout, $insecure)
            : null;

        // Build the lower-cased header map once so cookie lookup is insensitive
        // to the server's original Set-Cookie casing (Guzzle/PSR-7 preserves it).
        $headers = $this->normalizeHeaders($response);
        $setCookies = $headers['set-cookie'] ?? [];

        return new ProbeContext(
            url: $url,
            isHttps: $isHttps,
            isLocal: $this->isLocal($host),
            status: $response->status(),
            headers: $headers,
            cookies: $this->parseCookies($setCookies),
            httpRedirect: $httpRedirect,
        );
    }

    /**
     * Issue a second GET to the http:// variant without following redirects,
     * capturing the status + Location so HttpsRedirectProbe can verify the
     * app upgrades plain HTTP to HTTPS. Failures leave httpRedirect null.
     *
     * @return array{status: int, location: ?string}|null
     */
    private function captureHttpRedirect(string $url, int $timeout, bool $insecure): ?array
    {
        $httpUrl = preg_replace('/^https:/i', 'http:', $url);
        if (! is_string($httpUrl)) {
            return null;
        }

        try {
            $request = Http::withUserAgent(self::USER_AGENT)
                ->timeout($timeout)
                ->withOptions(['allow_redirects' => false]);

            if ($insecure) {
                $request = $request->withoutVerifying();
            }

            $response = $request->get($httpUrl);

            $location = $response->header('Location');

            return [
                'status' => $response->status(),
                'location' => $location !== '' ? $location : null,
            ];
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @return array<string, array<int, string>>
     */
    private function normalizeHeaders(Response $response): array
    {
        $normalized = [];
        foreach ($response->headers() as $name => $values) {
            $normalized[strtolower($name)] = array_values($values);
        }

        return $normalized;
    }

    /**
     * @param  array<int, string>  $setCookies  Set-Cookie header values from the normalized header map.
     * @return array<int, array{name: string, secure: bool, httponly: bool, samesite: ?string}>
     */
    private function parseCookies(array $setCookies): array
    {
        $cookies = [];
        foreach ($setCookies as $header) {
            $cookies[] = $this->parseCookie($header);
        }

        return $cookies;
    }

    /**
     * @return array{name: string, secure: bool, httponly: bool, samesite: ?string}
     */
    private function parseCookie(string $header): array
    {
        $parts = array_map('trim', explode(';', $header));
        $name = '';
        if (($parts[0] ?? '') !== '') {
            $name = explode('=', $parts[0], 2)[0];
        }

        $secure = false;
        $httponly = false;
        $samesite = null;

        foreach (array_slice($parts, 1) as $attr) {
            $lower = strtolower($attr);
            if ($lower === 'secure') {
                $secure = true;

                continue;
            }
            if ($lower === 'httponly') {
                $httponly = true;

                continue;
            }
            if (str_starts_with($lower, 'samesite=')) {
                $samesite = trim(explode('=', $attr, 2)[1] ?? '');
            }
        }

        return [
            'name' => $name,
            'secure' => $secure,
            'httponly' => $httponly,
            'samesite' => $samesite !== '' ? $samesite : null,
        ];
    }

    /**
     * A target is "local" only when its host looks like a development host —
     * a non-local plain-HTTP site keeps full severity so hsts/https-redirect
     * findings are not silently downgraded to Info.
     */
    private function isLocal(string $host): bool
    {
        if ($host === 'localhost' || $host === '127.0.0.1') {
            return true;
        }

        return str_ends_with($host, '.test') || str_ends_with($host, '.local');
    }
}
