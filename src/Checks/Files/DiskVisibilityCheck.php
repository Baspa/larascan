<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Files;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class DiskVisibilityCheck extends AbstractCheck
{
    private const SENSITIVE_KEYWORDS = '/private|secret|secure|backup|invoice|document|export|report|admin/i';

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'files.disk-visibility';
    }

    public function category(): Category
    {
        return Category::Files;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'Filesystem disk visibility should match the sensitivity of its contents';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        /** @var array<string, mixed> $disks */
        $disks = (array) $config->get('filesystems.disks', []);

        foreach ($disks as $name => $disk) {
            if (! is_array($disk)) {
                continue;
            }

            $name = (string) $name;

            if ($name !== 'public' && ($disk['visibility'] ?? null) === 'public' && $this->looksSensitive($name, $disk)) {
                yield new Finding(
                    checkId: $this->id(),
                    severity: Severity::Medium,
                    message: "Disk '{$name}' has visibility 'public' but its name or root path suggests sensitive contents — every stored file becomes world-readable. Use 'private' visibility or per-file visibility.",
                );
            }

            if (($disk['driver'] ?? null) === 's3' && ! array_key_exists('visibility', $disk)) {
                // A stock s3 disk without a bucket is unconfigured boilerplate.
                $bucket = $disk['bucket'] ?? null;
                if (! is_string($bucket) || $bucket === '') {
                    continue;
                }

                yield new Finding(
                    checkId: $this->id(),
                    severity: Severity::Low,
                    message: "S3 disk '{$name}' sets no 'visibility' key — Flysystem defaults to private, but make the reliance explicit with 'visibility' => 'private'.",
                );
            }
        }
    }

    /**
     * @param  array<mixed>  $disk
     */
    private function looksSensitive(string $name, array $disk): bool
    {
        if (preg_match(self::SENSITIVE_KEYWORDS, $name) === 1) {
            return true;
        }

        $root = $disk['root'] ?? null;

        return is_string($root) && preg_match(self::SENSITIVE_KEYWORDS, $root) === 1;
    }
}
