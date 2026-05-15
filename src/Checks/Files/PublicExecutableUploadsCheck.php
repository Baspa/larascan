<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Files;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node\Scalar\String_;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class PublicExecutableUploadsCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const EXECUTABLE_EXTENSIONS = ['php', 'phtml', 'phar', 'pht', 'phps'];

    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
        private readonly string $publicPath,
    ) {}

    public function id(): string
    {
        return 'files.public-executable-uploads';
    }

    public function category(): Category
    {
        return Category::Files;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'Upload validation allows executable extensions (php/phtml/phar) — RCE risk';
    }

    public function isApplicable(): bool
    {
        return is_dir($this->appPath);
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        yield from $this->scanValidationRules();
        yield from $this->scanPublicUploadDirs();
    }

    /**
     * Sub-check 1: AST scan validation rules for `mimes:` allowing executable extensions.
     *
     * @return iterable<Finding>
     */
    private function scanValidationRules(): iterable
    {
        $finder = new NodeFinder;

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->appPath, RecursiveDirectoryIterator::SKIP_DOTS),
        );

        foreach ($iterator as $file) {
            if (! $file instanceof SplFileInfo || ! $file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            $ast = $this->parser->parse($file->getPathname());
            if ($ast === null) {
                continue;
            }

            /** @var array<int, String_> $strings */
            $strings = $finder->findInstanceOf($ast, String_::class);

            foreach ($strings as $string) {
                $value = $string->value;

                if (! str_contains($value, 'mimes:')) {
                    continue;
                }

                $matches = [];
                if (preg_match('/mimes:([^|]+)/', $value, $matches) !== 1) {
                    continue;
                }

                $extensions = array_map('trim', explode(',', $matches[1]));
                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                $line = $string->getStartLine();

                foreach ($extensions as $extension) {
                    $normalized = strtolower($extension);
                    if (! in_array($normalized, self::EXECUTABLE_EXTENSIONS, true)) {
                        continue;
                    }

                    yield new Finding(
                        checkId: $this->id(),
                        severity: $this->severity(),
                        message: "Upload rule allows executable extension '{$normalized}' — uploaded PHP files in webroot get executed.",
                        file: $relative,
                        line: $line,
                    );
                }
            }
        }
    }

    /**
     * Sub-check 2: Filesystem scan for already-uploaded executable files under
     * `public/uploads/` or `public/storage/`.
     *
     * @return iterable<Finding>
     */
    private function scanPublicUploadDirs(): iterable
    {
        foreach (['uploads', 'storage'] as $subdir) {
            $path = $this->publicPath.DIRECTORY_SEPARATOR.$subdir;
            if (! is_dir($path)) {
                continue;
            }

            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            );

            foreach ($iterator as $file) {
                if (! $file instanceof SplFileInfo || ! $file->isFile()) {
                    continue;
                }

                $extension = strtolower($file->getExtension());
                if (! in_array($extension, self::EXECUTABLE_EXTENSIONS, true)) {
                    continue;
                }

                $relative = str_replace(dirname($this->publicPath).DIRECTORY_SEPARATOR, '', $file->getPathname());

                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: 'Executable file exists under public upload directory — uploaded PHP files in webroot get executed.',
                    file: $relative,
                    line: null,
                );
            }
        }
    }
}
