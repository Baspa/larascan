<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Ecosystem;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class LivewireUploadRulesCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'ecosystem.livewire-upload-rules';
    }

    public function category(): Category
    {
        return Category::Ecosystem;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'Customized Livewire temporary uploads must keep a max: size rule and throttle middleware (defaults are safe)';
    }

    public function isApplicable(): bool
    {
        return class_exists('Livewire\\Component');
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        $settings = $config->get('livewire.temporary_file_upload');

        // No published config: Livewire's defaults include max:12288 and
        // throttle middleware, so this is a pass — not a skip.
        if (! is_array($settings)) {
            return;
        }

        $rules = $settings['rules'] ?? null;
        if ($rules !== null && ! $this->hasMaxRule($rules)) {
            yield new Finding(
                checkId: $this->id(),
                severity: Severity::Medium,
                message: "livewire.temporary_file_upload.rules overrides Livewire's defaults without a max: size rule — unbounded temporary uploads can exhaust disk space. Add e.g. max:12288.",
            );
        }

        if (array_key_exists('middleware', $settings) && in_array($settings['middleware'], [null, '', []], true)) {
            yield new Finding(
                checkId: $this->id(),
                severity: Severity::Medium,
                message: "livewire.temporary_file_upload.middleware is explicitly empty — Livewire's default throttle on the upload endpoint is removed, enabling upload flooding. Restore e.g. 'throttle:60,1'.",
            );
        }
    }

    private function hasMaxRule(mixed $rules): bool
    {
        if (is_string($rules)) {
            $rules = explode('|', $rules);
        }

        if (! is_array($rules)) {
            return false;
        }

        foreach ($rules as $rule) {
            if (is_string($rule) && str_starts_with($rule, 'max:')) {
                return true;
            }
        }

        return false;
    }
}
