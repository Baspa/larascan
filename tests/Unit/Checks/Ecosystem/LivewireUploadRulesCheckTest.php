<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Ecosystem\LivewireUploadRulesCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new LivewireUploadRulesCheck($this->app);

    expect($check->id())->toBe('ecosystem.livewire-upload-rules')
        ->and($check->category())->toBe(Category::Ecosystem)
        ->and($check->severity())->toBe(Severity::Medium)
        ->and($check->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/checks/ecosystem/livewire-upload-rules.md');
});

it('is not applicable when Livewire is not installed', function () {
    if (class_exists('Livewire\\Component')) {
        $this->markTestSkipped('Livewire is installed; cannot test the not-installed branch.');
    }

    $check = new LivewireUploadRulesCheck($this->app);
    expect($check->isApplicable())->toBeFalse();
});

it('passes when livewire.temporary_file_upload is null (Livewire defaults are safe)', function () {
    config()->set('livewire.temporary_file_upload', null);

    $findings = iterator_to_array((new LivewireUploadRulesCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails Medium when string rules contain no max: rule', function () {
    config()->set('livewire.temporary_file_upload', ['rules' => 'required|mimes:png,jpg']);

    $findings = iterator_to_array((new LivewireUploadRulesCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('ecosystem.livewire-upload-rules')
        ->and($findings[0]->message)->toContain('max:');
});

it('passes when string rules contain a max: rule', function () {
    config()->set('livewire.temporary_file_upload', ['rules' => 'required|max:12288']);

    $findings = iterator_to_array((new LivewireUploadRulesCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails Medium when array rules contain no max: rule', function () {
    config()->set('livewire.temporary_file_upload', ['rules' => ['required', 'mimes:png,jpg']]);

    $findings = iterator_to_array((new LivewireUploadRulesCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium);
});

it('passes when array rules contain a max: rule', function () {
    config()->set('livewire.temporary_file_upload', ['rules' => ['file', 'max:12288']]);

    $findings = iterator_to_array((new LivewireUploadRulesCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('passes when rules are not customized (null) inside a published config', function () {
    config()->set('livewire.temporary_file_upload', ['rules' => null, 'middleware' => 'throttle:60,1']);

    $findings = iterator_to_array((new LivewireUploadRulesCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails Medium when middleware is explicitly null', function () {
    config()->set('livewire.temporary_file_upload', ['rules' => ['max:12288'], 'middleware' => null]);

    $findings = iterator_to_array((new LivewireUploadRulesCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->message)->toContain('throttle');
});

it('fails Medium when middleware is explicitly an empty string', function () {
    config()->set('livewire.temporary_file_upload', ['middleware' => '']);

    $findings = iterator_to_array((new LivewireUploadRulesCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium);
});

it('fails Medium when middleware is explicitly an empty array', function () {
    config()->set('livewire.temporary_file_upload', ['rules' => ['max:12288'], 'middleware' => []]);

    $findings = iterator_to_array((new LivewireUploadRulesCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->message)->toContain('throttle');
});

it('can yield both findings at once', function () {
    config()->set('livewire.temporary_file_upload', ['rules' => 'required', 'middleware' => null]);

    $findings = iterator_to_array((new LivewireUploadRulesCheck($this->app))->run());
    expect($findings)->toHaveCount(2);
});
