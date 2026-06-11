<?php

declare(strict_types=1);

use Baspa\Larascan\Advices\Ecosystem\WebhookSignatureAdvice;
use Baspa\Larascan\Support\AdviceStatus;
use Baspa\Larascan\Support\Category;
use Illuminate\Support\Facades\Route;

it('exposes correct metadata', function () {
    $advice = new WebhookSignatureAdvice($this->app);

    expect($advice->id())->toBe('advise.webhook-signature')
        ->and($advice->category())->toBe(Category::Ecosystem)
        ->and($advice->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/advices/ecosystem/webhook-signature.md');
});

it('is skipped when no webhook-looking routes exist', function () {
    Route::get('/dashboard', fn () => 'ok');
    Route::post('/orders', fn () => 'ok');

    $outcome = (new WebhookSignatureAdvice($this->app))->run();
    expect($outcome->status)->toBe(AdviceStatus::Skipped)
        ->and($outcome->skipReason)->toContain('webhook');
});

it('ignores GET routes with webhook-looking URIs', function () {
    Route::get('/webhooks/status', fn () => 'ok');

    $outcome = (new WebhookSignatureAdvice($this->app))->run();
    expect($outcome->status)->toBe(AdviceStatus::Skipped);
});

it('surfaces a POST webhook route without signature middleware', function () {
    Route::post('webhooks/stripe', fn () => 'ok');

    $outcome = (new WebhookSignatureAdvice($this->app))->run();
    expect($outcome->status)->toBe(AdviceStatus::Surfaced)
        ->and($outcome->evidence)->toHaveCount(1)
        ->and($outcome->evidence[0]->message)->toContain('webhooks/stripe');
});

it('surfaces callback and hook style URIs too', function () {
    Route::post('payments/callback', fn () => 'ok');
    Route::post('hooks/github', fn () => 'ok');

    $outcome = (new WebhookSignatureAdvice($this->app))->run();
    expect($outcome->status)->toBe(AdviceStatus::Surfaced)
        ->and($outcome->evidence)->toHaveCount(2);
});

it('does not surface a webhook route with signed middleware', function () {
    Route::post('webhooks/stripe', fn () => 'ok')->middleware('signed');

    $outcome = (new WebhookSignatureAdvice($this->app))->run();
    expect($outcome->status)->toBe(AdviceStatus::NotSurfaced);
});

it('does not surface a webhook route with a ValidateSignature class middleware', function () {
    Route::post('webhooks/stripe', fn () => 'ok')
        ->middleware('Illuminate\\Routing\\Middleware\\ValidateSignature');

    $outcome = (new WebhookSignatureAdvice($this->app))->run();
    expect($outcome->status)->toBe(AdviceStatus::NotSurfaced);
});

it('treats vendor webhook middleware as signature verification', function () {
    Route::post('webhooks/spatie', fn () => 'ok')
        ->middleware('Spatie\\WebhookClient\\Http\\Middleware\\VerifySignature');

    $outcome = (new WebhookSignatureAdvice($this->app))->run();
    expect($outcome->status)->toBe(AdviceStatus::NotSurfaced);
});

it('only surfaces the unprotected routes when some are protected', function () {
    Route::post('webhooks/stripe', fn () => 'ok')->middleware('signed');
    Route::post('webhooks/github', fn () => 'ok');

    $outcome = (new WebhookSignatureAdvice($this->app))->run();
    expect($outcome->status)->toBe(AdviceStatus::Surfaced)
        ->and($outcome->evidence)->toHaveCount(1)
        ->and($outcome->evidence[0]->message)->toContain('webhooks/github');
});
