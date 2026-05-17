<?php

declare(strict_types=1);

use Baspa\Larascan\Advices\Routing\BroadcastChannelsFlagsAdvice;
use Baspa\Larascan\Support\AdviceStatus;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;

function broadcastChannelsTmpDirRemove(string $dir): void
{
    if (! is_dir($dir)) {
        return;
    }
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );
    foreach ($it as $f) {
        $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
    }
    rmdir($dir);
}

beforeEach(function () {
    $this->tmpDir = sys_get_temp_dir().'/larascan-advise-channels-'.uniqid();
    mkdir($this->tmpDir.'/routes', recursive: true);
});

afterEach(function () {
    broadcastChannelsTmpDirRemove($this->tmpDir);
});

it('exposes correct metadata', function () {
    $advice = new BroadcastChannelsFlagsAdvice($this->tmpDir, new FileParser);

    expect($advice->id())->toBe('advise.broadcast-channels-flags')
        ->and($advice->category())->toBe(Category::Routing);
});

it('is skipped when routes/channels.php does not exist', function () {
    $outcome = (new BroadcastChannelsFlagsAdvice($this->tmpDir, new FileParser))->run();

    expect($outcome->status)->toBe(AdviceStatus::Skipped);
});

it('surfaces a list of channel names when channels.php has Broadcast::channel calls', function () {
    file_put_contents(
        $this->tmpDir.'/routes/channels.php',
        "<?php\nuse Illuminate\Support\Facades\Broadcast;\nBroadcast::channel('orders.{id}', function (\$user, \$id) { return true; });\nBroadcast::channel('chat.{room}', function (\$user, \$room) { return true; });\n",
    );

    $outcome = (new BroadcastChannelsFlagsAdvice($this->tmpDir, new FileParser))->run();

    expect($outcome->status)->toBe(AdviceStatus::Surfaced)
        ->and($outcome->evidence)->toHaveCount(2)
        ->and($outcome->evidence[0]->message)->toContain('orders.{id}')
        ->and($outcome->evidence[1]->message)->toContain('chat.{room}');
});

it('does not surface when channels.php exists but has no Broadcast::channel calls', function () {
    file_put_contents($this->tmpDir.'/routes/channels.php', "<?php\n// no channels yet\n");

    $outcome = (new BroadcastChannelsFlagsAdvice($this->tmpDir, new FileParser))->run();
    expect($outcome->status)->toBe(AdviceStatus::NotSurfaced);
});
