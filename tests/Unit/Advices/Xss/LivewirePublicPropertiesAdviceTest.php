<?php

declare(strict_types=1);

use Baspa\Larascan\Advices\Xss\LivewirePublicPropertiesAdvice;
use Baspa\Larascan\Support\AdviceStatus;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;

function livewirePropsTmpDirRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-advise-livewire-'.uniqid();
    mkdir($this->tmpDir.'/app/Livewire', recursive: true);
});

afterEach(function () {
    livewirePropsTmpDirRemove($this->tmpDir);
});

it('exposes correct metadata', function () {
    $advice = new LivewirePublicPropertiesAdvice($this->tmpDir.'/app', new FileParser);

    expect($advice->id())->toBe('advise.livewire-public-properties')
        ->and($advice->category())->toBe(Category::Xss);
});

it('is skipped when livewire is not installed', function () {
    $advice = new LivewirePublicPropertiesAdvice($this->tmpDir.'/app', new FileParser);
    expect($advice->isApplicable())->toBeFalse();
});

it('would surface when a Livewire component has public props without rules (logic check)', function () {
    file_put_contents(
        $this->tmpDir.'/app/Livewire/Counter.php',
        "<?php\nnamespace App\\Livewire;\nuse Livewire\\Component;\nclass Counter extends Component { public int \$count = 0; public string \$name = ''; }\n",
    );

    $forcedAdvice = new class($this->tmpDir.'/app', new FileParser) extends LivewirePublicPropertiesAdvice
    {
        public function isApplicable(): bool
        {
            return true;
        }
    };
    $outcome = $forcedAdvice->run();

    expect($outcome->status)->toBe(AdviceStatus::Surfaced)
        ->and($outcome->evidence)->not->toBeEmpty();
});

it('does not surface when component has protected $rules', function () {
    file_put_contents(
        $this->tmpDir.'/app/Livewire/Counter.php',
        "<?php\nnamespace App\\Livewire;\nuse Livewire\\Component;\nclass Counter extends Component { public int \$count = 0; protected \$rules = ['count' => 'integer']; }\n",
    );

    $forcedAdvice = new class($this->tmpDir.'/app', new FileParser) extends LivewirePublicPropertiesAdvice
    {
        public function isApplicable(): bool
        {
            return true;
        }
    };
    $outcome = $forcedAdvice->run();

    expect($outcome->status)->toBe(AdviceStatus::NotSurfaced);
});

it('does not surface when component uses #[Validate] attribute on its property', function () {
    file_put_contents(
        $this->tmpDir.'/app/Livewire/Counter.php',
        "<?php\nnamespace App\\Livewire;\nuse Livewire\\Attributes\\Validate;\nuse Livewire\\Component;\nclass Counter extends Component {\n    #[Validate('required|integer')]\n    public int \$count = 0;\n}\n",
    );

    $forcedAdvice = new class($this->tmpDir.'/app', new FileParser) extends LivewirePublicPropertiesAdvice
    {
        public function isApplicable(): bool
        {
            return true;
        }
    };
    $outcome = $forcedAdvice->run();

    expect($outcome->status)->toBe(AdviceStatus::NotSurfaced);
});
