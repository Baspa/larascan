<?php

declare(strict_types=1);

namespace Baspa\Larascan\Commands;

use Baspa\Larascan\LarascanServiceProvider;
use Illuminate\Console\Command;

class InstallCommand extends Command
{
    protected $signature = 'larascan:install';

    protected $description = 'Publish larascan config and verify environment';

    public function handle(): int
    {
        $this->info('Installing larascan...');

        $this->call('vendor:publish', [
            '--provider' => LarascanServiceProvider::class,
            '--tag' => 'larascan-config',
        ]);

        $this->info('Published config/larascan.php');
        $this->newLine();
        $this->line('Next: <comment>php artisan larascan</comment> to run your first scan.');

        return 0;
    }
}
