<?php

declare(strict_types=1);

namespace Baspa\Larascan\Commands;

use Illuminate\Console\Command;
use Symfony\Component\Process\ExecutableFinder;

class InstallCommand extends Command
{
    protected $signature = 'larascan:install
        {--workflow : Also publish the GitHub Actions workflow}
        {--all : Publish everything (config + workflow) without prompts}';

    protected $description = 'Publish larascan config and verify environment';

    public function handle(): int
    {
        $this->info('Installing larascan...');
        $this->newLine();

        // 1. Detect tools
        $this->line('<comment>Environment check:</comment>');
        $finder = new ExecutableFinder;

        $tools = [
            'PHP' => PHP_VERSION,
            'composer' => $finder->find('composer') ? 'found' : 'NOT FOUND',
            'npm (optional)' => is_file(base_path('package.json'))
                ? ($finder->find('npm') ? 'found' : 'NOT FOUND — required because package.json exists')
                : 'skipped (no package.json)',
            'semgrep (optional)' => $finder->find('semgrep') ? 'found' : 'not installed',
        ];

        foreach ($tools as $name => $status) {
            $this->line("  $name: $status");
        }
        $this->newLine();

        // 2. Publish config
        $this->call('vendor:publish', [
            '--tag' => 'larascan-config',
        ]);

        // 3. Publish workflow if requested
        $publishWorkflow = $this->option('workflow') || $this->option('all');
        if (! $publishWorkflow && ! $this->option('no-interaction')) {
            $publishWorkflow = $this->confirm('Publish .github/workflows/larascan.yml?', false);
        }

        if ($publishWorkflow) {
            $this->call('vendor:publish', [
                '--tag' => 'larascan-workflow',
            ]);
        }

        // 4. Summary
        $this->newLine();
        $this->info('Installation complete!');
        $this->line('Next:');
        $this->line('  <comment>php artisan larascan</comment>          # run a scan');
        $this->line('  <comment>php artisan larascan:list</comment>      # list registered checks');

        return 0;
    }
}
