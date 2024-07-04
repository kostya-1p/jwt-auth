<?php

namespace Kostyap\JwtAuth\Commands;

use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;

class CopyDefaultController extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'jwt-auth:install';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Copies default controller, routes and requests';

    /**
     * Execute the console command.
     */
    public function handle(): void
    {
        // Routes
        copy(__DIR__ . '/../../stubs/default/routes/auth.php', base_path('routes/auth.php'));

        // Controllers
        (new Filesystem)->ensureDirectoryExists(app_path('Http/Controllers'));
        (new Filesystem)->copyDirectory(
            __DIR__ . '/../../stubs/default/app/Http/Controllers',
            app_path('Http/Controllers')
        );

        // Requests
        (new Filesystem)->ensureDirectoryExists(app_path('Http/Requests'));
        (new Filesystem)->copyDirectory(
            __DIR__ . '/../../stubs/default/app/Http/Requests',
            app_path('Http/Requests')
        );
    }
}
