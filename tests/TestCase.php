<?php

namespace Kostyap\JwtAuth\Tests;

use Kostyap\JwtAuth\Providers\JwtAuthServiceProvider;
use Orchestra\Testbench\TestCase as BaseTestCase;

class TestCase extends BaseTestCase
{
    protected function getPackageProviders($app): array
    {
        return [JwtAuthServiceProvider::class];
    }
}