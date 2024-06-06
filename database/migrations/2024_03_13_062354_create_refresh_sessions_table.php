<?php

use Carbon\Carbon;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Kostyap\JwtAuth\JwtServices\Generators\PayloadGenerator;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('refresh_sessions', function (Blueprint $table) {
            $table->id();
            $table->uuid('refresh_token');
            $table->text('user_agent');
            $table->string('fingerprint', 200);
            $table->ipAddress('ip');
            $table->bigInteger('expires_in');

            $table->timestampTz('created_at')->default(Carbon::now(PayloadGenerator::CARBON_TIMEZONE));
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('refresh_sessions');
    }
};
