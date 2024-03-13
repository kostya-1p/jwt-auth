<?php

use Carbon\Carbon;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('refresh_sessions', function (Blueprint $table) {
            $table->id();
            $table->uuid('refresh_token');
            $table->string('user_agent', 200);
            $table->string('fingerprint', 200);
            $table->string('ip', 15);
            $table->bigInteger('expires_in');

            $table->timestampTz('created_at')->default(Carbon::now());
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('refresh_sessions');
    }
};
