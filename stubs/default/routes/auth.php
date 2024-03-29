<?php

use App\Http\Controllers\AuthApiController;
use Illuminate\Support\Facades\Route;

Route::controller(AuthApiController::class)->group(function () {
    Route::post('login', 'login');
    Route::post('refresh', 'refresh');
    Route::post('me', 'me')->middleware('auth:api');
});