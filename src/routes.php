<?php

use Illuminate\Support\Facades\Route;
use Brian\YahudAuth\Http\Controllers\AuthController;

Route::prefix('api/auth')->group(function () {
    Route::post('login', [AuthController::class, 'login']);
    Route::post('register', [AuthController::class, 'register']);
    Route::post('logout', [AuthController::class, 'logout']);
    Route::post('refresh', [AuthController::class, 'refresh']);
    Route::middleware('auth.jwt')->get('me', [AuthController::class, 'me']);
});
