<?php

use App\Http\Controllers\VerificationController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\PasswordController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/
Route::post('/register', [AuthController::class, 'register']);

Route::post('/login', [AuthController::class, 'login']);

Route::post('/logout', [AuthController::class, 'logout']);

Route::get('/email/verify/{id}', [VerificationController::class, 'verify'])->name('verification.verify');

Route::get('/email/resend', [VerificationController::class, 'resend'])->name('verification.resend');

Route::post('/forgot-password', [PasswordController::class, 'send']);

Route::get('/reset-password/{token}', [PasswordController::class, 'redirectReset'])->name('password.reset');

Route::post('/reset-password', [PasswordController::class, 'reset'])->name('password.update');

Route::middleware(['auth:sanctum'])->group(function () {
    Route::get('/user', function (Request $request) {
        return $request->user();
    });
});