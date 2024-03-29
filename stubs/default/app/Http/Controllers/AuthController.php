<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use Exception;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Kostyap\JwtAuth\Jwt\Data\TokenPair;

class AuthController extends Controller
{
    public function login(LoginRequest $request): Response
    {
        try {
            /** @var bool|TokenPair $tokenPair */
            $tokenPair = Auth::attempt($request->validated());
        } catch (Exception $e) {
            return new Response($e->getMessage(), 401);
        }

        if (!$tokenPair) {
            return new Response(['error' => 'Unauthorized'], 401);
        }

        return new Response([
            'access_token' => $tokenPair->accessToken,
            'refresh_token' => $tokenPair->refreshToken
        ]);
    }
}