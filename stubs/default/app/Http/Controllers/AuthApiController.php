<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginApiRequest;
use Exception;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Kostyap\JwtAuth\Jwt\Data\TokenPair;

class AuthApiController extends Controller
{
    public function login(LoginApiRequest $request): Response
    {
        try {
            /** @var bool|TokenPair $tokenPair */
            $tokenPair = Auth::attempt($request->validated());
        } catch (Exception $e) {
            return new Response(['error' => $e->getMessage()], Response::HTTP_UNAUTHORIZED);
        }

        if (!$tokenPair) {
            return new Response(['error' => 'Unauthorized'], Response::HTTP_UNAUTHORIZED);
        }

        return new Response([
            'access_token' => $tokenPair->accessToken,
            'refresh_token' => $tokenPair->refreshToken
        ]);
    }

    public function me(): Response
    {
        $user = Auth::user();
        if (is_null($user)) {
            return new Response(['error' => 'Unauthorized'], Response::HTTP_UNAUTHORIZED);
        }

        //TODO: Use a http resource instead of an explicit JSON model
        return new Response($user);
    }

    public function refresh(): Response
    {
        try {
            /** @var TokenPair $tokenPair */
            $tokenPair = Auth::refresh();
        } catch (Exception $e) {
            return new Response(['error' => $e->getMessage()], Response::HTTP_UNAUTHORIZED);
        }

        return new Response([
            'access_token' => $tokenPair->accessToken,
            'refresh_token' => $tokenPair->refreshToken
        ]);
    }
}