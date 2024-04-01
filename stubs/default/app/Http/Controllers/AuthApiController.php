<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginApiRequest;
use Exception;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Kostyap\JwtAuth\Enum\AccessTokenSource;
use Kostyap\JwtAuth\Enum\RefreshTokenSource;
use Kostyap\JwtAuth\Jwt\Data\TokenPair;
use Symfony\Component\HttpFoundation\Cookie;

class AuthApiController extends Controller
{
    private AccessTokenSource $accessTokenSource;
    private RefreshTokenSource $refreshTokenSource;
    private int $ttl;
    private int $refreshTtl;

    public function __construct()
    {
        $this->accessTokenSource = config('jwt.token_source.access_token');
        $this->refreshTokenSource = config('jwt.token_source.refresh_token');
        $this->ttl = config('jwt.ttl');
        $this->refreshTtl = config('jwt.refresh_ttl');
    }

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

        $response = new Response();
        $responseContent = [];

        match ($this->accessTokenSource) {
            AccessTokenSource::Bearer => $responseContent['access_token'] = $tokenPair->accessToken,
            AccessTokenSource::Cookie => $response->withCookie(Cookie::create(
                'access_token',
                $tokenPair->accessToken,
                $this->ttl
            )),
        };

        match ($this->refreshTokenSource) {
            RefreshTokenSource::Body => $responseContent['refresh_token'] = $tokenPair->refreshToken,
            RefreshTokenSource::Cookie => $response->withCookie(Cookie::create(
                'refresh_token',
                $tokenPair->refreshToken,
                $this->refreshTtl
            )),
        };

        $response->setContent(empty($responseContent) ? 'Authenticated' : $responseContent);
        return $response;
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