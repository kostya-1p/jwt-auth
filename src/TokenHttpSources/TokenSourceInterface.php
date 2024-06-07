<?php

namespace Kostyap\JwtAuth\TokenHttpSources;

use Illuminate\Http\Response;
use Kostyap\JwtAuth\Exceptions\InvalidTokenException;

interface TokenSourceInterface
{
    public const ACCESS_TOKEN_KEY = 'access_token';
    public const REFRESH_TOKEN_KEY = 'refresh_token';

    /**
     * @throws InvalidTokenException
     * @return non-empty-string
     */
    public function getToken(): string;

    public function setToken(Response $response, string $token): Response;
}