<?php

namespace Kostyap\JwtAuth\TokenHttpSources\Cookie;

use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Kostyap\JwtAuth\Exceptions\InvalidTokenException;
use Kostyap\JwtAuth\TokenHttpSources\TokenSourceInterface;
use Symfony\Component\HttpFoundation\Cookie;

abstract class AbstractTokenSource implements TokenSourceInterface
{
    public function __construct(protected Request $request, private int $refreshTtl)
    {
    }

    abstract protected function getTokenKey(): string;

    /**
     * @inheritDoc
     */
    public function getToken(): string
    {
        $token = $this->request->cookie($this->getTokenKey());
        $this->checkTokenIsFalse($token);
        return $token;
    }

    public function setToken(Response $response, string $token): Response
    {
        $response->withCookie(
            Cookie::create(
                $this->getTokenKey(),
                $token,
                Carbon::now()->addMinutes($this->refreshTtl),
            )
        );

        return $response;
    }

    /** @throws InvalidTokenException */
    protected function checkTokenIsFalse(?string $token): void
    {
        if (!$token) {
            throw new InvalidTokenException('Token is missing!');
        }
    }
}