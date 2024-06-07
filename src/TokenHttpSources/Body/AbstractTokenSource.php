<?php

namespace Kostyap\JwtAuth\TokenHttpSources\Body;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Kostyap\JwtAuth\Exceptions\InvalidTokenException;
use Kostyap\JwtAuth\TokenHttpSources\TokenSourceInterface;

abstract class AbstractTokenSource implements TokenSourceInterface
{
    public function __construct(protected Request $request)
    {
    }

    abstract protected function getTokenKey(): string;

    /**
     * @inheritDoc
     */
    abstract public function getToken(): string;

    public function setToken(Response $response, string $token): Response
    {
        $responseContent = $response->getOriginalContent();
        if (!is_array($responseContent)) {
            $responseContent = [];
        }

        $responseContent[$this->getTokenKey()] = $token;
        $response->setContent($responseContent);
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