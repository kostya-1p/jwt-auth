<?php

namespace Kostyap\JwtAuth;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;

class JWTGuard implements Guard
{
    use GuardHelpers;

    public function __construct(
        private JWT $jwt,
        UserProvider $provider,
    ) {
        $this->provider = $provider;
    }

    /**
     * @inheritDoc
     */
    public function user()
    {
        if ($this->user !== null) {
            return $this->user;
        }

        //TODO: Get user from token
        return $this->user;
    }

    /**
     * @inheritDoc
     */
    public function validate(array $credentials = []): bool
    {
        return (bool)$this->attempt($credentials, false);
    }

    public function attempt(array $credentials = [], bool $login = true): bool|string
    {
        /** @var Authenticatable|JWTSubject|null $user */
        $user = $this->provider->retrieveByCredentials($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {
            return $login ? $this->login($user) : true;
        }

        return false;
    }

    public function login(JWTSubject $user): string
    {
        return $this->jwt->fromSubject($user);
    }

    protected function hasValidCredentials(?Authenticatable $user, array $credentials): bool
    {
        return $user !== null && $this->provider->validateCredentials($user, $credentials);
    }
}