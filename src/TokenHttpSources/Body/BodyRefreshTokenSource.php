<?php

namespace Kostyap\JwtAuth\TokenHttpSources\Body;

class BodyRefreshTokenSource extends AbstractTokenSource
{
    protected function getTokenKey(): string
    {
        return self::REFRESH_TOKEN_KEY;
    }

    /**
     * @inheritDoc
     */
    public function getToken(): string
    {
        $token = $this->request->input($this->getTokenKey());
        $this->checkTokenIsFalse($token);
        return $token;
    }
}