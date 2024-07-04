<?php

namespace Kostyap\JwtAuth\TokenHttpSources\Body;


class BearerAccessTokenSource extends AbstractTokenSource
{
    protected function getTokenKey(): string
    {
        return self::ACCESS_TOKEN_KEY;
    }

    /**
     * @inheritDoc
     */
    public function getToken(): string
    {
        $token = $this->request->bearerToken();
        $this->checkTokenIsFalse($token);
        return $token;
    }
}