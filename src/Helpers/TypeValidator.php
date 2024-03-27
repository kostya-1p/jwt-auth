<?php

namespace Kostyap\JwtAuth\Helpers;

use Kostyap\JwtAuth\Exceptions\TokenTypeException;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;

class TypeValidator
{
    public static function checkUnencryptedTokenType(Token $token): UnencryptedToken
    {
        if (!($token instanceof UnencryptedToken)) {
            throw new TokenTypeException('Unexpected token implementation');
        }

        return $token;
    }
}