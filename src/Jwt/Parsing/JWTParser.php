<?php

namespace Kostyap\JwtAuth\Jwt\Parsing;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;

class JWTParser
{
    public function __construct(private Parser $parser)
    {
    }

    public function parse(string $token): Token
    {
        return $this->parser->parse($token);
    }

    public function getClaim(UnencryptedToken $token, string $claim): mixed
    {
        return $token->claims()->get($claim);
    }
}