<?php

namespace Kostyap\JwtAuth\Jwt\Parsing;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;

class JWTParser
{
    private Parser $parser;

    public function __construct()
    {
        //TODO: Don't create parser here
        $this->parser = new Parser(new JoseEncoder());
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