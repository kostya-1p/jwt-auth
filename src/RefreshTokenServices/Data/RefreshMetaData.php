<?php

namespace Kostyap\JwtAuth\RefreshTokenServices\Data;

class RefreshMetaData
{
    public function __construct(
        public string $userAgent,
        public string $fingerPrint,
        public string $ip
    ) {
    }
}