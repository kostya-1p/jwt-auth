<?php

namespace Kostyap\JwtAuth\Enum;

enum RefreshTokenStorage: string
{
    case Database = 'database';
    case Redis = 'redis';
}
