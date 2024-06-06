<?php

namespace Kostyap\JwtAuth\Enums;

enum RefreshTokenStorage: string
{
    case Database = 'database';
    case Redis = 'redis';
}
