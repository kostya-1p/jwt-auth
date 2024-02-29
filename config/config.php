<?php

return [
    'secret' => env('JWT_SECRET'),

    'keys' => [
        'public' => env('JWT_PUBLIC_KEY'),
        'private' => env('JWT_PRIVATE_KEY'),
    ],

    'algo' => env('JWT_ALGO', \Kostyap\JwtAuth\Jwt\Generation\JWTSigner::ALGO_HS256),

    'required_claims' => [
        'iss',
        'iat',
        'exp',
        'nbf',
        'sub',
        'jti',
    ],

    'ttl' => env('JWT_TTL', 60),

    'refresh_ttl' => env('JWT_REFRESH_TTL', 20160),
];