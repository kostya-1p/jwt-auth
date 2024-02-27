<?php

return [
    'secret' => env('JWT_SECRET'),

    'keys' => [
        'public' => env('JWT_PUBLIC_KEY'),
        'private' => env('JWT_PRIVATE_KEY'),
    ],

    'algo' => env('JWT_ALGO', \Kostyap\JwtAuth\JWTSigner::ALGO_HS256),
];