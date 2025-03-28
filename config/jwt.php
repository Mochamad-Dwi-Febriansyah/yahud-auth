<?php

return [
    'secret' => env('JWT_SECRET'),
    'ttl' => env('JWT_TTL', 60), // Waktu hidup token dalam menit
    'refresh_ttl' => env('JWT_REFRESH_TTL', 20160), // Waktu hidup refresh token dalam menit

    'user_model' => env('JWT_USER_MODEL', \App\Models\User::class),
];
