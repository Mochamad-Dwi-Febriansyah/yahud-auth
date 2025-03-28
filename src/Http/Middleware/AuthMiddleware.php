<?php 
 

namespace Brian\YahudAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        try {
            // Cek apakah token valid dan user terautentikasi
            if (! $user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['error' => 'User not found'], 404);
            }
        } catch (JWTException $e) {
            // Jika terjadi error pada token, misalnya token kadaluarsa
            return response()->json(['error' => 'Token is invalid or expired'], 401);
        }

        // Set user ke request untuk digunakan di controller
        $request->merge(['user' => $user]);

        return $next($request);
    }
}


?>