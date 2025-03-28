<?php

namespace Brian\YahudAuth\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    protected $userModel;

    public function __construct()
    {
        // Ambil model dari konfigurasi
        $this->userModel = config('jwt.user_model');
    }

    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:' . (new $this->userModel)->getTable(),
            'password' => 'required|string|min:6'
        ]);

        $user = $this->userModel::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        return response()->json(['message' => 'User created successfully'], 201);
    }

    public function login(Request $request)
    {
        $credentials = $request->only(['email', 'password']);

        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return response()->json(['token' => $token]);
    }

    public function me()
    {
        return response()->json(Auth::user());
    }

    public function logout()
    {
        JWTAuth::invalidate(JWTAuth::getToken());

        return response()->json(['message' => 'Logged out successfully']);
    }

    public function refresh()
    {
        return response()->json([
            'token' => JWTAuth::refresh()
        ]);
    }
    public function refreshToken(Request $request)
    { 
        $token = JWTAuth::getToken();

        if (!$token) {
            return response()->json(['error' => 'No token provided'], 400);
        }

        try { 

            $newToken = JWTAuth::refresh($token);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Could not refresh token'], 400);
        }

        return response()->json(['token' => $newToken]);
    }
 
    public function currentSession()
    {
        $user = Auth::user();
 
        if (!$user) {
            return response()->json(['error' => 'No active session'], 400);
        }
 
        $sessionData = [
            'user' => $user,
            'ip_address' => request()->ip(),
            'user_agent' => request()->userAgent(),
            'last_activity' => $user->last_activity, 
            'session_start' => now()->toDateTimeString(),
        ];

        return response()->json(['session' => $sessionData]);
    }
}
