<?php

namespace Brian\YahudAuth\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    protected $userModel;

    public function __construct()
    { 
        $this->userModel = config('jwt.user_model');
    }
 
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:' . (new $this->userModel)->getTable(),
            'password' => 'required|string|min:6'
        ]); 

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'errors in validation',
                'errors' => $validator->errors()
            ], 422);
        } 

        $user = $this->userModel::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        return response()->json(['message' => 'User created successfully'], 201);
    }
 
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required', 
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'errors in validation',
                'errors' => $validator->errors()
            ], 422);
        } 

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
 
    public function refreshToken()
    {
        $token = JWTAuth::getToken();

        if (!$token) {
            return response()->json(['error' => 'No token provided'], 400);
        }

        try {
            // Refresh token yang ada
            $newToken = JWTAuth::refresh($token);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Could not refresh token'], 400);
        }

        return response()->json(['token' => $newToken]);
    }
 
    public function currentSession(Request $request)
    {
        $user = Auth::user();

        if (!$user) {
            return response()->json(['error' => 'No active session'], 400);
        }

        // Ambil data perangkat dan lokasi dari request
        $deviceInfo = [
            'device' => $request->input('device', 'Unknown'),
            'build_brand' => $request->input('build_brand', 'Unknown'),
            'os_version' => $request->input('os_version', 'Unknown'),
            'sdk_version' => $request->input('sdk_version', 'Unknown'),
            'build_number' => $request->input('build_number', 'Unknown'),
            'build_incremental' => $request->input('build_incremental', 'Unknown'),
            'latitude' => $request->input('latitude', null),
            'longitude' => $request->input('longitude', null),
        ];

        // Menyimpan informasi sesi dan perangkat
        $sessionData = [
            'user' => $user,
            'device_info' => $deviceInfo,
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'last_activity' => now(),  // Anda bisa menyimpan waktu terakhir pengguna aktif
            'session_start' => now()->toDateTimeString(),
        ];

        return response()->json(['session' => $sessionData]);
    }
}
