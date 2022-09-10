<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{

    public function response(User $user)
    {
        $token = $user->createToken(str()->random(40))->plainTextToken;

        return response()->json([
            'user' => $user,
            'token' => $token,
            'token_type' => 'Bearer'
        ]);
    }

    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|min:6|unique:users',
            'password' => 'required|min:8',
            'email' => 'required|email|unique:users'
        ]);

        $user = User::create([
            'name' => ucwords($request->name),
            'password' => bcrypt($request->password),
            'email' => ucwords($request->email)
        ]);

        return $this->response($user);
    }

    public function login(Request $request)
    {
        $creds = $request->validate([
            'email' => 'required|email|exists:users',
            'password' => 'required|min:8'
        ]);

        if (!Auth::attempt($creds)) {

            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        }

        return $this->response(Auth::user());
    }

    public function user(Request $request)
    {
        return $request->user();
    }

    public function logout(Request $request)
    {

        Auth::user()->tokens()->delete();

        return response()->json([
            'message' => 'Successfully logged out'
        ]);
    }
}

