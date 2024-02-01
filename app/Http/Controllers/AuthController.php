<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Hash;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Facades\Validator;
use Laravel\Sanctum\PersonalAccessToken;

class AuthController extends Controller
{
    public function login(Request $request) {
        $validator = Validator::make($request->only(["email","password"]), [
            "email" => ["required","string","email", Rule::exists("users", "email"), "max:255"],
            "password" => "required|string|min:8|max:255",
        ]);
 
        if ($validator->fails()) {
            return response(["message"=> "Bad request", "errors" => $validator->errors()], 400);
        }

        $user = User::where('email', $request->email)->first();

        if (!Hash::check($request->password, $user->password)) {
            return response(["message"=> "Invalid credentials"], 400);
        }
 
        $user->tokens()->delete();
        $token = $user->createToken('ApiToken', [], now()->addMinutes(60))->plainTextToken;

        return response()->json([
            'user' => $user,
            'token' => $token
        ])->cookie("token", $token, 60, "/", null, env("APP_ENV") !== "local", false);
    }

    public function register(Request $request) {
        $validator = Validator::make($request->all(), [
            "name" => "required|string",
            "email" => ["required","string","email", "unique:App\Models\User,email", "max:255"],
            "password" => "required|string|min:8|confirmed",
            "consent" => ["required","boolean",Rule::in([1])],
        ]);
 
        if ($validator->fails()) {
            return response(["message"=> "Bad request", "errors" => $validator->errors()], 400);
        }
        
        $user = User::create($validator->validated());

        event(new Registered($user));

        return response(["message"=> "Successfully registered", "user" => $user], 201);
    }

    public function logout(Request $request) {
        if ($request->bearerToken()) {
            $token = PersonalAccessToken::findToken(request()->bearerToken());
            if ($token) $token->delete();
        }
        return response(["message"=> "Successfully logged out"], 200)->withoutCookie("token");
    }
}
