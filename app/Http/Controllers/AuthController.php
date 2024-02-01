<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Hash;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Facades\Validator;
use Laravel\Sanctum\PersonalAccessToken;

class AuthController extends Controller
{
    public function login(Request $request) {
        try {
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

            $token = $user->createToken('ApiToken', [], now()->addMinutes(60))->plainTextToken;
    
            return response()->json([
                'user' => $user,
                'token' => $token
            ])->cookie("token", $token, 60, "/", null, env("APP_ENV") !== "local", false);
        } catch (\Throwable $th) {
            report($th);
            return response(["message"=> $th->getMessage()], 500);
        }
    }

    public function register(Request $request) {
        try {
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
        } catch (\Throwable $th) {
            report($th);
            return response(["message"=> $th->getMessage()], 500);
        }
    }

    public function logout(Request $request) {
        try {
            if ($request->bearerToken()) {
                $token = PersonalAccessToken::findToken(request()->bearerToken());
                if ($token) $token->delete();
            }
            return response(["message"=> "Successfully logged out"], 200)->withoutCookie("token");
        } catch (\Throwable $th) {
            report($th);
            return response(["message"=> $th->getMessage()], 500);
        }
    }
}
