<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Auth;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Facades\Validator;

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
        
        // TODO: not login if email is not verified
 
        if (Auth::attempt($validator->validated())) {
            $user = Auth::user();
            return response()->json([
                'user' => $user,
                'token' => $user->createToken('ApiToken', [])->plainTextToken
            ]);
        }
 
        return response(["message"=> "Invalid credentials"], 400);
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

    public function logout() {
        Auth::logout();

        return response(["message"=> "Successfully logged out"], 200);
    }
}
