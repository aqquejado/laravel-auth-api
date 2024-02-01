<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Validator;

class PasswordController extends Controller
{
    public function send(Request $request) {
        try {
            $validator = Validator::make($request->only(["email","password"]), [
                "email" => ["required","string","email", Rule::exists("users", "email"), "max:255"]
            ]);
    
            if ($validator->fails()) {
                return response(["message"=> "Bad request", "errors" => $validator->errors()], 400);
            }
    
            $user = User::where("email", $request->email)->first();
    
            if (!$user->hasVerifiedEmail()) {
                return response(["message"=> "Email has not been verified"], 401);
            }
     
            $status = Password::sendResetLink(
                $request->only('email')
            );
        
            return $status === Password::RESET_LINK_SENT
                ? response(['message' => __($status)], 200)
                : response(['message' => __($status)], 500);
        } catch (\Throwable $th) {
            report($th);
            return response(["message"=> $th->getMessage()], 500);
        }
    }

    public function redirectReset(string $token) {
        return redirect()->to(env("CLIENT_APP_URL") . "/auth/reset-password?token=" . $token);
    }

    public function reset(Request $request) {
        try {
            $validator = Validator::make($request->all(), [
                "email" => ["required","string","email", Rule::exists("users", "email"), "max:255"],
                "password" => "required|string|min:8|max:255|confirmed",
                "token" => "required"
            ]);
    
            if ($validator->fails()) {
                return response(["message"=> "Bad request", "errors" => $validator->errors()], 400);
            }
    
            // TODO: check if new password is old password
     
            $status = Password::reset(
                $request->only("email", "password", "password_confirmation", "token"),
                function (User $user, string $password) {
                    $user->forceFill([
                        'password' => Hash::make($password)
                    ]);
         
                    $user->save();
         
                    event(new PasswordReset($user));
                }
            );
        
            return $status === Password::PASSWORD_RESET
                ? response(["message" => __($status)], 200)
                : response(["message" => __($status)], 500);
        } catch (\Throwable $th) {
            report($th);
            return response(["message"=> $th->getMessage()], 500);
        }
    }
}
