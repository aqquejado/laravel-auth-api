<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class VerificationController extends Controller
{
    public function verify($user_id, Request $request) {
        try {
            if (!$request->hasValidSignature()) {
                return response()->json(["message" => "Invalid/Expired url provided."], 401);
            }
        
            $user = User::findOrFail($user_id);
        
            if (!$user->hasVerifiedEmail()) {
                $user->markEmailAsVerified();
            }
        
            return redirect()->to(env("CLIENT_APP_URL") . "/auth/login?verified");
        } catch (\Throwable $th) {
            report($th);
            return response(["message"=> $th->getMessage()], 500);
        }
    }
    
    public function resend() {
        try {
            if (auth()->user()->hasVerifiedEmail()) {
                return response()->json(["message" => "Email already verified."], 400);
            }
        
            auth()->user()->sendEmailVerificationNotification();

            return response()->json(["message" => "Email verification link sent on your email id"]);
        } catch (\Throwable $th) {
            report($th);
            return response(["message"=> $th->getMessage()], 500);
        }
        
    }
}
