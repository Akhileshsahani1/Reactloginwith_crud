<?php

namespace App\Http\Controllers;

use JWTAuth;
use App\Models\User;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Validator;
use Hash;
use PhpParser\Node\Stmt\TryCatch;

class ApiController extends Controller
{
    public function register(Request $request)
    {
        
            
           $data = User::create([
                'name' => $request->name,
                'email' => $request->email,
             
                'password' =>Hash::make($request->password),
              
            ])->save();
            if ($data) {
                return response()->json([
                    'status' => true,
                    'message' => 'User created successfully',
                    'data' => $data
                ], 201);
            } else {
                return response()->json([
                    'status' => false,
                    'message' => 'User does not created.',
                ]);
            }


    }

    public function authenticate(Request $request)
    {
        $credentials = request(['email', 'password']);

        if (!$token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    public function logout(Request $request)
    {
        $validator = Validator::make($request->only('token'), [
            'token' => 'required'
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->messages()], 200);
        }
        try {
            JWTAuth::invalidate($request->token);

            return response()->json([
                'success' => true,
                'message' => 'User has been logged out'
            ]);
        } catch (JWTException $exception) {
            return response()->json([
                'success' => false,
                'message' => 'Sorry, user cannot be logged out'
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function get_user(Request $request)
    {

        // $this->validate($request, [
        //     'token' => 'required'
        // ]);

        $user = JWTAuth::authenticate($request->token);
        if ($user) {
            $data = User::get();
            return response()->json([
                'data' => $data,
                'status' => true,
                'message' => 'User get SuccessFully.'
            ], 200);
        } else {
            return response()->json([
                'status' => false,
                'message' => 'User fetch failed.'
            ], 400);
        }

    }
    public function delete_user(Request $request, $id)
    {

        // $this->validate($request, [
        //     'token' => 'required'
        // ]);

        $user = JWTAuth::authenticate($request->token);
        if ($user) {
            User::destroy($id);


            return response()->json([
                'status' => true,
                'message' => 'User deleted successFully.'
            ], 200);
        } else {
            return response()->json([
                'status' => false,
                'message' => 'User fetch failed.'
            ], 400);
        }

    }
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }

    public function Update_user(Request $request, $id)
    {

        $data = User::where('id', $id)->Update([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        return response()->json([
            'status' => true,
            'message' => 'User Updated SuccessFully.'
        ], 200);
    }
}