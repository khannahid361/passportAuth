<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class RegisterController extends Controller
{
    /**

     * Register api

     *

     * @return \Illuminate\Http\Response

     */

    public function register(Request $request)

    {

        $validator = Validator::make($request->all(), [

            'name' => 'required',

            'email' => 'required|email',

            'password' => 'required',

            'c_password' => 'required|same:password',

        ]);



        if ($validator->fails()) {

            return $this->sendError('Validation Error.', $validator->errors());
        }



        $input = $request->all();

        $input['password'] = bcrypt($input['password']);

        $user = User::create($input);

        $success['token'] =  $user->createToken('myapptoken')->accesToken;

        $success['name'] =  $user->name;



        return $this->sendResponse($success, 'User register successfully.');
    }



    /**
 
     * Login api
 
     *
 
     * @return \Illuminate\Http\Response
 
     */

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        // Attempt to log in the user with provided credentials
        if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            $user = Auth::user();

            $success['token'] = $user->createToken('myapptoken')->accessToken;
            $success['name'] = $user->name;

            return $this->sendResponse($success, 'User logged in successfully.');
        } else {
            return $this->sendError('Unauthorized', ['error' => 'Unauthorized']);
        }
    }

    #create a logout method

    public function logout(Request $request)
    {
        // Get the authenticated user
        $token = $request->user()->token();
        $token->revoke();
    
        $response = 'You have been succesfully logged out!';
        return response($response, 200);
    }



    public function sendResponse($result, $message)

    {

        $response = [

            'success' => true,

            'data'    => $result,

            'message' => $message,

        ];



        return response()->json($response, 200);
    }



    /**

     * return error response.

     *

     * @return \Illuminate\Http\Response

     */

    public function sendError($error, $errorMessages = [], $code = 404)

    {

        $response = [

            'success' => false,

            'message' => $error,

        ];



        if (!empty($errorMessages)) {

            $response['data'] = $errorMessages;
        }



        return response()->json($response, $code);
    }
}
