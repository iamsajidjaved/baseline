<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Media;
use App\City;
use App\Setting;
use App\Timeline;
use App\User;
use DB, Hash, Mail, Illuminate\Support\Facades\Password;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Intervention\Image\Facades\Image;
use JWTAuth;
use Twilio;
use Twilio\Exceptions\RestException;
use Tymon\JWTAuth\Exceptions\JWTException;


class AuthenticationController extends Controller
{

  /**
   * Registers a new user
   * @param Request $request [includes email, password & mobile only]
   * @return [json]           [includes registered user info]
   */
    public function register(Request $request)
    {
    	$credentials = $request->only('email', 'password','mobile');
        $rules = [
          'email' => 'required|email|max:255|unique:users',
          'password' => 'required|min:6',
          'mobile'=>'required|unique:users',
        ];
        $validator = Validator::make($credentials, $rules);
        if($validator->fails()) {
          return response()->json(['success'=> false, 'error'=> $validator->messages()]);
        }
        /* Getting some data from $request and creating some dummy data to register a user.
        Will update dummy data on update API call*/
        $email = $request->email;
        $name = 'Registering';
        $mobile = $request->mobile;
        $password = $request->password;
        $about="Some text about me";
        $type="user";
        $code = mt_rand(10000, 99999);
        /* Inserting requesting data into timelines table to get timeline_id first
        timeline_id can't be null in users table*/
        
        Timeline::create(['username' => $email, 'name' => $name,'about'=>$about,'type'=>$type]);
        $timeline = Timeline::where('username', $email)->where('type', $type)->first();
        $timeline_id=$timeline->id;
        $verification_code = str_random(30);
        // Registering users
        User::create(['email' => $email, 'password' => Hash::make($password),'mobile'=>$mobile,'mobile_verify_code'=>$code,'verification_code'=>$verification_code,'timeline_id'=> $timeline_id]);
        // Sending verification code to the user mobile
          $smsBody="Your CooMoTravel verification code is: $code";
          $twilio = new \Aloha\Twilio\Twilio("AC206e76f6819eb5dbadfc3fd193109490",
                  "0a0f569c592f291b3584c15d94576e16",
                  "+15125249456");
            try{
                  $twilio->message($mobile, $smsBody);
            }catch (RestException $e) {
        }
        try{
                    $user = User::where('email', $email)->first();
                    Mail::send('emails.welcome', ['user' => $user], function ($m) use ($user) {
                    $m->from(Setting::get('noreply_email'), Setting::get('site_name'));
                    $m->to($user->email, $user->name)->subject('Welcome to ' . Setting::get('site_name'));
                    });
                }catch (Exception $ex){}
        return $this->login($request);
    }
     /**
      * Login user
      * @param  Request $request [includes email and password only]
      * @return [json]           [includes user info]
      */
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');
        $rules = [
            'email' => 'required|email',
            'password' => 'required',
        ];
        $validator = Validator::make($credentials, $rules);
        if($validator->fails()) {
            return response()->json(['success'=> false, 'error'=> $validator->messages()]);
        }
        try {
            // attempt to verify the credentials and create a token for the user
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json(['success' => false, 'error' => 'We cant find an account with this credentials.'], 401);
            }
        } catch (JWTException $e) {
            // something went wrong whilst attempting to encode the token
            return response()->json(['success' => false, 'error' => 'Failed to login, please try again.'], 500);
        }
        // all good so return the token
        return response()->json(['success' => true, 'data'=> [ 'token' => $token ]]);
    }
    /**
     * Log out user
     * Invalidate the token, so user cannot use it anymore
     * They have to relogin to get a new token
     *
     * @param  Request $request [includes token only]
     * @return [json]           [includes success or failure message]
     */
    public function logout(Request $request) {
        $this->validate($request, ['token' => 'required']);
        try {
            JWTAuth::invalidate($request->input('token'));
            return response()->json(['success' => true, 'message'=> "You have successfully logged out."]);
        } catch (JWTException $e) {
            // something went wrong whilst attempting to encode the token
            return response()->json(['success' => false, 'error' => 'Failed to logout, please try again.'], 500);
        }
    }
    /**
     * Authenticate verification code
     * Set is_mobile_verified in users table into 1 if the code matched
     *
     * @param  Request $request [includes mobile and verification code only]
     * @return [json]           [includes success or failure message]
     */
    public function verify_OTP(Request $request){
      $validator = Validator::make($request->all(), [
           'mobile' => 'required',
           'code' => 'required'
       ]);
      if ($validator->fails()) {
            $errors = $validator->errors();
            return response()->json(['success'=> false, 'msg'=> $validator->messages()]);
        }else{
            $mobile=$request->mobile;
            $code=$request->code;
            if(DB::table('users')->where('mobile',$mobile)->count()==1)
            {
            $is_mobile_verified_json = DB::table('users')->select('is_mobile_verified')->where('mobile',$mobile)->first();
            $is_mobile_verified=$is_mobile_verified_json->is_mobile_verified;
            if($is_mobile_verified==1){
              return response()->json(['success'=> false, 'msg'=> 'This mobile is already verified']);
            }else{
            $code_db_json = DB::table('users')->select('mobile_verify_code')->where('mobile',$mobile)->first();
            $code_db_num=$code_db_json->mobile_verify_code;
            if($code==$code_db_num){
                $user_record = User::where('mobile', $mobile)->first();
                $user_record->is_mobile_verified = 1;
                $user_record->save();
                return response()->json(['success'=> true, 'msg'=> 'OTP matched.']);
            }else{
                $mobile_verify_tried_json = DB::table('users')->select('mobile_verify_tried')->where('mobile',$mobile)->first();
                $mobile_verify_tried=$mobile_verify_tried_json->mobile_verify_tried;
                if($mobile_verify_tried>=5){
                    return response()->json(['success'=> false, 'msg'=> 'Tries limit exceeded.']);
                }else{
                    $mobile_verify_tried=$mobile_verify_tried+1;
                    User::where('mobile', $mobile)
                    ->update(['mobile_verify_tried' => $mobile_verify_tried]);
                    return response()->json(['success'=> false, 'msg'=> 'Invalid Code.','try'=>$mobile_verify_tried]);
                }
            }
          }
        }else{
          return response()->json(['success'=> false, 'msg'=> 'This mobile no. does not exist.']);
        }
      }
    }
    /**
     * Code Resend
     * Checks the phone first if it exists
     * Checks resend tries
     *
     * @param Request $request
     */
    public function resend(Request $request){
        $validator = Validator::make($request->all(), [
           'mobile' => 'required'
       ]);
         if ($validator->fails()) {
            $errors = $validator->errors();
            return response()->json(['success'=> false, 'msg'=> $validator->messages()]);
        }else{
            $mobile=$request->mobile;
            $code = mt_rand(10000, 99999);
            if(DB::table('users')->where('mobile', $mobile)->count()==1){
              $mobile_resend_code_tried_json=DB::table('users')->select('mobile_resend_code_tried')->where('mobile',$mobile)->first();
              $mobile_resend_code_tried=$mobile_resend_code_tried_json->mobile_resend_code_tried;
                    if($mobile_resend_code_tried<=5){
                    User::where('mobile', $mobile)
                      ->update(['mobile_verify_code' => $code]);
                    $smsBody="Your CooMoTravel verification code is: $code";
                    $twilio = new \Aloha\Twilio\Twilio("AC206e76f6819eb5dbadfc3fd193109490",
                        "0a0f569c592f291b3584c15d94576e16",
                        "+15125249456");
                    try{
                          $twilio->message($mobile, $smsBody);
                          $mobile_resend_code_tried_json = DB::table('users')->select('mobile_resend_code_tried')->where('mobile',$mobile)->first();
                          $mobile_resend_code_tried=$mobile_resend_code_tried_json->mobile_resend_code_tried;
                          $mobile_resend_code_tried=$mobile_resend_code_tried+1;
                          User::where('mobile', $mobile)
                          ->update(['mobile_resend_code_tried' => $mobile_resend_code_tried]);
                          return response()->json(['success'=> true, 'msg'=>'Verification code is sent to the user']); 
                    }catch (RestException $e) {
                    return $e;
                }
              }else{
                return response()->json(['success'=> false, 'msg'=>'Tries limit crossed']);
              }
            }else{
                return response()->json(['success'=> false, 'msg'=> 'This mobile number does not exist']);
            }
        }
    }
    /**
     * Change user mobile
     * @param  Request $request [includes old mobile no. & new mobile no.]
     * @return [json]           [includes success or failure message]
     */
    public function changePhone(Request $request)
    {
      $validator = Validator::make($request->all(), [
           'mobile_old' => 'required',
           'mobile' => 'required|unique:users'
       ]);
      if ($validator->fails()) {
            $errors = $validator->errors();
            return response()->json(['success'=> false, 'msg'=> $validator->messages()]);
        }else{
            $mobile_old=$request->mobile_old;
            $mobile=$request->mobile;
            if($mobile_old!=$mobile)
            {
              if(DB::table('users')->where('mobile',$mobile_old)->count()==1)
            {
                $user_record = User::where('mobile', $mobile_old)->first();
                $user_record->mobile = $mobile;
                $user_record->is_mobile_verified = 0;
                $user_record->mobile_verify_code = null;
                $user_record->mobile_verify_tried = 0;
                $user_record->mobile_resend_code_tried = 0;
                $user_record->save();
                $code = mt_rand(10000, 99999);
                $smsBody="Your CooMoTravel verification code is: $code";
                $twilio = new \Aloha\Twilio\Twilio("AC206e76f6819eb5dbadfc3fd193109490",
                        "0a0f569c592f291b3584c15d94576e16",
                        "+15125249456");
                  try{
                        $twilio->message($mobile, $smsBody);
                        $user_record = User::where('mobile', $mobile)->first();
                        $user_record->mobile_verify_code = $code;
                        $user_record->mobile_verify_tried = 1;
                        $user_record->save();
                        return response()->json(['success'=> true, 'msg'=>'Verification code is sent to the user']); 
                  }catch (RestException $e) {
                  return $e;
              }

            }
            else{
              return response()->json(['success'=> false, 'msg'=> 'This mobile number does not exist']);
            }
          }else{
           return response()->json(['success'=> false, 'msg'=> 'Both numbers are same.']);
          }
        }
    }

    /**
     * Checks Username
     * @param  Request $request [includes username]
     * @return [json]           [includes success or failure message]
     */
  public function username(Request $request)
  {
    $validator = Validator::make($request->all(), [
      'username' => 'required'
      ]);
      if ($validator->fails()) {
        $errors = $validator->errors();
        return response()->json(['success'=> false, 'msg'=> $validator->messages()]);
      }else{
        $username=$request->username;
        if (Timeline::where('username', $username)->count()!=0) {
          return response()->json(['success'=> false, 'msg'=> 'Username is taken by someone else']);
        } else {
          return response()->json(['success'=> true, 'msg'=> 'Username is not taken']);
        }
      }
  }

  /**
   * [uploading avatar into storage/uploads/users/avatars and inserting it into media table]
   * Then get the media id and update the avatar_id in the timelines table
   * @param  Request $request [includes only email/username and avatar]
   * @return [json]           [includes success or failure message]
   */
  public function avatar(Request $request)
  {
    $validator = Validator::make($request->all(), [
      'avatar' => 'required',
      'email' => 'required'
      ]);
      if ($validator->fails()) {
        $errors = $validator->errors();
        return response()->json(['success'=> false, 'msg'=> $validator->messages()]);
      }else{
        $avatar = $request->file('avatar');
        $username = $request->email;
        if (Timeline::where('username', $username)->count()==1) {
           $avatar_stripped_name = str_replace(' ', '', $avatar->getClientOriginalName());
            $avatar_concat_name = date('YmdHis') . $avatar_stripped_name;
            // Lets resize the image to the square with dimensions of either width or height , which ever is smaller.
            list($width, $height) = getimagesize($avatar->getRealPath());
            $avatar = Image::make($avatar->getRealPath());

            if ($width > $height) {
                $avatar->crop($height, $height);
            } else {
                $avatar->crop($width, $width);
            }
            $timeline_type = 'user';
            if($avatar->save(storage_path() . '/uploads/' . $timeline_type . 's/avatars/' . $avatar_concat_name, 60)){
            if($media = Media::create([
                'title' => $avatar,
                'type' => 'image',
                'source' => $avatar_concat_name,
            ])){
              $timeline=Timeline::where('username', $username)->first();
              $timeline->avatar_id = $media->id;
              if($timeline->save()){
                return response()->json(['success'=> true, 'msg'=> 'Photo is uploadded successfully.']);
              }else{
                return response()->json(['success'=> false, 'msg'=> 'Sorry, Something went wrong while making an entry in timelines table']);
              }
            }else{
              return response()->json(['success'=> false, 'msg'=> 'Sorry, Something went wrong while making an entry of this photo in the database']);
            }
            }else{
              return response()->json(['success'=> false, 'msg'=> 'Sorry, Something went wrong while uploading/storing the image.']);
            }
            
        } else {
          return response()->json(['success'=> false, 'msg'=> 'Sorry, This email or username does not exist.']);
        }        
      }
  }

  /**
   * [updating user record in users and timelines table]
   * @param  Request $request [includes username, firstname, lastname and email]
   * @return [json]           [includes success or failure message]
   */
  public function update(Request $request)
  {
    $validator = Validator::make($request->all(), [
      'username' => 'required|unique:timelines',
      'fname' => 'required',
      'lname' => 'required',
      'city' => 'required',
      'email' => 'required',
      ]);
      if ($validator->fails()) {
        $errors = $validator->errors();
        return response()->json(['success'=> false, 'msg'=> $validator->messages()]);
      }else{
        $email = $request->email;
        $fname = $request->fname;
        $lname = $request->lname;
        $username = $request->username;
        $city = $request->city;
        $cities=$request->cars;
        // getting each city from the JSON array
        foreach ($cities as $city_name) {
          $city_from_array = $city_name;

          // Inserting into cities table
          $City_Obj = new City;
          $City_Obj->name = $city_from_array;
          $City_Obj->save();

          // Getting last inserted city id
          $latest_city = City::all()->last();
          $latest_city_id = $latest_city->id;

          // Getting current user id
          $user = User::where('email', $email)->first();
          $current_user_id = $user->id;

          // Inserting user_id and city_id into user_cities table
          DB::table('user_cities')->insert(
              ['user_id' => $current_user_id, 'city_id' => $latest_city_id]
          );
        }
        // updating timelines table
        $timeline = Timeline::where('username', $email)->first();
        $timeline->username = $username;
        $timeline->name = ucfirst($fname) .' '. ucfirst($lname);
        $timeline->save();
        // Updating users table
         $user->city = $city;
         $result =  $user->save();
         return response()->json(['success'=> true, 'msg'=> 'User info updated.']);
      }
  }
}
