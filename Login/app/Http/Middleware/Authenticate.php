<?php

namespace App\Http\Middleware;

use Illuminate\Auth\Middleware\Authenticate as Middleware;
use Illuminate\Support\Facades\Auth;

class Authenticate extends Middleware
{
    /**
     * Get the path the user should be redirected to when they are not authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string|null
     */
    protected function redirectTo($request)
    {
        if (! $request->expectsJson()) {
            return route('login');
        }
    }
    protected function authenticate($request, array $guards)
    {

        if (empty($guards)) {
            $guards = [null];
        }

        foreach ($guards as $guard) {
            if ($this->auth->guard($guard)->check()) {
                //Check logic
                // Lấy session hiện tại(sessionId)
                //So sánh với sessionId trong bảng user
                //=> Nếu khác nhau:Xử lí logout (Kèm message)
                //Nếu giống nhau:Bỏ qua
                $checkDevice=$this->checkDevice($request);
                if(!$checkDevice){
                    $this->unauthenticated($request, $guards);
                }
                return $this->auth->shouldUse($guard);
            }
        }

        $this->unauthenticated($request, $guards);
    }
    private function checkDevice($request){
        $sessionId=$request->session()->getId();
        $user=$request->user();
        $lastSessionId=$user->last_session;
        if($lastSessionId !== $sessionId){
            Auth::logout();
            return false;
        }
        return true;
    }

}
