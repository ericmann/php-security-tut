<?php
/**
 * Copyright 2013-2014 TOZNY, LLC. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
/**
 * The Remote Tozny User API.
 *
 * This is the interface for the PHP Remote API for Tozny's login system.
 *
 * PHP version 5
 *
 * LICENSE: Copyright Tozny LLC, All Rights Reserved
 *
 * @category   Security
 * @package    Tozny
 * @author     Isaac Potoczny-Jones <ijones@tozny.com>
 * @copyright  2014 Tozny LLC
 * @version    git: $Id$
 * @link       https://www.tozny.com
 * @since      File available since Release 1.0
 */
class Tozny_Remote_User_API
{

    /**
     * The Realm Key ID that this user is interacting with.
     * Usually a random string.
     *
     * @access private
     * @var string
     */
    private $_realm_key_id;

    /**
     * The Challenge package, once loginChallenge has been called.
     *
     * @access private
     * @var Tozny_Challenge
     */
    private $_challenge;
    private $_api_url;

    const DEFAULT_OCRA_SUITE = "OCRA-1:HOTP-SHA1-6:QH10-S";


    /**
     * Build this class based on the remote site's key ID.
     *
     * @param string $in_realm_key_id
     * @param string $in_api_url      (optional)
     * @throws Exception if the Tozny common libraries were not found
     */
    function __construct( $in_realm_key_id, $in_api_url = NULL)
    {
        $this->_realm_key_id = $in_realm_key_id;

        if ($in_api_url) {
            $this->_api_url = $in_api_url;
        } else {
            $apiTmp = getenv("API_URL");
            if ($apiTmp != false) {
                $this->_api_url = $apiTmp;
            } else {
                //TODO: Error
            }
        }
    }


    /**
     * Returns data about this realm.
     *
     * @return Array with realm_id, logo_url, info_url, display_name.
     */
    function realmGet()
    {
        $decodedValue = $this->rawCall(array('method' => 'user.realm_get', 'realm_key_id'  => $this->_realm_key_id));
        return $decodedValue;
    }


    /**
     * Return the login challenge for this realm. Can return an error
     * if the realm does not exist.
     *
     * @return string | boolean - the Tozny_Challenge or false on error.
     */
    function loginChallenge()
    {
        $decodedValue = $this->rawCall (array('method' => 'user.login_challenge','realm_key_id' => $this->_realm_key_id));
        //TODO: Handle error
        $this->_challenge = $decodedValue;
        return $decodedValue;
    }


    /**
     * Performs the login action by generating a response to the challenge.
     * Requires that login_challenge is called first.
     *
     * @param Tozny_User The user for this login.
     * if the login was successful | error
     * @param unknown $user
     * @return array result, which is a signed payload
     */
    function loginResult($user)
    {
        return $this->loginResultRaw ($user, $this->_challenge);
    }


    /**
     * Like login_result, but doesn't require that login_challenge be called.
     *
     *
     * @param array $user The user for this login.
     * @param array $challenge The challenge
     * @return array if the login was successful | error
     */
    function loginResultRaw($user, $challenge, $type = 'RSA')
    {
        $args = array(
            'method'       => 'user.login_result',
            'realm_key_id' => $this->_realm_key_id,
            'user_id'      => $user['user_id'],
            'user_key_id'  => $user['user_key_id'],
            'session_id'   => $challenge['session_id'],
            'push_token'   => isset($user['push_token']) ? $user['push_token'] : '',    // not required
            'push_platform'=> isset($user['push_platform']) ? $user['push_platform'] : ''  // not required
        );

        $response = '';

        if ($type == 'HMAC') {
            return false;
        }
        else if ($type == 'RSA') {
            $payload = $this->base64UrlEncode(json_encode(array(
                'challenge'  => $challenge['challenge'],
                'session_id' => $challenge['session_id'],
                'expires_at' => time() + 60 * 5 // server-side check is 5 min
            )));

            if (!openssl_sign(
                $payload,
                $signature,
                $user['user_secret'],
                OPENSSL_ALGO_SHA256
            )) {return false;}

            $envelope['signed_data'] = $payload;
            $envelope['signature']   = $this->base64UrlEncode($signature);

            $response = json_encode($envelope);

            $args['login_type'] = 'RSA';
        }

        if ($response == '') {
            return false;
        }

        $args['response'] = $response;
        //TODO: If null, return an error
        $signed_data = $this->rawCall($args);
        //TODO: Handle errors
        return $signed_data;
    }

    /**
     * Retrieves the question description.
     * @param string $session_id The session Id a question was asked for.
     * @return array The Question description.
     * @throws Exception if an error occurs while retrieving the question description.
     */
    function questionGet($session_id)
    {
        $args = array(
            'method'       => 'user.question_get',
            'session_id'   => $session_id,
            'realm_key_id' => $this->_realm_key_id
        );
        $question = $this->rawCall($args);

        if (empty($question['errors'][0]['error_message'])) return $question;

        throw new Exception($question['errors'][0]['error_message']);
    }

    /**
     * Like login_result, but doesn't require that login_challenge be called.
     *
     * @param array $user The user for this login.
     * @param array $challenge The challenge.
     * @param string $answer The answer to the question.
     * @return array if the login was successful | error
     */
    function questionResultRaw($user, $challenge, $answer, $type = 'RSA')
    {
        $args = array(
            'method'       => 'user.question_result',
            'realm_key_id' => $this->_realm_key_id,
            'user_id'      => $user['user_id'],
            'user_key_id'  => $user['user_key_id'],
            'session_id'   => $challenge['session_id'],
            'answer'       => $answer
        );

        $response = '';

        if ($type == 'HMAC') {
            return false;
        }
        else if ($type == 'RSA') {
            $payload = $this->base64UrlEncode(json_encode(array(
                'challenge'  => $challenge['challenge'],
                'session_id' => $challenge['session_id'],
                'expires_at' => time() + 60 * 5 // server-side check is 5 min
            )));

            if (!openssl_sign(
                $payload,
                $signature,
                $user['user_secret'],
                OPENSSL_ALGO_SHA256
            )) {return false;}

            $envelope['signed_data'] = $payload;
            $envelope['signature']   = $this->base64UrlEncode($signature);

            $response = json_encode($envelope);

            $args['login_type'] = 'RSA';
        }

        if ($response == '') {
            return false;
        }

        $args['response'] = $response;
        //TODO: If null, return an error
        $signed_data = $this->rawCall($args);
        //TODO: Handle errors
        return $signed_data;
    }



    /**
     * Add this user to the given realm.
     *
     * @param string  $defer    (optional) Whether to use deferred enrollment. Defaults false.
     * @param array $metadata (optional)
     * @return array The Tozny_API_User object if successful.
     */
    function userAdd($defer = 'false', $metadata = NULL, $pub_key = NULL)
    {
        $args = array(
            'method'       => 'user.user_add',
            'defer'        => $defer,
            'pub_key'      => $pub_key,
            'realm_key_id' => $this->_realm_key_id
        );

        if (!empty($metadata)) {
            $extras = self::base64UrlEncode(json_encode($metadata));
            $args['extra_fields'] = $extras;
        }

        $user_arr = $this->rawCall($args);
        //TODO: Handle errors

        return $user_arr;
    }


    /**
     * For deferred user enrollment, complete the enrollment
     *
     * @param string  $user_temp_key The temporary user key
     * @return array The new user data.
     */
    function userAddComplete($user_temp_key)
    {
        $newUser = $this->rawCall(array('method' => 'user.user_add_complete', 'user_temp_key' => $user_temp_key  , 'realm_key_id' => $this->_realm_key_id));
        return $newUser;
    }

    /**
     * Send a `user.link_challenge` call signed by the current realm.
     *
     * @param string $destination Email address to which we will send a challenge.
     * @param string $endpoint    URL endpoint to be used as a base for the challenge link
     * @param string [$context]   One of "verify," "authenticate," or "enroll"
     *
     * @return array
     */
    function userLinkChallenge( $destination, $endpoint, $context = null )
    {
        $params = array(
            'method'       => 'user.link_challenge',
            'realm_key_id' => $this->_realm_key_id,
            'destination'  => $destination,
            'endpoint'     => $endpoint,
        );

        if ( ! empty( $context ) ) {
            $params['context'] = $context;
        }

        return $this->rawCall( $params );
    }

    /**
     * Perform a user OTP request
     *
     * @param string [$presence]    Presence token
     * @param string [$type]        One of "email," "sms-otp-6," or "sms-otp-8"
     * @param string [$destination] Email address or phone number
     * @param string [$context]     One of "verify," "authenticate," or "enroll"
     *
     * @return mixed Success or error json objects.
     */
    function userOTPChallenge( $presence = null, $type = null, $destination = null, $context = null )
    {
        return $this->rawCall(
            array(
                'method'       => 'user.otp_challenge',
                'realm_key_id' => $this->_realm_key_id,
                'type'         => $type,
                'destination'  => $destination,
                'presence'     => $presence,
                'context'      => $context,
            )
        );
    }

    /**
     * Invoke a `user.link_result` call.
     *
     * @param string $otp The user's OTP as created by `realm.link_challenge`
     *
     * @return mixed If successful, this request returns a redirect to the registered callback. Otherwise it returns a JSON array.
     */
    function userLinkResult( $otp )
    {
        return $this->rawCall(
            array(
                'method'       => 'user.link_result',
                'realm_key_id' => $this->_realm_key_id,
                'otp'          => $otp,
            )
        );
    }

    /**
     * Complete an OTP challenge
     *
     * @param string $session_id ID of the OTP session
     * @param string $otp        Actual OTP
     *
     * @return mixed Success or error json objects.
     */
    function userOTPResult($session_id,$otp)
    {
        return $this->rawCall(
            array(
                'method' => 'user.otp_result',
                'realm_key_id' => $this->_realm_key_id,
                'session_id' => $session_id,
                'otp' => $otp
            )
        );
    }

    /**
     * Exchange a signed OTP challenge (from user.link_result or user.otp_result) for either an
     * enrollment challenge (if the original context was "enroll") or a signed user payload (if
     * the original context was "authenticate").
     *
     * @param string $signed_data  Signed data payload
     * @param string $signature    Realm-signed signature of the payload
     * @param string [$session_id] If this was an authentication challenge, provide the session ID to close the session
     *
     * @return array
     */
    function userChallengeExchange( $signed_data, $signature, $session_id = null )
    {
        $params = array(
            'method'       => 'user.challenge_exchange',
            'realm_key_id' => $this->_realm_key_id,
            'signed_data'  => $signed_data,
            'signature'    => $signature,
        );

        if ( ! empty( $session_id ) ) {
            $params['session_id'] = $session_id;
        }

        return $this->rawCall( $params );
    }

    /**
     * Check whether this session is expired, failed, or succeeded.
     *
     * @param string  $session_id
     * @return array The status json object.
     */
    function checkSessionStatus($session_id)
    {
        $check = $this->rawCall (array('method' => 'user.check_session_status', 'session_id' => $session_id, 'realm_key_id' => $this->_realm_key_id));
        return $check;
    }


    /**
     * Get the QR code for the add_complete call
     *
     * @param string  $user_temp_key
     * @return string A string representing a PNG of the QR code. Use imagecreatefromstring to convert this to an image resource.
     */
    function qrAddComplete($user_temp_key)
    {
        $args = array(
            'method'        => 'user.qr_add_complete',
            'user_temp_key' => $user_temp_key,
            'realm_key_id'  => $this->_realm_key_id
        );
        $url = $this->_api_url . "?" . http_build_query($args);
        $strImg = file_get_contents($url);
        return $strImg;
    }


    /**
     * Get the QR code representing the login_challenge from previously
     * callin guser.login_challenge
     *
     * @return string A string representing a PNG of the QR code. Use imagecreatefromstring to convert this to an image resource.
     */
    function qrLoginChallenge()
    {
        return $this->qrLoginChallengeRaw($this->_challenge);
    }


    /**
     * Get the QR code representing the supplied login_challenge
     *
     * @param string  $challenge The cryptographic challenge
     * @return A string representing a PNG of the QR code. Use imagecreatefromstring to convert this to an image resource.
     */
    function qrLoginChallengeRaw($challenge)
    {
        $args = array('method' => 'user.qr_login_challenge',
            'challenge'     => $challenge['challenge'],
            'session_id'    => $challenge['session_id'],
            'realm_key_id'  => $this->_realm_key_id
        );
        $url = $this->_api_url . "?" . http_build_query($args);
        $strImg = file_get_contents($url);
        return $strImg;
    }


    /**
     * Internal function to convert an array into a query and issue it
     * then decode the results.
     *
     * @param array   $args an associative array for the call
     * @return array either with the response or an error
     */
    function rawCall(array $args)
    {
        $url = $this->_api_url . "?" . http_build_query($args);
        $encodedResult = file_get_contents($url);
        return json_decode($encodedResult, true);
    }


    /**
     * encode according to rfc4648 for url-safe base64 encoding
     *
     *
     * @param string  $data The data to encode
     * @return string The encoded data
     */
    static function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

}// Tozny_Remote_User_API class