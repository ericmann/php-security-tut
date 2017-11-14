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
 * The Remote Tozny API.
 *
 * This is the interface for the PHP Remote API for Tozny's login system.
 *
 * PHP version 5
 *
 *
 * @category   Security
 * @copyright  2014 Tozny LLC
 * @version    git: $Id$
 * @link       https://www.tozny.com
 * @since      File available since Release 1.0
 * @author     Isaac Potoczny-Jones <ijones@tozny.com>
 * @package    Tozny
 */

class Tozny_Remote_Realm_API
{

    /**
     *
     *
     * @access private
     * @var string
     */
    private $_realm;

    private $_api_url;


    /**
     * Build this class based on the remote site's key ID.
     *
     * @param string $realm_key_id
     * @param unknown $realm_secret
     * @param unknown $in_api_url (optional)
     */
    function __construct($realm_key_id, $realm_secret, $in_api_url = NULL)
    {
        $this->setRealm($realm_key_id, $realm_secret);

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
     *
     *
     * @param unknown $realm_key_id
     * @param unknown $realm_secret
     */
    function setRealm($realm_key_id, $realm_secret)
    {
        $this->_realm['realm_key_id'] = $realm_key_id;
        $this->_realm['realm_priv_key'] = $realm_secret;
    }


    /**
     * We have received a sign package and signature
     * lets verify it
     *
     * @param string $signed_data - who's logging in
     * @param string $signature - the signature for the payload
     * @return mixed the decoded JSON data or FALSE
     */
    function verifyLogin($signed_data, $signature)
    {
        $check['signed_data'] = $signed_data;
        $check['signature'] = $signature;
        return self::checkSigGetData($check);

    }


    /**
     *
     *
     * @param unknown $user_id
     * @param unknown $session_id
     * @param unknown $expires_at
     * @return unknown
     */
    function _checkValidLogin($user_id, $session_id, $expires_at)
    {
        $cmdOut = $this->rawCall(
            array(
                'method' => 'realm.check_valid_login',
                'user_id' => $user_id,
                'session_id' => $session_id,
                'expires_at' => $expires_at
            )
        );
        if ($cmdOut['return'] === 'true') {
            return true;
        } else {
            return false;
        }
    }


    /**
     * An alias for questionChallengeText.
     *
     * @param string|array $question
     * @param null $user_id
     * @return mixed The response from the Tozny API
     */
    function questionChallenge($question, $user_id = NULL)
    {
        if (is_string($question))
            return $this->questionChallengeText($question, $user_id);
        else if (is_array($question))
            return $this->_callQuestionChallenge($question, $user_id);
        else
            return false;
    }

    /**
     * Creates a text question challenge session.
     *
     * @param string $question The text to display to the user before signing the Tozny question challenge.
     * @param string $user_id The user that should answer the question.
     * @return mixed The response from the Tozny API
     */
    function questionChallengeText($question, $user_id = NULL)
    {
        $question = array(
            "type" => "question",
            "question" => $question
        );
        return $this->_callQuestionChallenge($question, $user_id);
    }

    /**
     * Creates a callback question challenge session.
     *
     * @param string $question The text to display to the user before signing the Tozny question challenge.
     * @param string $successURL The URL the user's mobile browser should be redirected to after successful authentication.
     * @param string $errorURL The URL the user's mobile browser should be redirected to after unsuccessful authentication.
     * @param string $user_id The user that should answer the question.
     * @return mixed The response from the Tozny API
     */
    function questionChallengeCallback($question, $successURL, $errorURL, $user_id = NULL)
    {
        $question = array(
            "type"    => "callback",
            "question" => $question,
            "success" => $successURL,
            "error"   => $errorURL
        );
        return $this->_callQuestionChallenge($question, $user_id);
    }

    function _callQuestionChallenge($question, $user_id = NULL)
    {
        $args = array(
            'method' => 'realm.question_challenge',
            'question' => json_encode($question)
        );

        if (!empty($user_id)) {
            $args['user_id'] = $user_id;
        }

        $questionChallenge = $this->rawCall($args);
        return $questionChallenge;
    }


    /**
     * Does the given user exist in this realm?
     *
     * @param int $user_id The user ID of the user we're looking for
     * @return boolean true if the user is known and there are no errors.
     */
    function userExists($user_id)
    {
        $cmdOut = $this->rawCall(
            array(
                'method' => 'realm.user_exists',
                'user_id' => $user_id
            )
        );
        if ($cmdOut['return'] === 'true') {
            return true;
        } else {
            // TODO: This is wrong! we are not distinguishing between a call that succeeds but doesn't find a user, from a call that fails.
            return false;
        }
    }

    /**
     * Does the given user exist in this realm?
     *
     * @param  string $email The email of the user we're looking for
     * @return boolean|int false if the user does not exist, or there was an .
     */
    function userEmailExists($email)
    {
        $cmdOut = $this->rawCall(
            array(
                'method' => 'realm.user_exists',
                'tozny_email' => $email
            )
        );

        # Success & User found
        if ($cmdOut['return'] === 'true' && !empty($cmdOut['user_id'])) {
            return $cmdOut['user_id'];
        } # Success & User not found
        else if ($cmdOut['return'] === 'false') {
            return false;
        } # Failure
        else {
            $msg = $cmdOut['errors'][0]['error_message'];
            if (!empty($msg)) {
                throw new Exception($msg);
            } else {
                throw new Exception(sprintf("Unexpected error: %s", print_r($cmdOut, true)));

            }
        }
    }

    /**
     * Add this user to the given realm.
     *
     * @param string $defer (optional) Whether to use deferred enrollment. Defaults false.
     * @param array $metadata (optional)
     * @return The Tozny_API_User object if successful, otherwise false.
     */
    function userAdd($defer = 'false', $metadata = NULL, $pub_key = NULL)
    {
        $args = array(
            'method'  => 'realm.user_add',
            'defer'   => $defer,
        );

        // You must give a pub_key param, if you are not deferring enrollment.
        if ($defer === 'false') {
            if (!empty($pub_key)) $args['pub_key'] = $pub_key;
            else throw new Exception("Cannot enroll without a public key! Did you mean to defer enrollment?");
        }

        if (!empty ($metadata)) {

            $extras = self::base64UrlEncode(json_encode($metadata));

            $args['extra_fields'] = $extras;
        }
        $user_arr = $this->rawCall($args);
        if (!array_key_exists('return', $user_arr) || empty($user_arr['return']) || $user_arr['return'] !== 'ok') return false;
        else return $user_arr;
    }



    /**
     * Update a user's metadata
     *
     * @param unknown $user_id
     * @param unknown $extra_fields
     * @return array $user
     */
    function userUpdate($user_id, $extra_fields)
    {

        $extra_fields = $this->_base64UrlEncode(json_encode($extra_fields));

        $args = array(
            'method' => 'realm.user_update',
            'user_id' => $user_id,
            'extra_fields' => $extra_fields
        );

        $user_arr = $this->rawCall($args);

        return $user_arr;
    }

    /**
     * Get a user from the given realm
     *
     * @param string $user_id User id to fetch
     * @return array user_id, metadata
     */
    function userGet($user_id)
    {
        $args = array(
            'method' => 'realm.user_get',
            'user_id' => $user_id
        );

        $result = $this->rawCall($args);
        if (!empty($result['results'])) {return $result['results'];}
        throw new Exception(sprintf("Failed userGet() request: user_id %s; result: %s", $user_id, json_encode($result)));
    }


    /**
     *
     *
     * @param unknown $term (optional)
     * @param unknown $meta_advanced (optional)
     * @param unknown $tozny_advanced (optional)
     * @param unknown $meta_fields (optional)
     * @param unknown $tozny_fields (optional)
     * @param unknown $userid (optional)
     * @param unknown $rows (optional)
     * @param unknown $offset (optional)
     * @param unknown $page (optional)
     * @return unknown
     */
    function usersGet($term = NULL,
                      $meta_advanced = NULL,
                      $tozny_advanced = NULL,
                      $meta_fields = NULL,
                      $tozny_fields = NULL,
                      $userid = NULL,
                      $rows = NULL,
                      $offset = NULL,
                      $page = NULL)
    {

        if (!empty($meta_advanced)) {
            $meta_advanced = self::base64UrlEncode(json_encode($meta_advanced));
        }

        if (!empty($tozny_advanced)) {
            $tozny_advanced = self::base64UrlEncode(json_encode($tozny_advanced));
        }

        if (!empty($userid)) {
            if (is_array($userid)) {
                $userid = implode(",", $userid);
            }
        }

        $args = array(
            'method' => 'realm.users_get',
            'term' => $term,
            'meta_advanced' => $meta_advanced,
            'tozny_advanced' => $tozny_advanced,
            'meta_fields' => $meta_fields,
            'tozny_fields' => $tozny_fields,
            'user_ids' => $userid,
            'rows' => $rows,
            'offset' => $offset,
            'page' => $page
        );

        $user_arr = $this->rawCall($args);

        return $user_arr;
    }


    /**
     * Get the user id for the given user_key_id
     *
     * @param string $user_key_id
     * @return the user_id
     */
    function userGetId($user_key_id)
    {
        return $this->rawCall(
            array(
                'method' => 'realm.user_get_id',
                'user_key_id' => $user_key_id
            )
        );
    }

    /**
     * Get a user from the given realm identified by the given email address.
     *
     * @param string $email the email value to locate a user by
     * @return array user_id, metadata
     */
    function userGetEmail($email)
    {
        $args = array(
            'method'      => 'realm.user_get',
            'tozny_email' => $email
        );

        $response = $this->rawCall($args);
        if ($response['return'] === 'ok') {
            return $response['results'];
        } else {
            $getStatus = function($err){return $err['status_code'];};
            $filt404s  = function($s) {return $s === 404;};
            $has404 = count(array_filter(array_map($getStatus, $response['errors']),$filt404s)) > 0;
            if ($has404) {
                return false;
            }
            else {
                throw new Exception("Unexpected Response from server:".json_encode($response));
            }
        }

    }

    /**
     * Delete the given user
     *
     * @param string $user_id
     * @return Success or error json objects.
     */
    function userDelete($user_id)
    {
        return $this->rawCall(
            array(
                'method' => 'realm.user_delete',
                'user_id' => $user_id
            )
        );
    }


    // -----------------------------------
    // -- Fields
    // -----------------------------------


    /**
     * fieldsGet
     *
     * @param field_id
     * @return array of Field data
     */
    function fieldsGet($field_ids = NULL, $page = 1, $rows = 20, $offset = 0, $term = NULL)
    {
        $call = array(
            'method' => 'realm.fields_get',
            'field_id' => $field_ids,
            'page' => $page,
            'rows' => $rows,
            'offset' => $offset,
            'term' => $term
        );

        return $this->rawCall($call);

    }


    /**
     * fieldGet
     *
     * @param field_id
     * @return array of Field data
     */
    function fieldGet($field_id)
    {
        $call = array(
            'method' => 'realm.field_get',
            'field_id' => $field_id
        );

        return $this->rawCall($call);
    }


    /**
     * fieldAdd
     *
     * @param string $name
     * @param string $field
     * @param array $options array(
     *                required,
     *                  encrypted,
     *                  searchable,
     *                maps_to,
     *                uniq,
     *                  primary_view,
     *                secondary_view)
     * @return Field data
     */
    function fieldAdd($name, $field, $options = NULL)
    {
        $call = array(
            'method' => 'realm.field_add',
            'name' => $name,
            'field' => $field
        );

        if (is_array($options)) {
            $call = array_merge($call, $options);
        }

        return $this->rawCall($call);
    }


    /**
     * fieldUpdate
     *
     * @param string $field_id
     * @param array $options array(
     *                name,
     *                required,
     *                  encrypted,
     *                  searchable,
     *                maps_to,
     *                uniq,
     *                  primary_view,
     *                secondary_view)
     * @return Field data
     */
    function fieldUpdate($field_id, $options = NULL)
    {
        $call = array(
            'method' => 'realm.field_update',
            'field_id' => $field_id
        );

        if (is_array($options)) {
            $call = array_merge($call, $options);
        }

        return $this->rawCall($call);

    }


    /**
     * fieldDelete
     *
     * @param string $field_id
     * @return Delete confirmation
     */
    function fieldDelete($field_id)
    {
        $call = array(
            'method' => 'realm.field_delete',
            'field_id' => $field_id
        );

        return $this->rawCall($call);

    }


    // -----------------------------------
    // -- Postbacks
    // -----------------------------------


    /**
     *
     *
     * @param unknown $postback_id
     * @return unknown
     */
    function postbackGet($postback_id)
    {
        $args = array(
            'method' => 'realm.postback_get',
            'postback_id' => $postback_id
        );

        return $this->rawCall($args);
    }

    function postbacksGet($postback_ids = NULL, $page = 1, $rows = 20, $offset = 0, $term = NULL)
    {
        $args = array(
            'method' => 'realm.postbacks_get',
            'page' => $page,
            'rows' => $rows,
            'offset' => $offset,
            'term' => $term
        );

        if (!empty($postback_ids)) {
            if (is_array($postback_ids)) {
                $args['postback_ids'] = implode(",", $postback_ids);
            } else {
                $args['postback_ids'] = $postback_ids;
            }
        }

        return $this->rawCall($args);
    }


    /**
     * Add this postback
     *
     * @param string $postback_hook
     * @param string $postback_url
     * @param string $postback_type
     * @return Postback data like the postback_id
     */
    function postbackAdd($name, $postback_url, $postback_type, $postback_hook,
                         $postback_triggers = NULL)
    {
        return $this->rawCall(
            array(
                'method' => 'realm.postback_add',
                'postback_hook' => $postback_hook,
                'postback_url' => $postback_url,
                'postback_type' => $postback_type,
                'name' => $name,
                'postback_triggers' => $postback_triggers
            )
        );
    }


    /**
     *
     *
     * @param unknown $postback_id
     * @return unknown
     */
    function postbackUpdate($postback_id, $args)
    {
        $args['method'] = 'realm.postback_update';
        $args['postback_id'] = $postback_id;

        return $this->rawCall($args);
    }


    /**
     * Delete the given postback
     *
     * @param string $postback_id
     * @return Postback data like the postback_id
     */
    function postbackDelete($postback_id)
    {
        return $this->rawCall(
            array(
                'method' => 'realm.postback_delete',
                'postback_id' => $postback_id
            )
        );
    }


    /**
     *
     *
     * @param unknown $postback_id
     * @return unknown
     */
    function postbackExists($postback_id)
    {
        $args = array(
            'method' => 'realm.postback_exists',
            'postback_id' => $postback_id
        );

        return $this->rawCall($args);
    }


    // --------------------------
    // Postback Results calls
    // --------------------------


    /**
     *
     *
     * @param unknown $postback_id - comma separated list of postback id's
     * @return unknown
     */
    function postbacksResults($postback_ids = NULL)
    {
        $args = array(
            'method' => 'realm.postbacks_results',
            'postback_ids' => $postback_ids
        );

        $results = $this->rawCall($args);
        foreach ($results['results'] as $ret) {
            $out[$ret['id']] = $ret;
            $out[$ret['id']]['payload'] = json_decode($ret['payload']);
            // TODO - change this to encryption instead of unsigning
            $out[$ret['id']]['results'] = $this->siteApi->postbackReceive($results['payload']);
        }
        return $out;

    }


    // --------------------------
    // Postback Receive
    // --------------------------


    /**
     *
     *
     * @param unknown $postback_id - comma separated list of postback id's
     * @return unknown
     */
    function postbackReceive($signed_data, $signature)
    {
        $data['signed_data'] = $signed_data;
        $data['signature'] = $signature;

        $ret = $this->checkSigGetData($data);

        if (!$ret) {
            $out['return'] = "error";
            $out['errors'][0]['status_code'] = "400";
            $out['errors'][0]['error_message'] = "Invalid payload";
            $out['errors'][0]['location'] = "postbackReceive";
        } else {
            $out = $ret;
        }

        return $out;

    }



    // ----------------------------------
    // Realm calls
    // -----------------------------------


    /**
     * Get realm info
     *
     * @param string $realm_key_id Realm key id
     *  domain, logo_url,crypto_suite)
     * @return array(realm_id, open_enrollment, display_name, ip_address,
     */
    function realmGet()
    {
        $args = array(
            'method' => 'realm.realm_get'
        );

        $realm = $this->rawCall($args);

        //TODO error handling?
        return $realm;
    }

    function realmUpdate($realm)
    {
        $args = array(
            'method' => 'realm.realm_update'
        );
        foreach ($realm as $k => $v) {
            $args[$k] = $v;
        }

        return $this->rawCall($args);
    }


    /**
     * This decodes signed data
     *
     * @param string $signed_data
     * @return unknown
     */
    function decodeSignedData($signed_data)
    {
        return json_decode($this->_base64UrlDecode($signed_data), true);
    }


    /**
     *
     *
     * @param unknown $key_ids (optional)
     * @param unknown $rows (optional)
     * @param unknown $offset (optional)
     * @param unknown $page (optional)
     * @return unknown
     */
    function realmKeysGet($key_ids = NULL, $rows = 20, $offset = 0, $page = NULL)
    {
        $args = array(
            'method' => 'realm.keys_get',
            'rows' => $rows,
            'offset' => $offset,
            'page' => $page
        );

        if (!empty($key_ids)) {
            if (is_array($key_ids)) {
                $args['key_id'] = implode(",", $key_ids);
            } else {
                $args['key_id'] = $key_ids;
            }
        }


        return $this->rawCall($args);
    }


    /**
     *
     *
     * @param unknown $rki
     * @param unknown $name (optional)
     * @param unknown $roll (optional)
     * @return unknown
     */
    function realmKeyUpdate($rki, $name = NULL, $roll = false)
    {
        $args = array(
            'method' => 'realm.key_update',
            'key_id' => $rki,
            'name' => $name
        );

        if ($roll) {
            $args['roll_secret_key'] = "true";
        }

        return $this->rawCall($args);
    }


    /**
     *
     *
     * @param unknown $rki
     * @return unknown
     */
    function realmKeyGet($rki)
    {
        $args = array(
            'method' => 'realm.key_get',
            'key_id' => $rki
        );

        return $this->rawCall($args);
    }


    /**
     *
     *
     * @param unknown $rki
     * @return unknown
     */
    function realmKeyExists($rki)
    {
        $args = array(
            'method' => 'realm.key_exists',
            'key_id' => $rki
        );

        return $this->rawCall($args);
    }


    /**
     *
     *
     * @param unknown $rki
     * @return unknown
     */
    function realmKeyDelete($rki)
    {
        $args = array(
            'method' => 'realm.key_delete',
            'key_id' => $rki
        );

        return $this->rawCall($args);
    }


    /**
     *
     *
     * @param unknown $name
     * @return unknown
     */
    function realmKeyAdd($name)
    {
        $args = array(
            'method' => 'realm.key_add',
            'name' => $name
        );

        return $this->rawCall($args);
    }

    function realmUserDevices($user_id, $term = NULL, $page = 1, $rows = 20, $offset = 0)
    {
        $args = array(
            'method' => 'realm.user_devices',
            'user_id' => $user_id,
            'term' => $term,
            'page' => $page,
            'rows' => $rows,
            'offset' => $offset
        );

        return $this->rawCall($args);
    }

    function realmUserDeviceAdd($user_id)
    {
        $args = array(
            'method' => 'realm.user_device_add',
            'user_id' => $user_id
        );

        return $this->rawCall($args);

    }

    function realmUserDeviceUpdate($user_key_id, $device_description)
    {
        $args = array(
            'method' => 'realm.user_device_update',
            'user_key_id' => $user_key_id,
            'device_description' => $device_description
        );

        return $this->rawCall($args);

    }


    function realmUserDeviceGet($user_key_id)
    {
        $args = array(
            'method' => 'realm.user_device_get',
            'user_key_id' => $user_key_id
        );

        return $this->rawCall($args);
    }

    function realmUserDeviceDelete($user_key_id)
    {
        $args = array(
            'method' => 'realm.user_device_delete',
            'user_key_id' => $user_key_id
        );

        return $this->rawCall($args);
    }

    function realmActivity($user_id = NULL, $realm_key_id_param = NULL,
                           $user_key_id = NULL, $offset = 0, $rows = 20, $page = NULL)
    {
        $args = array(
            'method' => 'realm.activity',
            'user_id' => $user_id,
            'realm_key_id_param' => $realm_key_id_param,
            'user_key_id' => $user_key_id,
            'offset' => $offset,
            'rows' => $rows,
            'page' => $page,
        );

        return $this->rawCall($args);
    }


    /**
     * Send a `realm.link_challenge` call signed by the current realm.
     *
     * @param string $destination Email address to which we will send a challenge.
     * @param string $endpoint    URL endpoint to be used as a base for the challenge link
     * @param int    [$lifespan]  Number of seconds for which the link will be valid
     * @param string [$context]   One of "verify," "authenticate," or "enroll"
     * @param bool   [$send]      Optional flag whether or not to send the email. If false, will return the OTP URL instead of sending an email.
     * @param string [$data]      JSON-encoded string of data to be signed along with the request
     *
     * @return array
     */
    function realmLinkChallenge( $destination, $endpoint, $lifespan, $context = null, $send = true, $data = null )
    {
        $params = array(
            'method'       => 'realm.link_challenge',
            'realm_key_id' => $this->_realm['realm_key_id'],
            'destination'  => $destination,
            'endpoint'     => $endpoint,
            'send'         => $send ? 'yes' : 'no',
        );

        if ( ! empty( $lifespan ) ) {
            $params['lifespan'] = $lifespan;
        }
        if ( ! empty( $context ) ) {
            $params['context'] = $context;
        }
        if ( ! empty( $data ) ) {
            $params['data'] = $data;
        }

        return $this->rawCall( $params );
    }

    /**
     * Perform a realm OTP request
     *
     * @param string [$presence]    Presence token
     * @param string [$type]        One of "email," "sms-otp-6," or "sms-otp-8"
     * @param string [$destination] Email address or phone number
     * @param string [$data]        JSON-encoded string of data to be signed along with the request
     * @param string [$context]     One of "verify," "authenticate," or "enroll"
     *
     * @return mixed Success or error json objects.
     */
    function realmOTPChallenge( $presence, $type = null, $destination = null, $data = null, $context = null )
    {
        return $this->rawCall(
            array(
                'method'       => 'realm.otp_challenge',
                'realm_key_id' => $this->_realm['realm_key_id'],
                'data'         => $data,
                'type'         => $type,
                'destination'  => $destination,
                'presence'     => $presence,
                'context'      => $context,
            )
        );
    }

    /**
     * Internal function to convert an array into a query and issue it
     * then decode the results. Includes generation of the nonce and
     * signing of the message
     *
     * @param array $args an associative array for the call
     * @return array either with the response or an error
     */
    function rawCall(array $args)
    {
        $args["nonce"] = $this->_generateNonce();
        $args['expires_at'] = time() + (5 * 60);

        // key id is optional for convenience
        if (!isset($args['realm_key_id'])) {
            $args['realm_key_id'] = $this->_realm['realm_key_id'];
        }

        $sigArr = $this->_encodeAndSignArr(json_encode($args),
            $this->_realm['realm_priv_key']);
        $encodedResult = file_get_contents($this->_api_url
            . "?" . http_build_query($sigArr));
        return json_decode($encodedResult, true);
    }


    /**
     * Checks the signatured on this data and returns the data. TODO Error checking.
     *
     * @param array $data containing 'signed_data' and 'signature'
     * or false if the signature does not match
     * @return mixed The json_decoded, base64_decoded data or FALSE
     */
    function checkSigGetData($data)
    {
        $data_payload = $data["signed_data"];
        $sig_payload = $data["signature"];

        $sig = self::base64UrlDecode($sig_payload);
        if ($this->checkSig($sig, $data_payload)) {
            return json_decode(self::base64UrlDecode($data_payload), true);
        } else {
            return false;
        }
    }


    /**
     * Checks the signatured on this data.
     * returns true
     *
     * @param unknown $received_sig the signature that's claimed
     * @param unknown $data_payload the data payloda that should match
     * @return If the signature does not match, returns false. Otherwise
     */
    function checkSig($received_sig, $data_payload)
    {
        $expected_sig = hash_hmac('sha256', $data_payload,
            $this->_realm['realm_priv_key'], $raw = true);
        if ($received_sig !== $expected_sig) {
            return false;
        } else {
            return true;
        }
    }


    /**
     * Internal function to generate a random nonce.
     *
     * @return The random nonce
     */
    function _generateNonce()
    {
        // get 64 bits of randomness and hash it
        $data = openssl_random_pseudo_bytes(8);
        return hash('sha256', $data);
    }


    /**
     * This encodes data
     *
     * @param string $data
     * @return unknown
     */
    function _base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }


    /**
     * This decodes data
     *
     * @param string $data
     * @return unknown
     */
    function _base64UrlDecode($data)
    {
        return (base64_decode(str_pad(strtr($data, '-_', '+/'),
            strlen($data) % 4, '=   ', STR_PAD_RIGHT)));
    }


    /**
     * This checks a signature
     *
     * @param string $dangerous_signature - signature of request
     * @param string $dangerous_request - request
     * @param string $secret - secret key
     * @return unknown
     */
    function _checkSig($dangerous_signature, $dangerous_request, $secret)
    {

        $expected_sig = hash_hmac('sha256', $dangerous_request, $secret, $raw = true);

        if ($dangerous_signature == $expected_sig) {
            return true;
        } else {
            return false;
        }

    }


    /**
     * Internal function to bas64 encode this json object and sign it
     *
     * @param unknown $json_data the json object to encode and sign
     * @param unknown $secret the signing secret
     * @return A readied payload with signed_data and signature
     */
    function _encodeAndSignArr($json_data, $secret)
    {
        $encoded_data = self::base64UrlEncode($json_data);
        $sig = hash_hmac('sha256', $encoded_data, $secret, $raw = true);
        $encoded_sig = self::base64UrlEncode($sig);

        return (
        array(
            "signed_data" => $encoded_data,
            "signature" => $encoded_sig
        )
        );
    }


    /**
     * Internal function for taking in array and checking / setting values
     * prevents php warnings
     *
     * @param unknown $checkme array of key/val pairs to check
     * @param unknown $options array of vals to check against
     * @return A readied payload with signed_data and signature
     */
    function _setupSearchOptions($checkme, $options)
    {
        foreach ($options as $f) {
            if (!empty($checkme[$f])) {
                $output[$f] = $checkme[$f];
            } else {
                $output[$f] = NULL;
            }
        }
        return $output;
    }


    /**
     * encode according to rfc4648 for url-safe base64 encoding
     *
     *
     * @param string $data The data to encode
     * @return The encoded data
     */
    static function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }


    /**
     * decode according to rfc4648 for url-safe base64 encoding
     *
     *
     * @param string $data The data to decode
     * @return The decoded data
     */
    static function base64UrlDecode($data)
    {
        return (base64_decode(str_pad(strtr($data, '-_', '+/'),
            strlen($data) % 4, '=   ', STR_PAD_RIGHT)));
    }


}

// Tozny_Remote_Realm_API class