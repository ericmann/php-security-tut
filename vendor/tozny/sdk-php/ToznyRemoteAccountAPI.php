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
class Tozny_Remote_Account_API
{

    /**
     *
     *
     * @access private
     * @var string
     */
    private $_account;

    private $_api_url;


    /**
     * Build this class based on the remote site's key ID.
     *
     * @param string $user_id
     * @param string $account_priv
     * @param string $in_api_url (optional)
     */
    function __construct($user_id, $account_priv, $account_realm, $in_api_url = NULL)
    {
        $this->setAccount($user_id, $account_priv, $account_realm);

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
     */
    function setAccount($user_id, $account_priv_key, $account_realm)
    {
        $this->_account['user_id'] = $user_id;
        $this->_account['priv_key'] = $account_priv_key;
        $this->_account['realm_key'] = $account_realm;
    }
    function paymentMethodsGet() {
        $args = array('method' => 'account.payment_methods_get');
        return $this->rawCall($args);
    }
    function paymentMethodGet($realm_id) {
        $args = array('method' => 'account.payment_method_get', 'realm_id' => $realm_id);
        return $this->rawCall($args);
    }
    function paymentMethodAdd($realm_id, $payment_token) {
        $args = array('method' => 'account.payment_method_add', 'realm_id' => $realm_id, 'payment_token' => $payment_token);
        return $this->rawCall($args);
    }

    function paymentMethodUpdate($realm_id, $realm_payment_method_id) {
        $args = array('method' => 'account.payment_method_update', 'realm_id' => $realm_id, 'realm_payment_method_id' => $realm_payment_method_id);
        return $this->rawCall($args);
    }

    /**
     * Get's the list of realms for this account
     *
     * @
     * @return unknown
     * */
    function realmsGet()
    {
        $args = array('method' => 'account.realms_get');

        $realms_arr = $this->rawCall($args);

        return $realms_arr;
    }

    // array('open_enrollment', 'name', 'info_url', 'login_url');
    function realmAdd($open_enrollment, $name, $info_url, $logo_url)
    {
        $args = array('method' => 'account.realm_add',
            'open_enrollment' => $open_enrollment,
            'name' => $name,
            'info_url' => $info_url,
            'logo_url' => $logo_url);

        return $this->rawCall($args);
    }


    /**
     * We have received a sign package and signature
     * lets verify it
     *
     * @param string $signed_data - who's logging in
     * @param string $signature - the signature for the payload
     * @return unknown
     */
    function verifyLogin($signed_data, $signature)
    {
        $check['signed_data'] = $signed_data;
        $check['signature'] = $signature;
        return self::checkSigGetData($check);

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

        if (empty($args['realm_key_id'])) {
            $args['realm_key_id'] = $this->_account['realm_key'];
        }
        if (empty($args['user_id'])) {
            $args['user_id'] = $this->_account['user_id'];
        }

        $sigArr = $this->_encodeAndSignArr(json_encode($args), $this->_account['priv_key']);
        $call = $this->_api_url . "?" . http_build_query($sigArr);
        $encodedResult = file_get_contents($call);
        return json_decode($encodedResult, true);
    }


    /**
     * Checks the signatured on this data and returns the data. TODO Error checking.
     *
     * @param Array   with 'signed_data' and 'signature'
     * or false if the signature does not match
     * @param unknown $data
     * @return The json_decoded, base64_decoded data
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
            $this->_account['priv_key'], $raw = true);
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

        return (array("signed_data" => $encoded_data
        , "signature" => $encoded_sig));
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

// Tozny_Remote_Account_API class