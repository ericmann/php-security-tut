<?php
// Application middleware

// e.g: $app->add(new \Slim\Csrf\Guard);

// Route-specific Middleware
class PasswordAuthentication {
    /**
     * @var \Slim\Container
     */
    private $container;
    public function __construct( $container ) {
        $this->container = $container;
    }

    /**
     * Checks if a given code is valid for a given key, allowing for a certain amount of time drift
     *
     * @param string $key      The share secret key to use.
     * @param string $authcode The code to test.
     *
     * @return bool Whether the code is valid within the time frame
     */
    public static function is_valid_authcode( $key, $authcode ) {
        /**
         * Ticks are the allowed offset from the correct time in 30 second increments,
         * so the default of 4 allows codes that are two minutes to either side of server time
         */
        $max_ticks = 4;

        // Array of all ticks to allow, sorted using absolute value to test closest match first.
        $ticks = range( - $max_ticks, $max_ticks );
        usort( $ticks, array('PasswordAuthentication', 'abssort') );

        $time = time() / 30;

        foreach ( $ticks as $offset ) {
            $log_time = $time + $offset;
            if ( self::calc_totp( $key, $log_time ) === $authcode ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Pack stuff
     *
     * @param string $value The value to be packed.
     *
     * @return string Binary packed string.
     */
    private static function pack64( $value ) {
        if ( version_compare( PHP_VERSION, '5.6.3', '>=' ) ) {
            return pack( 'J', $value );
        }
        $highmap = 0xffffffff << 32;
        $lowmap  = 0xffffffff;
        $higher  = ( $value & $highmap ) >> 32;
        $lower   = $value & $lowmap;
        return pack( 'NN', $higher, $lower );
    }

    /**
     * Decode a base32 string and return a binary representation
     *
     * @param string $base32_string The base 32 string to decode.
     *
     * @throws \Exception If string contains non-base32 characters.
     *
     * @return string Binary representation of decoded string
     */
    private static function base32_decode( $base32_string ) {
        $base32_string 	= strtoupper( $base32_string );

        if ( ! preg_match( '/^[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]+$/', $base32_string, $match ) ) {
            throw new \Exception( 'Invalid characters in the base32 string.' );
        }

        $l 	= strlen( $base32_string );
        $n	= 0;
        $j	= 0;
        $binary = '';

        for ( $i = 0; $i < $l; $i++ ) {

            $n = $n << 5; // Move buffer left by 5 to make room.
            $n = $n + strpos( 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', $base32_string[ $i ] ); 	// Add value into buffer.
            $j += 5; // Keep track of number of bits in buffer.

            if ( $j >= 8 ) {
                $j -= 8;
                $binary .= chr( ( $n & ( 0xFF << $j ) ) >> $j );
            }
        }

        return $binary;
    }

    /**
     * Calculate a valid code given the shared secret key
     *
     * @param string $key        The shared secret key to use for calculating code.
     * @param mixed  $step_count The time step used to calculate the code, which is the floor of time() divided by step size.
     * @param int    $digits     The number of digits in the returned code.
     * @param string $hash       The hash used to calculate the code.
     * @param int    $time_step  The size of the time step.
     *
     * @return string The totp code
     */
    private static function calc_totp( $key, $step_count = false, $digits = 6, $hash = 'sha1', $time_step = 30 ) {
        $secret =  self::base32_decode( $key );

        if ( false === $step_count ) {
            $step_count = floor( time() / $time_step );
        }

        $timestamp = self::pack64( $step_count );

        $hash = hash_hmac( $hash, $timestamp, $secret, true );

        $offset = ord( $hash[19] ) & 0xf;

        $code = (
                    ( ( ord( $hash[ $offset + 0 ] ) & 0x7f ) << 24 ) |
                    ( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 ) |
                    ( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 ) |
                    ( ord( $hash[ $offset + 3 ] ) & 0xff )
                ) % pow( 10, $digits );

        return str_pad( $code, $digits, '0', STR_PAD_LEFT );
    }

    /**
     * Used with usort to sort an array by distance from 0
     *
     * @param int $a First array element.
     * @param int $b Second array element.
     *
     * @return int -1, 0, or 1 as needed by usort
     */
    private static function abssort( $a, $b ) {
        $a = abs( $a );
        $b = abs( $b );
        if ( $a === $b ) {
            return 0;
        }
        return ($a < $b) ? -1 : 1;
    }

    /**
     * If a email/password pair are submitted, authenticate that way.
     *
     * @param \Slim\Http\Request  $request
     * @param \Slim\Http\Response $response
     * @param callable            $next
     *
     * @return \Slim\Http\Response
     */
    public function __invoke($request, $response, $next) {
        $email = $request->getParam( 'email' );
        $password = $request->getParam( 'password' );
        $token = $request->getParam('2fa');

        // If no username/password, error
        if ( empty($email) || empty($password) ) {
            return $response = $response->withRedirect('/?error=invalidlogin');
        } else {
            $user = $this->container->users->get(bin2hex($email));
            if ( $user ) {
                /**
                 * Once we have a user, we need to compare the provided password (during login) with the stored
                 * hash in the database. If they match, great! If not, move on and set a generic "invalid login"
                 * error.
                 */
                $user_data = json_decode( $user, true );
                if (password_verify($password, $user_data['password'])) {
                    // The password works! Now let's verify the token
                    if (self::is_valid_authcode($user_data['totp_key'], $token)) {
                        $_SESSION['email'] = $email;
                        return $response = $response->withRedirect('/dashboard');
                    }
                }
            }

            return $response = $response->withRedirect('/?error=invalidlogin');
        }
    }
}