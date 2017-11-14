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

        // If no username/password, error
        if ( empty($email) || empty($password) ) {
            return $response = $response->withRedirect('/?error=invalidlogin');
        } else {
            $user = $this->container->users->get(bin2hex($email));
            var_dump($user);
            if ( $user ) {
                /**
                 * Once we have a user, we need to compare the provided password (during login) with the stored
                 * hash in the database. If they match, great! If not, move on and set a generic "invalid login"
                 * error.
                 */
                $user_data = json_decode( $user, true );
                if (password_verify($password, $user_data['password'])) {
                    $_SESSION['email'] = $email;
                    return $response = $response->withRedirect('/dashboard');
                }
            }

            return $response = $response->withRedirect('/?error=invalidlogin');
        }
        return $response;
    }
}