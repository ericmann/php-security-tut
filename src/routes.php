<?php

use Slim\Http\Request;
use Slim\Http\Response;

// Routes

$app->get('/', function (Request $request, Response $response, array $args) {
    $error = $request->getQueryParam( 'error' );
    if ( ! empty( $this->errors[ $error ] ) ) {
        $args['error'] = $this->errors[ $error ];
        $this->logger->error($args['error']);
    }
    $message = $request->getQueryParam( 'message' );
    if ( ! empty( $this->messages[ $message ] ) ) {
        $args['message'] = $this->messages[ $message ];
    }

    // Render index view
    return $this->renderer->render($response, 'index.phtml', $args);
});

$app->get('/register', function($request, $response, $args) {
    $error = $request->getQueryParam( 'error' );
    if ( ! empty( $this->errors[ $error ] ) ) {
        $args[ 'error' ] = $this->errors[ $error ];
        $this->logger->error($args['error']);
    }

    // Render registration view
    return $this->renderer->render($response, 'register.phtml', $args);
});

$app->post('/register', function($request, $response, $args) {
    $fname = $request->getParam('fname');
    $lname = $request->getParam('lname');
    $email = $request->getParam('email');
    $password = $request->getParam('password');
    $cpassword = $request->getParam('password_confirm');

    if ( empty( $email ) || ! filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $this->logger->error('Empty or invalid email address');
        return $response->withRedirect('/register?error=emptyemail');
    }
    if ( $this->users->get( base64_encode($email) ) ) {
        $this->logger->error(sprintf('Duplicate email %s', $email));
        return $response->withRedirect('/register?error=useduser');
    }
    if (! hash_equals($password, $cpassword) ) {
        return $response->withRedirect('/register?error=nomatch');
    }
    $user = [
        'email'     => $email,
        'firstName' => $fname,
        'lastName'  => $lname,
        'password'  => '' // @TODO What should be stored here?
    ];
    $this->users->set(base64_encode($email), json_encode( $user ) );
    $_SESSION['email'] = $email;
    return $response->withRedirect('/dashboard');
});