<?php
// DIC configuration

$container = $app->getContainer();

/**
 * Use a flat-file database housed in /data/users.dat to store user information.
 *
 * @return \Flintstone\Flintstone
 */
$container['users'] = function ($c) {
    return new Flintstone\Flintstone('users', array('dir' => __DIR__ . '/../data'));
};

// view renderer
$container['renderer'] = function ($c) {
    $settings = $c->get('settings')['renderer'];
    return new Slim\Views\PhpRenderer($settings['template_path']);
};

// monolog
$container['logger'] = function ($c) {
    $settings = $c->get('settings')['logger'];
    $logger = new Monolog\Logger($settings['name']);
    $logger->pushProcessor(new Monolog\Processor\UidProcessor());
    $logger->pushHandler(new Monolog\Handler\StreamHandler($settings['path'], $settings['level']));
    return $logger;
};
