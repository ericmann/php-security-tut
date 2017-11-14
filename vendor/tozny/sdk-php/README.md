sdk-php
=======

PHP client bindings to the TOZNY API

Can be installed with composer:

```
{
    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/tozny/sdk-php"
        }
    ],
    "require": {
        "tozny/sdk-php": "*"
    }
}
```

We'll be in packagist at some point.


Packaging (via Docker)
======================
Building a ubuntu/debian .deb package can be done using the included Dockerfile & Makefile
```
make package
```
