<?php

use PublishPress\Example\Container;

defined('ABSPATH') || exit;

return [
    'factory' => static function (Container $container) {
        return function ($id) use ($container) {
            return $id;
        };
    },
];
