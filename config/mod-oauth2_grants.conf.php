<?php
use Module\OAuth2;
use Module\OAuth2Grants\Grants\GrantSingleSignExtension;
use Module\OAuth2Grants\Grants\ServiceGrantSingleSignExtension;

return [

    ## OAuth2 Configurations:
    #
    \Module\OAuth2\Module::CONF_KEY => [

        OAuth2\Services\ServiceGrantsContainer::CONF => [
            // Capped Container Of Available Grants
            'grants' => [
                #GrantSingleSignExtension::TYPE_GRANT => ServiceGrantSingleSignExtension::class,
            ],
        ],
    ],

];