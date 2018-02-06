<?php
namespace Module\OAuth2Grants\Grants;

use Poirot\Ioc\Container\Service\aServiceContainer;


class ServiceGrantSingleSignExtension
    extends aServiceContainer
{
    protected $allowRegisterOnCall = false;
    protected $ttlAuthCode;
    protected $ttlRefreshToken;
    protected $ttlAccessToken;
    protected $repoAccessToken;


    /**
     * ServiceGrantSingleSignExtension constructor.
     *
     * @param array|null|string $nameOsetter
     * @param array $setter
     */
    function __construct($nameOsetter = null, $setter = array())
    {
        parent::__construct($nameOsetter, $setter);
    }


    /**
     * Create Service
     *
     * @return mixed
     */
    function newService()
    {
        $grantType = new GrantSingleSignExtension;
        $grantType
            ->setTtlAuthCode( $this->getTtlAuthCode() )
            ->setTtlRefreshToken( $this->getTtlRefreshToken() )
            ->setTtlAccessToken( $this->getTtlAccessToken() )

            ->setRepoUser( \Module\OAuth2\Services\Repository\IOC::Users() )
            ->setRepoClient( \Module\OAuth2\Services\Repository\IOC::Clients() )
            ->setRepoAccessToken( ($this->repoAccessToken) ? $this->repoAccessToken: \Module\OAuth2\Services\Repository\IOC::AccessTokens() )
            ->setRepoRefreshToken( \Module\OAuth2\Services\Repository\IOC::RefreshTokens() )
            ->setRepoValidationCodes( \Module\OAuth2\Services\Repository\IOC::ValidationCodes() )

            ->setAllowRegisterOnCall( $this->allowRegisterOnCall )
        ;

        return $grantType;
    }


    // ..

    /**
     * Allow Register User With Given Mobile Identity If Not Exists
     *
     * @param bool $allowRegisterOnCall
     */
    function setAllowRegisterOnCall($allowRegisterOnCall)
    {
        $this->allowRegisterOnCall = (boolean) $allowRegisterOnCall;
    }

    /**
     * @param mixed $ttlAuthCode
     */
    function setTtlAuthCode($ttlAuthCode)
    {
        // new \DateInterval('PT5M')
        $this->ttlAuthCode = $ttlAuthCode;
    }

    /**
     * @param mixed $ttlRefreshToken
     */
    function setTtlRefreshToken($ttlRefreshToken)
    {
        // new \DateInterval('P1M')
        $this->ttlRefreshToken = $ttlRefreshToken;
    }

    /**
     * @param mixed $ttlAccessToken
     */
    function setTtlAccessToken($ttlAccessToken)
    {
        // new \DateInterval('PT1H')
        $this->ttlAccessToken = $ttlAccessToken;
    }

    /**
     * To Generate Different Type Of Token
     *
     * @param mixed $repoAccessToken
     */
    function setRepoAccessToken($repoAccessToken)
    {
        // \Module\OAuth2\Services\Repository\IOC::AccessTokens()
        $this->repoAccessToken = $repoAccessToken;
    }


    /**
     * @return mixed
     */
    function getTtlAuthCode()
    {
        if (! $this->ttlAuthCode )
            $this->ttlAuthCode = new \DateInterval('PT5M');

        return $this->ttlAuthCode;
    }

    /**
     * @return mixed
     */
    function getTtlRefreshToken()
    {
        if (! $this->ttlRefreshToken )
            $this->ttlRefreshToken = new \DateInterval('P1Y');


        return $this->ttlRefreshToken;
    }

    /**
     * @return mixed
     */
    function getTtlAccessToken()
    {
        if (! $this->ttlAccessToken )
            $this->ttlAccessToken = new \DateInterval('P7D');


        return $this->ttlAccessToken;
    }
}
