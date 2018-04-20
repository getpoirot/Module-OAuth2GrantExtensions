<?php
namespace Module\OAuth2Grants\Grants;

use Module\OAuth2\Interfaces\Model\iOAuthUser;
use Module\OAuth2\Interfaces\Model\iUserIdentifierObject;
use Module\OAuth2\Interfaces\Model\iValidation;
use Module\OAuth2\Interfaces\Model\Repo\iRepoUsers;
use Module\OAuth2\Interfaces\Model\Repo\iRepoValidationCodes;
use Module\OAuth2\Model\Entity\User\IdentifierObject;
use Module\OAuth2\Model\Entity\UserEntity;
use Module\OAuth2\Model\Entity\Validation\AuthObject;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityRefreshToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoRefreshTokens;
use Poirot\OAuth2\Model\RefreshToken;
use Poirot\OAuth2\Server\Exception\exOAuthServer;
use Poirot\OAuth2\Server\Grant\aGrant;
use Poirot\OAuth2\Server\Response\GrantResponse;
use Poirot\OAuth2\Server\Response\GrantResponseJson;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;


class GrantSingleSignExtension
    extends aGrant
{
    const TYPE_GRANT = 'onetime_code';

    /** @var iRepoValidationCodes */
    protected $repoValidationCodes;
    /** @var iRepoRefreshTokens */
    protected $repoRefreshToken;
    /** @var iRepoUsers */
    protected $repoUser;

    protected $allowRegisterOnCall = false;

    /** @var \DateInterval */
    protected $ttlAuthCode;
    /** @var \DateInterval */
    protected $ttlRefreshToken;


    /**
     * Grant identifier (client_credentials, password, ...)
     *
     * @return string
     */
    function getGrantType()
    {
        return self::TYPE_GRANT;
    }

    /**
     * Can This Grant Respond To Request
     *
     * - usually it match against "grant_type" request
     *
     * @param ServerRequestInterface $request
     *
     * @return boolean
     */
    function canRespondToRequest(ServerRequestInterface $request)
    {
        $return = false;

        if ( $this->_isAuthorizationRequest($request) || $this->_isAccessTokenRequest($request) ) {
            $return = clone $this;
            $return->request = $request;
        }

        return $return;
    }

    protected function _isAccessTokenRequest(ServerRequestInterface $request)
    {
        $requestParameters = (array) $request->getParsedBody();

        $grantType      = \Poirot\Std\emptyCoalesce(@$requestParameters['grant_type']);
        $authCode       = \Poirot\Std\emptyCoalesce(@$requestParameters['auth_code']);
        $validationCode = \Poirot\Std\emptyCoalesce(@$requestParameters['validation_code']);

        return ($grantType === $this->getGrantType() && $authCode !== null && $validationCode !== null);
    }

    protected function _isAuthorizationRequest(ServerRequestInterface $request)
    {
        $requestParameters = (array) $request->getParsedBody();

        $grantType        = \Poirot\Std\emptyCoalesce(@$requestParameters['grant_type']);
        $mobileIdentifier = \Poirot\Std\emptyCoalesce(@$requestParameters['mobile']);

        return ($grantType === $this->getGrantType() && $mobileIdentifier !== null);
    }


    /**
     * Respond To Grant Request
     *
     * note: We consider that user approved the grant
     *       when respond() called...
     *       otherwise the handle of deny is on behalf of
     *       application structure. maybe you want throw exAccessDenied
     *
     * @param ResponseInterface $response
     *
     * @return ResponseInterface prepared response
     * @throws exOAuthServer
     */
    function respond(ResponseInterface $response)
    {
        $request = $this->request;

        if ( $this->_isAuthorizationRequest($request) )
            return $this->_respondAuthorizationCode($request, $response);
        elseif ( $this->_isAccessTokenRequest($request) )
            return $this->_respondAccessToken($request, $response);
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     *
     * @return ResponseInterface prepared response
     * @throws exOAuthServer
     */
    protected function _respondAuthorizationCode(ServerRequestInterface $request, ResponseInterface $response)
    {
        $client = $this->assertClient();

        $reqParams        = $request->getParsedBody();
        $mobileIdentifier = \Poirot\Std\emptyCoalesce(@$reqParams['mobile']);
        $mobileIdentifier = IdentifierObject::newMobileIdentifier($mobileIdentifier);


        # Attain User Mobile Identifier
        #
        $firstTime = false;

        $user = $this->repoUser->findOneMatchByIdentifiers([$mobileIdentifier]);
        if (false === $user) {
            if (! $this->allowRegisterOnCall)
                throw exOAuthServer::invalidGrant('Register On Call Not Allowed!', $this->newGrantResponse());


            $firstTime = true;

            // Register Given Identifier On OAuth User`s Database
            $user  = new UserEntity;
            $user->addIdentifier($mobileIdentifier);
            $user->setMeta([
                'client' => $client->getIdentifier(),
            ]);


            $user = \Module\OAuth2\Actions\IOC::Register()->persistUser($user);
        }


        /** @var iUserIdentifierObject $mobIdentifier */
        $mobIdentifier = $user->getIdentifiers(IdentifierObject::IDENTITY_MOBILE);
        $mobIdentifier->setValidated(false); // force send validation code

        # Build Validation State
        #
        $dt = new \DateTime();
        $dt->add( $this->getTtlAuthCode() );
        $validationEntity = \Module\OAuth2\Actions\IOC::Validation()
            ->madeValidationChallenge($user, [$mobIdentifier], null, $dt);


        # Send Auth Code To Medium (mobile)
        #
        /** @var AuthObject $authCodeObject */
        foreach ($validationEntity->getAuthCodes() as $authCodeObject)
            $_ = \Module\OAuth2\Actions\IOC::Validation()
                ->sendAuthCodeByMediumType($validationEntity, $authCodeObject->getType());



        # Build Response
        #
        $resendLinks = [
            $mobIdentifier->getType() => (string) \Module\HttpFoundation\Actions::url(
                'main/oauth/recover/validate_resend'
                , [
                    'validation_code'   => $validationEntity->getValidationCode()
                    , 'identifier_type' => $mobileIdentifier->getType()
                ]
            )
        ];

        $r = [
            'user' => [
                'uid' => (string) $user->getUid(),
            ],
            'register_on_call' => $firstTime,
            'validation_code'  => $validationEntity->getValidationCode(),
            '_link' => [
                'resend_authcode' => $resendLinks,
            ],
        ];

        $grantResponse = $this->newGrantResponse();
        $grantResponse->import($r);

        $response = $grantResponse->toResponseWith($response);
        return $response;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface      $response
     *
     * @return ResponseInterface prepared response
     * @throws exOAuthServer
     */
    protected function _respondAccessToken(ServerRequestInterface $request, ResponseInterface $response)
    {
        $client = $this->assertClient(true);

        $reqParams      = (array) $request->getParsedBody();
        $authCode       = \Poirot\Std\emptyCoalesce(@$reqParams['auth_code']);
        $validationCode = \Poirot\Std\emptyCoalesce(@$reqParams['validation_code']);


        if ($authCode === null || $validationCode === null)
            throw exOAuthServer::invalidRequest('code', null, $this->newGrantResponse());


        /** @var iValidation $validationEntity */
        $validationEntity = $this->repoValidationCodes->findOneByValidationCode($validationCode);
        if (false === $validationEntity)
            // Code is Revoked!!
            throw exOAuthServer::invalidGrant('Validation code has been revoked.', $this->newGrantResponse());


        # Validate Auth Code:
        #
        $isCodeValidated = \Module\OAuth2\Actions\IOC::Validation()
            ->validateAuthCodes(
                $validationEntity
                , [
                    IdentifierObject::IDENTITY_MOBILE => $authCode
                ]
                , true
            );

        if (false == $isCodeValidated)
            // Authorization code was not issued to this client
            throw exOAuthServer::invalidRequest('code', 'Authorization code is invalid', $this->newGrantResponse());


        ## Issue and persist access + refresh tokens
        #
        list($scopeRequested, $scopes) = $this->assertScopes( $client->getScope() );

        $user = $this->repoUser->findOneByUID($validationEntity->getUserUid());
        if (!$user instanceof iOAuthUser)
            // Resource Owner Not Found!!
            throw exOAuthServer::invalidRequest('code', 'Authorization code has expired', $this->newGrantResponse());


        $accToken      = $this->issueAccessToken($client, $this->getTtlAccessToken(), $user, $scopes);
        $refToken      = $this->issueRefreshToken($accToken, $this->getTtlRefreshToken());

        $grantResponse = $this->newGrantResponse('access_token');
        $grantResponse->setAccessToken($accToken);
        $grantResponse->setRefreshToken($refToken);
        if (array_diff($scopeRequested, $scopes))
            // the issued access token scope is different from the
            // one requested by the client, include the "scope"
            // response parameter to inform the client of the
            // actual scope granted.
            $grantResponse->import(array(
                'scope' => implode(' ' /* Scope Delimiter */, $scopes),
            ));


        // Token is issued so delete it!!
        $this->repoValidationCodes->deleteByValidationCode($validationCode);

        $response = $grantResponse->toResponseWith($response);
        return $response;
    }


    /**
     * New Grant Response
     *
     * @param string|null $type
     *
     * @return GrantResponse|GrantResponseJson
     */
    function newGrantResponse($type=null)
    {
        if ( $type === 'access_token' )
            return new GrantResponseJson();

        return new GrantResponse();
    }


    /**
     * Issue Refresh Token To Access Token and Persist It
     *
     * @param iEntityAccessToken $accessToken
     * @param \DateInterval      $refreshTokenTTL
     *
     * @return iEntityRefreshToken
     */
    protected function issueRefreshToken(iEntityAccessToken $accessToken, \DateInterval $refreshTokenTTL)
    {
        // refresh token have same data as access token
        $curTime = new \DateTime();
        $token   = new RefreshToken;
        $token
            ->setAccessTokenIdentifier( $accessToken->getIdentifier() )
            ->setClientIdentifier( $accessToken->getClientIdentifier() )
            ->setScopes( $accessToken->getScopes() )
            ->setOwnerIdentifier( $accessToken->getOwnerIdentifier() )
            ->setDateTimeExpiration( $curTime->add($refreshTokenTTL) )
        ;

        $iToken = $this->repoRefreshToken->insert($token);
        return $iToken;
    }


    // Options:

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
     * Set Auth Code Time To Live
     *
     * @param \DateInterval $dateInterval
     *
     * @return $this
     */
    function setTtlAuthCode(\DateInterval $dateInterval)
    {
        $this->ttlAuthCode = $dateInterval;
        return $this;
    }

    /**
     * Get Auth Code Time To Live
     *
     * @return \DateInterval
     */
    function getTtlAuthCode()
    {
        if (! $this->ttlAuthCode )
            $this->setTtlAuthCode(new \DateInterval('PT5M'));

        return $this->ttlAuthCode;
    }

    /**
     * Set Refresh Token Time To Live
     *
     * @param \DateInterval $dateInterval
     *
     * @return $this
     */
    function setTtlRefreshToken(\DateInterval $dateInterval)
    {
        $this->ttlRefreshToken = $dateInterval;
        return $this;
    }

    /**
     * Get Refresh Token Time To Live
     *
     * @return \DateInterval
     */
    function getTtlRefreshToken()
    {
        if (! $this->ttlRefreshToken )
            $this->setTtlRefreshToken( new \DateInterval('P1M') );

        return $this->ttlRefreshToken;
    }

    function setRepoRefreshToken(iRepoRefreshTokens $repoRefreshToken)
    {
        $this->repoRefreshToken = $repoRefreshToken;
        return $this;
    }

    function setRepoUser(iRepoUsers $repoUser)
    {
        $this->repoUser = $repoUser;
        return $this;
    }

    function setRepoValidationCodes(iRepoValidationCodes $repoValidation)
    {
        $this->repoValidationCodes = $repoValidation;
        return $this;
    }
}
