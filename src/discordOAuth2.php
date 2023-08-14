<?php

namespace hmcswModule\discordOAuth2\src;
use hmcsw\exception\ApiErrorException;
use hmcsw\objects\user\User;
use hmcsw\service\config\ConfigService;
use hmcsw\service\module\ModuleLoginMethodRepository;
use RestCord\DiscordClient;

class discordOAuth2 implements ModuleLoginMethodRepository
{
  private array $config;
  private readonly string $uri;
  private readonly string $public;
  private readonly string $secret;
  private readonly string $scope;
  private readonly string $resourceURL;
  private readonly string $tokenURL;

  public function __construct ()
  {
    $this->config = json_decode(file_get_contents(__DIR__.'/../config/config.json'), true);

    $this->tokenURL = "https://discordapp.com/api/oauth2/token";
    $this->resourceURL = "https://discordapp.com/api/users/@me";
    $this->uri = ConfigService::getWebUrl() . "/auth/r/".$this->getModuleInfo()['identifier'];
    $this->public = $this->config['public'];
    $this->secret = $this->config['secret'];
    $this->scope = "identify email";
  }

  public function startModule(): bool
  {
    if($this->config['enabled']){
      return true;
    } else {
      return false;
    }
  }


  public function getShortName(): string
  {
    return $this->config['shortName'];
  }

  public function getConfig(): array
  {
    return $this->config;
  }

  public function getModuleInfo(): array
  {
    return json_decode(file_get_contents(__DIR__.'/../module.json'), true);
  }

  public function initial(): void {}

  public function getDiscord(): DiscordClient
  {
    return new DiscordClient(['token' => $this->config['bot_token'], "throwOnRatelimit" => true]);
  }

  public function onConnect(User $user, $externalId): void
  {
    try {
      $this->getDiscord()->guild->addGuildMemberRole(['guild.id' => (int)$this->config['guild_id'], 'user.id' => (int)$externalId, 'role.id' => (int)$this->config['customer_role']]);
    } catch (\Exception $e) {
      
    }
  }

  public function onDisconnect(User $user, $externalId): void
  { 
    try {
      $this->getDiscord()->guild->removeGuildMemberRole(['guild.id' => $this->config['guild_id'], 'user.id' => (int)$externalId, 'role.id' => (int)$this->config['customer_role']]);
    } catch (\Exception $e) {

    }
  }

  public function getAuthURL(string $state): string
  {
    return "https://discordapp.com/oauth2/authorize?response_type=code&client_id=" . $this->public . "&state=".$state."&scope=" . rawurlencode($this->scope) . "&redirect_uri=" . $this->uri;
  }

  public function authorize(string $code): array
  {
    $token = curl_init();
    curl_setopt_array($token, [
      CURLOPT_URL => $this->tokenURL,
      CURLOPT_POST => 1,
      CURLOPT_POSTFIELDS => [
        "grant_type" => "authorization_code",
        "client_id" => $this->public,
        "client_secret" => $this->secret,
        "redirect_uri" => $this->uri,
        "code" => $code
      ]
    ]);
    curl_setopt($token, CURLOPT_RETURNTRANSFER, true);
    $resp = json_decode(curl_exec($token), true);
    curl_close($token);

    if (isset($resp['message'])) {
      throw new ApiErrorException($resp['message'], $resp['code']);
    }

    $scopes = explode(" ", $resp['scope']);
    $needScopes = explode(" ", $this->scope);

    foreach($needScopes as $scope){
      if(!in_array($scope, $needScopes)){
        throw new ApiErrorException("scope wrong", 400, ["give" => $resp['scope'], "need" => $this->scope]);
      }
    }

    $access_token = $resp['access_token'];

    $info = curl_init();
    curl_setopt_array($info, [CURLOPT_URL => $this->resourceURL, CURLOPT_CUSTOMREQUEST => "GET", CURLOPT_HTTPHEADER => ["Authorization: Bearer " . $access_token, "cache-control: no-cache"]]);
    curl_setopt($info, CURLOPT_RETURNTRANSFER, true);

    $info_resp = json_decode(curl_exec($info), true);

    if (isset($info_resp['message'])) {
      throw new ApiErrorException($info_resp['message'], $info_resp['code']);
    }

    return [
      "token" => [],
      "data" => [
        "user_id" => $info_resp['id'],
        "email" => $info_resp['email'],
        "username" => $info_resp['username'],
        "icon" => 'https://cdn.discord.com/avatars/'. $info_resp['id']. '/'. $info_resp['avatar'] .'.png'

      ]
    ];

  }

  public function getMessages (string $lang): array|bool
  {
    if(!file_exists(__DIR__.'/../messages/'.$lang.'.json')){
      return false;
    }

    return json_decode(file_get_contents(__DIR__.'/../messages/'.$lang.'.json'), true);
  }

  public function getProperties (): array
  {
    return [];
  }
}