<?php

namespace Drupal\ejabberd_auth\Controller;

use Drupal\Component\Utility\Crypt;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\Site\Settings;
use Drupal\user\UserAuthInterface;
use Drupal\user\UserInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

class AuthController extends ControllerBase {

  /**
   * The number of seconds a session-based secret is valid.
   *
   * @var int
   */
  const SESSION_TIMEOUT = 60;

  /**
   * @var \Drupal\user\UserAuthInterface
   */
  protected $auth;

  /**
   * @var \Drupal\Core\Flood\FloodInterface
   */
  protected $flood;

  /**
   * @var \Drupal\Core\Entity\EntityStorageInterface
   */
  protected $storage;

  /**
   * AuthController constructor.
   *
   * @param \Drupal\user\UserAuthInterface $auth
   * @param \Drupal\Core\Entity\EntityStorageInterface $storage
   * @param \Drupal\Core\Flood\FloodInterface $flood
   */
  public function __construct(UserAuthInterface $auth,
                              EntityStorageInterface $storage,
                              FloodInterface $flood) {
    $this->auth = $auth;
    $this->storage = $storage;
    $this->flood = $flood;
  }

  /**
   * {@inheritdoc}
   *
   * @throws \Symfony\Component\DependencyInjection\Exception\ServiceCircularReferenceException
   * @throws \Symfony\Component\DependencyInjection\Exception\ServiceNotFoundException
   * @throws \Drupal\Component\Plugin\Exception\InvalidPluginDefinitionException
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('user.auth'),
      $container->get('entity_type.manager')->getStorage('user'),
      $container->get('flood')
    );
  }

  /**
   * Process an incoming request.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   A POST request.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   {"result": true|false}
   */
  public function auth(Request $request) {
    $response['result'] = FALSE;
    try {
      $username = $request->request->get('user');
      $command = $request->request->get('command');
      switch ($command) {
        case 'isuser':
          $response['result'] = $this->isuser($username);
          break;
        case 'auth':
          $password = $request->request->get('password');
          $response['result'] = (
            $this->authenticateSession($username, $password) ||
            $this->authenticate($username, $password)
          );
          break;
        default:
          $response['error'] = "Unknown command '{$command}'.";
      }
    }
    catch (\Exception $exception) {
      $response['error'] = $exception->getMessage() ?: TRUE;
    }
    return new JsonResponse($response);
  }

  /**
   * Return a temporary hash for logging in on ejabberd.
   */
  public function session() {
    $response = [];
    if ($user = $this->storage->load(\Drupal::currentUser()->id())) {
      try {
        /** @var \Drupal\user\UserInterface $user */
        $timestamp = \Drupal::time()->getRequestTime();
        $hash = $this->getLoginHash($user, $timestamp);
        $response = [
          'user' => $user,
          'secret' => "$timestamp:$hash",
        ];
      }
      catch (\Exception $exception) {
        $response['error'] = $exception->getMessage() ?: TRUE;
      }
    }
    else {
      $response['error'] = 'Not logged in as a user.';
    }

    return new JsonResponse($response);
  }

  /**
   * Check if a given username belongs to an active account.
   *
   * @param string $username
   *   A username.
   *
   * @return bool
   *   TRUE iff an account with that name exists and is not blocked.
   */
  protected function isuser($username) {
    $user = $this->loadUser($username);
    return $user && $user->isActive();
  }

  /**
   * Attempt to use the password as a session-based secret.
   *
   * @param string $username
   *   The username to authenticate.
   * @param string $password
   *   The password, potentially matching timestamp:hash.
   *
   * @return bool
   *   TRUE iff the password is a valid session-based secret.
   *
   * @throws \RuntimeException
   */
  protected function authenticateSession($username, $password) {
    // Check if the password is a timestamp:hash.
    if (preg_match('/^(\d+):([\w-]+)$/', $password, $match)) {
      list($timestamp, $hash) = $match;

      // Verify that the secret hasn't expired or time-traveled.
      $current = \Drupal::time()->getRequestTime();
      if ($current < $timestamp || $current > $timestamp + static::SESSION_TIMEOUT) {
        return FALSE;
      }

      // Load the user and verify the hash.
      if ($user = $this->loadUser($username)) {
        return Crypt::hashEquals($this->getLoginHash($user, $timestamp), $hash);
      }
    }

    return FALSE;
  }

  /**
   * Checks if a username and password are valid.
   *
   * This request is subject to flood control.
   *
   * @param string $username
   * @param string $password
   *
   * @return bool
   *   TRUE iff the correct password was entered.
   *
   * @throws \InvalidArgumentException
   *   If the login attempt is blocked by flood control.
   */
  protected function authenticate($username, $password) {
    $user = $this->loadUser($username);
    if (!$user || !$user->hasPermission('authenticate on ejabberd with password')) {
      return FALSE;
    }

    $flood_config = $this->config('user.flood');

    // We cannot filter by IP, as the ejabberd server does not pass it on.
    // This does permit a Denial of Service attack, which we try to mitigate
    // by clearing the ejabberd flood control on a regular login.
    if (!$this->flood->isAllowed('ejabberd.failed_login_user',
      $flood_config->get('user_limit'),
      $flood_config->get('user_window'),
      $username)
    ) {
      throw new \InvalidArgumentException('Flood control was triggered.');
    }

    $result = (bool) $this->auth->authenticate($username, $password);
    if ($result) {
      $this->flood->clear('ejabberd.failed_login_user', $username);
    }
    else {
      $this->flood->register('ejabberd.failed_login_user',
        $flood_config->get('user_window'),
        $username);
    }
    return $result;
  }

  /**
   * Create an ejabberd login hash.
   *
   * @param \Drupal\user\UserInterface $user
   *   The user who may authenticate with the hash.
   * @param int $timestamp
   *   The timestamp of the hash.
   *
   * @return string
   *
   * @throws \RuntimeException
   *
   * @see user_pass_rehash().
   */
  protected function getLoginHash(UserInterface $user, $timestamp) {
    $data = implode(':', [
      // Module-specific string, to avoid leaking a hash that does anything else.
      // (For example, mirroring the exact format of user_pass_rehash() here would
      // create a token that can also be used to reset the password.)
      'ejabberd_auth',
      $timestamp,
      $user->uuid(),
    ]);

    return Crypt::hmacBase64($data, Settings::getHashSalt() . $user->getPassword());
  }

  /**
   * @param string $name
   *
   * @return \Drupal\user\UserInterface|null
   */
  protected function loadUser($name) {
    $users = $this->storage->loadByProperties(['name' => $name]);
    return reset($users);
  }

}
