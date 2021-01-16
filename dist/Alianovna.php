<?php
namespace Coercive\Security\Session;

use Exception;
use Coercive\Security\Crypt\Crypt;
use Coercive\Security\Cookie\Cookie;

/**
 * Class Alianovna
 *
 * @package 	Coercive\Security\Session
 * @link		https://github.com/Coercive/Session
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   2021 Anthony Moral
 * @license 	MIT
 *
 * For the full copyright and license information,
 * please view the LICENSE file that was distributed
 * with this source code.
 */
class Alianovna
{
	const NAME = 'Alianovna';
	const TMP_PREFIX = 'tmp_alianovna_';
	const REGISTRY = 'registry';
	const SESSION = 'session';

	const SSL_RANDOM_LENGTH = 128;

	const KEYS_NB = 3;
	const KEYS_NAME = 'ALIANOVNA_KEY_';

	/** @var int Cookie duration */
	private $expire;

	/** @var string The key for encrypt content */
	private $crypt;

	/** @var string The main directory */
	private $mainDir;

	/** @var string The registry directory */
	private $registryDir;

	/** @var string The session data directory */
	private $sessionDir;

	/** @var Cookie */
	private $cookie;

	/** @var string[] */
	private $keys = [];

	/** @var string */
	private $session = null;

	/** @var array */
	private $data = null;

	/**
	 * Alias encrypt
	 *
	 * @param string $text
	 * @return string
	 */
	private function encrypt(string $text): string
	{
		try {
			return Crypt::encrypt($text, Crypt::createNewKey($this->crypt));
		}
		catch (Exception $e) {
			return '';
		}
	}

	/**
	 * Alias decrypt
	 *
	 * @param string $cipher
	 * @return string
	 */
	private function decrypt(string $cipher)
	{
		try {
			return Crypt::decrypt($cipher, Crypt::createNewKey($this->crypt));
		}
		catch (Exception $e) {
			return '';
		}
	}

	/**
	 * OpenSSL random pseudo bytes
	 *
	 * @return string
	 */
	private function token(): string
	{
		return hash('sha512', openssl_random_pseudo_bytes(self::SSL_RANDOM_LENGTH), false);
	}

	/**
	 * Load keys from customer cookkies
	 *
	 * @return bool
	 */
	private function loadKeys(): bool
	{
		if(!$this->keys) {
			foreach (range(1,self::KEYS_NB) as $k) {
				$key = self::KEYS_NAME . $k;
				$registry = $this->cookie->getSafe($key);
				if($registry) {
					$this->keys[$key] = $registry;
				}
			}
			if(count($this->keys) !== self::KEYS_NB) {
				$this->keys = [];
				return false;
			}
		}
		return true;
	}

	/**
	 * Init new session file
	 *
	 * @return bool
	 * @throws Exception
	 */
	private function createSessionFile(): bool
	{
		do {
			$session = $this->token();
			$path = $this->sessionDir . DIRECTORY_SEPARATOR . $session;
			if(!file_exists($path)) {
				break;
			}
		} while(true);
		$this->data = [];
		$this->session = $session;
		return $this->write($path, '');
	}

	/**
	 * Init new registry files
	 *
	 * @return bool
	 * @throws Exception
	 */
	private function createRegistyFiles(): bool
	{
		$status = true;
		foreach (range(1,self::KEYS_NB) as $k) {
			$key = self::KEYS_NAME . $k;
			do {
				$registry = $this->token();
				$path = $this->registryDir . DIRECTORY_SEPARATOR . $registry;
				if(!file_exists($path)) {
					break;
				}
			} while(true);
			$this->keys[$key] = $registry;
			$written = $this->write($path, $this->session);
			$cooked = $this->cookie->setSafe($key, $registry, time() + $this->expire);
			$status = $status && $written && $cooked;
		}
		return $status;
	}

	/**
	 * Delete all registry files and cookies
	 *
	 * @return array List of sessions token contains in registry keys
	 */
	private function deleteRegistryFiles(): array
	{
		$sessions = [];
		foreach (range(1,self::KEYS_NB) as $k) {
			$key = self::KEYS_NAME . $k;
			$registry = $this->keys[$key] ?? '';
			if(!$registry) {
				$registry = $this->cookie->getSafe($key);
			}
			$path = $this->registryDir . DIRECTORY_SEPARATOR . $registry;
			if(!$this->session && is_file($path) && $session = file_get_contents($path)) {
				$sessions[$session] = $session;
			}
			if(is_file($path)) {
				unlink($path);
			}
			$this->cookie->delete(self::KEYS_NAME . $k);
		}
		return $sessions;
	}

	/**
	 * Delete session file
	 *
	 * @param array $sessions [optional]
	 * @return bool
	 */
	private function deleteSessionFile(array $sessions = []): bool
	{
		if($sessions) {
			foreach ($sessions as $k) {
				$path = $this->sessionDir . DIRECTORY_SEPARATOR . $k;
				if(is_file($path)) {
					unlink($path);
				}
			}
		}

		if($this->session) {
			if(is_file($this->session)) {
				unlink($this->session);
			}
		}

		return true;
	}

	/**
	 * Remove all
	 *
	 * @param string $directory [optional]
	 * @return bool
	 */
	private function rmdir(string $directory = null): bool
	{
		if(!$directory) {
			$directory = $this->mainDir;
		}
		if (!is_dir($directory)) {
			return false;
		}
		$dir = opendir($directory);
		while (false !== ($file = readdir($dir))) {
			if ($file !== '.' && $file !== '..') {
				$path = $directory . DIRECTORY_SEPARATOR . $file;
				if (is_dir($path)) {
					$this->rmdir($path);
				}
				else {
					unlink($path);
				}
			}
		}
		closedir($dir);
		return rmdir($directory);
	}

	/**
	 * Create all directories
	 *
	 * @return bool
	 */
	private function mkdir(): bool
	{
		$directory = is_dir($this->mainDir) || mkdir($this->mainDir, 0777, true);
		$registry = is_dir($this->registryDir) || mkdir($this->registryDir, 0777, true);
		$session = is_dir($this->sessionDir) || mkdir($this->sessionDir, 0777, true);
		return $directory && $registry && $session;
	}

	/**
	 * Write to temp file first to ensure atomicity
	 *
	 * @link https://blogs.msdn.microsoft.com/adioltean/2005/12/28/how-to-do-atomic-writes-in-a-file
	 *
	 * @param string $path
	 * @param string $data
	 * @return bool
	 * @throws Exception
	 */
	private function write(string $path, string $data): bool
	{
		$tmp = tempnam(sys_get_temp_dir(), self::TMP_PREFIX);
		$bytes = file_put_contents($tmp, $data, LOCK_EX);
		if (false === $bytes) {
			throw new Exception("Can't write data in file : $tmp");
		}
		$moved = rename($tmp, $path);
		$rights = chmod($path, 0600);
		return $moved && $rights;
	}

	/**
	 * Alianovna constructor.
	 *
	 * @param string $crypt
	 * @param string $directory
	 * @param Cookie $cookie
	 * @return void
	 */
	public function __construct(string $crypt, string $directory, Cookie $cookie)
	{
		$this->crypt = $crypt;

		$this->mainDir = $directory;
		$this->registryDir = $directory . DIRECTORY_SEPARATOR . self::REGISTRY;
		$this->sessionDir = $directory . DIRECTORY_SEPARATOR . self::SESSION;

		$this->cookie = $cookie;

		$this->expire = 365 * 24 * 60 * 60;
	}

	/**
	 * Cookie max lifetime
	 *
	 * @param int $seconds
	 * @return $this
	 */
	public function expire(int $seconds): Alianovna
	{
		$this->expire = $seconds;
		return $this;
	}

	/**
	 * Generate customer session
	 *
	 * @return bool
	 * @throws Exception
	 */
	public function create(): bool
	{
		if(!$this->createSessionFile()) {
			return false;
		}
		if(!$this->createRegistyFiles()) {
			return false;
		}
		return true;
	}

	/**
	 * Refresh registry tokens
	 *
	 * @return bool
	 * @throws Exception
	 */
	public function refresh(): bool
	{
		if(!$this->loadKeys() || !$this->session) {
			$this->destroy();
			return false;
		}

		$this->deleteRegistryFiles();
		if(!$this->createRegistyFiles()) {
			return false;
		}

		return true;
	}

	/**
	 * Try to load an existing session
	 *
	 * @return bool
	 */
	public function read(): bool
	{
		$this->data = null;

		if(!$this->loadKeys()) {
			return false;
		}

		if(!$this->session) {
			$file = null;
			foreach ($this->keys as $registry) {
				$path = $this->registryDir . DIRECTORY_SEPARATOR . $registry;
				if(!is_file($path)) {
					return false;
				}
				$session = file_get_contents($path);
				if(!$session) {
					return false;
				}
				elseif(null === $file) {
					$file = $session;
				}
				elseif($file !== $session) {
					return false;
				}
			}
			$this->session = $file;
		}

		$path = $this->sessionDir . DIRECTORY_SEPARATOR . $this->session;
		if($this->session && is_file($path)) {
			$raw = file_get_contents($path);
			if($raw && $serialized = $this->decrypt($raw)) {
				$this->data = unserialize($serialized);
			}
			elseif(null === $raw) {
				return false;
			}
			elseif(!$raw) {
				$this->data = [];
			}
		}
		else {
			return false;
		}

		return true;
	}

	/**
	 * Destroy an existing customer session
	 *
	 * @return $this
	 */
	public function destroy(): Alianovna
	{
		$sessions = $this->deleteRegistryFiles();
		$this->deleteSessionFile($sessions);

		$this->keys = [];
		$this->session = null;
		$this->data = null;
		return $this;
	}

	/**
	 * Save data in current session.
	 *
	 * @param array $overwrite []
	 * @return bool
	 * @throws Exception
	 */
	public function save(array $overwrite = null): bool
	{
		$path = $this->sessionDir . DIRECTORY_SEPARATOR . $this->session;
		if(!$this->session || !is_file($path)) {
			return false;
		}
		if(null !== $overwrite) {
			$this->data = $overwrite;
		}
		$serialized = serialize($this->data);
		$encrypted = $this->encrypt($serialized);
		return $this->write($path, $encrypted);
	}

	/**
	 * Expose current session data.
	 *
	 * @param array $overwrite [optional]
	 * @return array
	 */
	public function data(array $overwrite = null): array
	{
		if(null !== $overwrite) {
			$this->data = $overwrite;
		}
		return $this->data ?: [];
	}

	/**
	 * Entry exist in session data
	 *
	 * @param string $key
	 * @return bool
	 */
	public function exist(string $key): bool
	{
		return array_key_exists($key, $this->data);
	}

	/**
	 * Return the targeted entry
	 *
	 * @param string $key
	 * @return mixed|null
	 */
	public function get(string $key)
	{
		return $this->data[$key] ?? null;
	}

	/**
	 * Set the targeted entry
	 *
	 * @param string $key
	 * @param mixed|null $value [optional]
	 * @return $this
	 */
	public function set(string $key, $value = null): Alianovna
	{
		$this->data[$key] = $value;
		return $this;
	}

	/**
	 * Offload expired sessions.
	 * (one chance in 100)
	 *
	 * @param int $expire [optional]
	 * @return $this
	 */
	public function offload(int $expire = null): Alianovna
	{
		if(!rand(0,99)) {
			$now = time();
			if(null === $expire) {
				$expire = $this->expire;
			}

			$registries = glob($this->registryDir . '/{,.}*', GLOB_BRACE) ?: [];
			$sessions = glob($this->sessionDir . '/{,.}*', GLOB_BRACE) ?: [];
			$files = array_merge($registries, $sessions);

			foreach($files as $file) {
				if(false === strpos($file, '.') && is_file($file)) {
					if ($now - filemtime($file) >= $expire) {
						unlink($file);
					}
				}
			}
		}
		return $this;
	}

	/**
	 * Init new empty registry and sessions.
	 *
	 * @return bool
	 */
	public function kill(): bool
	{
		$this->destroy();
		$rmdir = $this->rmdir();
		$mkdir = $this->mkdir();
		return $rmdir && $mkdir;
	}
}