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

	const DEFAULT_SSL_RANDOM_LENGTH = 128;
	const DEFAULT_KEYS_NB = 3;
	const DEFAULT_PREFIX_KEYS = 'ALIANOVNA_KEY_';

	/** @var int Number of keys / cookies required for bind and open session */
	private $nbKeys = self::DEFAULT_KEYS_NB;

	/** @var int Name (prefix) of keys / cookies required for bind and open session */
	private $prefixKeys = self::DEFAULT_PREFIX_KEYS;

	/** @var int Openssl random pseudo bytes length */
	private $randomLength = self::DEFAULT_SSL_RANDOM_LENGTH;

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

	/** @var string */
	private $secret = null;

	/** @var array */
	private $data = null;

	/**
	 * Alias encrypt
	 *
	 * @param string $text
	 * @param string $crypt
	 * @return string
	 */
	private function encrypt(string $text, string $crypt): string
	{
		try {
			return Crypt::encrypt($text, Crypt::createNewKey($crypt));
		}
		catch (Exception $e) {
			return '';
		}
	}

	/**
	 * Alias decrypt
	 *
	 * @param string $cipher
	 * @param string $crypt
	 * @return string
	 */
	private function decrypt(string $cipher, string $crypt)
	{
		try {
			return Crypt::decrypt($cipher, Crypt::createNewKey($crypt));
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
		return hash('sha512', openssl_random_pseudo_bytes($this->randomLength), false);
	}

	/**
	 * Load keys from customer cookies
	 *
	 * @return bool
	 */
	private function loadKeys(): bool
	{
		if(!$this->keys) {
			foreach (range(1, $this->nbKeys) as $k) {
				$key = $this->prefixKeys . $k;
				$registry = $this->cookie->getSafe($key);
				if($registry) {
					$this->keys[$key] = $registry;
				}
			}
			if(count($this->keys) !== $this->nbKeys) {
				$this->keys = [];
				return false;
			}
		}
		return true;
	}

	/**
	 * Create registry content
	 *
	 * @return array
	 */
	private function createRegistryData(): array
	{
		$encrypted = $this->encrypt(json_encode([
			'secret' => $this->secret,
			'session' => $this->session
		]), $this->crypt);

		$length = round(strlen($encrypted) / $this->nbKeys);
		$chunks = str_split($encrypted, $length);

		array_unshift($chunks,'');
		unset($chunks[0]);
		return $chunks;
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
		$this->secret = $this->token() . $this->crypt;
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
		$this->keys = [];
		$datas = $this->createRegistryData();
		$range = range(1, $this->nbKeys);
		$keys = array_keys($datas);
		if(count($range) !== count($keys) || array_diff($range, $keys)) {
			return false;
		}

		$status = true;
		foreach ($range as $k) {
			$key = $this->prefixKeys . $k;
			do {
				$registry = $this->token();
				$path = $this->registryDir . DIRECTORY_SEPARATOR . $registry;
				if(!file_exists($path)) {
					break;
				}
			} while(true);
			$this->keys[$key] = $registry;
			$written = $this->write($path, $datas[$k]);
			$cooked = $this->cookie->setSafe($key, $registry, time() + $this->expire);
			$status = $status && $written && $cooked;
		}
		return $status;
	}

	/**
	 * Delete all registry files and cookies
	 *
	 * @return string List of sessions token contains in registry keys
	 */
	private function deleteRegistryFiles(): string
	{
		$session = '';
		foreach (range(1, $this->nbKeys) as $k) {
			$key = $this->prefixKeys . $k;
			$registry = $this->keys[$key] ?? '';
			if(!$registry) {
				$registry = $this->cookie->getSafe($key);
			}
			$path = $this->registryDir . DIRECTORY_SEPARATOR . $registry;
			if(!$this->session && is_file($path) && $chunk = file_get_contents($path)) {
				$session .= $chunk;
			}
			if(is_file($path)) {
				unlink($path);
			}
			$this->cookie->delete($this->prefixKeys . $k);
		}
		$decrypted = $this->decrypt($session, $this->crypt);
		$data = $decrypted ? json_decode($decrypted) : null;
		return strval($data->session ?? '');
	}

	/**
	 * Delete session file
	 *
	 * @param string $session [optional]
	 * @return bool
	 */
	private function deleteSessionFile(string $session = ''): bool
	{
		if($session) {
			$path = $this->sessionDir . DIRECTORY_SEPARATOR . $session;
			if(is_file($path)) {
				unlink($path);
			}
		}
		if($this->session) {
			$path = $this->sessionDir . DIRECTORY_SEPARATOR . $this->session;
			if(is_file($path)) {
				unlink($path);
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
	 * Openssl random pseudo bytes length
	 *
	 * @param int $length [optional]
	 * @return $this
	 */
	public function randomLength(int $length = self::DEFAULT_SSL_RANDOM_LENGTH): Alianovna
	{
		if($length >= self::DEFAULT_SSL_RANDOM_LENGTH) {
			$this->randomLength = $length;
		}
		return $this;
	}

	/**
	 * Number of keys / cookies required for bind and open session
	 *
	 * @param int $nb [optional]
	 * @return $this
	 */
	public function nbKeys(int $nb = self::DEFAULT_KEYS_NB): Alianovna
	{
		if($nb >= 1) {
			$this->nbKeys = $nb;
		}
		return $this;
	}

	/**
	 * Name (prefix) of keys / cookies required for bind and open session
	 *
	 * @param string $name [optional]
	 * @return $this
	 */
	public function prefixKeys(string $name = self::DEFAULT_PREFIX_KEYS): Alianovna
	{
		if($name) {
			$this->prefixKeys = $name;
		}
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
	 * @param bool $hard [optional]
	 * @return bool
	 * @throws Exception
	 */
	public function refresh(bool $hard = false): bool
	{
		if($hard) {
			$saved = true;
			$data = $this->data;
			$this->destroy();
			$created = $this->create();
			if($data) {
				$saved = $this->save($data);
			}
			return $created && $saved;
		}
		else {
			if(!$this->session || !$this->secret) {
				return false;
			}
			$this->deleteRegistryFiles();
			return $this->createRegistyFiles();
		}
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

		if(!$this->session || !$this->secret) {
			$raw = '';
			foreach ($this->keys as $registry) {
				$path = $this->registryDir . DIRECTORY_SEPARATOR . $registry;
				if(!is_file($path) || !($chunk = file_get_contents($path))) {
					return false;
				}
				$raw .= $chunk;
			}
			if($raw && $json = $this->decrypt($raw, $this->crypt)) {
				$params = json_decode($json);
				if($session = $params->session ?? null) {
					$this->session = $session;
				}
				if($secret = $params->secret ?? null) {
					$this->secret = $secret;
				}
			}
		}

		$path = $this->sessionDir . DIRECTORY_SEPARATOR . $this->session;
		if($this->session && $this->secret && is_file($path)) {
			$raw = file_get_contents($path);
			if($raw && $serialized = $this->decrypt($raw, $this->secret)) {
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
		$this->secret = null;
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
		if(!$this->session || !$this->secret || !is_file($path)) {
			return false;
		}
		if(null !== $overwrite) {
			$this->data = $overwrite;
		}
		$serialized = serialize($this->data);
		$encrypted = $this->encrypt($serialized, $this->secret);
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
	 *
	 * @param int $rand [optional]
	 * @param int $expire [optional]
	 * @return $this
	 */
	public function offload(int $rand = 0, int $expire = null): Alianovna
	{
		if(!rand(0, abs($rand))) {
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