<?php
namespace Coercive\Security\Session;

use Exception;

/**
 * @see \Coercive\Security\Session\Session
 */
class Connection {

	/** @var Session */
	private $_oSession = null;

	/** @var Config */
	private $_oConfig = null;

	/**
	 * Renvoie le nom de la table "protégée". Exemple : COMMON.SUPERADMIN => `COMMON`.`SUPERADMIN`
	 *
	 * @param string $sTableName
	 * @return string
	 */
	public function getProtectedTableName($sTableName) {

		/**
		 *
		 * @see Coercive PDO DBAL quoteField()
		 *
		 */

		return "`" . str_replace(".", "`.`", $sTableName) . "`";
	}

	/**
	 * Autorisation aléatoire pour la destruction de session
	 * Une chance sur 10
	 *
	 * @return bool
	 */
	private function _randomAuth() {
		return rand(1,10) === 10;
	}

	/**
	 * Vérifie la présence de session obsolette
	 *
	 * @return bool
	 */
	private function _isThereObsoleteSessions() {
		return (bool) $this->DB->getFieldValue("
			SELECT
				COUNT(`CODE`) AS 'NB'
			FROM
				`{$this->_sTableSession}`
			WHERE
				`TIME` <= '{$this->_sTime}'
		", 'NB');
	}

	/**
	 * Suppression des données périmées de la table session
	 *
	 * @return void
	 */
	private function _destroyObsoleteSessions() {
		if($this->_randomAuth() && $this->_isThereObsoleteSessions()) {
			$this->DB->execute("DELETE FROM `{$this->_sTableSession}` WHERE `TIME` <= '{$this->_sTime}'");
		}
	}

	/**
	 * Mise à jour de la session
	 *
	 * @return void
	 */
	private function _updateSession() {
		# Remise à zéro
		$this->_bIsConnected = false;

		# Si pas de session ou durée expirée
		if (empty($_SESSION['user']['time'])
			|| empty($_SESSION['user']['token'])
			|| $this->_sTime > ($_SESSION['user']['time'] + ($this->iSessionLength * 60))
		) {
			unset($_SESSION['user']);
			return;
		}

		# Token
		$sPreviousToken = $_SESSION['user']['token'];

		# Régénérer
		if ((bool) $this->DB->getFieldValue("SELECT COUNT(`CODE`) as 'COUNT' FROM `{$this->_sTableSession}` WHERE `TOKEN` = '$sPreviousToken'", 'COUNT')) {
			$this->connect($sPreviousToken);
		} else {
			// Destruction (antihack)
			unset($_SESSION['user']);
			Cookie::delete('user');
			Cookie::delete('remembre_me');
		}
	}

	/**
	 * Connexion automatique [COOKIE]
	 *
	 * Actualisation cookie / mise à jour session
	 *
	 * @return void
	 */
	private function _autoLoginByCookie() {
		# Si pas de cookie ou si déjà connecté -> skip
		if (empty($_COOKIE['user']) || $this->_bIsConnected) { return; }

		# Token en cours
		$sPreviousToken = Cookie::getSafe('user');

		# Information utilisateur de la session
		$aSessionUser = $this->DB->getRow("SELECT * FROM `{$this->_sTableSession}` WHERE `TOKEN` = '$sPreviousToken'");

		# Est-ce que ce token existe en base ?
		if (!$aSessionUser || empty($aSessionUser['TIME']) || empty($aSessionUser['LOGIN'])) { return; }

		# Token Expiré
		if ($this->_sTime > ($aSessionUser['TIME'] + ($this->iSessionLength * 60))) {
			Cookie::delete('user');
			return;
		}

		# Vérification de la correspondance des données
		// Pas de comparaison de l'IP, car peut être changeante
		// || $this->Browser->getIP() !== $aSessionUser['IP']
		if ($this->Browser->getAGENT() !== $aSessionUser['AGENT']) {
			Cookie::delete('user');
			return;
		}

		# Vérification de l'existence de l'utilisateur
		if (!$this->isGrantedUserAutoLoginByCookie($aSessionUser['LOGIN'])) {
			Cookie::delete('user');
			return;
		}

		# Connexion
		$this->connect(false, $aSessionUser['LOGIN']);
	}

	/**
	 * UPDATE USER LANGUAGE
	 *
	 * @return int
	 */
	private function _updateUserLanguage() {

		# LAST
		$sLastLang = empty($_SESSION['language']) ? null : $_SESSION['language'];
		if(!$this->getUserLogin() || $sLastLang && $sLastLang === LANGUAGE) { return null; }

		# NEW
		$_SESSION['language'] = LANGUAGE;
		return $this->app->Model->Member()->update(['LANGUAGE'=>LANGUAGE], ['EMAIL'=>$this->getUserLogin()]);
	}

	/**
	 * Auto Connexion par IP
	 */
	private function _ipAutoConnect() {

		# Une seule tentative de connexion
		if(null !== $this->getIpAutoConnect()) { return; }
		$this->setIpAutoConnect(false);

		# Récupérer l'ip actuelle
		$sIp = $this->Browser->getIP();

		# Comparer IP et BdD
		$aUserAccessGranted = $this->DB->getRow("SELECT `CODE`, `FIRST_NAME`, `LAST_NAME` FROM `USER_IP` WHERE '$sIp' RLIKE CONCAT('^', REPLACE(REPLACE(`IP`, '.', '\.'), '*', '[0-9]{3}'), '$') AND `STATUS` = 'activé'");
		if(!$aUserAccessGranted) { return; }

		# Connexion (pour les traitements en cours)
		$this->setIpAutoConnect(true);
		$this->_bIsConnected = true;

		// Nouvelle durée
		$sNewTime = $this->_sTime + $this->iSessionLength * 60;
		$_SESSION['user']['time'] = $this->_sTime;

		// Nouvel ID
		session_regenerate_id();

		// Nouveau Token
		$sNewToken = $this->Token->create('session', __FILE__);

		// Mise à jour du cookie
		Cookie::setSafe('user', $sNewToken, $sNewTime);

		// Mise à jour session
		$_SESSION['user']['login'] = "$aUserAccessGranted[FIRST_NAME] $aUserAccessGranted[LAST_NAME]";
		$_SESSION['user']['token'] = $sNewToken;

		// Mise à jour base
		$this->DB->insert($this->_sTableSession, '_ipAutoConnect', ['LOGIN'=>$_SESSION['user']['login'], 'TOKEN'=>$sNewToken, 'TIME'=>$sNewTime, 'IP'=>$this->Browser->getIP(), 'AGENT'=>$this->Browser->getAGENT()]);
	}

	/**
	 * Connection constructor.
	 *
	 * @param Session $oSession
	 * @throws Exception
	 */
	public function __construct(Session $oSession) {

		# INIT
		$this->_oSession = $oSession;
		$this->_oConfig = $oSession->Config();

		# IF DISABLED
		if(!$this->_oConfig->getConnectionState()) { return; }

		# Table
		$this->_setSessionTable();

		# Détruire les sessions obsolètes en base
		$this->_destroyObsoleteSessions();

		# Mise à jour de la session
		$this->_updateSession();

		# Connexion automatique par cookie
		$this->_autoLoginByCookie();

		# Auto connexion IP le cas échéant
		if(!$this->isConnected()) { $this->_ipAutoConnect(); }

		# Si connecté, mettre à jour la langue
		if($this->isConnected()) { $this->_updateUserLanguage(); }
	}

	/**
	 * Connecte l'utilisateur
	 *
	 * @param string      $sPreviousToken
	 * @param string|bool $sLogin
	 * @return void
	 */
	public function connect($sPreviousToken, $sLogin = false) {

		// Membre Connecté
		$this->_bIsConnected = true;

		// Nouvelle durée
		$sNewTime = $this->_sTime + $this->iSessionLength * 60;
		$_SESSION['user']['time'] = $this->_sTime;

		// Création / Mise à jour de la BDD
		if (!$sLogin) {

			# UPDATE

			// Si pas de token : log
			if (empty($sPreviousToken)) {
				$this->Error->log('Pas de token fourni pour l\'update de session');
				return;
			}

			// Mise à jour du cookie
			Cookie::setSafe('user', $sPreviousToken, $sNewTime);

			// Mise à jour base
			$this->DB->update($this->_sTableSession, null, ['TIME'=>$sNewTime], ['TOKEN'=>$sPreviousToken]);

		} else {

			# CREATE

			// Nouvel ID
			session_regenerate_id();

			// Nouveau Token
			$sNewToken = $this->Token->create('session', __FILE__);

			// Mise à jour du cookie
			Cookie::setSafe('user', $sNewToken, $sNewTime);

			// Mise à jour session
			$_SESSION['user']['login'] = $sLogin;
			$_SESSION['user']['token'] = $sNewToken;

			// Mise à jour base
			$this->DB->insert($this->_sTableSession, __METHOD__, ['LOGIN'=>$sLogin, 'TOKEN'=>$sNewToken, 'TIME'=>$sNewTime, 'IP'=>$this->Browser->getIP(), 'AGENT'=>$this->Browser->getAGENT()]);
		}
	}

	/**
	 * GETTER SESSION AUTO-CONNECT
	 *
	 * @return bool|null
	 */
	public function getIpAutoConnect() {
		return isset($_SESSION['user']['IpAutoConnect']) ? $_SESSION['user']['IpAutoConnect'] : null;
	}

	/**
	 * SETTER SESSION AUTO-CONNECT
	 *
	 * @param bool $bBool
	 * @return $this
	 */
	public function setIpAutoConnect($bBool) {
		$_SESSION['user']['IpAutoConnect'] = (bool)$bBool;
		return $this;
	}

	/**
	 * Relancer un update de la session séparément
	 */
	public function reload() {
		# Mise à jour de la session
		$this->_updateSession();
	}

	/**
	 * Déconnection
	 *
	 * @return void
	 */
	public function disconnect() {
		# Remise à zéro
		$this->_bIsConnected = false;

		// Nouvel ID
		session_regenerate_id();

		// Supprimer BDD
		$sToken = empty($_SESSION['user']['token']) ? false : filter_var($_SESSION['user']['token'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		if( !empty($sToken) ) { $this->DB->execute("DELETE FROM `{$this->_sTableSession}` WHERE `TOKEN` = '$sToken'"); }

		# Supprimer la session
		unset($_SESSION['user']);

		# Supprimer le cookie
		Cookie::delete('user');

	}

}