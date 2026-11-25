<?php

/* This file is part of Jeedom.
*
* Jeedom is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* Jeedom is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with Jeedom. If not, see <http://www.gnu.org/licenses/>.
*/

/* * ***************************Includes**********************************/
require_once dirname(__FILE__) . '/../../../../core/php/core.inc.php';

class AdGuard extends eqLogic {
	private static $_lastError = [];
	private static $_lastHttpCode = [];
	/***************************Attributs*******************************/	
	public static function serviceList() {
		$serviceList=self::getServicesList();
		if($serviceList !== null) { return $serviceList; }
		return [
			"9gag"=>"9Gag", 
			"amazon"=>"Amazon",
			"bilibili"=>"Bilibili",
			"cloudflare"=>"CloudFlare", 
			"dailymotion"=>"Dailymotion", 
			"discord"=>"Discord", 
			"disneyplus"=>"Disney+", 
			"ebay"=>"EBay", 
			"epic_games"=>"Epic Games", 
			"facebook"=>"Facebook", 
			"hulu"=>"Hulu", 
			"imgur"=>"Imgur", 
			"instagram"=>"Instagram", 
			"mail_ru"=>"Mail.ru", 
			"netflix"=>"Netflix", 
			"ok"=>"OK.ru", 
			"origin"=>"Origin", 
			"pinterest"=>"Pinterest", 
			"qq"=>"QQ", 
			"reddit"=>"Reddit", 
			"skype"=>"Skype", 
			"snapchat"=>"Snapchat", 
			"spotify"=>"Spotify", 
			"steam"=>"Steam", 
			"telegram"=>"Telegram", 
			"tiktok"=>"TikTok", 
			"tinder"=>"Tinder", 
			"twitch"=>"Twitch", 
			"twitter"=>"Twitter", 
			"viber"=>"Viber", 
			"vimeo"=>"Vimeo", 
			"vk"=>"VK.com", 
			"wechat"=>"WeChat", 
			"weibo"=>"Weibo", 
			"whatsapp"=>"WhatsApp", 
			"youtube"=>"YouTube"
		];
	}
	public static function serviceGroupList() {
		// groupes de services d'AdGuard Home (>= v0.107.68), voir blocked_services/all
		return [
			"ai"=>__("Intelligence artificielle", __FILE__),
			"cdn"=>__("CDN", __FILE__),
			"dating"=>__("Rencontres", __FILE__),
			"gambling"=>__("Jeux d'argent", __FILE__),
			"gaming"=>__("Jeux vidéo", __FILE__),
			"hosting"=>__("Hébergement", __FILE__),
			"messenger"=>__("Messageries", __FILE__),
			"privacy"=>__("Vie privée", __FILE__),
			"shopping"=>__("Achats en ligne", __FILE__),
			"social_network"=>__("Réseaux sociaux", __FILE__),
			"software"=>__("Logiciels", __FILE__),
			"streaming"=>__("Streaming", __FILE__)
		];
	}
	public static function getConfigForCommunity()
	{
		$update=update::byTypeAndLogicalId('plugin',__CLASS__);
		$ver=$update->getLocalVersion();
		$conf=$update->getConfiguration();
		$CommunityInfo="```\n== Jeedom ".jeedom::version()." sur ".trim(shell_exec("lsb_release -d -s")).'/'.trim(shell_exec('dpkg --print-architecture')).'/'.trim(shell_exec('arch')).'/'.trim(shell_exec('getconf LONG_BIT'))."bits aka '".jeedom::getHardwareName()."' ".__CLASS__." (".$conf['version'].") ".$ver." (avant:".config::byKey('previousVersion',__CLASS__,'inconnu',true).")\n```";
		return $CommunityInfo;
	}
	public static function setServicesList($services) {
		// get existing services to compare with the new list, if different, update all eqLogics 
		$preServices=self::serviceList();
		$ret=false;
		if($services && is_array($services) && count($services) && count($preServices) != count($services)) {
			log::add('AdGuard', 'info', __('Des nouveaux services ont été ajoutés à AdGuard, mise à jour du cache des services et des commandes', __FILE__).'('.(count($services)-count($preServices)).')');
			exec(system::getCmdSudo() . 'chown -R www-data:www-data ' . dirname(__FILE__) . '/../../data/');
			exec(system::getCmdSudo() . 'chmod -R 775 ' . dirname(__FILE__) . '/../../data/');
			$ret = file_put_contents(dirname(__FILE__) . '/../../data/services.json', json_encode($services, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
			
			foreach (eqLogic::byType('AdGuard') as $AdGuard) {
				$AdGuard->save();
			}
		}
		
		return (($ret === false) ? false : true);
	}

	public static function getServicesList() {
		exec(system::getCmdSudo() . 'chown -R www-data:www-data ' . dirname(__FILE__) . '/../../data/');
		exec(system::getCmdSudo() . 'chmod -R 775 ' . dirname(__FILE__) . '/../../data/');
		exec('touch ' . dirname(__FILE__) . '/../../data/services.json');
		exec(system::getCmdSudo() . 'chown -R www-data:www-data ' . dirname(__FILE__) . '/../../data/');
		exec(system::getCmdSudo() . 'chmod -R 775 ' . dirname(__FILE__) . '/../../data/');
		
		return json_decode(file_get_contents(dirname(__FILE__) . '/../../data/services.json') , true);
	}
	
	public static function cron($_eqlogic_id = null) {
		$eqLogics = ($_eqlogic_id !== null) ? array(eqLogic::byId($_eqlogic_id)) : eqLogic::byType('AdGuard', true);
		foreach ($eqLogics as $AdGuard) {
			if($AdGuard->getConfiguration('type','AdGuardGlobal') != 'AdGuardGlobal') continue;
			$autorefresh = $AdGuard->getConfiguration('autorefresh','*/5 * * * *');
			if ($autorefresh != '') {
				try {
					$c = new Cron\CronExpression(checkAndFixCron($autorefresh), new Cron\FieldFactory);
					if ($c->isDue()) {
						$AdGuard->getAdGuardInfo(true);
					}
				} catch (Exception $exc) {
					log::add('AdGuard', 'error', __('Expression cron non valide pour ', __FILE__) . $AdGuard->getHumanName() . ' : ' . $autorefresh);
				}
			}
		}
	}	
	public static function cronDaily() {
		foreach (eqLogic::byType('AdGuard') as $AdGuard) {
			if($AdGuard->getConfiguration('type','') == 'AdGuardGlobal') $AdGuard->save();
		}
	}
	public static function nameExists($name,$objectId=null) {
		$allAdGuard = eqLogic::byObjectId($objectId,false);
		foreach ($allAdGuard as $u) {
			if ($name == $u->getName()) return true;
		}
		return false;
	}
	public static function createEq($eq,$event=true) {
		$eqp = eqLogic::byLogicalId($eq['logicalId'],'AdGuard');
		if (!is_object($eqp)){
			if($eq['name']) {
				if(AdGuard::nameExists($eq['name'],$eq['object_id'])) {
					$name=$eq['name'];
					$eq['name']=$eq['name'].'_'.$eq['serverName'];
					log::add('AdGuard', 'debug', "Nom en double " . $name . " renommé en " . $eq['name']);
				}
				log::add('AdGuard', 'info', 'Création de l\'équipement ' . $eq['name'] .'('. $eq['logicalId'] . ')');
				$eqp = new AdGuard();
				$eqp->setEqType_name('AdGuard');
				if($eq['object_id']) $eqp->setObject_id($eq['object_id']);
				$eqp->setLogicalId($eq['logicalId']);
				$eqp->setName($eq['name']);
				foreach($eq['configuration'] as $c => $v) {
					$eqp->setConfiguration($c, $v);
				}
				$eqp->setConfiguration('toRemove',0);
				$eqp->setIsEnable($eq['enable']);
				$eqp->setIsVisible($eq['visible']);
				$eqp->save(false);
				if($event) event::add('AdGuard::includeDevice');
			} else {
				log::add('AdGuard', 'warning', 'Etrange l\'équipement ' . $eq['name'] .'('. $eq['logicalId'] . ') n\'a pas de nom... vérifiez dans AdGuard : '.json_encode($eq));
			}
		} else {
			if($eq['name']) {
				log::add('AdGuard', 'debug', 'Modification de l\'équipement ' . $eq['name'] .'('. $eq['logicalId'] . ')');	
				foreach($eq['configuration'] as $c => $v) {
					$eqp->setConfiguration($c, $v);
				}
				$eqp->setConfiguration('toRemove',0);
				$eqp->save(true);
			} else {
				log::add('AdGuard', 'warning', 'Etrange l\'équipement ' . $eq['name'] .'('. $eq['logicalId'] . ') n\'a pas de nom... vérifiez dans AdGuard : '.json_encode($eq));
			}
		}
		return $eqp;
	}
	
	public static function getStructure($name) {
	
		switch($name) {
			case "stats" :
				return ["num_dns_queries"=>"Requêtes DNS",
						"num_blocked_filtering"=>"Bloqués par Filtres",
						"num_replaced_safebrowsing"=>"Tentatives de malware-hameçonnage bloquées",
						"num_replaced_parental"=>"Sites à contenu adulte bloqués",						
						"num_replaced_safesearch"=>"Recherches sécurisées forcées",
						"avg_processing_time"=>"Temps moyen de traitement"
					];
			break;
		}		
	}
	
	public static function devicesParameters($type = '') {
		$path = dirname(__FILE__) . '/../config/devices/' . $type;
		if (!is_dir($path)) {
			return false;
		}
		try {
			$file = $path . '/' . $type.'.json';
			$content = file_get_contents($file);
			if($content) {
				$content=translate::exec($content,realpath($file));
			}
			$return = json_decode($content, true);
		} catch (Exception $e) {
			return false;
		}
		
        	return $return;
    	}
	
	// Encrypt in DB
	public function decrypt() {
		$this->setConfiguration('ip', utils::decrypt($this->getConfiguration('ip')));
		$this->setConfiguration('user', utils::decrypt($this->getConfiguration('user')));
		$this->setConfiguration('password', utils::decrypt($this->getConfiguration('password')));
	}
	public function encrypt() {
		$this->setConfiguration('ip', utils::encrypt($this->getConfiguration('ip')));
		$this->setConfiguration('user', utils::encrypt($this->getConfiguration('user')));
		$this->setConfiguration('password', utils::encrypt($this->getConfiguration('password')));
	}
	
	public function postAdGuard($cmd,$params,$type="POST",$_quiet404=false) {
		$proto=$this->getConfiguration('proto','http');
		$ip = $this->getConfiguration('ip','');
		
		$url = $proto.'://' . $ip . '/control/'.$cmd;
		
		$user = $this->getConfiguration('user','');
		$pass = $this->getConfiguration('password','');

		$this->setAdGuardLastError(null);
		self::$_lastHttpCode[$this->getId()] = 0;
		if(!$ip || !$user || !$pass) {
			$this->setAdGuardLastError(__('Configuration incomplète : adresse IP, utilisateur ou mot de passe manquant', __FILE__));
			return false;
		}

		//$request_http = new com_http($url,$user,$pass);
		
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_HEADER, false);
		curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
		
		//$request_http->setNoSslCheck(true);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
		
		
		$params=((is_array($params))?json_encode($params):$params);
		if($params==null) {
			$header=array(
				'Accept: application/json, text/plain, */*'
			);
		} else {
			$header=array(
				'Content-Type: application/json',
				'Accept: application/json, text/plain, */*'
			);	
		}
		curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_TIMEOUT, 10);
		curl_setopt($ch, CURLOPT_FORBID_REUSE, true);
		curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
		curl_setopt($ch, CURLOPT_USERPWD, $user . ':' . $pass);
		//$request_http->setCURLOPT_HTTPAUTH(CURLAUTH_BASIC);
		curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
		
		//$params=(($params==null)?[]:$params);
		//$request_http->setPost($params);
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $type); // type=POST by default
		if($params!=null) {
			curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
		}
				
		$AdGuardinfo = '';
		$http_code = 0;
		try {
			log::add('AdGuard','info','Exécution commande '.$cmd);
			log::add('AdGuard','debug','Exécution commande '.$cmd.' avec params '.json_encode($params));
			//$AdGuardinfo=$request_http->exec(10,1);
			$result = curl_exec($ch);
			// En PHP 8, $ch est un objet CurlHandle (plus une ressource) : on lit l'erreur sans tester is_resource()
			$curl_errno = curl_errno($ch);
			$curl_error = curl_error($ch);
			$http_code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
			$ch = null; // libère le handle (curl_close est sans effet depuis PHP 8)
			if ($result === false || $curl_errno) {
				throw new Exception(__('Echec de la requête HTTP :', __FILE__) . ' ' . $url . ' cURL error : ' . $curl_error, 404);
			}
			self::$_lastHttpCode[$this->getId()] = $http_code;
			$AdGuardinfo = (string) $result;
			if($AdGuardinfo) log::add('AdGuard','debug',"Retour brut : ".$AdGuardinfo);
		} catch (Exception $e) {
			log::add('AdGuard','error',"Impossible de communiquer POST avec le serveur AdGuard $ip $cmd ! Message : ".$e->getMessage());
			$this->setAdGuardLastError(__('AdGuard Home ne répond pas', __FILE__) . ' (' . $e->getMessage() . ')');
			$online = $this->getCmd(null, 'online');
			if (is_object($online)) {
				$this->checkAndUpdateCmd($online, '0');
			}
			return null;
		}

		if(trim($AdGuardinfo) == "Forbidden" || $http_code == 401 || $http_code == 403) {
			log::add('AdGuard','error',"Impossible de communiquer POST avec le serveur AdGuard $ip $cmd, vérifiez vos crédentials ! Message : ".$AdGuardinfo);
			$this->setAdGuardLastError(__('AdGuard Home refuse la connexion, vérifiez l\'utilisateur et le mot de passe', __FILE__));
			$online = $this->getCmd(null, 'online');
			if (is_object($online)) {
				$this->checkAndUpdateCmd($online, '0');
			}
		} elseif(trim($AdGuardinfo) == "404 page not found" || $http_code == 404) {
			if (trim($AdGuardinfo) == "404 page not found") self::$_lastHttpCode[$this->getId()] = 404;
			log::add('AdGuard',(($_quiet404) ? 'debug' : 'error'),"Impossible de communiquer POST avec le serveur AdGuard $ip $cmd, la commande n'existe pas ! Message : ".$AdGuardinfo);
			$this->setAdGuardLastError(__('Cette commande n\'existe pas sur votre version d\'AdGuard Home', __FILE__) . ' (' . $cmd . ')');
		} elseif($http_code >= 400) {
			log::add('AdGuard',(($_quiet404 && $http_code == 405) ? 'debug' : 'error'),"Le serveur AdGuard $ip a refusé la commande $cmd (HTTP $http_code) ! Message : ".$AdGuardinfo);
			$this->setAdGuardLastError(__('AdGuard Home a refusé la commande', __FILE__) . ' (HTTP ' . $http_code . ')' . ((trim($AdGuardinfo) != '') ? ' : ' . trim($AdGuardinfo) : ''));
		}

		return json_decode($AdGuardinfo,true);
	}

	public function getAdGuardLastError() {
		return isset(self::$_lastError[$this->getId()]) ? self::$_lastError[$this->getId()] : null;
	}

	public function setAdGuardLastError($_error) {
		self::$_lastError[$this->getId()] = $_error;
	}

	public function getAdGuardLastHttpCode() {
		return isset(self::$_lastHttpCode[$this->getId()]) ? self::$_lastHttpCode[$this->getId()] : 0;
	}
	
	public function putAdGuard($cmd,$params) {
		$this->postAdGuard($cmd,$params,"PUT");	
	}
	
	public function getAdGuard($cmd,$params=null) {
		$proto=$this->getConfiguration('proto','http');
		$ip = $this->getConfiguration('ip','');
		
		$url = $proto.'://' . $ip . '/control/'.$cmd;
		$url.=(($params && count($params))?"?".http_build_query($params):'');
		
		$user = $this->getConfiguration('user','');
		$pass = $this->getConfiguration('password','');
		
		$this->setAdGuardLastError(null);
		if(!$ip || !$user || !$pass) {
			$this->setAdGuardLastError(__('Configuration incomplète : adresse IP, utilisateur ou mot de passe manquant', __FILE__));
			return false;
		}

		$request_http = new com_http($url,$user,$pass);
		$request_http->setNoSslCheck(true);
		$request_http->setCURLOPT_HTTPAUTH(CURLAUTH_BASIC);
		$request_http->setHeader(array(
			'Content-Type: application/json',
			'Accept: application/json, text/plain, */*'
		));
		$AdGuardinfo='';
		try {		
			$AdGuardinfo=$request_http->exec(10,1);
		} catch (Exception $e) {
			$this->setAdGuardLastError(__('AdGuard Home ne répond pas', __FILE__) . ' (' . $e->getMessage() . ')');
			if($cmd != 'version.json') {
				log::add('AdGuard','error',"Impossible de communiquer GET avec le serveur AdGuard $ip $cmd ! Message : ".$e->getMessage());
				$online = $this->getCmd(null, 'online');
				if (is_object($online)) {
					$this->checkAndUpdateCmd($online, '0');
				}
			}
		}
		if(trim($AdGuardinfo) == "Forbidden") {
			log::add('AdGuard','error',"Impossible de communiquer GET avec le serveur AdGuard $ip $cmd, vérifiez vos crédentials ! Message : ".$AdGuardinfo);
			$this->setAdGuardLastError(__('AdGuard Home refuse la connexion, vérifiez l\'utilisateur et le mot de passe', __FILE__));
			$online = $this->getCmd(null, 'online');
			if (is_object($online)) {
				$this->checkAndUpdateCmd($online, '0');
			}
		}
		if(trim($AdGuardinfo) == "404 page not found") {
			log::add('AdGuard','error',"Impossible de communiquer GET avec le serveur AdGuard $ip $cmd, la commande n'existe pas ! Message : ".$AdGuardinfo);
			$this->setAdGuardLastError(__('Cette commande n\'existe pas sur votre version d\'AdGuard Home', __FILE__) . ' (' . $cmd . ')');
		}
		
		return json_decode($AdGuardinfo,true);
	}
	
	public function getAdGuardStatut() {
		$AdGuardinfo=$this->getAdGuard('status');
		if(!$AdGuardinfo) return false;
		$AdGuardinfo['safebrowsing']=$this->getAdGuard('safebrowsing/status');
		$AdGuardinfo['parental']=$this->getAdGuard('parental/status');
		$AdGuardinfo['safesearch']=$this->getAdGuard('safesearch/status');
		$AdGuardinfo['filtering']=$this->getAdGuard('filtering/status');
		$AdGuardinfo['filtering']['filters']="deleted";
		$AdGuardinfo['stats']=$this->getAdGuard('stats');
		$AdGuardinfo['stats']['top_queried_domains']="deleted";
		$AdGuardinfo['stats']['top_clients']="deleted";
		$AdGuardinfo['stats']['top_blocked_domains']="deleted";
		$AdGuardinfo['stats']['dns_queries']="deleted";
		$AdGuardinfo['stats']['blocked_filtering']="deleted";
		$AdGuardinfo['stats']['replaced_safebrowsing']="deleted";
		$AdGuardinfo['stats']['replaced_parental']="deleted";
		$AdGuardinfo['version']=$this->getAdGuard('version.json');
		$AdGuardinfo['clients']=$this->getAdGuard('clients');
		$AdGuardinfo['clients']['auto_clients']="deleted";
		$AdGuardinfo['clients']['supported_tags']="deleted";
		$AdGuardinfo['blocked_services']=$this->getAdGuard('blocked_services/get');
		
		$temp_services_list=$this->getAdGuard('blocked_services/all');
		$AdGuardinfo['services_list']=[];
		if($temp_services_list && is_array($temp_services_list)) {
			foreach($temp_services_list['blocked_services'] as $i=>$s) {
				$AdGuardinfo['services_list'][$temp_services_list['blocked_services'][$i]['id']]=$temp_services_list['blocked_services'][$i]['name'];
			}
		}
		$temp_services_list=null;

		return $AdGuardinfo;
	}
	
	public function getAdGuardInfo($allowListServices=false) {
		if(!$this->getIsEnable()) return;
		try {
				
			$AdGuardinfo=$this->getAdGuardStatut();
			if(!$AdGuardinfo) return;

			log::add('AdGuard','info','Reçu info de AdGuard Home');
			log::add('AdGuard','debug','Reçu:'.json_encode($AdGuardinfo));
			
			$protection_enabled = $this->getCmd(null, 'protection_enabled');
			$this->checkAndUpdateCmd($protection_enabled, (($AdGuardinfo['protection_enabled']===true)?1:0));

			// temps de pause restant, renvoyé en millisecondes par AdGuard Home
			$protection_disabled_duration = $this->getCmd(null, 'protection_disabled_duration');
			$pauseMs = (isset($AdGuardinfo['protection_disabled_duration']) && is_numeric($AdGuardinfo['protection_disabled_duration'])) ? $AdGuardinfo['protection_disabled_duration'] : 0;
			$this->checkAndUpdateCmd($protection_disabled_duration, (($AdGuardinfo['protection_enabled']===true) ? 0 : (int) ceil($pauseMs/1000)));
			
			// filtering
			$filtering_enabled = $this->getCmd(null, 'filtering_enabled');
			$this->checkAndUpdateCmd($filtering_enabled, (($AdGuardinfo['filtering']['enabled']===true)?1:0));
			// safebrowsing
			$safebrowsing_enabled = $this->getCmd(null, 'safebrowsing_enabled');
			$this->checkAndUpdateCmd($safebrowsing_enabled, (($AdGuardinfo['safebrowsing']['enabled']===true)?1:0));
			// parental
			$parental_enabled = $this->getCmd(null, 'parental_enabled');
			$this->checkAndUpdateCmd($parental_enabled, (($AdGuardinfo['parental']['enabled']===true)?1:0));
			// safesearch
			$safesearch_enabled = $this->getCmd(null, 'safesearch_enabled');
			$this->checkAndUpdateCmd($safesearch_enabled, (($AdGuardinfo['safesearch']['enabled']===true)?1:0));
			// blocked_services
			$blocked_services = $this->getCmd(null, 'blocked_services');
			$this->checkAndUpdateCmd($blocked_services, str_replace(['"','[',']','null'],'',json_encode($AdGuardinfo['blocked_services']['ids'])));
			
			// write new servicesList if it's the cron only (to avoid infinite loop with postSave
			if($allowListServices) {
				self::setServicesList($AdGuardinfo['services_list']);
			}
			
			// internet_block
			$blocked_internet = $this->getCmd(null, 'blocked_internet');
			$blockString='||*^$important';
			$filtering_status=$AdGuardinfo['filtering'];
			if(!is_array($filtering_status['user_rules'])) $filtering_status['user_rules']=[];
			$ruleList=implode("\n",(array)$filtering_status['user_rules']);
			if(strpos($ruleList,$blockString) !== false) {
				$this->checkAndUpdateCmd($blocked_internet, 1);
			} else {
				$this->checkAndUpdateCmd($blocked_internet, 0);
			}
			
			// stats
			$stats = AdGuard::getStructure('stats');
			foreach($stats as $id => $trad) {
				$AdGuardCmd = $this->getCmd(null, $id);
				if(strpos($id,'avg_processing_time') !== false) $AdGuardinfo['stats'][$id]=round($AdGuardinfo['stats'][$id]*1000,0);
				$this->checkAndUpdateCmd($AdGuardCmd, $AdGuardinfo['stats'][$id]);
			}
			
			// updates
			if($AdGuardinfo['version'] !== null && !$AdGuardinfo['version']['disabled']) {
				if($AdGuardinfo['version']['can_autoupdate']) { // if new version -> update new_version number
					$newVersion = $this->getCmd(null, 'newVersion');
					$this->checkAndUpdateCmd($newVersion, $AdGuardinfo['version']['new_version']);
				} else { // update current version number
					$currentVersion = $this->getCmd(null, 'currentVersion');
					$this->checkAndUpdateCmd($currentVersion, $AdGuardinfo['version']['new_version']);
					$newVersion = $this->getCmd(null, 'newVersion');
					$this->checkAndUpdateCmd($newVersion, '');
				}
				$hasUpdateAdGuard = $this->getCmd(null, 'hasUpdateAdGuard');
				$this->checkAndUpdateCmd($hasUpdateAdGuard, (($AdGuardinfo['version']['can_autoupdate']===true)?1:0));
			}elseif($AdGuardinfo['version'] === null) {
				$currentVersion = $this->getCmd(null, 'currentVersion');
				$this->checkAndUpdateCmd($currentVersion, __("Inconnu", __FILE__));
				$newVersion = $this->getCmd(null, 'newVersion');
				$this->checkAndUpdateCmd($newVersion, '');
				$hasUpdateAdGuard = $this->getCmd(null, 'hasUpdateAdGuard');
				$this->checkAndUpdateCmd($hasUpdateAdGuard, 0);
				log::add('AdGuard','info','version.json pas disponible sur AdGuard, version inconnue');
			}
			// clients
			if(is_array($AdGuardinfo['clients']['clients'])) {
				foreach($AdGuardinfo['clients']['clients'] as $client) {
					$eqp = eqLogic::byLogicalId($this->getId().'-'.$client['name'],'AdGuard');
					
					if(is_object($eqp)) {
						// client_ids
						$client_ids = $eqp->getCmd(null, 'client_ids');
						$eqp->checkAndUpdateCmd($client_ids, str_replace(['"','[',']'],'',json_encode($client['ids'])));
						// filtering
						$client_filtering_enabled = $eqp->getCmd(null, 'client_filtering_enabled');
						$eqp->checkAndUpdateCmd($client_filtering_enabled, (($client['filtering_enabled']===true)?1:0));
						// safebrowsing
						$client_safebrowsing_enabled = $eqp->getCmd(null, 'client_safebrowsing_enabled');
						$eqp->checkAndUpdateCmd($client_safebrowsing_enabled, (($client['safebrowsing_enabled']===true)?1:0));
						// parental
						$client_parental_enabled = $eqp->getCmd(null, 'client_parental_enabled');
						$eqp->checkAndUpdateCmd($client_parental_enabled, (($client['parental_enabled']===true)?1:0));
						// safesearch
						$client_safesearch_enabled = $eqp->getCmd(null, 'client_safesearch_enabled');
						$eqp->checkAndUpdateCmd($client_safesearch_enabled, (($client['safe_search']['enabled']===true)?1:0));
						// client_use_global_blocked_services
						$client_use_global_blocked_services = $eqp->getCmd(null, 'client_use_global_blocked_services');
						$eqp->checkAndUpdateCmd($client_use_global_blocked_services, (($client['use_global_blocked_services']===true)?1:0));
						// client_use_global_settings
						$client_use_global_settings = $eqp->getCmd(null, 'client_use_global_settings');
						$eqp->checkAndUpdateCmd($client_use_global_settings, (($client['use_global_settings']===true)?1:0));
						// client_blocked_services
						$client_blocked_services = $eqp->getCmd(null, 'client_blocked_services');
						$eqp->checkAndUpdateCmd($client_blocked_services, str_replace(['"','[',']','null'],'',json_encode($client['blocked_services'])));
						// client_blocked_internet
						$client_blocked_internet = $eqp->getCmd(null, 'client_blocked_internet');
						
						$name=addcslashes(addslashes($client['name']), ',|');
						$blockString="||*^\$client='".$name."',important";
						$filtering_status=$AdGuardinfo['filtering'];
						$ruleList=implode("\n",(array)$filtering_status['user_rules']);
						if(strpos($ruleList,$blockString) !== false) {
							$eqp->checkAndUpdateCmd($client_blocked_internet, 1);
						} else {
							$eqp->checkAndUpdateCmd($client_blocked_internet, 0);
						}
					} 
				}
			}
			
			$online = $this->getCmd(null, 'online');
			if (is_object($online)) {
				$this->checkAndUpdateCmd($online, '1');
			}
		} catch (Exception $e) {
			if($e->getCode() == "404") {
				$online = $this->getCmd(null, 'online');
				if (is_object($online)) {
					$this->checkAndUpdateCmd($online, '0');
				}
			}
		}
	} 
	
	public function createCmd($cmd, $order) {

		$newCmd = $this->getCmd(null, $cmd['logicalId']);
		if (!is_object($newCmd)) {
			log::add('AdGuard', 'info', 'Création commande:' . $cmd['logicalId']);
			$newCmd = new AdGuardCmd();
			$newCmd->setLogicalId($cmd['logicalId']);
			$newCmd->setType($cmd['type']);
			$newCmd->setSubType($cmd['subtype']);
			$newCmd->setIsVisible($cmd['isVisible']);
			if($cmd['type'] == 'info' && isset($cmd['isHistorized'])) $newCmd->setIsHistorized($cmd['isHistorized']);
			$newCmd->setOrder($order);
			$newCmd->setEqLogic_id($this->getId());
		}
		else {
			log::add('AdGuard', 'debug', 'Modification commande:' . $cmd['logicalId']);
		}
		$newCmd->setName($cmd['name']);
		if (isset($cmd['unit'])) {
			$newCmd->setUnite($cmd['unit']);
		}
		if (isset($cmd['configuration'])) {
			foreach ($cmd['configuration'] as $configuration_type => $configuration_value) {
				if($configuration_type == 'listValue' && strpos($cmd['logicalId'],'service_') !== false) {
					$list=[];
					foreach(AdGuard::serviceList() as $val => $label) {
						array_push($list,$val.'|'.$label);
					}
					$configuration_value=join(';',$list);
				} elseif($configuration_type == 'listValue' && strpos($cmd['logicalId'],'group_') !== false) {
					$list=[];
					foreach(AdGuard::serviceGroupList() as $val => $label) {
						array_push($list,$val.'|'.$label);
					}
					$configuration_value=join(';',$list);
				}
				$newCmd->setConfiguration($configuration_type, $configuration_value);
			}
		}
		if (isset($cmd['template'])) {
			foreach ($cmd['template'] as $template_type => $template_value) {
				$newCmd->setTemplate($template_type, $template_value);
			}
		}
		if (isset($cmd['display'])) {
			foreach ($cmd['display'] as $display_type => $display_value) {
				if ($display_type == "generic_type") {
					$newCmd->setGeneric_type($display_value);
				}
				else {
					if ($newCmd->getDisplay($display_type) == "") {
						$newCmd->setDisplay($display_type, $display_value);
					}
				}
			}
		}
		
		if ($cmd['type'] == 'action' && isset($cmd['value'])) {
			$linkStatus = $this->getCmd(null, $cmd['value']);
			if (is_object($linkStatus)) $newCmd->setValue($linkStatus->getId());
		}
		$newCmd->save();
	}
	
	public function getImage(){
		if ($this->getConfiguration('type','') == 'AdGuardGlobal'){
			return 'plugins/AdGuard/plugin_info/AdGuard_icon.png';
		}else {
			return 'plugins/AdGuard/plugin_info/AdGuard_user.png';
		}
	}
	
	public function preSave() {
		if ($this->getConfiguration('type','') == ''){
			$this->setConfiguration('type','AdGuardGlobal');
		}
	}

	public function postSave() {
		$type=$this->getConfiguration('type','');
		//if($type != 'AdGuardGlobal') return true;
		
		$order=0;
		$device = self::devicesParameters($type);
	
		foreach($device['commands'] as $cmd) {
			$order++;
			$this->createCmd($cmd,$order);
		}
		
		if($type == 'AdGuardGlobal') {
			// stats
			$stats = self::getStructure('stats');
			foreach($stats as $id => $trad) {
				$order++;
				$cmd = [
					"name" => $trad,
					"type" => 'info',
					"subtype" => 'numeric',
					"template" => [
						"dashboard" => 'line',
						"mobile" => 'line'
					],
					"display" => [
						"generic_type" => 'GENERIC_INFO'
					],
					"isVisible"=> 1,
					"isHistorized"=> 0,
					"logicalId"=> $id
				];
				if(strpos($id,'avg_processing_time') !== false) $cmd['unit']='ms';
				$this->createCmd($cmd,$order);		
			}
			
			$clientList=[];
			$clients=$this->getAdGuard('clients');
			if($clients && $clients['clients'] && is_array($clients['clients'])) {
				foreach($clients['clients'] as $client) {
					$eq = [
						"name"=>$client['name'],
						"logicalId"=>$this->getId().'-'.$client['name'],
						"enable"=>1,
						"visible"=>1,
						"object_id"=>$this->getObject_id(),
						"configuration"=>[
							"server"=>$this->getId(),
							"type"=>'Client'
						],
						"serverName"=>$this->getName()
					];
					self::createEq($eq);
					array_push($clientList,$this->getId().'-'.$client['name']);
				}
			}
			$eqLogics = eqLogic::byType('AdGuard');
			foreach ($eqLogics as $eqLogic) {
				if($eqLogic->getConfiguration('type','') != 'Client') continue;
				if($eqLogic->getConfiguration('server','') != $this->getId()) continue;
				
				if(!in_array($eqLogic->getLogicalId(),$clientList)) {
					log::add('AdGuard','info','Pas trouvé dans la liste de clients de AdGuard : '.$eqLogic->getLogicalId().' -> désactivation de l\'équipement');
					$eqLogic->setIsEnable(0);
					$eqLogic->save(true);
				}
			}
			
			$this->getAdGuardInfo(false);
		}
	}
	public function preRemove() {
		if($this->getConfiguration('type','') == "AdGuardGlobal") {
			$eqLogics = eqLogic::byType('AdGuard');
			foreach ($eqLogics as $eqLogic) {
				if($eqLogic->getConfiguration('type','') != "Client") continue;
				
				if($eqLogic->getConfiguration('server','') == $this->getId()) { // if this bridgedAccessory logicalId contains this bridge logicalId
					$eqLogic->remove();
				}
			}
		}
	}
}

class AdGuardCmd extends cmd {
	/***************************Attributs*******************************/


	/*************************Methode static****************************/

	/***********************Methode d'instance**************************/
  	public function refresh() {
		$this->execute();
	}
	
	/**
	 * Lit une réponse JSON d'AdGuard Home et lève une exception claire si elle est vide ou invalide.
	 */
	private static function fetchFromAdGuard($AdGuard, $endpoint) {
		$data = $AdGuard->getAdGuard($endpoint);
		if (!is_array($data)) {
			$error = $AdGuard->getAdGuardLastError();
			throw new Exception(__('AdGuard Home n\'a pas renvoyé de réponse valide pour', __FILE__) . ' ' . $endpoint . (($error) ? ' : ' . $error : ''));
		}
		return $data;
	}

	private static function getFilteringStatus($AdGuard) {
		$filtering_status = self::fetchFromAdGuard($AdGuard, 'filtering/status');
		if (!isset($filtering_status['user_rules']) || !is_array($filtering_status['user_rules'])) {
			$filtering_status['user_rules'] = []; // aucune règle personnalisée
		}
		return $filtering_status;
	}

	private static function getBlockedServices($AdGuard) {
		$blocked_services = self::fetchFromAdGuard($AdGuard, 'blocked_services/get');
		if (!isset($blocked_services['ids']) || !is_array($blocked_services['ids'])) {
			$blocked_services['ids'] = []; // aucun service bloqué
		}
		if (isset($blocked_services['schedule']) && (!is_array($blocked_services['schedule']) || count($blocked_services['schedule']) == 0)) {
			unset($blocked_services['schedule']); // un planning vide serait renvoyé en [] au lieu de {}
		}
		return $blocked_services;
	}

	private static function getGroupServices($AdGuard, $groupId) {
		$all = self::fetchFromAdGuard($AdGuard, 'blocked_services/all');
		$ids = [];
		if (isset($all['blocked_services']) && is_array($all['blocked_services'])) {
			foreach ($all['blocked_services'] as $service) {
				if (isset($service['group_id']) && $service['group_id'] === $groupId && isset($service['id'])) {
					$ids[] = $service['id'];
				}
			}
		}
		if (count($ids) == 0) {
			throw new Exception(__('Aucun service trouvé pour ce groupe, votre version d\'AdGuard Home gère-t-elle les groupes (v0.107.68 ou plus) ?', __FILE__) . ' (' . $groupId . ')');
		}
		return $ids;
	}

	private static function formatCheckHost($host, $result) {
		$reason = (isset($result['reason'])) ? $result['reason'] : '';
		$labels = [
			'NotFilteredNotFound' => __('Autorisé', __FILE__),
			'NotFilteredAllowList' => __('Autorisé par une règle d\'autorisation', __FILE__),
			'NotFilteredError' => __('Erreur lors du test', __FILE__),
			'FilteredBlackList' => __('Bloqué par un filtre', __FILE__),
			'FilteredSafeBrowsing' => __('Bloqué par la navigation sécurisée', __FILE__),
			'FilteredParental' => __('Bloqué par le contrôle parental', __FILE__),
			'FilteredInvalid' => __('Bloqué (requête invalide)', __FILE__),
			'FilteredSafeSearch' => __('Recherche sécurisée forcée', __FILE__),
			'FilteredBlockedService' => __('Bloqué par le service', __FILE__),
			'Rewrite' => __('Réécrit', __FILE__),
			'RewriteEtcHosts' => __('Réécrit par le fichier hosts', __FILE__),
			'RewriteRule' => __('Réécrit par une règle', __FILE__)
		];
		$text = $host . ' : ' . ((isset($labels[$reason])) ? $labels[$reason] : $reason);
		if ($reason == 'FilteredBlockedService' && !empty($result['service_name'])) {
			$text .= ' ' . $result['service_name'];
		}
		if (strpos($reason, 'Rewrite') === 0) {
			$targets = [];
			if (!empty($result['cname'])) $targets[] = $result['cname'];
			if (!empty($result['ip_addrs']) && is_array($result['ip_addrs'])) $targets = array_merge($targets, $result['ip_addrs']);
			if (count($targets)) $text .= ' → ' . implode(', ', $targets);
		}
		if (!empty($result['rules']) && is_array($result['rules'])) {
			$rules = [];
			foreach ($result['rules'] as $rule) {
				if (!empty($rule['text'])) $rules[] = $rule['text'];
			}
			if (count($rules)) $text .= ' (' . __('règle', __FILE__) . ' : ' . implode(' ; ', $rules) . ')';
		}
		return $text;
	}

	private static function checkHost($AdGuard, $eqLogic, $infoLogicalId, $_options, $clientId = null) {
		$host = (isset($_options['message'])) ? trim($_options['message']) : '';
		if ($host === '') {
			throw new Exception(__('Le domaine à tester est vide', __FILE__));
		}
		$params = ['name' => $host];
		if ($clientId !== null) $params['client'] = $clientId;
		$result = $AdGuard->getAdGuard('filtering/check_host', $params);
		if (!is_array($result)) {
			$error = $AdGuard->getAdGuardLastError();
			throw new Exception(__('Echec du test du domaine', __FILE__) . ' ' . $host . (($error) ? ' : ' . $error : ''));
		}
		$eqLogic->checkAndUpdateCmd($infoLogicalId, self::formatCheckHost($host, $result));
		return true;
	}

	private static function getClientName($eqLogic) {
		// logicalId = <id serveur>-<nom du client>, le nom peut lui-même contenir des tirets
		$name = explode('-', $eqLogic->getLogicalId(), 2);
		if (!isset($name[1]) || $name[1] === '') {
			throw new Exception(__('Identifiant de client invalide :', __FILE__) . ' ' . $eqLogic->getLogicalId());
		}
		return $name[1];
	}

	private static function getClient($AdGuard, $eqLogic) {
		$name = self::getClientName($eqLogic);
		$clients = self::fetchFromAdGuard($AdGuard, 'clients');
		if (isset($clients['clients']) && is_array($clients['clients'])) {
			foreach ($clients['clients'] as $client) {
				if (isset($client['name']) && $client['name'] == $name) {
					return $client;
				}
			}
		}
		throw new Exception(__('Client introuvable dans AdGuard Home :', __FILE__) . ' ' . $name);
	}

	private static function clientUpdate($client) {
		return ["name" => $client['name'], "data" => $client];
	}

	public function execute($_options = null) {
		if ($this->getType() == '') {
			return '';
		}
		$eqLogic = $this->getEqlogic();
		$type = $eqLogic->getConfiguration('type','');
		$AdGuard = null;
		if($type == "Client") {
			$serverId = $eqLogic->getConfiguration('server','');
			if($serverId) {
				$AdGuard=eqLogic::byId($serverId);
			}
		} else {
			$AdGuard=$eqLogic;
		}
		if (!is_object($AdGuard)) {
			throw new Exception(__('Aucun serveur AdGuard Home associé à', __FILE__) . ' ' . $eqLogic->getHumanName());
		}
		$logical = $this->getLogicalId();
		$cmd=null;
		$params=null;
		$sleep=null;
		$type='POST';
		$fallback=null; // ancien appel à utiliser si la version d'AdGuard Home ne connaît pas le nouveau
		if ($logical != 'refresh'){
			switch ($logical) {
				case 'protection_disable':
					$cmd = 'protection';
					$params = ["enabled" => false];
					if(isset($_options['select']) && is_numeric($_options['select']) && $_options['select']>0 ) { 
						$params['duration'] = $_options['select']*1000;
					}
				break;
				case 'protection_enable':
					$cmd = 'protection';
					$params = ["enabled" => true];
				break;
				case 'UpdateAdGuard':
					$cmd = 'update';
					$sleep=1;
				break;
				case 'filtering_enable':
				case 'filtering_disable':
					$filtering_status=self::fetchFromAdGuard($AdGuard, 'filtering/status');
					if (!isset($filtering_status['interval'])) {
						throw new Exception(__('AdGuard Home n\'a pas renvoyé l\'intervalle de mise à jour des filtres', __FILE__));
					}
					$cmd = 'filtering/config';
					$params = ["enabled" => ($logical == 'filtering_enable'),"interval"=> $filtering_status['interval']];
				break;
				// AdGuard Home >= v1.0.1 : PUT /safebrowsing et PUT /parental, les anciens POST .../enable|disable sont dépréciés
				case 'safebrowsing_enable':
				case 'safebrowsing_disable':
				case 'parental_enable':
				case 'parental_disable':
					list($feature, $action) = explode('_', $logical);
					$cmd = $feature;
					$params = ["enabled" => ($action == 'enable')];
					$type = "PUT";
					$fallback = ['cmd' => $feature.'/'.$action, 'params' => null, 'type' => 'POST'];
				break;
				case 'safesearch_enable':
				case 'safesearch_disable':
					// on garde les choix moteur par moteur faits dans AdGuard Home, seul "enabled" change
					$safesearch = self::fetchFromAdGuard($AdGuard, 'safesearch/status');
					$safesearch['enabled'] = ($logical == 'safesearch_enable');
					if ($safesearch['enabled']) {
						$engines = ['bing', 'duckduckgo', 'ecosia', 'google', 'pixabay', 'yandex', 'youtube'];
						$anyEngine = false;
						foreach ($engines as $engine) {
							if (!empty($safesearch[$engine])) $anyEngine = true;
						}
						if (!$anyEngine) { // aucun moteur coché (ex : désactivé par une ancienne version du plugin) -> on les active tous
							foreach ($engines as $engine) {
								$safesearch[$engine] = true;
							}
						}
					}
					$cmd = 'safesearch/settings';
					$params = $safesearch;
					$type = "PUT";
				break;
				case 'reset_stats':
					$cmd = 'stats_reset';
				break;
				case 'cache_clear':
					$cmd = 'cache_clear';
				break;
				case 'filters_refresh':
					$cmd = 'filtering/refresh';
					$params = ["whitelist" => false];
				break;
				case 'check_host':
					return self::checkHost($AdGuard, $eqLogic, 'check_host_result', $_options);
				case 'group_block':
				case 'group_unblock':
					if(!isset($_options['select']) || $_options['select'] == "") break;
					$groupServices=self::getGroupServices($AdGuard, $_options['select']);
					$blocked_services=self::getBlockedServices($AdGuard);
					if ($logical == 'group_block') {
						$blocked_services['ids']=array_values(array_unique(array_merge($blocked_services['ids'],$groupServices),SORT_STRING));
					} else {
						$blocked_services['ids']=array_values(array_diff($blocked_services['ids'],$groupServices));
					}
					$cmd='blocked_services/update';
					$params=$blocked_services; // renvoie aussi le planning, sinon AdGuard Home l'efface
					$type = "PUT";
				break;
				case 'service_block':
					if(!isset($_options['select']) || $_options['select'] == "") break;
					$blocked_services=self::getBlockedServices($AdGuard);
					array_push($blocked_services['ids'],$_options['select']);
					$blocked_services['ids']=array_values(array_unique($blocked_services['ids'],SORT_STRING));
					$cmd='blocked_services/update';
					$params=$blocked_services; // renvoie aussi le planning, sinon AdGuard Home l'efface
					$type = "PUT";
				break;
				case 'service_unblock':
					if(!isset($_options['select']) || $_options['select'] == "") break;
					$blocked_services=self::getBlockedServices($AdGuard);
					if (($key = array_search($_options['select'], $blocked_services['ids'])) !== false) {
						array_splice($blocked_services['ids'],$key,1);
						$cmd='blocked_services/update';
						$params=$blocked_services;
						$type = "PUT";
					}
				break;
				case 'services_block':
				case 'services_unblock':
					$blocked_services=self::getBlockedServices($AdGuard);
					$blocked_services['ids']=(($logical == 'services_block') ? array_keys(AdGuard::serviceList()) : []);
					$cmd='blocked_services/update';
					$params=$blocked_services; // renvoie aussi le planning, sinon AdGuard Home l'efface
					$type = "PUT";
				break;
				case 'internet_block':
				case 'add_custom_rule':
				case 'client_internet_block':
					if ($logical == 'add_custom_rule') {
						$blockString = (isset($_options['message'])) ? trim($_options['message']) : '';
						if ($blockString === '') {
							throw new Exception(__('La règle à ajouter est vide', __FILE__));
						}
					} elseif ($logical == 'client_internet_block') {
						$name=addcslashes(addslashes(self::getClientName($eqLogic)), ',|');
						$blockString="||*^\$client='".$name."',important";
					} else {
						$blockString='||*^$important';
					}
					$filtering_status=self::getFilteringStatus($AdGuard);
					if (in_array($blockString, $filtering_status['user_rules'], true)) break; // déjà présente
					array_unshift($filtering_status['user_rules'],$blockString);
					$cmd="filtering/set_rules";
					$params=["rules"=>$filtering_status['user_rules']];
				break;
				case 'internet_unblock':
				case 'del_custom_rule':
				case 'client_internet_unblock':
					if ($logical == 'del_custom_rule') {
						$blockString = (isset($_options['message'])) ? trim($_options['message']) : '';
						if ($blockString === '') {
							throw new Exception(__('La règle à supprimer est vide', __FILE__));
						}
					} elseif ($logical == 'client_internet_unblock') {
						$name=addcslashes(addslashes(self::getClientName($eqLogic)), ',|');
						$blockString="||*^\$client='".$name."',important";
					} else {
						$blockString='||*^$important';
					}
					$filtering_status=self::getFilteringStatus($AdGuard);
					$ruleIndex=array_search($blockString,$filtering_status['user_rules'],true);
					if($ruleIndex === false) break; // rien à supprimer
					array_splice($filtering_status['user_rules'],$ruleIndex,1);
					$cmd="filtering/set_rules";
					$params=["rules"=>$filtering_status['user_rules']];
				break;
				
				// block everything for a client (first rule !) : ||*^$client='Nebz iPhone',important 
				// Use the backslash (\) to escape quotes (" and '), commas (,), and pipes (|) in client name
				
				// CLIENT
				case 'client_use_global_settings_enable':
				case 'client_use_global_settings_disable':
					$client=self::getClient($AdGuard, $eqLogic);
					$client['use_global_settings']=($logical == 'client_use_global_settings_enable');
					$cmd='clients/update';
					$params=self::clientUpdate($client);
				break;
				case 'client_filtering_enable':
				case 'client_filtering_disable':
					$client=self::getClient($AdGuard, $eqLogic);
					$client['filtering_enabled']=($logical == 'client_filtering_enable');
					$cmd='clients/update';
					$params=self::clientUpdate($client);
				break;
				case 'client_safebrowsing_enable':
				case 'client_safebrowsing_disable':
					$client=self::getClient($AdGuard, $eqLogic);
					$client['safebrowsing_enabled']=($logical == 'client_safebrowsing_enable');
					$cmd='clients/update';
					$params=self::clientUpdate($client);
				break;
				case 'client_parental_enable':
				case 'client_parental_disable':
					$client=self::getClient($AdGuard, $eqLogic);
					$client['parental_enabled']=($logical == 'client_parental_enable');
					$cmd='clients/update';
					$params=self::clientUpdate($client);
				break;
				case 'client_safesearch_enable':
				case 'client_safesearch_disable':
					$enabled=($logical == 'client_safesearch_enable');
					$client=self::getClient($AdGuard, $eqLogic);
					$client['safe_search']=["enabled" => $enabled,"bing" => $enabled, "duckduckgo" => $enabled, "google" => $enabled, "pixabay" => $enabled, "yandex" => $enabled, "youtube" => $enabled];
					$cmd='clients/update';
					$params=self::clientUpdate($client);
				break;
				case 'client_use_global_blocked_services_enable':
				case 'client_use_global_blocked_services_disable':
					$client=self::getClient($AdGuard, $eqLogic);
					$client['use_global_blocked_services']=($logical == 'client_use_global_blocked_services_enable');
					$cmd='clients/update';
					$params=self::clientUpdate($client);
				break;
				case 'client_service_block':
					if(!isset($_options['select']) || $_options['select'] == "") break;
					$client=self::getClient($AdGuard, $eqLogic);
					if(!isset($client['blocked_services']) || !is_array($client['blocked_services'])) $client['blocked_services']=[];
					array_push($client['blocked_services'],$_options['select']);
					$client['blocked_services']=array_values(array_unique($client['blocked_services'],SORT_STRING));
					$cmd='clients/update';
					$params=self::clientUpdate($client);
				break;
				case 'client_service_unblock':
					if(!isset($_options['select']) || $_options['select'] == "") break;
					$client=self::getClient($AdGuard, $eqLogic);
					if(!isset($client['blocked_services']) || !is_array($client['blocked_services'])) break;
					if (($key = array_search($_options['select'], $client['blocked_services'])) !== false) {
						array_splice($client['blocked_services'],$key,1);
						$cmd='clients/update';
						$params=self::clientUpdate($client);
					}
				break;
				case 'client_services_block':
					$client=self::getClient($AdGuard, $eqLogic);
					$client['blocked_services']=array_keys(AdGuard::serviceList());
					$cmd='clients/update';
					$params=self::clientUpdate($client);
				break;
				case 'client_services_unblock':
					$client=self::getClient($AdGuard, $eqLogic);
					$client['blocked_services']=[];
					$cmd='clients/update';
					$params=self::clientUpdate($client);
				break;
				case 'client_group_block':
				case 'client_group_unblock':
					if(!isset($_options['select']) || $_options['select'] == "") break;
					$groupServices=self::getGroupServices($AdGuard, $_options['select']);
					$client=self::getClient($AdGuard, $eqLogic);
					if(!isset($client['blocked_services']) || !is_array($client['blocked_services'])) $client['blocked_services']=[];
					if ($logical == 'client_group_block') {
						$client['blocked_services']=array_values(array_unique(array_merge($client['blocked_services'],$groupServices),SORT_STRING));
					} else {
						$client['blocked_services']=array_values(array_diff($client['blocked_services'],$groupServices));
					}
					$cmd='clients/update';
					$params=self::clientUpdate($client);
				break;
				case 'client_check_host':
					$client=self::getClient($AdGuard, $eqLogic);
					$clientId=null;
					if(isset($client['ids']) && is_array($client['ids'])) {
						foreach($client['ids'] as $id) {
							if(strpos($id, 'notused') === false) { $clientId=$id; break; }
						}
					}
					if($clientId === null) {
						throw new Exception(__('Ce client n\'a aucun identifiant utilisable pour le test', __FILE__));
					}
					return self::checkHost($AdGuard, $eqLogic, 'client_check_host_result', $_options, $clientId);
				case 'client_ids_add':
					$newId = (isset($_options['message'])) ? trim($_options['message']) : '';
					if ($newId === '') {
						throw new Exception(__('L\'identifiant à ajouter est vide', __FILE__));
					}
					$client=self::getClient($AdGuard, $eqLogic);
					if(!isset($client['ids']) || !is_array($client['ids'])) $client['ids']=[];
					if(count($client['ids']) == 1 && strpos($client['ids'][0], 'notused') !== false) $client['ids']=[]; // was a not used client
					if(in_array($newId, $client['ids'], true)) break; // déjà présent
					array_push($client['ids'],$newId);
					$cmd='clients/update';
					$params=self::clientUpdate($client);
				break;
				case 'client_ids_del':
					$delId = (isset($_options['message'])) ? trim($_options['message']) : '';
					if ($delId === '') {
						throw new Exception(__('L\'identifiant à supprimer est vide', __FILE__));
					}
					$client=self::getClient($AdGuard, $eqLogic);
					if(!isset($client['ids']) || !is_array($client['ids'])) break;
					if (($key = array_search($delId, $client['ids'])) !== false) {
						array_splice($client['ids'],$key,1);
						if(count($client['ids']) == 0) array_push($client['ids'],'notused'.str_pad(rand(0,1000),4,0,STR_PAD_LEFT)); // is a not used client
						$cmd='clients/update';
						$params=self::clientUpdate($client);
					}
				break;
				/*
				@@||app-measurement.com^$important
				@@||www.littlefabrics.com^$important
				@@||self.events.data.microsoft.com^$important
				*/
			}
			
			if(!$cmd) return false;
			
			$AdGuardinfo=$AdGuard->postAdGuard($cmd,$params,$type,($fallback !== null));
			if($fallback && in_array($AdGuard->getAdGuardLastHttpCode(), [404, 405])) {
				log::add('AdGuard','debug','Commande '.$cmd.' inconnue de cette version d\'AdGuard Home, utilisation de '.$fallback['cmd']);
				$AdGuardinfo=$AdGuard->postAdGuard($fallback['cmd'],$fallback['params'],$fallback['type']);
			}
			$error=$AdGuard->getAdGuardLastError();
			if($error) {
				throw new Exception(__('Echec de la commande', __FILE__) . ' ' . $this->getHumanName() . ' : ' . $error);
			}
			if($sleep) sleep($sleep);
		}
		
		$AdGuard->getAdGuardInfo(true);
	}

	/************************Getteur Setteur****************************/
}
?>
